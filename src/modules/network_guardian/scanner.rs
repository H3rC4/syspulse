use crate::modules::network_guardian::adapters::calculate_subnet_range;
use crate::modules::network_guardian::device_models::*;
use crate::modules::network_guardian::oui::lookup_vendor;
use anyhow::Result;
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[cfg(target_os = "windows")]
use std::ffi::c_void;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::NO_ERROR;
#[cfg(target_os = "windows")]
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIpNetTable2, SendARP, MIB_IPNET_ROW2, MIB_IPNET_TABLE2,
};
#[cfg(target_os = "windows")]
use windows::Win32::Networking::WinSock::{gethostbyaddr, AF_INET};

/// Cadencia predeterminada de escaneo activo: 40 ms por solicitud (~25 paquetes/segundo).
pub const DEFAULT_ACTIVE_SCAN_RATE_MS: u64 = 40;

/// Límite predeterminado de hosts a escanear en escaneo activo (256 hosts).
pub const DEFAULT_MAX_ACTIVE_HOSTS: usize = 256;

/// Tiempo máximo total permitido para un escaneo activo antes de finalizarlo por seguridad.
pub const DEFAULT_ACTIVE_SCAN_TIMEOUT: Duration = Duration::from_secs(15);

/// Tiempo de vida (TTL) de la caché de nombres de host resueltos (5 minutos).
pub const HOSTNAME_CACHE_TTL: Duration = Duration::from_secs(300);

/// Cantidad máxima de trabajadores concurrentes para resolución inversa de hostnames.
pub const MAX_HOSTNAME_RESOLVER_WORKERS: usize = 4;

type HostnameCache = Arc<Mutex<HashMap<Ipv4Addr, (Option<String>, Instant)>>>;

/// Escáner de dispositivos en red local (pasivo por caché ARP y activo bajo demanda con SendARP).
///
/// **Nota de Seguridad de Red:**
/// - El modo **pasivo** (predeterminado) lee la caché ARP del kernel del SO sin generar ningún paquete en la red.
/// - El modo **activo** emite solicitudes unicast SendARP a IPs del rango. Aunque se modula a baja cadencia (~25 req/s),
///   sistemas IDS/IPS corporativos (Suricata, Snort) o switches con Dynamic ARP Inspection (DAI) pueden detectar
///   un barrido secuencial como actividad anómala. Por este motivo, el escaneo activo opera exclusivamente
///   bajo demanda explícita del usuario y con límites estrictos de concurrencia y hosts.
#[derive(Clone)]
pub struct DeviceScanner {
    active_rate_ms: u64,
    max_active_hosts: usize,
    known_trusted_macs: Arc<Mutex<HashSet<String>>>,
    custom_aliases: Arc<Mutex<HashMap<String, String>>>,
    hostname_cache: HostnameCache,
    dns_semaphore: Arc<tokio::sync::Semaphore>,
}

impl Default for DeviceScanner {
    fn default() -> Self {
        Self::new(DEFAULT_ACTIVE_SCAN_RATE_MS, DEFAULT_MAX_ACTIVE_HOSTS)
    }
}

impl DeviceScanner {
    pub fn new(active_rate_ms: u64, max_active_hosts: usize) -> Self {
        Self {
            active_rate_ms,
            max_active_hosts,
            known_trusted_macs: Arc::new(Mutex::new(HashSet::new())),
            custom_aliases: Arc::new(Mutex::new(HashMap::new())),
            hostname_cache: Arc::new(Mutex::new(HashMap::new())),
            dns_semaphore: Arc::new(tokio::sync::Semaphore::new(MAX_HOSTNAME_RESOLVER_WORKERS)),
        }
    }

    /// Configura el límite máximo de hosts a escanear en escaneos activos.
    pub fn set_max_active_hosts(&mut self, max: usize) {
        self.max_active_hosts = max;
    }

    /// Retorna el límite configurado de hosts para escaneo activo.
    pub fn max_active_hosts(&self) -> usize {
        self.max_active_hosts
    }

    /// Configura la cadencia en milisegundos entre solicitudes SendARP.
    pub fn set_active_rate_ms(&mut self, rate_ms: u64) {
        self.active_rate_ms = rate_ms;
    }

    /// Retorna la cadencia en milisegundos entre solicitudes SendARP.
    pub fn active_rate_ms(&self) -> u64 {
        self.active_rate_ms
    }

    /// Marca una MAC como de confianza explícita del usuario.
    pub async fn mark_trusted(&self, mac: &str) {
        let mut set = self.known_trusted_macs.lock().await;
        set.insert(mac.trim().to_ascii_uppercase());
    }

    /// Asigna un alias personalizado a un dispositivo.
    pub async fn set_custom_alias(&self, mac: &str, alias: String) {
        let mut map = self.custom_aliases.lock().await;
        map.insert(mac.trim().to_ascii_uppercase(), alias);
    }

    /// Escaneo pasivo instantáneo leyendo la tabla ARP del kernel del sistema operativo local.
    /// Operación estrictamente local que consulta la MIB del kernel sin generar paquetes en el medio de transmisión.
    pub async fn scan_passive_arp(&self, network_id: &str) -> Result<Vec<DiscoveredDevice>> {
        let net_id = network_id.to_string();
        tokio::task::spawn_blocking(move || Self::read_arp_table_native(&net_id)).await?
    }

    /// Ejecuta un escaneo activo unicast SendARP sobre el prefijo real detectado dinámicamente.
    /// - Vincula `SendARP` a la IP de origen local para evitar fugas en VPNs.
    /// - Respeta el token de cancelación y el timeout máximo de ejecución.
    /// - Acota el escaneo al límite `max_active_hosts` y reporta si el escaneo fue parcial.
    pub async fn scan_active_subnet(
        &self,
        local_ip: Ipv4Addr,
        prefix_len: u8,
        gateway_ip: Option<Ipv4Addr>,
        network_id: &str,
        cancel_token: Option<Arc<AtomicBool>>,
    ) -> Result<(Vec<DiscoveredDevice>, bool, u32, u32)> {
        let (first_host, last_host, total_subnet_hosts) = calculate_subnet_range(local_ip, prefix_len);

        let first_u32 = u32::from(first_host);
        let last_u32 = u32::from(last_host);

        let total_hosts_in_range = if last_u32 >= first_u32 {
            (last_u32 - first_u32) + 1
        } else {
            0
        };

        let hosts_to_scan = total_hosts_in_range.min(self.max_active_hosts as u32);
        let mut is_partial_scan = total_subnet_hosts > self.max_active_hosts as u32;

        let rate_ms = self.active_rate_ms;
        let start_time = Instant::now();
        let timeout = DEFAULT_ACTIVE_SCAN_TIMEOUT;

        let mut discovered = Vec::new();
        let mut scanned_count = 0u32;

        for offset in 0..hosts_to_scan {
            // Verificar cancelación temprana
            if let Some(token) = &cancel_token {
                if token.load(Ordering::Relaxed) {
                    tracing::info!(target: "network_guardian::scanner", "Active scan cancelled by user or interface change");
                    is_partial_scan = true;
                    break;
                }
            }

            // Verificar timeout global
            if start_time.elapsed() >= timeout {
                tracing::warn!(target: "network_guardian::scanner", "Active scan timed out after {:?}", timeout);
                is_partial_scan = true;
                break;
            }

            let target_ip = Ipv4Addr::from(first_u32 + offset);
            scanned_count += 1;

            // Evitar enviar ARP a la propia máquina
            if target_ip == local_ip {
                continue;
            }

            // Realizar SendARP nativo vinculando explícitamente a la IP de origen local
            let src_ip_opt = Some(local_ip);
            let mac_opt = tokio::task::spawn_blocking(move || {
                Self::send_arp_native(target_ip, src_ip_opt)
            })
            .await?;

            if let Some(mac_str) = mac_opt {
                let is_gw = Some(target_ip) == gateway_ip;
                let is_loc = target_ip == local_ip;
                let vendor = lookup_vendor(&mac_str).map(|s| s.to_string());
                let now = Utc::now();

                let category = if is_loc {
                    DeviceDisplayCategory::ThisDevice
                } else if is_gw {
                    DeviceDisplayCategory::GatewayRouter
                } else if let Some(ref v) = vendor {
                    if v.contains("LAA") {
                        DeviceDisplayCategory::LocallyAdministered
                    } else {
                        DeviceDisplayCategory::KnownVendor(v.clone())
                    }
                } else {
                    DeviceDisplayCategory::Unknown
                };

                discovered.push(DiscoveredDevice {
                    network_id: network_id.to_string(),
                    mac: mac_str,
                    ip: target_ip.to_string(),
                    hostname: None, // Se resuelve en segunda etapa desacoplada
                    vendor,
                    is_trusted: is_loc, // Por seguridad, solo este equipo es confiable por defecto
                    is_gateway: is_gw,
                    is_local_machine: is_loc,
                    custom_alias: None,
                    display_category: category,
                    first_seen_utc: now,
                    last_seen_utc: now,
                    detection_source: DeviceDetectionSource::ActiveScan,
                });
            }

            // Cadencia controlada para evitar congestión de radio y switches
            if rate_ms > 0 {
                tokio::time::sleep(Duration::from_millis(rate_ms)).await;
            }
        }

        Ok((discovered, is_partial_scan, total_subnet_hosts, scanned_count))
    }

    /// Resuelve el hostname con caché y timeout rápido para no bloquear la visualización de dispositivos.
    /// Retiene el permiso del semáforo dentro del hilo bloqueante nativo para que permanezca ocupado
    /// hasta que termine la operación nativa en Windows, evitando acumulación de tareas bloqueantes.
    pub async fn resolve_hostname_cached(&self, ip: Ipv4Addr) -> Option<String> {
        // 1. Consultar caché local
        {
            let cache = self.hostname_cache.lock().await;
            if let Some((cached_name, cached_at)) = cache.get(&ip) {
                if cached_at.elapsed() < HOSTNAME_CACHE_TTL {
                    return cached_name.clone();
                }
            }
        }

        // 2. Adquirir permiso del semáforo acotado y delegar a la variante protegida
        if let Ok(permit) = self.dns_semaphore.clone().acquire_owned().await {
            self.resolve_hostname_cached_with_permit(ip, permit).await
        } else {
            None
        }
    }

    /// Variante protegida que retiene un OwnedSemaphorePermit hasta la culminación del hilo bloqueante.
    pub async fn resolve_hostname_cached_with_permit(
        &self,
        ip: Ipv4Addr,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Option<String> {
        // 1. Consultar caché local
        {
            let cache = self.hostname_cache.lock().await;
            if let Some((cached_name, cached_at)) = cache.get(&ip) {
                if cached_at.elapsed() < HOSTNAME_CACHE_TTL {
                    drop(permit);
                    return cached_name.clone();
                }
            }
        }

        // 2. Ejecutar en spawn_blocking reteniendo el permit hasta que el hilo bloqueante termine realmente
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::task::spawn_blocking(move || {
            let res = Self::resolve_hostname_native(ip);
            let _ = tx.send(res);
            drop(permit); // Se libera ÚNICAMENTE cuando la llamada bloqueante nativa de Windows retorna
        });

        let resolved = match tokio::time::timeout(Duration::from_millis(600), rx).await {
            Ok(Ok(name_opt)) => name_opt,
            _ => None,
        };

        // 3. Guardar en caché
        let mut cache = self.hostname_cache.lock().await;
        cache.insert(ip, (resolved.clone(), Instant::now()));

        resolved
    }

    /// Combina el escaneo pasivo con el activo (si fue solicitado), valida el contexto de red
    /// y genera el reporte unificado respetando Modo Simple y Modo Avanzado.
    #[allow(clippy::too_many_arguments)]
    pub async fn perform_full_scan(
        &self,
        local_ip: Option<Ipv4Addr>,
        prefix_len_opt: Option<u8>,
        gateway_ip: Option<Ipv4Addr>,
        interface_id: Option<String>,
        is_vpn_or_virtual: bool,
        run_active: bool,
        cancel_token: Option<Arc<AtomicBool>>,
    ) -> Result<DeviceScanReport> {
        let start_time = Instant::now();

        let prefix_len = prefix_len_opt.unwrap_or(24);
        let iface_id = interface_id.unwrap_or_else(|| "primary_iface".to_string());

        let subnet_cidr = match local_ip {
            Some(ip) => {
                let mask = if prefix_len == 0 { 0 } else { !((1u32 << (32 - prefix_len)) - 1) };
                let net_ip = Ipv4Addr::from(u32::from(ip) & mask);
                format!("{}/{}", net_ip, prefix_len)
            }
            None => "0.0.0.0/0".to_string(),
        };

        let gw_ip_str = gateway_ip.map(|g| g.to_string());
        let loc_ip_str = local_ip.map(|l| l.to_string());

        let network_context = NetworkContext::new(
            subnet_cidr.clone(),
            prefix_len,
            gw_ip_str.clone(),
            iface_id,
            is_vpn_or_virtual,
        );

        let mut devices_by_mac: HashMap<String, DiscoveredDevice> = HashMap::new();

        // 1. Escaneo pasivo de la tabla ARP (Siempre se ejecuta: costo cero en red)
        if let Ok(passive_devices) = self.scan_passive_arp(&network_context.network_id).await {
            for dev in passive_devices {
                devices_by_mac.insert(dev.mac.clone(), dev);
            }
        }

        let mut is_partial_scan = false;
        let mut total_subnet_hosts = 254;
        let mut scanned_hosts_count = 0;

        // 2. Escaneo activo SendARP (Solo si el usuario lo solicita explícitamente y no es VPN por defecto)
        if run_active {
            if is_vpn_or_virtual {
                tracing::warn!(
                    target: "network_guardian::scanner",
                    "Active scan omitted on virtual / VPN interface for safety"
                );
            } else if let Some(loc_ip) = local_ip {
                if let Ok((active_devices, partial, total_hosts, scanned)) = self
                    .scan_active_subnet(
                        loc_ip,
                        prefix_len,
                        gateway_ip,
                        &network_context.network_id,
                        cancel_token,
                    )
                    .await
                {
                    is_partial_scan = partial;
                    total_subnet_hosts = total_hosts;
                    scanned_hosts_count = scanned;

                    for dev in active_devices {
                        devices_by_mac
                            .entry(dev.mac.clone())
                            .and_modify(|existing| {
                                existing.ip = dev.ip.clone();
                                existing.last_seen_utc = Utc::now();
                            })
                            .or_insert(dev);
                    }
                }
            }
        }

        // 3. Aplicar alias, confianza explícita y resolución de nombres desacoplada
        let trusted_set = self.known_trusted_macs.lock().await;
        let aliases_map = self.custom_aliases.lock().await;

        let mut final_devices = Vec::with_capacity(devices_by_mac.len());

        for (_, mut dev) in devices_by_mac {
            if Some(&dev.ip) == gw_ip_str.as_ref() {
                dev.is_gateway = true;
                dev.display_category = DeviceDisplayCategory::GatewayRouter;
            }
            if Some(&dev.ip) == loc_ip_str.as_ref() {
                dev.is_local_machine = true;
                dev.is_trusted = true;
                dev.display_category = DeviceDisplayCategory::ThisDevice;
            }
            if trusted_set.contains(&dev.mac) {
                dev.is_trusted = true;
            }
            if let Some(alias) = aliases_map.get(&dev.mac) {
                dev.custom_alias = Some(alias.clone());
            }

            final_devices.push(dev);
        }
        drop(trusted_set);
        drop(aliases_map);

        // 3.1. Resolver hostnames con caché, timeout y concurrencia acotada (trabajadores limitados)
        let semaphore = self.dns_semaphore.clone();
        let mut join_set = tokio::task::JoinSet::new();

        for (idx, dev) in final_devices.iter().enumerate() {
            if dev.hostname.is_none() {
                if let Ok(ip_parsed) = dev.ip.parse::<Ipv4Addr>() {
                    let sem = semaphore.clone();
                    let scanner = self.clone();
                    join_set.spawn(async move {
                        if let Ok(permit) = sem.acquire_owned().await {
                            let resolved = scanner.resolve_hostname_cached_with_permit(ip_parsed, permit).await;
                            (idx, resolved)
                        } else {
                            (idx, None)
                        }
                    });
                }
            }
        }

        while let Some(res) = join_set.join_next().await {
            if let Ok((idx, resolved_name)) = res {
                if resolved_name.is_some() {
                    final_devices[idx].hostname = resolved_name;
                }
            }
        }

        // Ordenar con prioridad: Este equipo > Router > Confiables > Desconocidos
        final_devices.sort_by(|a, b| {
            if a.is_local_machine != b.is_local_machine {
                return b.is_local_machine.cmp(&a.is_local_machine);
            }
            if a.is_gateway != b.is_gateway {
                return b.is_gateway.cmp(&a.is_gateway);
            }
            if a.is_trusted != b.is_trusted {
                return b.is_trusted.cmp(&a.is_trusted);
            }
            a.ip.cmp(&b.ip)
        });

        // 4. Construir vistas Simple y Avanzada
        let duration_ms = start_time.elapsed().as_millis() as u64;

        let mut trusted_count = 0;
        let mut unknown_count = 0;
        let mut simple_items = Vec::new();

        for dev in &final_devices {
            if dev.is_trusted {
                trusted_count += 1;
            } else {
                unknown_count += 1;
            }

            simple_items.push(SimpleDeviceItem {
                display_name: dev.display_name(),
                device_type_label: dev.display_category.label_es(),
                category_key: dev.display_category.i18n_key().to_string(),
                is_trusted: dev.is_trusted,
                ip: dev.ip.clone(),
                is_unknown_warning: !dev.is_trusted && !dev.is_local_machine,
            });
        }

        let alert_title = if unknown_count > 0 {
            Some(format!(
                "Se detectaron {} dispositivos en tu red",
                final_devices.len()
            ))
        } else {
            None
        };

        let alert_recommendation = if unknown_count > 0 {
            Some("Si utilizas dispositivos nuevos (teléfonos, televisores o consolas), puedes identificarlos y marcarlos como de confianza.".to_string())
        } else {
            None
        };

        let partial_scan_notice = if is_partial_scan {
            Some(format!(
                "Escaneo activo acotado a {} de {} hosts de la subred para proteger el rendimiento de red.",
                scanned_hosts_count, total_subnet_hosts
            ))
        } else {
            None
        };

        let simple = DeviceSimpleView {
            total_devices_count: final_devices.len(),
            trusted_count,
            unknown_count,
            alert_title,
            alert_recommendation,
            partial_scan_notice,
            devices: simple_items,
        };

        let advanced = DeviceAdvancedView {
            network_context,
            devices: final_devices,
            scan_duration_ms: duration_ms,
            last_scan_utc: Utc::now().to_rfc3339(),
            is_partial_scan,
            total_hosts_in_subnet: total_subnet_hosts,
            scanned_hosts_count,
            pie_correlation_note: Some("Evidencias contextualizadas por network_id listas para correlación con Process Hunter y Network Guardian.".to_string()),
        };

        Ok(DeviceScanReport { simple, advanced })
    }

    #[cfg(target_os = "windows")]
    fn read_arp_table_native(network_id: &str) -> Result<Vec<DiscoveredDevice>> {
        let mut p_table: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
        let ret = unsafe {
            GetIpNetTable2(
                AF_INET,
                &mut p_table,
            )
        };

        if ret != NO_ERROR || p_table.is_null() {
            return Ok(Vec::new());
        }

        struct TableGuard(*mut MIB_IPNET_TABLE2);
        impl Drop for TableGuard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe {
                        FreeMibTable(self.0 as *const c_void);
                    }
                }
            }
        }
        let _guard = TableGuard(p_table);

        let table = unsafe { &*p_table };
        let count = table.NumEntries as usize;
        if count == 0 {
            return Ok(Vec::new());
        }

        let mut devices = Vec::new();
        let rows_ptr = table.Table.as_ptr();

        for i in 0..count {
            let row = unsafe { &*rows_ptr.add(i) };

            // Filtrar entradas sin MAC o inválidas (longitud != 6)
            if row.PhysicalAddressLength != 6 {
                continue;
            }

            let mac = format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                row.PhysicalAddress[0],
                row.PhysicalAddress[1],
                row.PhysicalAddress[2],
                row.PhysicalAddress[3],
                row.PhysicalAddress[4],
                row.PhysicalAddress[5]
            );

            // Ignorar direcciones broadcast / multicast (FF:FF:FF:FF:FF:FF o 01:00:5E:...)
            if mac == "FF:FF:FF:FF:FF:FF" || mac.starts_with("01:00:5E") || mac == "00:00:00:00:00:00" {
                continue;
            }

            // Extraer IPv4 de SOCKADDR_INET
            let ip_bytes = unsafe { row.Address.Ipv4.sin_addr.S_un.S_un_b };
            let ip = format!("{}.{}.{}.{}", ip_bytes.s_b1, ip_bytes.s_b2, ip_bytes.s_b3, ip_bytes.s_b4);

            // Ignorar direcciones 0.0.0.0, 255.255.255.255 o multicast 224.0.0.0+
            if ip.starts_with("224.") || ip.starts_with("239.") || ip == "0.0.0.0" || ip == "255.255.255.255" {
                continue;
            }

            let vendor = lookup_vendor(&mac).map(|s| s.to_string());
            let now = Utc::now();

            let category = if let Some(ref v) = vendor {
                if v.contains("LAA") {
                    DeviceDisplayCategory::LocallyAdministered
                } else {
                    DeviceDisplayCategory::KnownVendor(v.clone())
                }
            } else {
                DeviceDisplayCategory::Unknown
            };

            devices.push(DiscoveredDevice {
                network_id: network_id.to_string(),
                mac,
                ip,
                hostname: None,
                vendor,
                is_trusted: false, // Dispositivos descubiertos no son confiables por defecto
                is_gateway: false, // Se asigna en perform_full_scan comparando con gateway_ip
                is_local_machine: false,
                custom_alias: None,
                display_category: category,
                first_seen_utc: now,
                last_seen_utc: now,
                detection_source: DeviceDetectionSource::ArpCache,
            });
        }

        Ok(devices)
    }

    #[cfg(not(target_os = "windows"))]
    fn read_arp_table_native(network_id: &str) -> Result<Vec<DiscoveredDevice>> {
        let _ = network_id;
        Ok(Vec::new())
    }

    #[cfg(target_os = "windows")]
    fn send_arp_native(dest_ip: Ipv4Addr, src_ip: Option<Ipv4Addr>) -> Option<String> {
        let dest_u32 = u32::from_ne_bytes(dest_ip.octets());
        let src_u32 = src_ip.map(|ip| u32::from_ne_bytes(ip.octets())).unwrap_or(0);
        let mut mac_buf = [0u8; 6];
        let mut mac_len = 6u32;

        let ret = unsafe {
            SendARP(
                dest_u32,
                src_u32,
                mac_buf.as_mut_ptr() as *mut c_void,
                &mut mac_len,
            )
        };

        if ret == NO_ERROR.0 && mac_len == 6 {
            let mac = format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                mac_buf[0], mac_buf[1], mac_buf[2], mac_buf[3], mac_buf[4], mac_buf[5]
            );
            if mac != "00:00:00:00:00:00" {
                return Some(mac);
            }
        }

        None
    }

    #[cfg(not(target_os = "windows"))]
    fn send_arp_native(_dest_ip: Ipv4Addr, _src_ip: Option<Ipv4Addr>) -> Option<String> {
        None
    }

    #[cfg(target_os = "windows")]
    fn resolve_hostname_native(ip: Ipv4Addr) -> Option<String> {
        let octets = ip.octets();
        let hostent_ptr = unsafe {
            gethostbyaddr(
                &octets,
                AF_INET.0 as i32,
            )
        };

        if !hostent_ptr.is_null() {
            let h_name = unsafe { (*hostent_ptr).h_name };
            if !h_name.is_null() {
                if let Ok(name) = unsafe { h_name.to_string() } {
                    let trimmed = name.trim();
                    if !trimmed.is_empty() && trimmed != ip.to_string() {
                        return Some(trimmed.to_string());
                    }
                }
            }
        }

        None
    }

    #[cfg(not(target_os = "windows"))]
    fn resolve_hostname_native(_ip: Ipv4Addr) -> Option<String> {
        None
    }
}
