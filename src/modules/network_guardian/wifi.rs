use crate::modules::network_guardian::wifi_models::*;
use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

#[cfg(target_os = "windows")]
use std::ffi::c_void;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SUCCESS, HANDLE};
#[cfg(target_os = "windows")]
use windows::Win32::NetworkManagement::WiFi::*;
#[cfg(target_os = "windows")]
use windows::core::GUID;

const SCAN_CACHE_TTL: Duration = Duration::from_secs(30);

/// Estructura de caché para evitar sondeos de radio excesivos.
struct WifiScanCache {
    last_scan: Instant,
    cached_report: WifiDiagnosticsReport,
}

/// Analizador de redes inalámbricas Wi-Fi nativo de Windows (WlanAPI).
pub struct WifiAnalyzer {
    cache: Arc<Mutex<Option<WifiScanCache>>>,
}

impl Default for WifiAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl WifiAnalyzer {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(None)),
        }
    }

    /// Obtiene el diagnóstico Wi-Fi completo, utilizando caché si no ha expirado el TTL.
    pub async fn get_diagnostics(&self, force_refresh: bool) -> Result<WifiDiagnosticsReport> {
        if !force_refresh {
            let cache_guard = self.cache.lock().await;
            if let Some(ref cached) = *cache_guard {
                if cached.last_scan.elapsed() < SCAN_CACHE_TTL {
                    let mut report = cached.cached_report.clone();
                    report.advanced.scan_cached = true;
                    return Ok(report);
                }
            }
        }

        let report = tokio::task::spawn_blocking(Self::collect_wifi_data_native).await??;

        let mut cache_guard = self.cache.lock().await;
        *cache_guard = Some(WifiScanCache {
            last_scan: Instant::now(),
            cached_report: report.clone(),
        });

        Ok(report)
    }

    #[cfg(target_os = "windows")]
    fn collect_wifi_data_native() -> Result<WifiDiagnosticsReport> {
        let mut negotiated_version = 0u32;
        let mut client_handle = HANDLE::default();

        let ret = unsafe {
            WlanOpenHandle(
                2, // Client version 2 (Windows 7/8/10/11)
                None,
                &mut negotiated_version,
                &mut client_handle,
            )
        };

        if ret != ERROR_SUCCESS.0 {
            // El servicio WLAN no está disponible (ej. Desktop sin Wi-Fi o Windows Server)
            return Ok(Self::build_no_adapter_report(
                WifiAdapterState::NoAdapter,
                "Servicio de configuración automática inalámbrica (WlanSvc) no disponible.",
            ));
        }

        // RAII Guard para asegurar cierre del handle
        struct WlanHandleGuard(HANDLE);
        impl Drop for WlanHandleGuard {
            fn drop(&mut self) {
                unsafe {
                    let _ = WlanCloseHandle(self.0, None);
                }
            }
        }
        let _guard = WlanHandleGuard(client_handle);

        let mut p_interface_list: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
        let enum_ret = unsafe {
            WlanEnumInterfaces(
                client_handle,
                None,
                &mut p_interface_list,
            )
        };

        if enum_ret != ERROR_SUCCESS.0 || p_interface_list.is_null() {
            return Ok(Self::build_no_adapter_report(
                WifiAdapterState::NoAdapter,
                "No se detectaron tarjetas de red inalámbricas en el sistema.",
            ));
        }

        struct WlanMemoryGuard(*mut c_void);
        impl Drop for WlanMemoryGuard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe {
                        WlanFreeMemory(self.0);
                    }
                }
            }
        }
        let _iface_list_guard = WlanMemoryGuard(p_interface_list as *mut c_void);

        let iface_list = unsafe { &*p_interface_list };
        if iface_list.dwNumberOfItems == 0 {
            return Ok(Self::build_no_adapter_report(
                WifiAdapterState::NoAdapter,
                "No hay adaptadores Wi-Fi instalados o habilitados.",
            ));
        }

        // Obtener la primera interfaz Wi-Fi (o la que esté conectada)
        let num_items = iface_list.dwNumberOfItems as usize;
        let interfaces_slice = unsafe {
            std::slice::from_raw_parts(
                iface_list.InterfaceInfo.as_ptr(),
                num_items,
            )
        };

        let selected_iface = interfaces_slice
            .iter()
            .find(|info| info.isState == wlan_interface_state_connected)
            .or_else(|| interfaces_slice.first())
            .expect("Interfaces list is not empty");

        let iface_guid = selected_iface.InterfaceGuid;
        let iface_name = String::from_utf16_lossy(&selected_iface.strInterfaceDescription)
            .trim_matches('\0')
            .trim()
            .to_string();

        let iface_state = selected_iface.isState;

        // Si la interfaz está deshabilitada
        if iface_state == wlan_interface_state_not_ready {
            return Ok(Self::build_disabled_report(
                WifiAdapterState::DisabledOrOff,
                Some(iface_name),
                "El adaptador Wi-Fi está desactivado o en modo avión.",
            ));
        }

        // 1. Consultar conexión actual (si está conectada)
        let current_connection = if iface_state == wlan_interface_state_connected {
            Self::query_current_connection(client_handle, &iface_guid)
        } else {
            None
        };

        // 2. Escanear redes BSS circundantes
        let (nearby_networks, location_denied) =
            Self::scan_nearby_bss_networks(client_handle, &iface_guid);

        let adapter_state = if location_denied {
            WifiAdapterState::LocationPermissionDenied
        } else if current_connection.is_some() {
            WifiAdapterState::Connected
        } else {
            WifiAdapterState::Disconnected
        };

        // 3. Analizar congestión y calcular recomendaciones
        let (congestion_data, recommendations) =
            Self::analyze_channels_and_congestion(&nearby_networks, &current_connection);

        // 4. Construir vistas Simple y Avanzada
        let (simple, advanced) = Self::build_presentation_views(
            adapter_state,
            Some(iface_name),
            current_connection,
            nearby_networks,
            congestion_data,
            recommendations,
            location_denied,
        );

        Ok(WifiDiagnosticsReport {
            adapter_state,
            simple,
            advanced,
        })
    }

    #[cfg(not(target_os = "windows"))]
    fn collect_wifi_data_native() -> Result<WifiDiagnosticsReport> {
        Ok(Self::build_no_adapter_report(
            WifiAdapterState::NoAdapter,
            "Diagnóstico Wi-Fi no implementado en plataformas no Windows.",
        ))
    }

    #[cfg(target_os = "windows")]
    fn query_current_connection(
        client_handle: HANDLE,
        iface_guid: &GUID,
    ) -> Option<WifiConnectionInfo> {
        let mut data_size = 0u32;
        let mut p_data: *mut c_void = std::ptr::null_mut();
        let mut opcode_type = WLAN_OPCODE_VALUE_TYPE::default();

        let ret = unsafe {
            WlanQueryInterface(
                client_handle,
                iface_guid,
                wlan_intf_opcode_current_connection,
                None,
                &mut data_size,
                &mut p_data,
                Some(&mut opcode_type),
            )
        };

        if ret != ERROR_SUCCESS.0 || p_data.is_null() {
            return None;
        }

        struct QueryMemoryGuard(*mut c_void);
        impl Drop for QueryMemoryGuard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe {
                        WlanFreeMemory(self.0);
                    }
                }
            }
        }
        let _data_guard = QueryMemoryGuard(p_data);

        let conn_attr = unsafe { &*(p_data as *const WLAN_CONNECTION_ATTRIBUTES) };
        let assoc = &conn_attr.wlanAssociationAttributes;
        let sec = &conn_attr.wlanSecurityAttributes;

        // Extraer SSID
        let ssid_len = assoc.dot11Ssid.uSSIDLength as usize;
        let ssid = if ssid_len > 0 && ssid_len <= 32 {
            String::from_utf8_lossy(&assoc.dot11Ssid.ucSSID[..ssid_len]).to_string()
        } else {
            "(Red Oculta)".to_string()
        };

        // Extraer BSSID (MAC del Access Point)
        let bssid = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            assoc.dot11Bssid[0],
            assoc.dot11Bssid[1],
            assoc.dot11Bssid[2],
            assoc.dot11Bssid[3],
            assoc.dot11Bssid[4],
            assoc.dot11Bssid[5]
        );

        let signal_quality = assoc.wlanSignalQuality.min(100);
        // Aproximación estándar IEEE de RSSI (dBm) desde Link Quality (0..100)
        // RSSI ~= (SignalQuality / 2) - 100 dBm  (ej: 100% -> -50 dBm, 50% -> -75 dBm)
        let rssi_dbm = Some(((signal_quality as i32) / 2) - 100);

        let tx_rate_mbps = if assoc.ulTxRate > 0 {
            Some(assoc.ulTxRate as f32 / 1000.0)
        } else {
            None
        };

        let rx_rate_mbps = if assoc.ulRxRate > 0 {
            Some(assoc.ulRxRate as f32 / 1000.0)
        } else {
            None
        };

        let phy_type = match assoc.dot11PhyType {
            x if x == dot11_phy_type_he => "802.11ax (Wi-Fi 6)".to_string(),
            x if x == dot11_phy_type_vht => "802.11ac (Wi-Fi 5)".to_string(),
            x if x == dot11_phy_type_ht => "802.11n (Wi-Fi 4)".to_string(),
            x if x == dot11_phy_type_erp => "802.11g".to_string(),
            x if x == dot11_phy_type_hrdsss => "802.11b".to_string(),
            x if x == dot11_phy_type_ofdm => "802.11a".to_string(),
            _ => "802.11 Inalámbrico".to_string(),
        };

        // Algoritmos de Autenticación y Cifrado
        let (auth_str, security_level) = match sec.dot11AuthAlgorithm {
            DOT11_AUTH_ALGO_80211_OPEN => {
                if sec.bSecurityEnabled.as_bool() {
                    ("WEP / Abierta".to_string(), WifiSecurityLevel::InsecureWep)
                } else {
                    ("Abierta (Sin cifrar)".to_string(), WifiSecurityLevel::InsecureOpen)
                }
            }
            DOT11_AUTH_ALGO_80211_SHARED_KEY => {
                ("WEP Clave Compartida".to_string(), WifiSecurityLevel::InsecureWep)
            }
            DOT11_AUTH_ALGO_WPA => ("WPA-Enterprise".to_string(), WifiSecurityLevel::Enterprise),
            DOT11_AUTH_ALGO_WPA_PSK => ("WPA-Personal".to_string(), WifiSecurityLevel::WeakWpa),
            DOT11_AUTH_ALGO_RSNA => ("WPA2-Enterprise".to_string(), WifiSecurityLevel::Enterprise),
            DOT11_AUTH_ALGO_RSNA_PSK => ("WPA2-Personal".to_string(), WifiSecurityLevel::SecureWpa2),
            DOT11_AUTH_ALGO_WPA3 => ("WPA3-Enterprise".to_string(), WifiSecurityLevel::Enterprise),
            DOT11_AUTH_ALGO_WPA3_SAE => ("WPA3-Personal (SAE)".to_string(), WifiSecurityLevel::ModernWpa3),
            _ => ("Desconocido".to_string(), WifiSecurityLevel::Unknown),
        };

        let cipher_str = match sec.dot11CipherAlgorithm {
            DOT11_CIPHER_ALGO_NONE => "Ninguno",
            DOT11_CIPHER_ALGO_WEP40 => "WEP-40",
            DOT11_CIPHER_ALGO_TKIP => "TKIP (Antiguo)",
            DOT11_CIPHER_ALGO_CCMP => "AES-CCMP",
            DOT11_CIPHER_ALGO_WEP104 => "WEP-104",
            DOT11_CIPHER_ALGO_GCMP => "GCMP (WPA3)",
            _ => "Estándar",
        }
        .to_string();

        Some(WifiConnectionInfo {
            ssid,
            bssid,
            signal_quality,
            rssi_dbm,
            channel: 0, // Se complementa con la lista BSS
            frequency_khz: 0,
            band: WifiBand::Unknown,
            channel_width_mhz: None,
            phy_type,
            auth_algorithm: auth_str,
            cipher_algorithm: cipher_str,
            security_level,
            tx_rate_mbps,
            rx_rate_mbps,
        })
    }

    #[cfg(target_os = "windows")]
    fn scan_nearby_bss_networks(
        client_handle: HANDLE,
        iface_guid: &GUID,
    ) -> (Vec<NearbyNetwork>, bool) {
        let mut p_bss_list: *mut WLAN_BSS_LIST = std::ptr::null_mut();
        let ret = unsafe {
            WlanGetNetworkBssList(
                client_handle,
                iface_guid,
                None,
                dot11_BSS_type_any,
                windows::Win32::Foundation::BOOL(0),
                None,
                &mut p_bss_list,
            )
        };

        if ret == ERROR_ACCESS_DENIED.0 {
            tracing::warn!(
                target: "network_guardian::wifi",
                "WlanGetNetworkBssList access denied. Windows location services permission might be required."
            );
            return (Vec::new(), true);
        }

        if ret != ERROR_SUCCESS.0 || p_bss_list.is_null() {
            return (Vec::new(), false);
        }

        struct BssMemoryGuard(*mut c_void);
        impl Drop for BssMemoryGuard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    unsafe {
                        WlanFreeMemory(self.0);
                    }
                }
            }
        }
        let _bss_guard = BssMemoryGuard(p_bss_list as *mut c_void);

        let bss_list = unsafe { &*p_bss_list };
        let count = bss_list.dwNumberOfItems as usize;
        if count == 0 {
            return (Vec::new(), false);
        }

        let mut results = Vec::with_capacity(count);
        let first_entry_ptr = bss_list.wlanBssEntries.as_ptr();

        for i in 0..count {
            let entry = unsafe { &*first_entry_ptr.add(i) };

            let ssid_len = entry.dot11Ssid.uSSIDLength as usize;
            let (ssid, is_hidden) = if ssid_len > 0 && ssid_len <= 32 {
                let s = String::from_utf8_lossy(&entry.dot11Ssid.ucSSID[..ssid_len]).to_string();
                if s.trim().is_empty() || s.chars().all(|c| c == '\0') {
                    ("(Red Oculta)".to_string(), true)
                } else {
                    (s, false)
                }
            } else {
                ("(Red Oculta)".to_string(), true)
            };

            let bssid = format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                entry.dot11Bssid[0],
                entry.dot11Bssid[1],
                entry.dot11Bssid[2],
                entry.dot11Bssid[3],
                entry.dot11Bssid[4],
                entry.dot11Bssid[5]
            );

            let freq_khz = entry.ulChCenterFrequency;
            let band = WifiBand::from_frequency_khz(freq_khz);
            let channel = frequency_khz_to_channel(freq_khz).unwrap_or(0);
            let rssi_dbm = entry.lRssi;
            let signal_quality = entry.uLinkQuality.min(100);

            // Determinar seguridad preliminar según capability
            // Bit 4 (0x0010) de CapabilityInformation indica Privacy (WEP/WPA/WPA2/WPA3)
            let is_privacy = (entry.usCapabilityInformation & 0x0010) != 0;
            let (sec_level, auth_algo, cipher_algo) = if !is_privacy {
                (
                    WifiSecurityLevel::InsecureOpen,
                    "Abierta".to_string(),
                    "Ninguno".to_string(),
                )
            } else {
                // Si tiene privacidad, por defecto WPA2 o WPA3
                (
                    WifiSecurityLevel::SecureWpa2,
                    "WPA2/WPA3".to_string(),
                    "AES-CCMP".to_string(),
                )
            };

            results.push(NearbyNetwork {
                ssid,
                is_hidden,
                bssid,
                signal_quality,
                rssi_dbm,
                channel,
                frequency_khz: freq_khz,
                band,
                security_level: sec_level,
                auth_algorithm: auth_algo,
                cipher_algorithm: cipher_algo,
            });
        }

        (results, false)
    }

    /// Analiza solapamiento de canales, congestión ponderada por RSSI y recomendaciones.
    pub fn analyze_channels_and_congestion(
        nearby: &[NearbyNetwork],
        current: &Option<WifiConnectionInfo>,
    ) -> (Vec<ChannelCongestion>, Vec<ChannelRecommendation>) {
        let current_channel = current.as_ref().map(|c| c.channel);

        // Agrupar redes por canal
        let mut channel_networks: HashMap<(WifiBand, u32), Vec<&NearbyNetwork>> = HashMap::new();
        for net in nearby {
            if net.channel > 0 {
                channel_networks
                    .entry((net.band, net.channel))
                    .or_default()
                    .push(net);
            }
        }

        let mut congestion_list = Vec::new();

        // ── 1. Evaluar canales de 2.4 GHz (1 al 13) ──
        let candidate_2_4 = [1, 6, 11]; // Canales no solapados estándar
        for ch in 1..=13 {
            let direct_nets = channel_networks
                .get(&(WifiBand::Band2_4GHz, ch))
                .cloned()
                .unwrap_or_default();
            let direct_count = direct_nets.len();

            // En 2.4 GHz, canales adyacentes a distancia < 5 se solapan
            let mut overlapping_count = 0;
            let mut weighted_rssi_sum = 0.0f32;

            for net in nearby.iter().filter(|n| n.band == WifiBand::Band2_4GHz) {
                let diff = (net.channel as i32 - ch as i32).abs();
                if diff < 5 {
                    if diff != 0 {
                        overlapping_count += 1;
                    }
                    // Ponderación por potencia: redes fuertes (-40 dBm) saturan más que débiles (-90 dBm)
                    // Normalizamos RSSI (-100 a -30) a un factor (0.1 a 1.0)
                    let norm_rssi = ((net.rssi_dbm + 100).clamp(5, 70) as f32) / 70.0;
                    weighted_rssi_sum += norm_rssi * if diff == 0 { 1.5 } else { 1.0 };
                }
            }

            let congestion_score = (weighted_rssi_sum * 15.0).min(100.0);
            let is_current = current_channel == Some(ch);

            congestion_list.push(ChannelCongestion {
                channel: ch,
                band: WifiBand::Band2_4GHz,
                network_count: direct_count,
                overlapping_count,
                congestion_score,
                is_current_channel: is_current,
                is_recommended: false, // se marca abajo
                reason: format!(
                    "{} redes co-canal, {} solapadas en 2.4 GHz",
                    direct_count, overlapping_count
                ),
            });
        }

        // ── 2. Evaluar canales de 5 GHz ──
        let common_5ghz = [36, 40, 44, 48, 149, 153, 157, 161];
        for &ch in &common_5ghz {
            let direct_nets = channel_networks
                .get(&(WifiBand::Band5GHz, ch))
                .cloned()
                .unwrap_or_default();
            let direct_count = direct_nets.len();

            let mut weighted_rssi_sum = 0.0f32;
            for net in &direct_nets {
                let norm_rssi = ((net.rssi_dbm + 100).clamp(5, 70) as f32) / 70.0;
                weighted_rssi_sum += norm_rssi * 1.5;
            }

            let congestion_score = (weighted_rssi_sum * 20.0).min(100.0);
            let is_current = current_channel == Some(ch);

            congestion_list.push(ChannelCongestion {
                channel: ch,
                band: WifiBand::Band5GHz,
                network_count: direct_count,
                overlapping_count: 0, // En 5 GHz los canales estándar de 20 MHz no se solapan entre sí
                congestion_score,
                is_current_channel: is_current,
                is_recommended: false,
                reason: format!("{} redes en canal {} (5 GHz)", direct_count, ch),
            });
        }

        // ── 3. Calcular Canales Recomendados ──
        let mut recommendations = Vec::new();

        // Recomendación 2.4 GHz (elegir entre 1, 6 y 11 el de menor score)
        let mut best_2_4 = 1;
        let mut min_score_2_4 = f32::MAX;
        for &ch in &candidate_2_4 {
            if let Some(entry) = congestion_list
                .iter()
                .find(|c| c.band == WifiBand::Band2_4GHz && c.channel == ch)
            {
                if entry.congestion_score < min_score_2_4 {
                    min_score_2_4 = entry.congestion_score;
                    best_2_4 = ch;
                }
            }
        }

        // Marcar recomendado en la lista
        if let Some(entry) = congestion_list
            .iter_mut()
            .find(|c| c.band == WifiBand::Band2_4GHz && c.channel == best_2_4)
        {
            entry.is_recommended = true;
        }

        let alts_2_4: Vec<u32> = candidate_2_4
            .iter()
            .copied()
            .filter(|&c| c != best_2_4)
            .collect();

        recommendations.push(ChannelRecommendation {
            band: WifiBand::Band2_4GHz,
            current_channel: current_channel.filter(|&c| c <= 14),
            recommended_channel: best_2_4,
            alternative_channels: alts_2_4,
            reason: format!(
                "El canal {} tiene la menor saturación estimada ({:.1}%) entre los canales estándar libres de solapamiento.",
                best_2_4, min_score_2_4
            ),
            physical_rf_disclaimer: "Estimación basada en densidad de redes Wi-Fi visibles. No incluye interferencias no Wi-Fi como microondas o Bluetooth.".to_string(),
        });

        // Recomendación 5 GHz (elegir entre 36..48 el de menor score)
        let unii_1 = [36, 40, 44, 48];
        let mut best_5 = 36;
        let mut min_score_5 = f32::MAX;
        for &ch in &unii_1 {
            if let Some(entry) = congestion_list
                .iter()
                .find(|c| c.band == WifiBand::Band5GHz && c.channel == ch)
            {
                if entry.congestion_score < min_score_5 {
                    min_score_5 = entry.congestion_score;
                    best_5 = ch;
                }
            }
        }

        if let Some(entry) = congestion_list
            .iter_mut()
            .find(|c| c.band == WifiBand::Band5GHz && c.channel == best_5)
        {
            entry.is_recommended = true;
        }

        let alts_5: Vec<u32> = unii_1.iter().copied().filter(|&c| c != best_5).collect();

        recommendations.push(ChannelRecommendation {
            band: WifiBand::Band5GHz,
            current_channel: current_channel.filter(|&c| c >= 36),
            recommended_channel: best_5,
            alternative_channels: alts_5,
            reason: format!(
                "El canal {} (banda UNII-1) ofrece compatibilidad total y baja ocupación ({:.1}%).",
                best_5, min_score_5
            ),
            physical_rf_disclaimer: "Estimación calculada a partir de los puntos de acceso cercanos detectados.".to_string(),
        });

        (congestion_list, recommendations)
    }

    /// Construye las vistas duales (Simple y Avanzada) unificadas.
    fn build_presentation_views(
        state: WifiAdapterState,
        iface_name: Option<String>,
        mut current: Option<WifiConnectionInfo>,
        nearby: Vec<NearbyNetwork>,
        congestion: Vec<ChannelCongestion>,
        recommendations: Vec<ChannelRecommendation>,
        location_denied: bool,
    ) -> (WifiSimpleView, WifiAdvancedView) {
        let mut problems = Vec::new();
        let mut user_recommendations = Vec::new();

        // Completar canal y frecuencia de la conexión actual a partir de la lista de BSS
        if let Some(ref mut conn) = current {
            if let Some(matching_bss) = nearby.iter().find(|n| n.bssid.eq_ignore_ascii_case(&conn.bssid)) {
                conn.channel = matching_bss.channel;
                conn.frequency_khz = matching_bss.frequency_khz;
                conn.band = matching_bss.band;
                conn.rssi_dbm = Some(matching_bss.rssi_dbm);
            }
        }

        // Evaluar problemas y recomendaciones para Modo Simple
        let (signal_rating, stability_rating) = match &current {
            Some(conn) => {
                let sig = if conn.signal_quality >= 80 {
                    "Excelente"
                } else if conn.signal_quality >= 55 {
                    "Buena"
                } else if conn.signal_quality >= 35 {
                    problems.push("La señal Wi-Fi es débil, lo que puede causar desconexiones o velocidad lenta.".to_string());
                    user_recommendations.push("Acércate al router o utiliza un repetidor Wi-Fi si experimentas lentitud.".to_string());
                    "Débil"
                } else {
                    problems.push("La señal Wi-Fi es crítica. Alta probabilidad de pérdidas de conexión.".to_string());
                    user_recommendations.push("Conéctate por cable de red o reubica el equipo más cerca del router.".to_string());
                    "Crítica"
                };

                if conn.security_level.is_insecure() {
                    problems.push(format!(
                        "La red '{}' tiene seguridad deficiente ({}). Cualquier usuario cercano podría interceptar tu tráfico.",
                        conn.ssid,
                        conn.security_level.simple_label()
                    ));
                    user_recommendations.push("Configura cifrado WPA2 o WPA3 en tu router y evita ingresar datos bancarios en redes abiertas.".to_string());
                }

                // Verificar congestión del canal actual
                if conn.channel > 0 {
                    if let Some(c) = congestion.iter().find(|cg| cg.channel == conn.channel && cg.band == conn.band) {
                        if c.congestion_score > 65.0 {
                            problems.push(format!(
                                "El canal actual ({}) está saturado por múltiples redes vecinas.",
                                conn.channel
                            ));
                            if let Some(rec) = recommendations.iter().find(|r| r.band == conn.band) {
                                user_recommendations.push(format!(
                                    "Considera cambiar el canal de tu router al canal {} en la banda {}.",
                                    rec.recommended_channel,
                                    rec.band.as_str()
                                ));
                            }
                        }
                    }
                }

                (sig.to_string(), "Estable".to_string())
            }
            None => {
                if state == WifiAdapterState::Connected {
                    ("Desconocida".to_string(), "Incierta".to_string())
                } else {
                    ("Sin señal".to_string(), "Desconectado".to_string())
                }
            }
        };

        if location_denied {
            problems.push("Windows ha restringido el acceso a la lista de redes Wi-Fi cercanas (permiso de Ubicación desactivado).".to_string());
            user_recommendations.push("Para ver las redes cercanas y el análisis de canales, activa la Ubicación en Configuración de Windows > Privacidad.".to_string());
        }

        let security_status = current
            .as_ref()
            .map(|c| c.security_level.simple_label().to_string())
            .unwrap_or_else(|| "No conectado".to_string());

        let status_title = match state {
            WifiAdapterState::Connected => {
                if let Some(c) = &current {
                    format!("Conectado a '{}'", c.ssid)
                } else {
                    "Conectado a red inalámbrica".to_string()
                }
            }
            WifiAdapterState::Disconnected => "Wi-Fi activado (Sin conexión a ninguna red)".to_string(),
            WifiAdapterState::DisabledOrOff => "El adaptador Wi-Fi está desactivado".to_string(),
            WifiAdapterState::NoAdapter => "Sin tarjeta de red inalámbrica (Ethernet / No Wi-Fi)".to_string(),
            WifiAdapterState::LocationPermissionDenied => "Permiso de escaneo de redes denegado por Windows".to_string(),
        };

        let simple = WifiSimpleView {
            status_title,
            signal_rating,
            security_status,
            stability_rating,
            problems_detected: problems,
            recommendations: user_recommendations,
        };

        let advanced = WifiAdvancedView {
            interface_name: iface_name,
            connection: current,
            congestion_data: congestion,
            nearby_networks: nearby,
            channel_recommendations: recommendations,
            last_scan_utc: Utc::now().to_rfc3339(),
            scan_cached: false,
            pie_correlation_note: Some("Métricas correlacionables con latencia ICMP y jitter para detectar degradación por RF.".to_string()),
        };

        (simple, advanced)
    }

    fn build_no_adapter_report(state: WifiAdapterState, reason: &str) -> WifiDiagnosticsReport {
        WifiDiagnosticsReport {
            adapter_state: state,
            simple: WifiSimpleView {
                status_title: "Conexión por cable Ethernet activa o equipo sin Wi-Fi".to_string(),
                signal_rating: "N/A".to_string(),
                security_status: "Protegida por cable Ethernet".to_string(),
                stability_rating: "Máxima (Cableada)".to_string(),
                problems_detected: Vec::new(),
                recommendations: vec![
                    "El equipo está conectado por cable Ethernet o no posee tarjeta inalámbrica. No se requiere diagnóstico Wi-Fi.".to_string(),
                ],
            },
            advanced: WifiAdvancedView {
                interface_name: None,
                connection: None,
                congestion_data: Vec::new(),
                nearby_networks: Vec::new(),
                channel_recommendations: Vec::new(),
                last_scan_utc: Utc::now().to_rfc3339(),
                scan_cached: false,
                pie_correlation_note: Some(reason.to_string()),
            },
        }
    }

    fn build_disabled_report(
        state: WifiAdapterState,
        iface_name: Option<String>,
        reason: &str,
    ) -> WifiDiagnosticsReport {
        WifiDiagnosticsReport {
            adapter_state: state,
            simple: WifiSimpleView {
                status_title: "Adaptador Wi-Fi apagado o en Modo Avión".to_string(),
                signal_rating: "Apagado".to_string(),
                security_status: "Inactivo".to_string(),
                stability_rating: "Desactivado".to_string(),
                problems_detected: vec![reason.to_string()],
                recommendations: vec![
                    "Activa el Wi-Fi desde el panel de red de Windows o desactiva el Modo Avión si deseas conectarte a una red inalámbrica.".to_string(),
                ],
            },
            advanced: WifiAdvancedView {
                interface_name: iface_name,
                connection: None,
                congestion_data: Vec::new(),
                nearby_networks: Vec::new(),
                channel_recommendations: Vec::new(),
                last_scan_utc: Utc::now().to_rfc3339(),
                scan_cached: false,
                pie_correlation_note: Some(reason.to_string()),
            },
        }
    }
}
