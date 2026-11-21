#![allow(dead_code)]
#![allow(unused_imports)]

pub mod adapters;
pub mod device_models;
pub mod models;
pub mod oui;
pub mod ping;
pub mod scanner;
pub mod socket_correlator;
pub mod ui_adapter;
pub mod wifi;
pub mod wifi_models;

#[cfg(test)]
mod tests;

pub use adapters::{calculate_subnet_range, get_network_interfaces, get_primary_active_interface};
pub use device_models::*;
pub use models::{
    GatewayHealth, InternetHealth, NetworkHealthDiagnostics, NetworkInterfaceInfo, PingSample,
};
pub use oui::lookup_vendor;
pub use ping::PingMonitor;
pub use scanner::DeviceScanner;
pub use socket_correlator::{CorrelatedSocket, SocketCorrelator, SocketProtocol, TcpState};
pub use wifi::WifiAnalyzer;
pub use wifi_models::*;

use crate::modules::pie::PulseEventBus;
use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// Coordinador principal del módulo Network Guardian (Fases 1, 2 y 3).
pub struct NetworkGuardian {
    ping_monitor: PingMonitor,
    wifi_analyzer: WifiAnalyzer,
    device_scanner: DeviceScanner,
    last_known_gateway: Option<String>,
    last_known_dns: Option<Vec<String>>,
    last_known_network_id: Option<String>,
    last_wifi_ssid: Option<String>,
    last_wifi_bssid: Option<String>,
    last_wifi_signal: Option<u32>,
    known_devices_by_network: HashMap<String, HashSet<String>>,
    baseline_initialized_networks: HashSet<String>,
    cancel_flag: Arc<AtomicBool>,
    event_bus: Option<PulseEventBus>,
}

impl Default for NetworkGuardian {
    fn default() -> Self {
        Self::new(None)
    }
}

impl NetworkGuardian {
    pub fn new(event_bus: Option<PulseEventBus>) -> Self {
        Self {
            ping_monitor: PingMonitor::new(),
            wifi_analyzer: WifiAnalyzer::new(),
            device_scanner: DeviceScanner::default(),
            last_known_gateway: None,
            last_known_dns: None,
            last_known_network_id: None,
            last_wifi_ssid: None,
            last_wifi_bssid: None,
            last_wifi_signal: None,
            known_devices_by_network: HashMap::new(),
            baseline_initialized_networks: HashSet::new(),
            cancel_flag: Arc::new(AtomicBool::new(false)),
            event_bus,
        }
    }

    pub fn set_event_bus(&mut self, bus: PulseEventBus) {
        self.event_bus = Some(bus);
    }

    /// Retorna una referencia al monitor de ping.
    pub fn ping_monitor(&self) -> &PingMonitor {
        &self.ping_monitor
    }

    /// Retorna una referencia al analizador Wi-Fi.
    pub fn wifi_analyzer(&self) -> &WifiAnalyzer {
        &self.wifi_analyzer
    }

    /// Retorna una referencia al escáner de dispositivos.
    pub fn device_scanner(&self) -> &DeviceScanner {
        &self.device_scanner
    }

    /// Retorna una referencia mutable al escáner de dispositivos.
    pub fn device_scanner_mut(&mut self) -> &mut DeviceScanner {
        &mut self.device_scanner
    }

    /// Determina el identificador de contexto de red activo capturado en el momento de la observación.
    pub fn current_network_id(&self) -> String {
        match get_primary_active_interface() {
            Ok(Some(iface)) => {
                let subnet_cidr = match (iface.ipv4_addresses.first().and_then(|ip| Ipv4Addr::from_str(ip).ok()), iface.prefix_length) {
                    (Some(ip), Some(p)) => format!("{}/{}", ip, p),
                    _ => "0.0.0.0/0".to_string(),
                };
                NetworkContext::new(
                    subnet_cidr,
                    iface.prefix_length.unwrap_or(24),
                    iface.gateway_ipv4.clone(),
                    iface.id.clone(),
                    iface.is_vpn_or_virtual,
                ).network_id
            }
            _ => "disconnected".to_string(),
        }
    }

    /// Configura el límite máximo de hosts a escanear en escaneos activos.
    pub fn set_max_active_hosts(&mut self, max: usize) {
        self.device_scanner.set_max_active_hosts(max);
    }

    /// Retorna el límite configurado de hosts para escaneo activo.
    pub fn max_active_hosts(&self) -> usize {
        self.device_scanner.max_active_hosts()
    }

    /// Configura la cadencia en milisegundos entre solicitudes SendARP.
    pub fn set_active_rate_ms(&mut self, rate_ms: u64) {
        self.device_scanner.set_active_rate_ms(rate_ms);
    }

    /// Retorna la cadencia en milisegundos entre solicitudes SendARP.
    pub fn active_rate_ms(&self) -> u64 {
        self.device_scanner.active_rate_ms()
    }

    /// Cancela cualquier escaneo activo de red en curso.
    pub fn cancel_current_scan(&self) {
        self.cancel_flag.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Reinicia la bandera de cancelación antes de iniciar un nuevo escaneo activo.
    pub fn reset_cancel_flag(&self) {
        self.cancel_flag.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// Ejecuta el escaneo de dispositivos de red.
    /// - Por defecto opera en modo **pasivo** (`run_active: false`), con cero tráfico de red.
    /// - Implementa un inventario inicial silencioso (baseline) por red para evitar tormentas de alertas.
    /// - En escaneos subsecuentes, emite `PulseCriticalEvent::NewDeviceDiscovered` solo ante dispositivos no vistos.
    pub async fn run_device_scan(&mut self, run_active: bool) -> Result<DeviceScanReport> {
        self.reset_cancel_flag();
        let net_id_before = self.current_network_id();

        let active_iface = get_primary_active_interface()?;
        let (local_ip, gateway_ip, prefix_len, iface_id, is_vpn) = match &active_iface {
            Some(iface) => {
                let gw = iface.gateway_ipv4.as_deref().and_then(|g| Ipv4Addr::from_str(g).ok());
                let loc = iface.ipv4_addresses.first().and_then(|ip| Ipv4Addr::from_str(ip).ok());
                (loc, gw, iface.prefix_length, Some(iface.id.clone()), iface.is_vpn_or_virtual)
            }
            None => (None, None, None, None, false),
        };

        let report = self
            .device_scanner
            .perform_full_scan(
                local_ip,
                prefix_len,
                gateway_ip,
                iface_id,
                is_vpn,
                run_active,
                Some(self.cancel_flag.clone()),
            )
            .await?;

        // Re-validación del contexto al finalizar la medición para evitar contaminación cruzada
        let net_id_after = self.current_network_id();
        if net_id_before != net_id_after || net_id_after == "disconnected" {
            tracing::warn!(
                target: "network_guardian",
                "Network context changed during device scan ('{}' -> '{}'); discarding observations to prevent cross-contamination",
                net_id_before, net_id_after
            );
            return Ok(report);
        }

        let network_id = report.advanced.network_context.network_id.clone();
        let is_baseline = !self.baseline_initialized_networks.contains(&network_id);

        let known_set = self
            .known_devices_by_network
            .entry(network_id.clone())
            .or_default();

        if is_baseline {
            // Inventario inicial silencioso: registrar dispositivos existentes sin emitir alertas masivas
            for dev in &report.advanced.devices {
                known_set.insert(dev.mac.clone());
            }
            self.baseline_initialized_networks.insert(network_id.clone());
            tracing::info!(
                target: "network_guardian",
                "Silent baseline inventory initialized for network '{}' ({} devices registered)",
                network_id,
                report.advanced.devices.len()
            );
        } else {
            // Escaneo subsecuente: emitir evento crítico a PIE únicamente para dispositivos nuevos
            if let Some(bus) = &self.event_bus {
                for dev in &report.advanced.devices {
                    if !known_set.contains(&dev.mac) {
                        known_set.insert(dev.mac.clone());

                        if !dev.is_local_machine && !dev.is_gateway {
                            tracing::info!(
                                target: "network_guardian",
                                "New device detected on network '{}': IP {}, MAC {}",
                                network_id, dev.ip, dev.mac
                            );

                            let _ = bus.try_emit_critical(
                                crate::modules::pie::PulseCriticalEvent::NewDeviceDiscovered {
                                    network_id: network_id.clone(),
                                    mac: dev.mac.clone(),
                                    ip: dev.ip.clone(),
                                    hostname: dev.hostname.clone(),
                                    vendor: dev.vendor.clone(),
                                    is_trusted: dev.is_trusted,
                                },
                            );
                        }
                    }
                }
            }
        }

        Ok(report)
    }

    /// Ejecuta el diagnóstico Wi-Fi, evalúa seguridad, detecta cambios y publica eventos en PIE.
    pub async fn run_wifi_check(&mut self, force_refresh: bool) -> Result<WifiDiagnosticsReport> {
        let net_id_before = self.current_network_id();
        let mut report = self.wifi_analyzer.get_diagnostics(force_refresh).await?;

        // Re-validación del contexto al finalizar la observación de radio Wi-Fi
        let net_id_after = self.current_network_id();
        if net_id_before != net_id_after || net_id_after == "disconnected" {
            tracing::warn!(
                target: "network_guardian::wifi",
                "Network context changed during Wi-Fi check ('{}' -> '{}'); discarding ambiguous observations",
                net_id_before, net_id_after
            );
            return Ok(report);
        }
        let network_id = net_id_after;

        if let Some(conn) = &report.advanced.connection {
            // ── 1. Detección de cifrado inseguro (Open / WEP / WPA1) ──
            if conn.security_level.is_insecure() {
                if let Some(bus) = &self.event_bus {
                    let _ = bus.try_emit_critical(
                        crate::modules::pie::PulseCriticalEvent::InsecureWifiConnected {
                            network_id: network_id.clone(),
                            ssid: conn.ssid.clone(),
                            bssid: conn.bssid.clone(),
                            security_type: conn.security_level.simple_label().to_string(),
                        },
                    );
                }
            }

            // ── 2. Detección de cambio de SSID / BSSID ──
            let is_new_bssid = match &self.last_wifi_bssid {
                Some(last) => last != &conn.bssid,
                None => false,
            };

            if is_new_bssid {
                tracing::info!(
                    target: "network_guardian::wifi",
                    "Wi-Fi connection changed to SSID '{}' (BSSID {}) on network '{}'",
                    conn.ssid,
                    conn.bssid,
                    network_id
                );

                if let Some(bus) = &self.event_bus {
                    let adapter_name = report.advanced.interface_name.clone().unwrap_or_else(|| "Wi-Fi".to_string());
                    let _ = bus.try_emit_critical(
                        crate::modules::pie::PulseCriticalEvent::WifiConnectionChanged {
                            network_id: network_id.clone(),
                            adapter_name,
                            old_ssid: self.last_wifi_ssid.clone(),
                            new_ssid: conn.ssid.clone(),
                            bssid: conn.bssid.clone(),
                            channel: conn.channel,
                        },
                    );
                }
            }

            // ── 3. Detección de degradación severa de señal ──
            if let Some(prev_sig) = self.last_wifi_signal {
                if prev_sig >= 60 && conn.signal_quality < 25 {
                    tracing::warn!(
                        target: "network_guardian::wifi",
                        "Severe Wi-Fi signal drop detected: {}% -> {}%",
                        prev_sig,
                        conn.signal_quality
                    );

                    if let Some(bus) = &self.event_bus {
                        let _ = bus.try_emit_critical(
                            crate::modules::pie::PulseCriticalEvent::WifiSignalDegradation {
                                network_id: network_id.clone(),
                                ssid: conn.ssid.clone(),
                                bssid: conn.bssid.clone(),
                                signal_percent: conn.signal_quality,
                                rssi_dbm: conn.rssi_dbm,
                            },
                        );
                    }
                }
            }

            // ── 4. Telemetría periódica de señal Wi-Fi ──
            if let Some(bus) = &self.event_bus {
                bus.emit_telemetry(crate::modules::pie::TelemetryEvent::WifiSignalSample {
                    network_id: network_id.clone(),
                    ssid: conn.ssid.clone(),
                    signal_percent: conn.signal_quality,
                    rssi_dbm: conn.rssi_dbm,
                    channel: conn.channel,
                });
            }

            // Actualizar estado de referencia
            self.last_wifi_ssid = Some(conn.ssid.clone());
            self.last_wifi_bssid = Some(conn.bssid.clone());
            self.last_wifi_signal = Some(conn.signal_quality);

            // ── 5. Correlación mínima con métricas de latencia de Fase 1 ──
            let jitter = self.ping_monitor.jitter_ms();
            let loss = self.ping_monitor.packet_loss_percent();

            if conn.signal_quality < 35 && (jitter > 20.0 || loss > 5.0) {
                let correlation = format!(
                    "Inestabilidad de red (Jitter {:.1} ms, Pérdida {:.0}%) correlacionada con señal Wi-Fi degradada ({}%).",
                    jitter, loss, conn.signal_quality
                );
                report.advanced.pie_correlation_note = Some(correlation.clone());
                report.simple.problems_detected.push(correlation);
                report.simple.stability_rating = "Inestable por baja señal Wi-Fi".to_string();
            }
        }

        Ok(report)
    }

    /// Ejecuta una ronda de diagnóstico completa de red y publica telemetría y eventos en PIE.
    pub async fn run_health_check(&mut self) -> Result<NetworkHealthDiagnostics> {
        let active_iface = get_primary_active_interface()?;

        let (network_id, adapter_name, local_ip, gateway_ip_str, gateway_ip) = match &active_iface {
            Some(iface) => {
                let gw_str = iface.gateway_ipv4.clone();
                let gw_parsed = gw_str.as_deref().and_then(|g| Ipv4Addr::from_str(g).ok());
                let loc_ip = iface.ipv4_addresses.first().cloned();
                let subnet_cidr = match (loc_ip.as_deref().and_then(|ip| Ipv4Addr::from_str(ip).ok()), iface.prefix_length) {
                    (Some(ip), Some(p)) => format!("{}/{}", ip, p),
                    _ => "0.0.0.0/0".to_string(),
                };
                let net_ctx = NetworkContext::new(
                    subnet_cidr,
                    iface.prefix_length.unwrap_or(24),
                    gw_str.clone(),
                    iface.id.clone(),
                    iface.is_vpn_or_virtual,
                );
                (net_ctx.network_id, Some(iface.friendly_name.clone()), loc_ip, gw_str, gw_parsed)
            }
            None => ("disconnected".to_string(), None, None, None, None),
        };

        // ── Detección de cambio de Gateway para el Event Bus de PIE ──
        if let Some(gw) = &gateway_ip_str {
            if let Some(last_gw) = &self.last_known_gateway {
                if last_gw != gw {
                    tracing::info!(
                        target: "network_guardian",
                        "Default Gateway changed from '{}' to '{}' on network '{}'",
                        last_gw,
                        gw,
                        network_id
                    );

                    if let Some(bus) = &self.event_bus {
                        let _ = bus.try_emit_critical(
                            crate::modules::pie::PulseCriticalEvent::GatewayChanged {
                                old_network_id: self.last_known_network_id.clone(),
                                new_network_id: network_id.clone(),
                                adapter_name: adapter_name.clone().unwrap_or_else(|| "Unknown".to_string()),
                                old_gateway: Some(last_gw.clone()),
                                new_gateway: gw.clone(),
                            },
                        );
                    }
                }
            }
            self.last_known_gateway = Some(gw.clone());
        }

        // ── Detección de cambio de DNS para el Event Bus de PIE ──
        if let Some(iface) = &active_iface {
            if !iface.dns_servers.is_empty() {
                if let Some(last_dns) = &self.last_known_dns {
                    if last_dns != &iface.dns_servers {
                        tracing::info!(
                            target: "network_guardian",
                            "DNS servers changed on network '{}': {:?} -> {:?}",
                            network_id,
                            last_dns,
                            iface.dns_servers
                        );

                        if let Some(bus) = &self.event_bus {
                            let _ = bus.try_emit_critical(
                                crate::modules::pie::PulseCriticalEvent::DnsServerChanged {
                                    network_id: Some(network_id.clone()),
                                    adapter_name: adapter_name.clone().unwrap_or_else(|| "Unknown".to_string()),
                                    old_dns: last_dns.clone(),
                                    new_dns: iface.dns_servers.clone(),
                                },
                            );
                        }
                    }
                }
                self.last_known_dns = Some(iface.dns_servers.clone());
            }
        }
        self.last_known_network_id = Some(network_id.clone());

        // ── Ejecutar sondeo Wi-Fi (utiliza caché de 30s) ──
        if let Err(e) = self.run_wifi_check(false).await {
            tracing::debug!(target: "network_guardian", "Wi-Fi background check note: {}", e);
        }

        // Ejecutar diagnóstico ICMP
        let diagnostics = self
            .ping_monitor
            .run_diagnostic(gateway_ip, adapter_name.clone(), local_ip)
            .await?;

        // Re-validación del contexto al finalizar la medición para evitar atribuir mediciones ambiguas
        let net_id_after = self.current_network_id();
        if network_id != net_id_after || net_id_after == "disconnected" {
            tracing::warn!(
                target: "network_guardian",
                "Network context changed during health check ('{}' -> '{}'); discarding ambiguous metrics",
                network_id, net_id_after
            );
            return Ok(diagnostics);
        }

        // ── Emitir telemetría de latencia al Event Bus de PIE ──
        if let Some(bus) = &self.event_bus {
            bus.emit_telemetry(crate::modules::pie::TelemetryEvent::NetworkLatencySample {
                network_id: network_id.clone(),
                interface_name: adapter_name.clone(),
                target: diagnostics.gateway_ip.clone().unwrap_or_else(|| "1.1.1.1".to_string()),
                gateway_rtt_ms: diagnostics.gateway_rtt_ms,
                internet_rtt_ms: diagnostics.internet_rtt_ms,
                jitter_ms: self.ping_monitor.jitter_ms_opt(),
                packet_loss_percent: self.ping_monitor.packet_loss_percent_opt(),
                internet_health: diagnostics.internet_health,
            });
        }

        Ok(diagnostics)
    }
}
