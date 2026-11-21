use crate::modules::network_guardian::device_models::{DeviceDisplayCategory, DiscoveredDevice};
use crate::modules::network_guardian::models::{GatewayHealth, InternetHealth, NetworkHealthDiagnostics};
use crate::modules::network_guardian::wifi_models::{WifiAdapterState, WifiDiagnosticsReport};
use crate::modules::pie::models::{Incident, IncidentEvidence, IncidentStatus, PersistedNetDevice};
use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection};

/// Estructura de presentación para un dispositivo de red en la interfaz Slint.
#[derive(Debug, Clone, PartialEq)]
pub struct UiNetDevice {
    pub mac: String,
    pub ip: String,
    pub hostname: String,
    pub vendor: String,
    pub is_trusted: bool,
    pub is_gateway: bool,
    pub is_local: bool,
    pub display_name: String,
    pub category_label: String,
    pub first_seen: String,
    pub last_seen: String,
}

/// Estructura de presentación para la conexión Wi-Fi activa.
#[derive(Debug, Clone, PartialEq)]
pub struct UiWifiInfo {
    pub is_available: bool,
    pub adapter_state: String,
    pub ssid: String,
    pub bssid: String,
    pub signal_quality: i32,
    pub rssi_dbm: i32,
    pub channel: i32,
    pub band: String,
    pub security_level: String,
    pub phy_type: String,
    pub tx_rate_mbps: f32,
    pub rx_rate_mbps: f32,
    pub signal_rating: String,
    pub stability_rating: String,
    pub recommendation: String,
}

impl Default for UiWifiInfo {
    fn default() -> Self {
        Self {
            is_available: false,
            adapter_state: "Desconectado".to_string(),
            ssid: String::new(),
            bssid: String::new(),
            signal_quality: 0,
            rssi_dbm: 0,
            channel: 0,
            band: String::new(),
            security_level: String::new(),
            phy_type: String::new(),
            tx_rate_mbps: 0.0,
            rx_rate_mbps: 0.0,
            signal_rating: "Sin señal".to_string(),
            stability_rating: "No disponible".to_string(),
            recommendation: String::new(),
        }
    }
}

/// Estructura de presentación para canales Wi-Fi y congestión.
#[derive(Debug, Clone, PartialEq)]
pub struct UiWifiChannel {
    pub channel: i32,
    pub band: String,
    pub network_count: i32,
    pub congestion_score: f32,
    pub is_current: bool,
    pub is_recommended: bool,
    pub reason: String,
}

/// Estructura de presentación para redes Wi-Fi circundantes.
#[derive(Debug, Clone, PartialEq)]
pub struct UiWifiNearby {
    pub ssid: String,
    pub bssid: String,
    pub signal: i32,
    pub channel: i32,
    pub band: String,
    pub security: String,
}

/// Estructura de presentación para la calidad y salud del enlace de red.
#[derive(Debug, Clone, PartialEq)]
pub struct UiLinkQuality {
    pub adapter_name: String,
    pub local_ip: String,
    pub gateway_ip: String,
    pub gateway_health: String,
    pub internet_health: String,
    pub gateway_rtt_ms: f32,
    pub internet_rtt_ms: f32,
    pub jitter_ms: f32,
    pub packet_loss: f32,
    pub status_title: String,
    pub status_description: String,
    pub recommendation: String,
    pub technical_summary: String,
    pub is_connected: bool,
}

impl Default for UiLinkQuality {
    fn default() -> Self {
        Self {
            adapter_name: "-".to_string(),
            local_ip: "-".to_string(),
            gateway_ip: "-".to_string(),
            gateway_health: "No disponible".to_string(),
            internet_health: "No disponible".to_string(),
            gateway_rtt_ms: -1.0,
            internet_rtt_ms: -1.0,
            jitter_ms: 0.0,
            packet_loss: 0.0,
            status_title: "Verificando enlace...".to_string(),
            status_description: "Iniciando diagnóstico de red".to_string(),
            recommendation: String::new(),
            technical_summary: String::new(),
            is_connected: false,
        }
    }
}

/// Estructura de presentación para un socket o conexión activa en Slint.
#[derive(Debug, Clone, PartialEq)]
pub struct UiSocketConnection {
    pub protocol: String,
    pub local_endpoint: String,
    pub remote_endpoint: String,
    pub state: String,
    pub pid: i32,
    pub process_name: String,
    pub is_alive: bool,
}

/// Evidencia observable presentada en la UI de PIE.
#[derive(Debug, Clone, PartialEq)]
pub struct UiPieEvidence {
    pub id: i32,
    pub timestamp: String,
    pub source_module: String,
    pub event_type: String,
    pub observable_json: String,
}

/// Incidente forense presentado en la UI de PIE.
#[derive(Debug, Clone, PartialEq)]
pub struct UiPieIncident {
    pub id: i32,
    pub timestamp: String,
    pub category: String,
    pub severity: String,
    pub risk_score: i32,
    pub confidence: f32,
    pub status: String,
    pub title: String,
    pub simple_summary: String,
    pub simple_recommendation: String,
    pub technical_rule_id: String,
    pub technical_impact: String,
    pub technical_mitigation: String,
    pub diagnostic_limitations: String,
    pub evidence_count: i32,
    pub evidences: Vec<UiPieEvidence>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Conversores de Dominio a Modelo UI
// ─────────────────────────────────────────────────────────────────────────────

pub fn map_discovered_device(dev: &DiscoveredDevice, lang_es: bool) -> UiNetDevice {
    let category_label = if lang_es {
        dev.display_category.label_es()
    } else {
        dev.display_category.label_en()
    };

    let display_name = dev.display_name();

    UiNetDevice {
        mac: dev.mac.clone(),
        ip: dev.ip.clone(),
        hostname: dev.hostname.clone().unwrap_or_else(|| "-".to_string()),
        vendor: dev.vendor.clone().unwrap_or_else(|| "Desconocido".to_string()),
        is_trusted: dev.is_trusted,
        is_gateway: dev.is_gateway,
        is_local: dev.is_local_machine,
        display_name,
        category_label,
        first_seen: dev.first_seen_utc.format("%Y-%m-%d %H:%M").to_string(),
        last_seen: dev.last_seen_utc.format("%Y-%m-%d %H:%M:%S").to_string(),
    }
}

pub fn map_persisted_device(dev: &PersistedNetDevice, lang_es: bool) -> UiNetDevice {
    let is_gateway = dev.custom_alias.as_deref() == Some("Router") || dev.ip.ends_with(".1");
    let display_name = if let Some(alias) = &dev.custom_alias {
        alias.clone()
    } else if let Some(host) = &dev.hostname {
        host.clone()
    } else if let Some(vendor) = &dev.vendor {
        format!("Dispositivo {}", vendor)
    } else {
        format!("Dispositivo ({})", dev.ip)
    };

    let category_label = if dev.is_trusted {
        if lang_es { "Confiable".to_string() } else { "Trusted".to_string() }
    } else if let Some(vendor) = &dev.vendor {
        vendor.clone()
    } else {
        if lang_es { "Desconocido".to_string() } else { "Unknown".to_string() }
    };

    UiNetDevice {
        mac: dev.mac.clone(),
        ip: dev.ip.clone(),
        hostname: dev.hostname.clone().unwrap_or_else(|| "-".to_string()),
        vendor: dev.vendor.clone().unwrap_or_else(|| "Desconocido".to_string()),
        is_trusted: dev.is_trusted,
        is_gateway,
        is_local: false,
        display_name,
        category_label,
        first_seen: dev.first_seen.format("%Y-%m-%d %H:%M").to_string(),
        last_seen: dev.last_seen.format("%Y-%m-%d %H:%M:%S").to_string(),
    }
}

pub fn map_wifi_report(report: &WifiDiagnosticsReport) -> (UiWifiInfo, Vec<UiWifiChannel>, Vec<UiWifiNearby>) {
    let mut info = UiWifiInfo::default();
    info.is_available = matches!(report.adapter_state, WifiAdapterState::Connected | WifiAdapterState::Disconnected);
    info.adapter_state = report.adapter_state.as_str().to_string();

    if let Some(conn) = &report.advanced.connection {
        info.ssid = conn.ssid.clone();
        info.bssid = conn.bssid.clone();
        info.signal_quality = conn.signal_quality as i32;
        info.rssi_dbm = conn.rssi_dbm.unwrap_or(0);
        info.channel = conn.channel as i32;
        info.band = conn.band.as_str().to_string();
        info.security_level = conn.security_level.simple_label().to_string();
        info.phy_type = conn.phy_type.clone();
        info.tx_rate_mbps = conn.tx_rate_mbps.unwrap_or(0.0);
        info.rx_rate_mbps = conn.rx_rate_mbps.unwrap_or(0.0);
        info.signal_rating = report.simple.signal_rating.clone();
        info.stability_rating = report.simple.stability_rating.clone();
        info.recommendation = report.simple.recommendations.first().cloned().unwrap_or_default();
    } else {
        info.signal_rating = report.simple.signal_rating.clone();
        info.stability_rating = report.simple.stability_rating.clone();
    }

    let channels = report.advanced.congestion_data.iter().map(|c| UiWifiChannel {
        channel: c.channel as i32,
        band: c.band.as_str().to_string(),
        network_count: c.network_count as i32,
        congestion_score: c.congestion_score,
        is_current: c.is_current_channel,
        is_recommended: c.is_recommended,
        reason: c.reason.clone(),
    }).collect();

    let nearby = report.advanced.nearby_networks.iter().take(15).map(|n| UiWifiNearby {
        ssid: if n.is_hidden { "<Red oculta>".to_string() } else { n.ssid.clone() },
        bssid: n.bssid.clone(),
        signal: n.signal_quality as i32,
        channel: n.channel as i32,
        band: n.band.as_str().to_string(),
        security: n.security_level.simple_label().to_string(),
    }).collect();

    (info, channels, nearby)
}

pub fn map_health_diagnostics(diag: &NetworkHealthDiagnostics) -> UiLinkQuality {
    let gw_health_str = match diag.gateway_health {
        GatewayHealth::Reachable => "Alcanzable (Saludable)",
        GatewayHealth::HighLatency => "Latencia elevada",
        GatewayHealth::Unreachable => "Inalcanzable",
        GatewayHealth::NoGatewayConfigured => "Sin Gateway",
    };

    let inet_health_str = match diag.internet_health {
        InternetHealth::Connected => "Conectado a Internet",
        InternetHealth::Degraded => "Conexión degradada",
        InternetHealth::Disconnected => "Sin conexión a Internet",
        InternetHealth::IcmpFiltered => "ICMP Filtrado (HTTP activo)",
        InternetHealth::Unknown => "Estado desconocido",
    };

    let is_connected = matches!(diag.internet_health, InternetHealth::Connected | InternetHealth::IcmpFiltered)
        || matches!(diag.gateway_health, GatewayHealth::Reachable);

    UiLinkQuality {
        adapter_name: diag.active_adapter_name.clone().unwrap_or_else(|| "Adaptador local".to_string()),
        local_ip: diag.local_ip.clone().unwrap_or_else(|| "127.0.0.1".to_string()),
        gateway_ip: diag.gateway_ip.clone().unwrap_or_else(|| "-".to_string()),
        gateway_health: gw_health_str.to_string(),
        internet_health: inet_health_str.to_string(),
        gateway_rtt_ms: diag.gateway_rtt_ms.unwrap_or(-1.0),
        internet_rtt_ms: diag.internet_rtt_ms.unwrap_or(-1.0),
        jitter_ms: diag.jitter_ms,
        packet_loss: diag.packet_loss_percent,
        status_title: diag.simple_status_title.clone(),
        status_description: diag.simple_description.clone(),
        recommendation: diag.simple_recommendation.clone(),
        technical_summary: diag.technical_summary.clone(),
        is_connected,
    }
}

pub fn map_correlated_socket(
    socket: &crate::modules::network_guardian::socket_correlator::CorrelatedSocket,
) -> UiSocketConnection {
    let local_endpoint = format!("{}:{}", socket.local_addr, socket.local_port);
    let remote_endpoint = match (socket.remote_addr, socket.remote_port) {
        (Some(addr), Some(port)) => format!("{}:{}", addr, port),
        _ => "-".to_string(),
    };
    let state = socket
        .tcp_state
        .map(|s| s.as_str().to_string())
        .unwrap_or_else(|| "-".to_string());
    let process_name = socket
        .process_name
        .clone()
        .unwrap_or_else(|| "-".to_string());

    UiSocketConnection {
        protocol: socket.protocol.as_str().to_string(),
        local_endpoint,
        remote_endpoint,
        state,
        pid: socket.pid as i32,
        process_name,
        is_alive: socket.is_process_alive,
    }
}

pub fn map_incident(inc: &Incident) -> UiPieIncident {
    let evidences = inc.evidences.iter().map(|e| UiPieEvidence {
        id: e.id.unwrap_or(0) as i32,
        timestamp: e.timestamp_utc.format("%Y-%m-%d %H:%M:%S").to_string(),
        source_module: e.source_module.clone(),
        event_type: e.event_type.clone(),
        observable_json: e.observable_json.clone(),
    }).collect();

    UiPieIncident {
        id: inc.id.unwrap_or(0) as i32,
        timestamp: inc.timestamp_utc.format("%Y-%m-%d %H:%M:%S").to_string(),
        category: inc.category.as_str().to_string(),
        severity: inc.severity.as_str().to_string(),
        risk_score: inc.risk_score as i32,
        confidence: inc.confidence,
        status: inc.status.as_str().to_string(),
        title: inc.title.clone(),
        simple_summary: inc.simple_summary.clone(),
        simple_recommendation: inc.simple_recommendation.clone(),
        technical_rule_id: inc.technical_rule_id.clone(),
        technical_impact: inc.technical_impact.clone(),
        technical_mitigation: inc.technical_mitigation.clone(),
        diagnostic_limitations: inc.diagnostic_limitations.clone(),
        evidence_count: inc.evidences.len() as i32,
        evidences,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Consultas SQLite Seguras de Solo Lectura
// ─────────────────────────────────────────────────────────────────────────────

pub fn query_persisted_net_devices(conn: &Connection) -> Result<Vec<UiNetDevice>> {
    let mut stmt = conn.prepare(
        "SELECT network_id, mac, ip, hostname, vendor, is_trusted, custom_alias, first_seen, last_seen
         FROM net_devices
         ORDER BY last_seen DESC"
    ).context("Failed to prepare net_devices query")?;

    let rows = stmt.query_map([], |row| {
        let network_id: String = row.get(0)?;
        let mac: String = row.get(1)?;
        let ip: String = row.get(2)?;
        let hostname: Option<String> = row.get(3)?;
        let vendor: Option<String> = row.get(4)?;
        let is_trusted_num: i32 = row.get(5)?;
        let custom_alias: Option<String> = row.get(6)?;
        let first_seen_str: String = row.get(7)?;
        let last_seen_str: String = row.get(8)?;

        let first_seen = chrono::DateTime::parse_from_rfc3339(&first_seen_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        let last_seen = chrono::DateTime::parse_from_rfc3339(&last_seen_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        Ok(PersistedNetDevice {
            network_id,
            mac,
            ip,
            hostname,
            vendor,
            is_trusted: is_trusted_num != 0,
            custom_alias,
            first_seen,
            last_seen,
        })
    })?;

    let mut list = Vec::new();
    for r in rows {
        let dev = r?;
        list.push(map_persisted_device(&dev, true));
    }
    Ok(list)
}

pub fn query_persisted_incidents(
    conn: &Connection,
    status_filter: Option<IncidentStatus>,
) -> Result<Vec<UiPieIncident>> {
    let incidents = crate::modules::pie::exporter::ForensicExporter::query_incidents(conn, status_filter)?;
    Ok(incidents.iter().map(map_incident).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::network_guardian::device_models::DeviceDetectionSource;
    use crate::modules::network_guardian::wifi_models::*;
    use crate::modules::pie::models::{IncidentCategory, IncidentSeverity};

    #[test]
    fn test_ui_net_device_mapping() {
        let dev = DiscoveredDevice {
            network_id: "192.168.1.0/24_gw:192.168.1.1".to_string(),
            mac: "AA:BB:CC:DD:EE:01".to_string(),
            ip: "192.168.1.1".to_string(),
            hostname: Some("router.lan".to_string()),
            vendor: Some("Netgear".to_string()),
            is_trusted: true,
            is_gateway: true,
            is_local_machine: false,
            custom_alias: None,
            display_category: DeviceDisplayCategory::GatewayRouter,
            first_seen_utc: Utc::now(),
            last_seen_utc: Utc::now(),
            detection_source: DeviceDetectionSource::ArpCache,
        };

        let ui_dev = map_discovered_device(&dev, true);
        assert_eq!(ui_dev.mac, "AA:BB:CC:DD:EE:01");
        assert_eq!(ui_dev.ip, "192.168.1.1");
        assert!(ui_dev.is_gateway);
        assert!(ui_dev.is_trusted);
        assert_eq!(ui_dev.hostname, "router.lan");
        assert_eq!(ui_dev.display_name, "Router / Puerta de Enlace");
        assert_eq!(ui_dev.category_label, "Router / Puerta de Enlace");
    }

    #[test]
    fn test_ui_wifi_report_mapping() {
        let report = WifiDiagnosticsReport {
            adapter_state: WifiAdapterState::Connected,
            simple: WifiSimpleView {
                status_title: "Conexión Wi-Fi activa".to_string(),
                signal_rating: "Excelente (85%)".to_string(),
                security_status: "Segura (WPA2)".to_string(),
                stability_rating: "Estable".to_string(),
                problems_detected: vec![],
                recommendations: vec!["Canal 6 óptimo".to_string()],
            },
            advanced: WifiAdvancedView {
                interface_name: Some("Wi-Fi".to_string()),
                connection: Some(WifiConnectionInfo {
                    ssid: "SysPulse_Home".to_string(),
                    bssid: "11:22:33:44:55:66".to_string(),
                    signal_quality: 85,
                    rssi_dbm: Some(-52),
                    channel: 6,
                    frequency_khz: 2437000,
                    band: WifiBand::Band2_4GHz,
                    channel_width_mhz: Some(20),
                    phy_type: "802.11ax".to_string(),
                    auth_algorithm: "WPA2-Personal".to_string(),
                    cipher_algorithm: "AES-CCMP".to_string(),
                    security_level: WifiSecurityLevel::SecureWpa2,
                    tx_rate_mbps: Some(300.0),
                    rx_rate_mbps: Some(300.0),
                }),
                congestion_data: vec![
                    ChannelCongestion {
                        channel: 6,
                        band: WifiBand::Band2_4GHz,
                        network_count: 2,
                        overlapping_count: 3,
                        congestion_score: 25.0,
                        is_current_channel: true,
                        is_recommended: true,
                        reason: "Baja interferencia".to_string(),
                    }
                ],
                nearby_networks: vec![],
                channel_recommendations: vec![],
                last_scan_utc: Utc::now().to_rfc3339(),
                scan_cached: false,
                pie_correlation_note: None,
            },
        };

        let (info, channels, _) = map_wifi_report(&report);
        assert!(info.is_available);
        assert_eq!(info.ssid, "SysPulse_Home");
        assert_eq!(info.signal_quality, 85);
        assert_eq!(info.channel, 6);
        assert_eq!(channels.len(), 1);
        assert!(channels[0].is_current);
        assert!(channels[0].is_recommended);
    }

    #[test]
    fn test_ui_health_diagnostics_mapping() {
        let diag = NetworkHealthDiagnostics {
            active_adapter_name: Some("Ethernet".to_string()),
            local_ip: Some("192.168.1.50".to_string()),
            gateway_ip: Some("192.168.1.1".to_string()),
            gateway_health: GatewayHealth::Reachable,
            internet_health: InternetHealth::Connected,
            gateway_rtt_ms: Some(1.2),
            internet_rtt_ms: Some(15.4),
            jitter_ms: 1.8,
            packet_loss_percent: 0.0,
            simple_status_title: "Conexión a Internet Excelente".to_string(),
            simple_description: "Tu conexión es rápida y estable.".to_string(),
            simple_recommendation: "Sin acciones requeridas.".to_string(),
            technical_summary: "Gateway 1.2ms, Internet 15.4ms, Jitter 1.8ms".to_string(),
        };

        let ui_link = map_health_diagnostics(&diag);
        assert!(ui_link.is_connected);
        assert_eq!(ui_link.gateway_rtt_ms, 1.2);
        assert_eq!(ui_link.internet_rtt_ms, 15.4);
        assert_eq!(ui_link.jitter_ms, 1.8);
        assert_eq!(ui_link.packet_loss, 0.0);
        assert_eq!(ui_link.adapter_name, "Ethernet");
    }

    #[test]
    fn test_ui_incident_and_evidence_mapping() {
        let evidence = IncidentEvidence {
            id: Some(10),
            incident_id: Some(1),
            timestamp_utc: Utc::now(),
            source_module: "network_guardian".to_string(),
            event_type: "untrusted_mac".to_string(),
            observable_json: "{\"ip\":\"192.168.1.99\",\"mac\":\"AA:11:22:33:44:55\"}".to_string(),
        };

        let incident = Incident {
            id: Some(1),
            timestamp_utc: Utc::now(),
            category: IncidentCategory::Network,
            severity: IncidentSeverity::Medium,
            risk_score: 55,
            confidence: 0.85,
            status: IncidentStatus::Active,
            title: "Dispositivo desconocido en la red".to_string(),
            simple_summary: "Se detectó un equipo no reconocido.".to_string(),
            simple_recommendation: "Revisa los dispositivos conectados.".to_string(),
            technical_rule_id: "PIE-R-NET-NEW-DEVICE".to_string(),
            correlation_key: Some("net_dev_AA:11:22:33:44:55".to_string()),
            last_updated_utc: Utc::now(),
            technical_impact: "Riesgo de acceso no autorizado".to_string(),
            technical_mitigation: "Aislar MAC en router".to_string(),
            diagnostic_limitations: "Basado en escaneo ARP".to_string(),
            evidences: vec![evidence],
        };

        let ui_inc = map_incident(&incident);
        assert_eq!(ui_inc.id, 1);
        assert_eq!(ui_inc.risk_score, 55);
        assert_eq!(ui_inc.severity, "medium");
        assert_eq!(ui_inc.status, "active");
        assert_eq!(ui_inc.evidence_count, 1);
        assert_eq!(ui_inc.evidences[0].source_module, "network_guardian");
        assert_eq!(ui_inc.evidences[0].event_type, "untrusted_mac");
    }

    #[test]
    fn test_sqlite_query_net_devices_and_incidents_empty_and_populated() {
        let conn = Connection::open_in_memory().unwrap();

        // Crear esquemas mínimos de PIE y Network Guardian
        conn.execute_batch(
            "CREATE TABLE net_devices (
                network_id TEXT NOT NULL,
                mac TEXT NOT NULL,
                ip TEXT NOT NULL,
                hostname TEXT,
                vendor TEXT,
                is_trusted INTEGER NOT NULL DEFAULT 0,
                custom_alias TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                PRIMARY KEY (network_id, mac)
            );

            CREATE TABLE pie_incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                confidence REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                title TEXT NOT NULL,
                simple_summary TEXT NOT NULL,
                simple_recommendation TEXT NOT NULL,
                technical_rule_id TEXT NOT NULL,
                correlation_key TEXT,
                last_updated TEXT NOT NULL,
                technical_impact TEXT NOT NULL DEFAULT '',
                technical_mitigation TEXT NOT NULL DEFAULT '',
                diagnostic_limitations TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE pie_incident_evidences (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                source_module TEXT NOT NULL,
                event_type TEXT NOT NULL,
                observable_json TEXT NOT NULL,
                FOREIGN KEY(incident_id) REFERENCES pie_incidents(id) ON DELETE CASCADE
            );"
        ).unwrap();

        // 1. Estado vacío: manejo elegante sin errores
        let devices = query_persisted_net_devices(&conn).unwrap();
        assert!(devices.is_empty());

        let incidents = query_persisted_incidents(&conn, None).unwrap();
        assert!(incidents.is_empty());

        // 2. Insertar registros
        conn.execute(
            "INSERT INTO net_devices (network_id, mac, ip, hostname, vendor, is_trusted, custom_alias, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                "net1", "AA:BB:CC:11:22:33", "192.168.1.10", "laptop.local", "Dell", 1, "Mi Laptop",
                Utc::now().to_rfc3339(), Utc::now().to_rfc3339()
            ],
        ).unwrap();

        conn.execute(
            "INSERT INTO pie_incidents (timestamp, category, severity, risk_score, confidence, status, title, simple_summary, simple_recommendation, technical_rule_id, last_updated)
             VALUES (?1, 'network', 'high', 80, 0.95, 'active', 'Conflicto IP', 'Conflicto detectado', 'Reiniciar DHCP', 'PIE-R-NET-IP-CONFLICT', ?1)",
            params![Utc::now().to_rfc3339()],
        ).unwrap();

        let inc_id = conn.last_insert_rowid();

        conn.execute(
            "INSERT INTO pie_incident_evidences (incident_id, timestamp, source_module, event_type, observable_json)
             VALUES (?1, ?2, 'network_guardian', 'ip_conflict', '{\"ip\":\"192.168.1.10\"}')",
            params![inc_id, Utc::now().to_rfc3339()],
        ).unwrap();

        // 3. Consultar y verificar datos
        let devices = query_persisted_net_devices(&conn).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].display_name, "Mi Laptop");
        assert!(devices[0].is_trusted);

        let incidents = query_persisted_incidents(&conn, None).unwrap();
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].title, "Conflicto IP");
        assert_eq!(incidents[0].evidence_count, 1);
        assert_eq!(incidents[0].evidences[0].event_type, "ip_conflict");
    }

    #[test]
    fn test_ui_socket_connection_mapping() {
        use std::net::{IpAddr, Ipv4Addr};
        use crate::modules::network_guardian::socket_correlator::{CorrelatedSocket, SocketProtocol, TcpState};

        let socket = CorrelatedSocket {
            protocol: SocketProtocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            local_port: 8080,
            remote_addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
            remote_port: Some(54321),
            tcp_state: Some(TcpState::Established),
            pid: 1234,
            process_name: Some("syspulse.exe".to_string()),
            process_path: Some("C:\\bin\\syspulse.exe".to_string()),
            is_process_alive: true,
        };

        let ui_conn = map_correlated_socket(&socket);
        assert_eq!(ui_conn.protocol, "TCP");
        assert_eq!(ui_conn.local_endpoint, "127.0.0.1:8080");
        assert_eq!(ui_conn.remote_endpoint, "192.168.1.10:54321");
        assert_eq!(ui_conn.state, "ESTABLISHED");
        assert_eq!(ui_conn.pid, 1234);
        assert_eq!(ui_conn.process_name, "syspulse.exe");
        assert!(ui_conn.is_alive);

        // Caso listening / sin remote
        let listen_socket = CorrelatedSocket {
            protocol: SocketProtocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            local_port: 80,
            remote_addr: None,
            remote_port: None,
            tcp_state: Some(TcpState::Listen),
            pid: 4,
            process_name: None,
            process_path: None,
            is_process_alive: false,
        };

        let ui_listen = map_correlated_socket(&listen_socket);
        assert_eq!(ui_listen.remote_endpoint, "-");
        assert_eq!(ui_listen.state, "LISTEN");
        assert_eq!(ui_listen.process_name, "-");
        assert!(!ui_listen.is_alive);
    }
}
