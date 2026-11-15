use serde::{Deserialize, Serialize};

/// Información detallada de un adaptador o interfaz de red del equipo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterfaceInfo {
    pub id: String,
    pub name: String,
    pub friendly_name: String,
    pub mac_address: Option<String>,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub gateway_ipv4: Option<String>,
    pub dns_servers: Vec<String>,
    pub is_up: bool,
    pub is_loopback: bool,
    pub prefix_length: Option<u8>,
    pub is_vpn_or_virtual: bool,
}

/// Estado de conectividad con la Puerta de Enlace (Router local).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatewayHealth {
    Reachable,
    HighLatency,
    Unreachable,
    NoGatewayConfigured,
}

/// Estado de salida hacia Internet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InternetHealth {
    Connected,
    Degraded,
    Disconnected,
    IcmpFiltered, // El router funciona, pero el host ICMP no responde (ICMP bloqueado)
    Unknown,
}

/// Resultado de un sondeo ICMP individual.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingSample {
    pub target: String,
    pub ip: String,
    pub rtt_ms: Option<f32>,
    pub is_success: bool,
    pub status_code: u32,
}

/// Diagnóstico de salud de red diseñado tanto para Modo Simple como Modo Avanzado.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHealthDiagnostics {
    pub active_adapter_name: Option<String>,
    pub local_ip: Option<String>,
    pub gateway_ip: Option<String>,
    pub gateway_health: GatewayHealth,
    pub internet_health: InternetHealth,
    pub gateway_rtt_ms: Option<f32>,
    pub internet_rtt_ms: Option<f32>,
    pub jitter_ms: f32,
    pub packet_loss_percent: f32,

    // ── Modo Simple (Comprensible sin conocimientos técnicos) ──
    pub simple_status_title: String,
    pub simple_description: String,
    pub simple_recommendation: String,

    // ── Modo Avanzado (Profesional / Diagnóstico) ──
    pub technical_summary: String,
}
