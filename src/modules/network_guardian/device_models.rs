use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Contexto e identidad de la red local actual.
/// Permite segmentar el inventario de dispositivos entre diferentes entornos (ej. Hogar vs. Oficina).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkContext {
    pub network_id: String,           // Clave unívoca del contexto (ej: "192.168.1.0/24_gw:192.168.1.1")
    pub subnet_cidr: String,          // Notación CIDR (ej: "192.168.1.0/24")
    pub prefix_length: u8,            // Longitud del prefijo detectado dinámicamente
    pub gateway_ip: Option<String>,
    pub interface_id: String,
    pub is_vpn_or_virtual: bool,
}

impl NetworkContext {
    pub fn new(
        subnet_cidr: String,
        prefix_length: u8,
        gateway_ip: Option<String>,
        interface_id: String,
        is_vpn_or_virtual: bool,
    ) -> Self {
        let gw_str = gateway_ip.as_deref().unwrap_or("no_gw");
        let network_id = format!("{}_gw:{}_if:{}", subnet_cidr, gw_str, interface_id);
        Self {
            network_id,
            subnet_cidr,
            prefix_length,
            gateway_ip,
            interface_id,
            is_vpn_or_virtual,
        }
    }
}

/// Categoría tipada del dispositivo para presentación e internacionalización (i18n).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceDisplayCategory {
    ThisDevice,
    GatewayRouter,
    KnownVendor(String),
    LocallyAdministered,
    Unknown,
}

impl DeviceDisplayCategory {
    pub fn label_es(&self) -> String {
        match self {
            DeviceDisplayCategory::ThisDevice => "Tu equipo".to_string(),
            DeviceDisplayCategory::GatewayRouter => "Router / Puerta de Enlace".to_string(),
            DeviceDisplayCategory::KnownVendor(v) => format!("Dispositivo {}", v),
            DeviceDisplayCategory::LocallyAdministered => "Dirección LAA (Virtual / Privada)".to_string(),
            DeviceDisplayCategory::Unknown => "Dispositivo Desconocido".to_string(),
        }
    }

    pub fn label_en(&self) -> String {
        match self {
            DeviceDisplayCategory::ThisDevice => "This PC".to_string(),
            DeviceDisplayCategory::GatewayRouter => "Router / Gateway".to_string(),
            DeviceDisplayCategory::KnownVendor(v) => format!("{} Device", v),
            DeviceDisplayCategory::LocallyAdministered => "LAA Address (Virtual / Private)".to_string(),
            DeviceDisplayCategory::Unknown => "Unknown Device".to_string(),
        }
    }

    pub fn label(&self, lang_code: &str) -> String {
        if lang_code.starts_with("es") {
            self.label_es()
        } else {
            self.label_en()
        }
    }

    pub fn i18n_key(&self) -> &'static str {
        match self {
            DeviceDisplayCategory::ThisDevice => "net_device_this_pc",
            DeviceDisplayCategory::GatewayRouter => "net_device_gateway",
            DeviceDisplayCategory::KnownVendor(_) => "net_device_vendor",
            DeviceDisplayCategory::LocallyAdministered => "net_device_laa",
            DeviceDisplayCategory::Unknown => "net_device_unknown",
        }
    }
}

/// Método por el cual se descubrió el dispositivo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceDetectionSource {
    ArpCache,   // Detectado de forma pasiva en la tabla ARP del kernel (sin tráfico de red)
    ActiveScan, // Detectado mediante solicitud unicast ARP (SendARP) bajo demanda del usuario
}

/// Dispositivo descubierto en la red de área local (LAN).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredDevice {
    pub network_id: String,               // Contexto de red donde fue descubierto
    pub mac: String,                      // Formato unificado "AA:BB:CC:DD:EE:FF"
    pub ip: String,                       // Formato IPv4
    pub hostname: Option<String>,         // Nombre de host resuelto (NetBIOS / mDNS / PTR)
    pub vendor: Option<String>,           // Fabricante detectado mediante OUI
    pub is_trusted: bool,                 // Solo true si el usuario lo confirmó explícitamente o es este equipo
    pub is_gateway: bool,                 // Si coincide con la IP del Router
    pub is_local_machine: bool,           // Si es la IP / MAC de este propio equipo
    pub custom_alias: Option<String>,     // Alias personalizado definido por el usuario
    pub display_category: DeviceDisplayCategory,
    pub first_seen_utc: DateTime<Utc>,
    pub last_seen_utc: DateTime<Utc>,
    pub detection_source: DeviceDetectionSource,
}

impl DiscoveredDevice {
    /// Nombre de presentación amigable para Modo Simple.
    pub fn display_name(&self) -> String {
        if let Some(alias) = &self.custom_alias {
            alias.clone()
        } else if self.is_local_machine {
            "Este equipo (SysPulse)".to_string()
        } else if self.is_gateway {
            "Router / Puerta de Enlace".to_string()
        } else if let Some(hostname) = &self.hostname {
            hostname.clone()
        } else if self.display_category == DeviceDisplayCategory::LocallyAdministered {
            "Dispositivo con MAC Privada / Virtual".to_string()
        } else if let Some(vendor) = &self.vendor {
            format!("Dispositivo {}", vendor)
        } else {
            format!("Dispositivo ({})", self.ip)
        }
    }
}

/// Elemento simplificado para la presentación en Modo Simple.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleDeviceItem {
    pub display_name: String,
    pub device_type_label: String, // Label amigable según idioma
    pub category_key: String,      // Clave tipada para i18n
    pub is_trusted: bool,
    pub ip: String,
    pub is_unknown_warning: bool,
}

/// Vista Modo Simple orientada a usuarios no técnicos.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSimpleView {
    pub total_devices_count: usize,
    pub trusted_count: usize,
    pub unknown_count: usize,
    pub alert_title: Option<String>,
    pub alert_recommendation: Option<String>,
    pub partial_scan_notice: Option<String>,
    pub devices: Vec<SimpleDeviceItem>,
}

/// Vista Modo Avanzado con detalles técnicos completos para auditoría y PIE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAdvancedView {
    pub network_context: NetworkContext,
    pub devices: Vec<DiscoveredDevice>,
    pub scan_duration_ms: u64,
    pub last_scan_utc: String,
    pub is_partial_scan: bool,
    pub total_hosts_in_subnet: u32,
    pub scanned_hosts_count: u32,
    pub pie_correlation_note: Option<String>,
}

/// Reporte completo unificado del descubrimiento de dispositivos.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceScanReport {
    pub simple: DeviceSimpleView,
    pub advanced: DeviceAdvancedView,
}
