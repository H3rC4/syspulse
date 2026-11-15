use serde::{Deserialize, Serialize};

/// Banda de frecuencia de la red inalámbrica.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WifiBand {
    Band2_4GHz,
    Band5GHz,
    Band6GHz,
    Unknown,
}

impl WifiBand {
    pub fn as_str(&self) -> &'static str {
        match self {
            WifiBand::Band2_4GHz => "2.4 GHz",
            WifiBand::Band5GHz => "5 GHz",
            WifiBand::Band6GHz => "6 GHz",
            WifiBand::Unknown => "Desconocida",
        }
    }

    /// Determina la banda según la frecuencia central en kHz.
    pub fn from_frequency_khz(freq_khz: u32) -> Self {
        if (2_400_000..=2_500_000).contains(&freq_khz) {
            WifiBand::Band2_4GHz
        } else if (5_150_000..=5_895_000).contains(&freq_khz) {
            WifiBand::Band5GHz
        } else if (5_925_000..=7_125_000).contains(&freq_khz) {
            WifiBand::Band6GHz
        } else {
            WifiBand::Unknown
        }
    }
}

/// Nivel de seguridad y robustez del cifrado inalámbrico.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WifiSecurityLevel {
    InsecureOpen,   // Red abierta sin contraseña / sin cifrar
    InsecureWep,    // WEP (Obsoleto, altamente vulnerable)
    WeakWpa,        // WPA1 / TKIP (Débil ante ataques modernos)
    SecureWpa2,     // WPA2-Personal (AES-CCMP, estándar seguro)
    ModernWpa3,     // WPA3-Personal (SAE, máxima protección)
    Enterprise,     // 802.1X Enterprise (Radius)
    Unknown,
}

impl WifiSecurityLevel {
    pub fn is_insecure(&self) -> bool {
        matches!(
            self,
            WifiSecurityLevel::InsecureOpen | WifiSecurityLevel::InsecureWep | WifiSecurityLevel::WeakWpa
        )
    }

    pub fn simple_label(&self) -> &'static str {
        match self {
            WifiSecurityLevel::InsecureOpen => "Insegura (Abierta)",
            WifiSecurityLevel::InsecureWep => "Muy Insegura (WEP Obsoleto)",
            WifiSecurityLevel::WeakWpa => "Poco Segura (WPA Antiguo)",
            WifiSecurityLevel::SecureWpa2 => "Segura (WPA2)",
            WifiSecurityLevel::ModernWpa3 => "Excelente (WPA3)",
            WifiSecurityLevel::Enterprise => "Corporativa (802.1X)",
            WifiSecurityLevel::Unknown => "Desconocido",
        }
    }
}

/// Estado de la interfaz y del servicio Wi-Fi de Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WifiAdapterState {
    Connected,
    Disconnected,
    DisabledOrOff,
    NoAdapter,
    LocationPermissionDenied,
}

impl WifiAdapterState {
    pub fn as_str(&self) -> &'static str {
        match self {
            WifiAdapterState::Connected => "Conectado",
            WifiAdapterState::Disconnected => "Desconectado",
            WifiAdapterState::DisabledOrOff => "Desactivado",
            WifiAdapterState::NoAdapter => "Sin adaptador Wi-Fi",
            WifiAdapterState::LocationPermissionDenied => "Permiso de ubicación denegado",
        }
    }
}

/// Información técnica de la conexión Wi-Fi actualmente activa.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiConnectionInfo {
    pub ssid: String,
    pub bssid: String,
    pub signal_quality: u32, // 0 a 100%
    pub rssi_dbm: Option<i32>,
    pub channel: u32,
    pub frequency_khz: u32,
    pub band: WifiBand,
    pub channel_width_mhz: Option<u32>,
    pub phy_type: String,       // ej: "802.11ax (Wi-Fi 6)", "802.11ac"
    pub auth_algorithm: String, // ej: "WPA2-Personal"
    pub cipher_algorithm: String, // ej: "AES-CCMP"
    pub security_level: WifiSecurityLevel,
    pub tx_rate_mbps: Option<f32>,
    pub rx_rate_mbps: Option<f32>,
}

/// Red Wi-Fi circundante detectada en el escaneo BSS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NearbyNetwork {
    pub ssid: String,
    pub is_hidden: bool,
    pub bssid: String,
    pub signal_quality: u32,
    pub rssi_dbm: i32,
    pub channel: u32,
    pub frequency_khz: u32,
    pub band: WifiBand,
    pub security_level: WifiSecurityLevel,
    pub auth_algorithm: String,
    pub cipher_algorithm: String,
}

/// Congestión estimada para un canal radioeléctrico.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelCongestion {
    pub channel: u32,
    pub band: WifiBand,
    pub network_count: usize,       // Redes en el canal exacto (co-canal)
    pub overlapping_count: usize,   // Redes en canales adyacentes solapados
    pub congestion_score: f32,      // 0.0 (limpio) a 100.0 (saturado)
    pub is_current_channel: bool,
    pub is_recommended: bool,
    pub reason: String,
}

/// Recomendación explicable de canales óptimos.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelRecommendation {
    pub band: WifiBand,
    pub current_channel: Option<u32>,
    pub recommended_channel: u32,
    pub alternative_channels: Vec<u32>,
    pub reason: String,
    pub physical_rf_disclaimer: String,
}

/// Vista Modo Simple orientada a usuarios sin conocimientos técnicos.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiSimpleView {
    pub status_title: String,
    pub signal_rating: String,     // "Excelente", "Buena", "Débil", "Crítica"
    pub security_status: String,   // "Segura", "Insegura", etc.
    pub stability_rating: String,  // "Estable", "Fluctuante"
    pub problems_detected: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Vista Modo Avanzado orientada a administradores, gráficos y evidencias de PIE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiAdvancedView {
    pub interface_name: Option<String>,
    pub connection: Option<WifiConnectionInfo>,
    pub congestion_data: Vec<ChannelCongestion>,
    pub nearby_networks: Vec<NearbyNetwork>,
    pub channel_recommendations: Vec<ChannelRecommendation>,
    pub last_scan_utc: String,
    pub scan_cached: bool,
    pub pie_correlation_note: Option<String>,
}

/// Reporte completo unificado del diagnóstico inalámbrico.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiDiagnosticsReport {
    pub adapter_state: WifiAdapterState,
    pub simple: WifiSimpleView,
    pub advanced: WifiAdvancedView,
}

/// Convierte frecuencia en kHz al número de canal estándar IEEE 802.11.
pub fn frequency_khz_to_channel(freq_khz: u32) -> Option<u32> {
    if freq_khz == 2_484_000 {
        return Some(14); // Canal 14 (Japón)
    }

    if (2_412_000..=2_472_000).contains(&freq_khz) {
        // Canales 1 al 13 en 2.4 GHz (separación 5 MHz, canal 1 = 2412 MHz)
        let ch = (freq_khz - 2_407_000) / 5_000;
        return Some(ch);
    }

    if (5_160_000..=5_885_000).contains(&freq_khz) {
        // Canales 5 GHz (UNII-1, UNII-2, UNII-3)
        let ch = (freq_khz - 5_000_000) / 5_000;
        return Some(ch);
    }

    if (5_955_000..=7_115_000).contains(&freq_khz) {
        // Canales 6 GHz (Wi-Fi 6E)
        let ch = (freq_khz - 5_950_000) / 5_000;
        return Some(ch);
    }

    None
}
