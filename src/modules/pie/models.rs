use crate::modules::network_guardian::models::InternetHealth;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Identidad unívoca de un proceso en el sistema.
/// Combina el PID con el timestamp UTC de inicio del proceso para neutralizar
/// colisiones por reciclaje o reutilización de PID en el sistema operativo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_time_utc: u64, // Unix epoch en segundos (UTC)
}

impl ProcessIdentity {
    pub fn new(pid: u32, start_time_utc: u64) -> Self {
        Self { pid, start_time_utc }
    }
}

/// Nivel de severidad de un incidente o alerta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IncidentSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl IncidentSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            IncidentSeverity::Info => "info",
            IncidentSeverity::Low => "low",
            IncidentSeverity::Medium => "medium",
            IncidentSeverity::High => "high",
            IncidentSeverity::Critical => "critical",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "critical" => IncidentSeverity::Critical,
            "high" => IncidentSeverity::High,
            "medium" => IncidentSeverity::Medium,
            "low" => IncidentSeverity::Low,
            _ => IncidentSeverity::Info,
        }
    }
}

/// Estado de resolución de un incidente.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentStatus {
    Active,
    Acknowledged,
    Resolved,
}

impl IncidentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            IncidentStatus::Active => "active",
            IncidentStatus::Acknowledged => "acknowledged",
            IncidentStatus::Resolved => "resolved",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "acknowledged" => IncidentStatus::Acknowledged,
            "resolved" => IncidentStatus::Resolved,
            _ => IncidentStatus::Active,
        }
    }
}

/// Categorías funcionales de incidentes detectados por PIE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IncidentCategory {
    Network,
    Process,
    Performance,
    Security,
}

impl IncidentCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            IncidentCategory::Network => "network",
            IncidentCategory::Process => "process",
            IncidentCategory::Performance => "performance",
            IncidentCategory::Security => "security",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "network" => IncidentCategory::Network,
            "process" => IncidentCategory::Process,
            "performance" => IncidentCategory::Performance,
            _ => IncidentCategory::Security,
        }
    }
}

/// Modelo unificado de Incidente de PIE, diseñado tanto para Modo Simple como Modo Avanzado.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: Option<i64>,
    pub timestamp_utc: DateTime<Utc>,
    pub last_updated_utc: DateTime<Utc>,
    pub correlation_key: Option<String>,
    pub category: IncidentCategory,
    pub severity: IncidentSeverity,
    pub risk_score: u8,       // 0 a 100 (heurística de riesgo)
    pub confidence: f32,      // 0.0 a 1.0 (nivel de certidumbre basado en evidencias)
    pub status: IncidentStatus,

    // ── Modo Simple (Comprensible para cualquier usuario) ──
    pub title: String,
    pub simple_summary: String,
    pub simple_recommendation: String,

    // ── Modo Avanzado (Profesional / Forense) ──
    pub technical_rule_id: String,
    pub technical_impact: String,
    pub technical_mitigation: String,
    pub diagnostic_limitations: String,
    pub evidences: Vec<IncidentEvidence>,
}

/// Evidencia individual observable que respalda un incidente.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentEvidence {
    pub id: Option<i64>,
    pub incident_id: Option<i64>,
    pub timestamp_utc: DateTime<Utc>,
    pub source_module: String,  // ej: "process_hunter", "network_guardian", "sys_monitor"
    pub event_type: String,     // ej: "transient_exec", "untrusted_mac", "gateway_change"
    pub observable_json: String,// Datos crudos medidos en JSON
}

/// Envoltorio de evento crítico con timestamp monotónico para cálculo de ventanas.
#[derive(Debug, Clone)]
pub struct PulseEnvelope {
    pub timestamp_utc: DateTime<Utc>,
    pub monotonic_time: Instant,
    pub event: PulseCriticalEvent,
}

impl PulseEnvelope {
    pub fn new(event: PulseCriticalEvent) -> Self {
        Self {
            timestamp_utc: Utc::now(),
            monotonic_time: Instant::now(),
            event,
        }
    }
}

/// Eventos críticos de seguridad, procesos y red (canal sin pérdidas con backpressure).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PulseCriticalEvent {
    // ── Eventos de Procesos ──
    ProcessSpawned {
        process: ProcessIdentity,
        parent_pid: Option<u32>,
        name: String,
        executable_path: String,
        command_line: String,
    },
    ProcessTerminated {
        process: ProcessIdentity,
        lifetime_seconds: Option<u64>,
    },
    TransientProcessDetected {
        process: ProcessIdentity,
        name: String,
        executable_path: String,
        lifetime_seconds: u64,
    },

    // ── Eventos de Red (Network Guardian) ──
    NewDeviceDiscovered {
        network_id: String,
        mac: String,
        ip: String,
        hostname: Option<String>,
        vendor: Option<String>,
        is_trusted: bool,
    },
    GatewayChanged {
        old_network_id: Option<String>,
        new_network_id: String,
        adapter_name: String,
        old_gateway: Option<String>,
        new_gateway: String,
    },
    DnsServerChanged {
        network_id: Option<String>,
        adapter_name: String,
        old_dns: Vec<String>,
        new_dns: Vec<String>,
    },
    SocketConnectionOpened {
        process: ProcessIdentity,
        local_ip: String,
        local_port: u16,
        remote_ip: String,
        remote_port: u16,
        protocol: String, // "TCP" o "UDP"
    },

    // ── Eventos de Seguridad y Persistencia ──
    RegistryAutostartModified {
        key_path: String,
        value_name: String,
        command_line: String,
    },
    UntrustedExecutionLocation {
        process: ProcessIdentity,
        executable_path: String,
        location_type: String, // "Temp", "AppDataLocal", "Downloads"
    },

    // ── Eventos de Wi-Fi y Conectividad Inalámbrica (Network Guardian) ──
    InsecureWifiConnected {
        network_id: String,
        ssid: String,
        bssid: String,
        security_type: String, // "Open", "WEP", "WPA-TKIP"
    },
    WifiConnectionChanged {
        network_id: String,
        adapter_name: String,
        old_ssid: Option<String>,
        new_ssid: String,
        bssid: String,
        channel: u32,
    },
    WifiSignalDegradation {
        network_id: String,
        ssid: String,
        bssid: String,
        signal_percent: u32,
        rssi_dbm: Option<i32>,
    },
}

/// Telemetría descartable de alta cadencia (CPU, RAM, Temperaturas, Rendimiento).
/// Se propaga mediante canal broadcast con política lossy para no bloquear el sistema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TelemetryEvent {
    CpuLoad {
        global_usage: f32,
        top_process: Option<(u32, String, f32, f32)>, // PID, nombre, % CPU normalizado (0..100), % CPU raw
    },
    MemoryPressure {
        used_bytes: u64,
        total_bytes: u64,
        usage_percent: f32,
        top_processes: Vec<(ProcessIdentity, String, u64)>, // Monitoreo de procesos: PID+startTime, nombre, working_set_bytes
    },
    DiskSaturation {
        disk_name: String,
        available_bytes: u64,
        total_bytes: u64,
    },
    ThermalAlert {
        sensor_label: String,
        temp_celsius: f32,
    },
    NetworkThroughput {
        rx_bytes_sec: u64,
        tx_bytes_sec: u64,
    },
    NetworkLatencySample {
        network_id: String,
        interface_name: Option<String>,
        target: String,
        gateway_rtt_ms: Option<f32>,
        internet_rtt_ms: Option<f32>,
        jitter_ms: Option<f32>,
        packet_loss_percent: Option<f32>,
        internet_health: InternetHealth,
    },
    WifiSignalSample {
        network_id: String,
        ssid: String,
        signal_percent: u32,
        rssi_dbm: Option<i32>,
        channel: u32,
    },
}

/// Dispositivo de red persistido en `syspulse.db` (tabla `net_devices`).
/// Clave primaria compuesta por `(network_id, mac)` para aislar baselines, alias y estados de confianza.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedNetDevice {
    pub network_id: String,
    pub mac: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub is_trusted: bool,
    pub custom_alias: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// Muestra histórica de métricas de red persistida en `syspulse.db` (tabla `net_metrics_history`).
/// Almacena métricas particionadas por red e interfaz, con tipado `Option<f32>` para distinguir
/// valores indisponibles (`None` -> `NULL`) de valores medidos cero (0.0 ms o 0.0% loss).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PersistedNetMetric {
    pub id: Option<i64>,
    pub network_id: String,
    pub interface_name: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub gateway_rtt_ms: Option<f32>,
    pub internet_rtt_ms: Option<f32>,
    pub jitter_ms: Option<f32>,
    pub packet_loss_percent: Option<f32>,
}
