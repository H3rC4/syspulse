use crate::modules::network_guardian::InternetHealth;
use crate::modules::pie::bus::PulseEventReceiver;
use crate::modules::pie::models::{
    Incident, IncidentCategory, IncidentEvidence, IncidentSeverity, IncidentStatus,
    PersistedNetDevice, PersistedNetMetric, ProcessIdentity, PulseCriticalEvent, PulseEnvelope,
    TelemetryEvent,
};
use crate::modules::pie::rules::CorrelationRule;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const MAX_EVENT_BUFFER_SIZE: usize = 500;
const EVIDENCE_DEBOUNCE_SECS: u64 = 10;

type NetQualitySample = (Option<f32>, Option<f32>, Option<f32>, Instant);

/// Motor central de inteligencia y correlación heurística de SysPulse (PIE Core).
pub struct PulseIntelligenceEngine {
    pub(crate) db: Arc<Mutex<Connection>>,
    recent_events: VecDeque<PulseEnvelope>,
    rules: Vec<CorrelationRule>,
    last_purge_time: Instant,
    last_event_time: Instant,

    // Caché de incidentes activos por correlation_key para deduplicación entre reinicios
    active_incidents_cache: HashMap<String, i64>,
    last_evidence_time: HashMap<String, Instant>,

    // Muestras recientes de calidad de red por network_id para correlación con Wi-Fi
    // network_id -> (gateway_rtt_ms, jitter_ms, packet_loss_percent, timestamp)
    recent_net_quality: HashMap<String, NetQualitySample>,

    // Seguimiento de condiciones sostenidas e histéresis
    cpu_streak: HashMap<u32, (usize, Instant, f32)>, // PID -> (consecutive_samples, first_seen, last_cpu)
    cpu_sustained_duration: Duration,                // Duración configurable (15–30s) para confirmación
    memory_streak: usize,
    process_memory_history: HashMap<ProcessIdentity, (Instant, u64)>, // Historial acotado de consumo de procesos
    ext_down_streak: HashMap<String, usize>,        // network_id -> consecutive_samples
    wifi_deg_streak: HashMap<String, usize>,        // network_id -> consecutive_samples
    wifi_recov_streak: HashMap<String, usize>,      // network_id -> consecutive_healthy_samples
}

impl PulseIntelligenceEngine {
    /// Inicializa el motor de inteligencia y asegura las tablas SQLite en `syspulse.db`.
    pub fn new() -> Result<Self> {
        let db_path = crate::modules::config::Settings::db_path()?;
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create DB directory {:?}", parent))?;
        }

        let conn = Connection::open(&db_path)
            .with_context(|| format!("Failed to open DB {:?}", db_path))?;

        Self::with_connection(conn)
    }

    /// Inicializa el motor con una conexión existente ejecutando migraciones transaccionales y versionadas.
    pub fn with_connection(mut conn: Connection) -> Result<Self> {
        Self::migrate_schema(&mut conn)?;

        // Cargar conjunto completo de reglas heurísticas aprobadas
        let rules = vec![
            CorrelationRule::wifi_degradation(),
            CorrelationRule::external_connectivity_down(),
            CorrelationRule::network_anomaly(),
            CorrelationRule::ip_mac_conflict(),
            CorrelationRule::sustained_process_cpu(),
            CorrelationRule::sustained_memory_pressure(),
            CorrelationRule::resource_saturation(),
            CorrelationRule::suspicious_temp_exec(),
        ];

        // Precargar mapa de incidentes activos para deduplicación entre reinicios
        let mut active_cache = HashMap::new();
        {
            let mut stmt = conn.prepare(
                "SELECT id, correlation_key FROM pie_incidents WHERE status = 'active' AND correlation_key IS NOT NULL"
            )?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let id: i64 = row.get(0)?;
                let key: String = row.get(1)?;
                active_cache.insert(key, id);
            }
        }

        let now = Instant::now();
        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
            recent_events: VecDeque::with_capacity(MAX_EVENT_BUFFER_SIZE),
            rules,
            last_purge_time: now,
            last_event_time: now,
            active_incidents_cache: active_cache,
            last_evidence_time: HashMap::new(),
            recent_net_quality: HashMap::new(),
            cpu_streak: HashMap::new(),
            cpu_sustained_duration: Duration::from_secs(15),
            memory_streak: 0,
            process_memory_history: HashMap::new(),
            ext_down_streak: HashMap::new(),
            wifi_deg_streak: HashMap::new(),
            wifi_recov_streak: HashMap::new(),
        })
    }

    /// Ejecuta migraciones SQLite versionadas (PRAGMA user_version), transaccionales y no destructivas.
    pub fn migrate_schema(conn: &mut Connection) -> Result<()> {
        let current_version: i32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;

        // ── Versión 1: Tablas base de incidentes y evidencias ──
        if current_version < 1 {
            let tx = conn.transaction()?;
            tx.execute(
                "CREATE TABLE IF NOT EXISTS pie_incidents (
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
                    technical_rule_id TEXT NOT NULL
                )",
                [],
            )?;

            tx.execute(
                "CREATE TABLE IF NOT EXISTS pie_incident_evidences (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id INTEGER NOT NULL,
                    timestamp TEXT NOT NULL,
                    source_module TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    observable_json TEXT NOT NULL,
                    FOREIGN KEY(incident_id) REFERENCES pie_incidents(id) ON DELETE CASCADE
                )",
                [],
            )?;

            tx.execute("CREATE INDEX IF NOT EXISTS idx_pie_incidents_timestamp ON pie_incidents(timestamp)", [])?;
            tx.execute("CREATE INDEX IF NOT EXISTS idx_pie_evidences_incident ON pie_incident_evidences(incident_id)", [])?;
            tx.pragma_update(None, "user_version", 1)?;
            tx.commit()?;
        }

        // ── Versión 2: Tablas de red con clave compuesta (network_id, mac) ──
        let version_after_v1: i32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version_after_v1 < 2 {
            let tx = conn.transaction()?;

            let has_net_devices: bool = tx.query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='net_devices'",
                [],
                |row| Ok(row.get::<_, i64>(0)? > 0),
            )?;

            if has_net_devices {
                let has_network_id: bool = {
                    let mut stmt = tx.prepare("PRAGMA table_info(net_devices)")?;
                    let mut rows = stmt.query([])?;
                    let mut found = false;
                    while let Some(row) = rows.next()? {
                        let name: String = row.get(1)?;
                        if name == "network_id" {
                            found = true;
                            break;
                        }
                    }
                    found
                };

                if !has_network_id {
                    tracing::info!(target: "pie::engine", "Migrando net_devices a esquema versionado v2");
                    tx.execute("ALTER TABLE net_devices RENAME TO net_devices_legacy_v1", [])?;
                    tx.execute(
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
                        )",
                        [],
                    )?;

                    tx.execute(
                        "INSERT INTO net_devices (
                            network_id, mac, ip, hostname, vendor, is_trusted, custom_alias, first_seen, last_seen
                        ) SELECT 'legacy_unassigned', mac, ip, hostname, vendor, 0, custom_alias, first_seen, last_seen
                          FROM net_devices_legacy_v1",
                        [],
                    )?;

                    tx.execute("DROP TABLE net_devices_legacy_v1", [])?;
                }
            } else {
                tx.execute(
                    "CREATE TABLE IF NOT EXISTS net_devices (
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
                    )",
                    [],
                )?;
            }

            let has_metrics: bool = tx.query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='net_metrics_history'",
                [],
                |row| Ok(row.get::<_, i64>(0)? > 0),
            )?;

            if has_metrics {
                let has_network_id_metrics: bool = {
                    let mut stmt = tx.prepare("PRAGMA table_info(net_metrics_history)")?;
                    let mut rows = stmt.query([])?;
                    let mut found = false;
                    while let Some(row) = rows.next()? {
                        let name: String = row.get(1)?;
                        if name == "network_id" {
                            found = true;
                            break;
                        }
                    }
                    found
                };

                if !has_network_id_metrics {
                    tracing::info!(target: "pie::engine", "Migrando net_metrics_history a esquema versionado v2");
                    tx.execute("ALTER TABLE net_metrics_history RENAME TO net_metrics_history_legacy_v1", [])?;

                    tx.execute(
                        "CREATE TABLE net_metrics_history (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            network_id TEXT NOT NULL,
                            interface_name TEXT,
                            timestamp TEXT NOT NULL,
                            gateway_rtt_ms REAL,
                            internet_rtt_ms REAL,
                            jitter_ms REAL,
                            packet_loss_percent REAL
                        )",
                        [],
                    )?;

                    tx.execute(
                        "INSERT INTO net_metrics_history (
                            id, network_id, interface_name, timestamp, gateway_rtt_ms, internet_rtt_ms, jitter_ms, packet_loss_percent
                        ) SELECT id, 'legacy_unassigned', NULL, timestamp, gateway_rtt_ms, internet_rtt_ms, jitter_ms, packet_loss_percent
                          FROM net_metrics_history_legacy_v1",
                        [],
                    )?;

                    tx.execute("DROP TABLE net_metrics_history_legacy_v1", [])?;
                }
            } else {
                tx.execute(
                    "CREATE TABLE IF NOT EXISTS net_metrics_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        network_id TEXT NOT NULL,
                        interface_name TEXT,
                        timestamp TEXT NOT NULL,
                        gateway_rtt_ms REAL,
                        internet_rtt_ms REAL,
                        jitter_ms REAL,
                        packet_loss_percent REAL
                    )",
                    [],
                )?;
            }

            tx.execute("CREATE INDEX IF NOT EXISTS idx_net_devices_network_mac ON net_devices(network_id, mac)", [])?;
            tx.execute("CREATE INDEX IF NOT EXISTS idx_net_devices_network_last_seen ON net_devices(network_id, last_seen)", [])?;
            tx.execute("CREATE INDEX IF NOT EXISTS idx_net_devices_ip ON net_devices(ip)", [])?;
            tx.execute("CREATE INDEX IF NOT EXISTS idx_net_metrics_history_net_ts ON net_metrics_history(network_id, timestamp)", [])?;
            tx.execute("CREATE INDEX IF NOT EXISTS idx_net_metrics_history_ts ON net_metrics_history(timestamp)", [])?;

            tx.pragma_update(None, "user_version", 2)?;
            tx.commit()?;
        }

        // ── Versión 3: Explicabilidad estructurada y correlation_key para deduplicación e histéresis ──
        let version_after_v2: i32 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version_after_v2 < 3 {
            let tx = conn.transaction()?;

            let mut existing_cols = Vec::new();
            {
                let mut stmt = tx.prepare("PRAGMA table_info(pie_incidents)")?;
                let mut rows = stmt.query([])?;
                while let Some(row) = rows.next()? {
                    let name: String = row.get(1)?;
                    existing_cols.push(name);
                }
            }

            if !existing_cols.contains(&"last_updated".to_string()) {
                tx.execute("ALTER TABLE pie_incidents ADD COLUMN last_updated TEXT", [])?;
                tx.execute("UPDATE pie_incidents SET last_updated = timestamp WHERE last_updated IS NULL", [])?;
            }
            if !existing_cols.contains(&"correlation_key".to_string()) {
                tx.execute("ALTER TABLE pie_incidents ADD COLUMN correlation_key TEXT", [])?;
            }
            if !existing_cols.contains(&"technical_impact".to_string()) {
                tx.execute("ALTER TABLE pie_incidents ADD COLUMN technical_impact TEXT NOT NULL DEFAULT ''", [])?;
            }
            if !existing_cols.contains(&"technical_mitigation".to_string()) {
                tx.execute("ALTER TABLE pie_incidents ADD COLUMN technical_mitigation TEXT NOT NULL DEFAULT ''", [])?;
            }
            if !existing_cols.contains(&"diagnostic_limitations".to_string()) {
                tx.execute("ALTER TABLE pie_incidents ADD COLUMN diagnostic_limitations TEXT NOT NULL DEFAULT ''", [])?;
            }

            tx.execute("CREATE INDEX IF NOT EXISTS idx_pie_incidents_key_status ON pie_incidents(correlation_key, status)", [])?;

            tx.pragma_update(None, "user_version", 3)?;
            tx.commit()?;
        }

        Ok(())
    }

    /// Comprueba si ha ocurrido un salto monotónico (>60s) debido a suspensión o hibernación del sistema.
    /// Si ocurre, resetea todas las rachas para evitar correlaciones falsas al reanudar.
    fn check_monotonic_gap(&mut self, now: Instant) {
        if now.duration_since(self.last_event_time) > Duration::from_secs(60) {
            tracing::info!(target: "pie::engine", "Detectado salto monotónico (>60s) por suspensión del sistema; reiniciando rachas transitorias");
            self.cpu_streak.clear();
            self.memory_streak = 0;
            self.process_memory_history.clear();
            self.ext_down_streak.clear();
            self.wifi_deg_streak.clear();
            self.wifi_recov_streak.clear();
        }
        self.last_event_time = now;
    }

    /// Bucle principal asíncrono de procesamiento de eventos en segundo plano.
    pub async fn run_loop(mut self, mut receiver: PulseEventReceiver) {
        tracing::info!(target: "pie::engine", "Pulse Intelligence Engine started");

        loop {
            tokio::select! {
                Some(envelope) = receiver.critical_rx.recv() => {
                    self.process_critical_event(envelope).await;
                }

                Ok(telemetry) = receiver.telemetry_rx.recv() => {
                    self.process_telemetry_event(telemetry).await;
                }

                else => {
                    tracing::info!(target: "pie::engine", "Event channels closed; stopping PIE loop");
                    break;
                }
            }
        }
    }

    /// Procesa un evento crítico, lo registra en el buffer temporal y evalúa reglas de correlación.
    pub async fn process_critical_event(&mut self, envelope: PulseEnvelope) {
        let now = Instant::now();
        self.check_monotonic_gap(now);

        // 1. Manejo específico según el tipo de evento crítico
        match &envelope.event {
            PulseCriticalEvent::DeviceObserved {
                network_id,
                mac,
                ip,
                hostname,
                vendor,
                is_trusted,
            } => {
                // Persistencia silenciosa de línea base sin emitir alertas (reglas 3 y 4 omitidas)
                let dev = PersistedNetDevice {
                    network_id: network_id.clone(),
                    mac: mac.clone(),
                    ip: ip.clone(),
                    hostname: hostname.clone(),
                    vendor: vendor.clone(),
                    is_trusted: *is_trusted,
                    custom_alias: None,
                    first_seen: envelope.timestamp_utc,
                    last_seen: envelope.timestamp_utc,
                };
                if let Err(e) = self.upsert_net_device(&dev).await {
                    tracing::warn!(target: "pie::engine", "Error persistiendo dispositivo {} en {}: {}", mac, network_id, e);
                }
            }

            PulseCriticalEvent::NewDeviceDiscovered {
                network_id,
                mac,
                ip,
                hostname,
                vendor,
                is_trusted,
            } => {
                // A) Persistencia / actualización automática del dispositivo en net_devices
                let dev = PersistedNetDevice {
                    network_id: network_id.clone(),
                    mac: mac.clone(),
                    ip: ip.clone(),
                    hostname: hostname.clone(),
                    vendor: vendor.clone(),
                    is_trusted: *is_trusted,
                    custom_alias: None,
                    first_seen: envelope.timestamp_utc,
                    last_seen: envelope.timestamp_utc,
                };
                if let Err(e) = self.upsert_net_device(&dev).await {
                    tracing::warn!(target: "pie::engine", "Error persistiendo dispositivo {} en {}: {}", mac, network_id, e);
                }

                // B) Regla 4: Detectar colisión o conflicto de IP en la misma red
                self.evaluate_ip_conflict(network_id, mac, ip).await;

                // C) Regla 3: Detectar correlación con cambio de Gateway reciente en la misma red
                if !*is_trusted {
                    self.evaluate_untrusted_device_with_recent_gateway_change(network_id, mac, ip).await;
                }
            }

            PulseCriticalEvent::GatewayChanged {
                old_network_id,
                new_network_id,
                adapter_name,
                new_gateway,
                old_gateway,
            } => {
                // Regla 3: Detectar cambio de Gateway con dispositivo no confiable reciente
                self.evaluate_gateway_change_with_untrusted_device(
                    old_network_id.as_deref(),
                    new_network_id,
                    adapter_name,
                    new_gateway,
                    old_gateway.as_deref(),
                ).await;
            }

            PulseCriticalEvent::DnsServerChanged {
                network_id,
                adapter_name,
                old_dns,
                new_dns,
            } => {
                // Regla 3: Evaluar cambio de servidores DNS
                self.evaluate_dns_change(
                    network_id.as_deref(),
                    adapter_name,
                    old_dns,
                    new_dns,
                ).await;
            }

            PulseCriticalEvent::WifiSignalDegradation {
                network_id,
                ssid,
                bssid,
                signal_percent,
                rssi_dbm,
            } => {
                // Regla 1: Degradación del enlace Wi-Fi correlacionada con telemetría de enlace
                self.evaluate_wifi_degradation_event(
                    network_id,
                    ssid,
                    bssid,
                    *signal_percent,
                    *rssi_dbm,
                ).await;
            }

            PulseCriticalEvent::SocketConnectionOpened {
                process,
                local_ip: _,
                local_port: _,
                remote_ip,
                remote_port,
                protocol: _,
            } => {
                // Regla 8: Ejecución desde temporal con conexión externa activa
                let has_temp_exec = self.recent_events.iter().any(|e| {
                    if let PulseCriticalEvent::UntrustedExecutionLocation { process: p, .. } = &e.event {
                        p.pid == process.pid && p.start_time_utc == process.start_time_utc
                    } else {
                        false
                    }
                });

                if has_temp_exec {
                    let rule = CorrelationRule::suspicious_temp_exec();
                    let key = format!("temp_exec_socket_{}_{}", process.pid, process.start_time_utc);
                    let _ = self.find_or_create_incident(
                        &rule,
                        Some(key),
                        "network_guardian",
                        "socket_connection_opened",
                        serde_json::json!({
                            "pid": process.pid,
                            "start_time_utc": process.start_time_utc,
                            "remote_ip": remote_ip,
                            "remote_port": remote_port
                        }),
                    ).await;
                }
            }

            _ => {}
        }

        // 2. Limpieza de eventos expirados del buffer monotónico (mayores a 2 minutos)
        while let Some(front) = self.recent_events.front() {
            if now.duration_since(front.monotonic_time) > Duration::from_secs(120) {
                self.recent_events.pop_front();
            } else {
                break;
            }
        }

        // 3. Añadir evento al buffer circular
        if self.recent_events.len() >= MAX_EVENT_BUFFER_SIZE {
            self.recent_events.pop_front();
        }
        self.recent_events.push_back(envelope);
    }

    /// Procesa telemetría periódica descartable, persistiendo métricas y evaluando condiciones sostenidas.
    pub async fn process_telemetry_event(&mut self, telemetry: TelemetryEvent) {
        let now = Instant::now();
        self.check_monotonic_gap(now);

        match telemetry {
            TelemetryEvent::NetworkLatencySample {
                network_id,
                interface_name,
                target: _,
                gateway_rtt_ms,
                internet_rtt_ms,
                jitter_ms,
                packet_loss_percent,
                internet_health,
            } => {
                // A) Guardar calidad reciente para correlación Wi-Fi
                self.recent_net_quality.insert(
                    network_id.clone(),
                    (gateway_rtt_ms, jitter_ms, packet_loss_percent, now),
                );

                // B) Persistencia de la muestra periódica en net_metrics_history
                let metric = PersistedNetMetric {
                    id: None,
                    network_id: network_id.clone(),
                    interface_name: interface_name.clone(),
                    timestamp: Utc::now(),
                    gateway_rtt_ms,
                    internet_rtt_ms,
                    jitter_ms,
                    packet_loss_percent,
                };
                let _ = self.record_net_metrics(&metric).await;

                // C) Purga automática según retención configurada (cada 1 hora)
                if now.duration_since(self.last_purge_time) > Duration::from_secs(3600) {
                    let retention_days = crate::modules::config::Settings::load()
                        .map(|s| s.net_metrics_retention_days)
                        .unwrap_or(7);
                    let _ = self.purge_old_metrics(retention_days).await;
                    self.last_purge_time = now;
                }

                // D) Regla 2: Evaluar conectividad externa propagando InternetHealth
                self.evaluate_external_connectivity(
                    &network_id,
                    interface_name.as_deref(),
                    gateway_rtt_ms,
                    internet_rtt_ms,
                    packet_loss_percent,
                    internet_health,
                ).await;
            }

            TelemetryEvent::CpuLoad { global_usage, top_process } => {
                // Regla 5: Consumo elevado y sostenido de CPU por proceso (con normalización y duración monotónica)
                self.evaluate_sustained_cpu(global_usage, top_process).await;
            }

            TelemetryEvent::MemoryPressure {
                used_bytes,
                total_bytes,
                usage_percent,
                top_processes,
            } => {
                // Regla 6: Saturación sostenida de memoria física con evidencia de top_processes
                self.evaluate_memory_pressure(used_bytes, total_bytes, usage_percent, top_processes).await;
            }

            TelemetryEvent::WifiSignalSample {
                network_id,
                ssid,
                signal_percent,
                rssi_dbm,
                channel: _,
            } => {
                // Regla 1 (Telemetría): Seguimiento de histéresis y resolución de Wi-Fi
                self.evaluate_wifi_signal_sample(&network_id, &ssid, signal_percent, rssi_dbm).await;
            }

            TelemetryEvent::ThermalAlert { sensor_label, temp_celsius } => {
                // Regla 7: Estrés térmico crítico con umbrales diferenciados por componente
                self.evaluate_thermal_alert(&sensor_label, temp_celsius).await;
            }

            _ => {}
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Evaluaciones Heurísticas Específicas por Regla
    // ─────────────────────────────────────────────────────────────────────────────

    /// Regla 4: Detecta si una IP ya registrada en la red responde ahora con una MAC distinta.
    /// Diferencia reasignaciones DHCP normales (>10 minutos sin actividad de la MAC anterior)
    /// de posibles conflictos o colisiones activas (presencia simultánea o cambio en <10 minutos).
    async fn evaluate_ip_conflict(&mut self, network_id: &str, new_mac: &str, ip: &str) {
        let db = self.db.lock().await;
        let prev_row: Result<Option<(String, String)>, rusqlite::Error> = db.query_row(
            "SELECT mac, last_seen FROM net_devices WHERE network_id = ?1 AND ip = ?2 AND mac != ?3 LIMIT 1",
            params![network_id, ip, new_mac],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).map(Some).or_else(|e| if e == rusqlite::Error::QueryReturnedNoRows { Ok(None) } else { Err(e) });
        drop(db);

        if let Ok(Some((conflict_mac, last_seen_str))) = prev_row {
            let last_seen = DateTime::parse_from_rfc3339(&last_seen_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            let elapsed_secs = (Utc::now() - last_seen).num_seconds();

            // Solo alertar si la MAC previa estuvo activa en los últimos 10 minutos (600s).
            // Si pasaron más de 10 minutos, se trata de una rotación o reasignación DHCP normal.
            if elapsed_secs <= 600 {
                let rule = CorrelationRule::ip_mac_conflict();
                let key = format!("ip_conflict_{}_{}", network_id, ip);
                let _ = self.find_or_create_incident(
                    &rule,
                    Some(key),
                    "network_guardian",
                    "ip_mac_conflict",
                    serde_json::json!({
                        "network_id": network_id,
                        "ip": ip,
                        "previous_mac": conflict_mac,
                        "new_mac": new_mac,
                        "previous_last_seen_secs_ago": elapsed_secs
                    }),
                ).await;
            } else {
                tracing::debug!(
                    target: "pie::engine",
                    "Reasignación DHCP normal detectada en {}: IP {} pasó de {} a {} tras {}s",
                    network_id, ip, conflict_mac, new_mac, elapsed_secs
                );
            }
        }
    }

    /// Regla 3: Evalúa si un dispositivo no confiable apareció justo tras un cambio de Gateway en la misma red o adaptador.
    async fn evaluate_untrusted_device_with_recent_gateway_change(&mut self, network_id: &str, mac: &str, ip: &str) {
        let now = Instant::now();
        let recent_gw = self.recent_events.iter().find(|e| {
            if now.duration_since(e.monotonic_time) <= Duration::from_secs(45) {
                if let PulseCriticalEvent::GatewayChanged { old_network_id, new_network_id, new_gateway, .. } = &e.event {
                    new_network_id == network_id
                        || old_network_id.as_deref() == Some(network_id)
                        || new_gateway == ip
                } else {
                    false
                }
            } else {
                false
            }
        });

        if let Some(gw_env) = recent_gw {
            if let PulseCriticalEvent::GatewayChanged { adapter_name, new_gateway, old_gateway, old_network_id, new_network_id } = &gw_env.event {
                let rule = CorrelationRule::network_anomaly();
                let key = format!("rogue_gw_{}", network_id);
                let _ = self.find_or_create_incident(
                    &rule,
                    Some(key),
                    "network_guardian",
                    "gateway_changed_with_untrusted_device",
                    serde_json::json!({
                        "old_network_id": old_network_id,
                        "new_network_id": new_network_id,
                        "adapter": adapter_name,
                        "old_gateway": old_gateway,
                        "new_gateway": new_gateway,
                        "untrusted_mac": mac,
                        "untrusted_ip": ip
                    }),
                ).await;
            }
        }
    }

    /// Regla 3: Evalúa si un cambio de Gateway se acompaña de un dispositivo no confiable descubierto recientemente.
    async fn evaluate_gateway_change_with_untrusted_device(
        &mut self,
        old_network_id: Option<&str>,
        new_network_id: &str,
        adapter_name: &str,
        new_gateway: &str,
        old_gateway: Option<&str>,
    ) {
        let now = Instant::now();
        let recent_untrusted = self.recent_events.iter().find(|e| {
            if now.duration_since(e.monotonic_time) <= Duration::from_secs(45) {
                if let PulseCriticalEvent::NewDeviceDiscovered { network_id: dev_net, is_trusted, ip, .. } = &e.event {
                    if !*is_trusted {
                        dev_net == new_network_id
                            || old_network_id.map(|old| dev_net == old).unwrap_or(false)
                            || ip == new_gateway
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        });

        if let Some(dev_env) = recent_untrusted {
            if let PulseCriticalEvent::NewDeviceDiscovered { mac, ip, .. } = &dev_env.event {
                let rule = CorrelationRule::network_anomaly();
                let key = format!("rogue_gw_{}", new_network_id);
                let _ = self.find_or_create_incident(
                    &rule,
                    Some(key),
                    "network_guardian",
                    "gateway_changed_with_untrusted_device",
                    serde_json::json!({
                        "old_network_id": old_network_id,
                        "new_network_id": new_network_id,
                        "adapter": adapter_name,
                        "old_gateway": old_gateway,
                        "new_gateway": new_gateway,
                        "untrusted_mac": mac,
                        "untrusted_ip": ip
                    }),
                ).await;
            }
        }
    }

    /// Regla 3: Evalúa cambios en la lista de servidores DNS en una interfaz.
    async fn evaluate_dns_change(
        &mut self,
        network_id: Option<&str>,
        adapter_name: &str,
        old_dns: &[String],
        new_dns: &[String],
    ) {
        let net_id = network_id.unwrap_or("unknown");
        let key = format!("dns_change_{}_{}", net_id, adapter_name);
        let rule = CorrelationRule::network_anomaly();
        let _ = self.find_or_create_incident(
            &rule,
            Some(key),
            "network_guardian",
            "dns_server_changed",
            serde_json::json!({
                "network_id": network_id,
                "adapter": adapter_name,
                "old_dns": old_dns,
                "new_dns": new_dns,
            }),
        ).await;
    }

    /// Regla 1: Evalúa evento de degradación de señal Wi-Fi correlacionándolo con la telemetría del enlace.
    async fn evaluate_wifi_degradation_event(
        &mut self,
        network_id: &str,
        ssid: &str,
        bssid: &str,
        signal_percent: u32,
        rssi_dbm: Option<i32>,
    ) {
        // Verificar si la telemetría reciente muestra degradación real de calidad (jitter > 20ms, packet loss > 5%, o RTT > 50ms)
        let is_link_degraded = self.recent_net_quality.get(network_id).map(|(gw, jit, loss, ts)| {
            if ts.elapsed() <= Duration::from_secs(60) {
                jit.unwrap_or(0.0) > 20.0 || loss.unwrap_or(0.0) > 5.0 || gw.unwrap_or(0.0) > 50.0
            } else {
                false
            }
        }).unwrap_or(false);

        // Si la señal es baja (<25%) Y además hay evidencia de degradación de enlace:
        if signal_percent < 25 && is_link_degraded {
            let rule = CorrelationRule::wifi_degradation();
            let key = format!("wifi_deg_{}", network_id);
            let _ = self.find_or_create_incident(
                &rule,
                Some(key),
                "network_guardian",
                "wifi_signal_degradation",
                serde_json::json!({
                    "network_id": network_id,
                    "ssid": ssid,
                    "bssid": bssid,
                    "signal_percent": signal_percent,
                    "rssi_dbm": rssi_dbm,
                    "link_degraded": true
                }),
            ).await;
        }
    }

    /// Regla 2: Evalúa falla de salida externa (Gateway local alcanzable pero Internet inalcanzable),
    /// utilizando `InternetHealth` para no generar falsos positivos cuando ICMP esté filtrado pero TCP responda.
    async fn evaluate_external_connectivity(
        &mut self,
        network_id: &str,
        interface_name: Option<&str>,
        gateway_rtt_ms: Option<f32>,
        internet_rtt_ms: Option<f32>,
        packet_loss_percent: Option<f32>,
        internet_health: InternetHealth,
    ) {
        let key = format!("ext_down_{}", network_id);

        match internet_health {
            InternetHealth::Connected => {
                if let Some(streak) = self.ext_down_streak.get_mut(network_id) {
                    *streak = 0;
                }
                let _ = self.resolve_incident_by_key(&key, "Salida a Internet restablecida y verificada").await;
            }
            InternetHealth::IcmpFiltered => {
                // ICMP no respondió pero la comprobación complementaria TCP/DNS confirmó salida externa.
                // NO alertar caída y resolver si había alerta previa.
                if let Some(streak) = self.ext_down_streak.get_mut(network_id) {
                    *streak = 0;
                }
                let _ = self.resolve_incident_by_key(&key, "Conectividad externa confirmada mediante sondeo TCP (ICMP filtrado)").await;
            }
            InternetHealth::Unknown | InternetHealth::Degraded => {
                // Estado indeterminado o degradación leve; no alertar corte total
            }
            InternetHealth::Disconnected => {
                // Enlace local activo hacia el router pero sin salida externa verificable
                let gateway_ok = gateway_rtt_ms.map(|r| r < 40.0).unwrap_or(false);
                if gateway_ok {
                    let streak = {
                        let s = self.ext_down_streak.entry(network_id.to_string()).or_insert(0);
                        *s += 1;
                        *s
                    };

                    if streak >= 2 {
                        let rule = CorrelationRule::external_connectivity_down();
                        let _ = self.find_or_create_incident(
                            &rule,
                            Some(key),
                            "network_guardian",
                            "external_connectivity_down",
                            serde_json::json!({
                                "network_id": network_id,
                                "interface": interface_name,
                                "gateway_rtt_ms": gateway_rtt_ms,
                                "internet_rtt_ms": internet_rtt_ms,
                                "packet_loss_percent": packet_loss_percent,
                                "internet_health": "Disconnected"
                            }),
                        ).await;
                    }
                }
            }
        }
    }

    /// Regla 5: Evalúa consumo sostenido de CPU por proceso con normalización por núcleos,
    /// duración monotónica configurable (15–30 segundos), histéresis y resolución.
    async fn evaluate_sustained_cpu(&mut self, global_usage: f32, top_process: Option<(u32, String, f32, f32)>) {
        let now = Instant::now();
        if global_usage > 70.0 {
            if let Some((pid, name, normalized_cpu, raw_cpu)) = top_process {
                if normalized_cpu > 45.0 {
                    let (streak_count, first_seen) = {
                        let entry = self.cpu_streak.entry(pid).or_insert((0, now, normalized_cpu));
                        entry.0 += 1;
                        entry.2 = normalized_cpu;
                        (entry.0, entry.1)
                    };

                    let sustained_duration = now.duration_since(first_seen);

                    // Exigir al menos 3 muestras consecutivas Y una duración monotónica real de al menos el tiempo configurable (15–30s)
                    if streak_count >= 3 && sustained_duration >= self.cpu_sustained_duration {
                        let rule = CorrelationRule::sustained_process_cpu();
                        let key = format!("high_cpu_{}", pid);
                        let _ = self.find_or_create_incident(
                            &rule,
                            Some(key),
                            "sys_monitor",
                            "sustained_high_cpu",
                            serde_json::json!({
                                "pid": pid,
                                "name": name,
                                "normalized_cpu_percent": normalized_cpu,
                                "raw_cpu_percent": raw_cpu,
                                "global_cpu_percent": global_usage,
                                "streak_samples": streak_count,
                                "duration_secs": sustained_duration.as_secs(),
                                "configured_threshold_secs": self.cpu_sustained_duration.as_secs()
                            }),
                        ).await;
                    }
                    return;
                }
            }
        }

        // Histéresis: cuando el uso de CPU baja a niveles moderados (< 50%)
        if global_usage < 50.0 {
            let active_keys: Vec<String> = self.active_incidents_cache.keys()
                .filter(|k| k.starts_with("high_cpu_"))
                .cloned()
                .collect();

            for key in active_keys {
                let _ = self.resolve_incident_by_key(&key, "Carga de procesador normalizada por debajo de 50%").await;
            }
            self.cpu_streak.clear();
        }
    }

    /// Regla 6: Evalúa presión sostenida de memoria física correlacionándola con los procesos de mayor consumo.
    /// Realiza seguimiento acotado del crecimiento de memoria de varios procesos mediante ProcessIdentity,
    /// sin afirmar fugas de memoria sin evidencia concluyente.
    async fn evaluate_memory_pressure(
        &mut self,
        used_bytes: u64,
        total_bytes: u64,
        usage_percent: f32,
        top_processes: Vec<(ProcessIdentity, String, u64)>,
    ) {
        let key = "global_mem_pressure".to_string();
        let now = Instant::now();

        // 1. Seguimiento acotado del crecimiento de memoria de los procesos reportados mediante ProcessIdentity
        let mut procs_json = Vec::new();
        for (proc_id, name, ws) in top_processes.iter().take(5) {
            let (_, prev_ws) = self.process_memory_history.get(proc_id).copied().unwrap_or((now, *ws));
            let delta_bytes = *ws as i64 - prev_ws as i64;
            let delta_mb = delta_bytes / (1024 * 1024);

            let growth_trend = if delta_mb > 5 {
                format!("Creciendo (+{} MB)", delta_mb)
            } else if delta_mb < -5 {
                format!("Descendiendo ({} MB)", delta_mb)
            } else {
                "Estable".to_string()
            };

            procs_json.push(serde_json::json!({
                "pid": proc_id.pid,
                "start_time_utc": proc_id.start_time_utc,
                "name": name,
                "working_set_mb": ws / (1024 * 1024),
                "growth_trend": growth_trend,
                "delta_mb": delta_mb
            }));

            self.process_memory_history.insert(*proc_id, (now, *ws));
        }

        // Acotar memoria del mapa a un máximo de 20 entradas purgando obsoletas (> 120s)
        if self.process_memory_history.len() > 20 {
            self.process_memory_history.retain(|_, (sample_time, _)| {
                now.duration_since(*sample_time) <= Duration::from_secs(120)
            });
        }

        if usage_percent > 85.0 {
            self.memory_streak += 1;
            if self.memory_streak >= 3 {
                let rule = CorrelationRule::sustained_memory_pressure();
                let _ = self.find_or_create_incident(
                    &rule,
                    Some(key),
                    "sys_monitor",
                    "sustained_memory_pressure",
                    serde_json::json!({
                        "used_bytes": used_bytes,
                        "total_bytes": total_bytes,
                        "usage_percent": usage_percent,
                        "streak": self.memory_streak,
                        "top_consumers": procs_json
                    }),
                ).await;
            }
        } else if usage_percent < 75.0 {
            // Histéresis: liberación por debajo de 75%
            self.memory_streak = 0;
            let _ = self.resolve_incident_by_key(&key, "Memoria RAM liberada por debajo de 75%").await;
        }
    }

    /// Regla 7: Evalúa alerta térmica diferenciada por sensor y componente de hardware.
    async fn evaluate_thermal_alert(&mut self, sensor_label: &str, temp_celsius: f32) {
        let rule = CorrelationRule::resource_saturation();
        let sensor_sanitized = sensor_label.replace(|c: char| !c.is_alphanumeric(), "_");
        let key = format!("thermal_{}", sensor_sanitized);

        let _ = self.find_or_create_incident(
            &rule,
            Some(key),
            "sys_monitor",
            "thermal_threshold_exceeded",
            serde_json::json!({
                "sensor": sensor_label,
                "celsius": temp_celsius,
                "diagnostic_note": "Alerta térmica diferenciada por componente; no se afirma estrangulamiento térmico (throttling) sin evidencia de degradación de reloj"
            }),
        ).await;
    }

    /// Regla 1 (Telemetría): Evalúa muestras continuas de señal Wi-Fi para confirmación y resolución.
    async fn evaluate_wifi_signal_sample(&mut self, network_id: &str, ssid: &str, signal_percent: u32, rssi_dbm: Option<i32>) {
        let key = format!("wifi_deg_{}", network_id);

        // Verificar si existe degradación del enlace local en las muestras recientes
        let is_link_degraded = self.recent_net_quality.get(network_id).map(|(gw, jit, loss, ts)| {
            if ts.elapsed() <= Duration::from_secs(60) {
                jit.unwrap_or(0.0) > 20.0 || loss.unwrap_or(0.0) > 5.0 || gw.unwrap_or(0.0) > 50.0
            } else {
                false
            }
        }).unwrap_or(false);

        if signal_percent < 25 && is_link_degraded {
            let streak = {
                let s = self.wifi_deg_streak.entry(network_id.to_string()).or_insert(0);
                *s += 1;
                *s
            };

            if streak >= 2 {
                let rule = CorrelationRule::wifi_degradation();
                let _ = self.find_or_create_incident(
                    &rule,
                    Some(key),
                    "network_guardian",
                    "wifi_low_signal_sustained",
                    serde_json::json!({
                        "network_id": network_id,
                        "ssid": ssid,
                        "signal_percent": signal_percent,
                        "rssi_dbm": rssi_dbm,
                        "link_degraded": true
                    }),
                ).await;
            }
            if let Some(recov) = self.wifi_recov_streak.get_mut(network_id) {
                *recov = 0;
            }
        } else if signal_percent >= 45 {
            let recov = self.wifi_recov_streak.entry(network_id.to_string()).or_insert(0);
            *recov += 1;

            if *recov >= 2 {
                if let Some(streak) = self.wifi_deg_streak.get_mut(network_id) {
                    *streak = 0;
                }
                let _ = self.resolve_incident_by_key(&key, "Señal Wi-Fi normalizada y recuperada por encima de 45%").await;
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Gestión del Ciclo de Vida de Incidentes (Deduplicación, Evidencias, Resolución)
    // ─────────────────────────────────────────────────────────────────────────────

    /// Busca un incidente activo existente por su `correlation_key` o crea uno nuevo en SQLite.
    /// Retorna una tupla `(incident_id, is_new)`.
    /// - Si ya existe: no crea nuevo incidente, actualiza `last_updated` y, si pasaron más de 10s,
    ///   anexa la nueva evidencia sin disparar alertas duplicadas.
    /// - Si no existe: crea el incidente en estado `'active'` y emite la evidencia inicial.
    pub async fn find_or_create_incident(
        &mut self,
        rule: &CorrelationRule,
        correlation_key: Option<String>,
        evidence_source: &str,
        event_type: &str,
        observable_json: serde_json::Value,
    ) -> Result<(i64, bool)> {
        let now = Instant::now();
        let now_utc = Utc::now();

        // 1. Verificar si ya existe en la caché en memoria de incidentes activos
        if let Some(key) = &correlation_key {
            if let Some(&incident_id) = self.active_incidents_cache.get(key) {
                // Verificar debouncing para no inundar SQLite con evidencias continuas
                let should_attach_evidence = match self.last_evidence_time.get(key) {
                    Some(last) => now.duration_since(*last) >= Duration::from_secs(EVIDENCE_DEBOUNCE_SECS),
                    None => true,
                };

                if should_attach_evidence {
                    let db = self.db.lock().await;
                    let _ = db.execute(
                        "UPDATE pie_incidents SET last_updated = ?1 WHERE id = ?2",
                        params![now_utc.to_rfc3339(), incident_id],
                    );

                    let _ = db.execute(
                        "INSERT INTO pie_incident_evidences (
                            incident_id, timestamp, source_module, event_type, observable_json
                        ) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            incident_id,
                            now_utc.to_rfc3339(),
                            evidence_source,
                            event_type,
                            observable_json.to_string(),
                        ],
                    );
                    drop(db);

                    self.last_evidence_time.insert(key.clone(), now);
                }

                return Ok((incident_id, false));
            }
        }

        // 2. Crear nuevo incidente activo en la base de datos
        let incident = Incident {
            id: None,
            timestamp_utc: now_utc,
            last_updated_utc: now_utc,
            correlation_key: correlation_key.clone(),
            category: rule.category,
            severity: rule.severity,
            risk_score: rule.base_risk_score,
            confidence: rule.confidence,
            status: IncidentStatus::Active,
            title: rule.simple_title.to_string(),
            simple_summary: rule.simple_summary.to_string(),
            simple_recommendation: rule.simple_recommendation.to_string(),
            technical_rule_id: rule.id.to_string(),
            technical_impact: rule.technical_impact.to_string(),
            technical_mitigation: rule.technical_mitigation.to_string(),
            diagnostic_limitations: rule.diagnostic_limitations.to_string(),
            evidences: vec![IncidentEvidence {
                id: None,
                incident_id: None,
                timestamp_utc: now_utc,
                source_module: evidence_source.to_string(),
                event_type: event_type.to_string(),
                observable_json: observable_json.to_string(),
            }],
        };

        let incident_id = self.persist_incident(&incident).await?;

        if let Some(key) = correlation_key {
            self.active_incidents_cache.insert(key.clone(), incident_id);
            self.last_evidence_time.insert(key, now);
        }

        Ok((incident_id, true))
    }

    /// Resuelve un incidente activo por su `correlation_key`, actualizando su estado a `'resolved'`
    /// e insertando una evidencia de normalización.
    pub async fn resolve_incident_by_key(
        &mut self,
        correlation_key: &str,
        resolution_reason: &str,
    ) -> Result<Option<i64>> {
        if let Some(incident_id) = self.active_incidents_cache.remove(correlation_key) {
            self.last_evidence_time.remove(correlation_key);
            let now_utc = Utc::now();

            let db = self.db.lock().await;
            db.execute(
                "UPDATE pie_incidents SET status = 'resolved', last_updated = ?1 WHERE id = ?2",
                params![now_utc.to_rfc3339(), incident_id],
            )?;

            db.execute(
                "INSERT INTO pie_incident_evidences (
                    incident_id, timestamp, source_module, event_type, observable_json
                ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    incident_id,
                    now_utc.to_rfc3339(),
                    "pie::engine",
                    "condition_normalized",
                    serde_json::json!({
                        "reason": resolution_reason,
                        "resolved_at": now_utc.to_rfc3339()
                    }).to_string(),
                ],
            )?;

            tracing::info!(
                target: "pie::engine",
                "Incident #{} [key: {}] marked as RESOLVED: {}",
                incident_id,
                correlation_key,
                resolution_reason
            );

            return Ok(Some(incident_id));
        }

        Ok(None)
    }

    /// Configura la duración de confirmación sostenida para CPU (acotada entre 15 y 30 segundos).
    pub fn set_cpu_sustained_duration(&mut self, duration: Duration) {
        self.cpu_sustained_duration = duration.clamp(Duration::from_secs(15), Duration::from_secs(30));
    }

    /// Retorna la duración de confirmación sostenida configurada para CPU.
    pub fn cpu_sustained_duration(&self) -> Duration {
        self.cpu_sustained_duration
    }

    /// Comprueba si existe un incidente activo para una `correlation_key` dada.
    pub fn is_incident_active(&self, correlation_key: &str) -> bool {
        self.active_incidents_cache.contains_key(correlation_key)
    }

    /// Persiste un incidente y sus evidencias observables en SQLite de forma atómica.
    pub async fn persist_incident(&self, incident: &Incident) -> Result<i64> {
        let db = self.db.lock().await;

        let incident_id = db.query_row(
            "INSERT INTO pie_incidents (
                timestamp, last_updated, correlation_key, category, severity, risk_score, confidence, status,
                title, simple_summary, simple_recommendation, technical_rule_id, technical_impact,
                technical_mitigation, diagnostic_limitations
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
            RETURNING id",
            params![
                incident.timestamp_utc.to_rfc3339(),
                incident.last_updated_utc.to_rfc3339(),
                incident.correlation_key,
                incident.category.as_str(),
                incident.severity.as_str(),
                incident.risk_score,
                incident.confidence,
                incident.status.as_str(),
                incident.title,
                incident.simple_summary,
                incident.simple_recommendation,
                incident.technical_rule_id,
                incident.technical_impact,
                incident.technical_mitigation,
                incident.diagnostic_limitations,
            ],
            |row| row.get(0),
        ).context("Failed to insert into pie_incidents")?;

        for evidence in &incident.evidences {
            db.execute(
                "INSERT INTO pie_incident_evidences (
                    incident_id, timestamp, source_module, event_type, observable_json
                ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    incident_id,
                    evidence.timestamp_utc.to_rfc3339(),
                    evidence.source_module,
                    evidence.event_type,
                    evidence.observable_json,
                ],
            ).context("Failed to insert into pie_incident_evidences")?;
        }

        tracing::info!(
            target: "pie::engine",
            "Incident #{} registered: '{}' [Risk: {}, Conf: {:.2}]",
            incident_id,
            incident.title,
            incident.risk_score,
            incident.confidence
        );

        Ok(incident_id)
    }

    /// Recupera los incidentes activos para presentarlos en la interfaz gráfica (Modo Simple y Avanzado).
    pub async fn get_active_incidents(&self) -> Result<Vec<Incident>> {
        let db = self.db.lock().await;

        let mut stmt = db.prepare(
            "SELECT id, timestamp, last_updated, correlation_key, category, severity, risk_score, confidence, status,
                    title, simple_summary, simple_recommendation, technical_rule_id, technical_impact,
                    technical_mitigation, diagnostic_limitations
             FROM pie_incidents
             WHERE status = 'active'
             ORDER BY risk_score DESC, last_updated DESC
             LIMIT 50"
        )?;

        let incident_rows = stmt.query_map([], |row| {
            let id: i64 = row.get(0)?;
            let ts_str: String = row.get(1)?;
            let last_up_str: Option<String> = row.get(2)?;
            let correlation_key: Option<String> = row.get(3)?;
            let category_str: String = row.get(4)?;
            let severity_str: String = row.get(5)?;
            let risk_score: u8 = row.get(6)?;
            let confidence: f32 = row.get(7)?;
            let status_str: String = row.get(8)?;
            let title: String = row.get(9)?;
            let simple_summary: String = row.get(10)?;
            let simple_recommendation: String = row.get(11)?;
            let technical_rule_id: String = row.get(12)?;
            let technical_impact: String = row.get(13).unwrap_or_default();
            let technical_mitigation: String = row.get(14).unwrap_or_default();
            let diagnostic_limitations: String = row.get(15).unwrap_or_default();

            let timestamp_utc = DateTime::parse_from_rfc3339(&ts_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            let last_updated_utc = last_up_str
                .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or(timestamp_utc);

            Ok(Incident {
                id: Some(id),
                timestamp_utc,
                last_updated_utc,
                correlation_key,
                category: IncidentCategory::from_str(&category_str),
                severity: IncidentSeverity::from_str(&severity_str),
                risk_score,
                confidence,
                status: IncidentStatus::from_str(&status_str),
                title,
                simple_summary,
                simple_recommendation,
                technical_rule_id,
                technical_impact,
                technical_mitigation,
                diagnostic_limitations,
                evidences: Vec::new(),
            })
        })?;

        let mut incidents = Vec::new();
        for inc_res in incident_rows {
            let mut inc = inc_res?;

            if let Some(inc_id) = inc.id {
                let mut ev_stmt = db.prepare(
                    "SELECT id, timestamp, source_module, event_type, observable_json
                     FROM pie_incident_evidences
                     WHERE incident_id = ?1
                     ORDER BY timestamp ASC"
                )?;

                let ev_rows = ev_stmt.query_map(params![inc_id], |row| {
                    let ts_str: String = row.get(1)?;
                    let timestamp_utc = DateTime::parse_from_rfc3339(&ts_str)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now());

                    Ok(IncidentEvidence {
                        id: Some(row.get(0)?),
                        incident_id: Some(inc_id),
                        timestamp_utc,
                        source_module: row.get(2)?,
                        event_type: row.get(3)?,
                        observable_json: row.get(4)?,
                    })
                })?;

                for ev in ev_rows {
                    inc.evidences.push(ev?);
                }
            }

            incidents.push(inc);
        }

        Ok(incidents)
    }

    /// Actualiza el estado de un incidente (ej: 'acknowledged' o 'resolved').
    pub async fn update_incident_status(&self, id: i64, status: IncidentStatus) -> Result<()> {
        let db = self.db.lock().await;
        db.execute(
            "UPDATE pie_incidents SET status = ?1, last_updated = ?2 WHERE id = ?3",
            params![status.as_str(), Utc::now().to_rfc3339(), id],
        )?;
        Ok(())
    }

    /// Exporta incidentes persistidos y sus evidencias a JSON o CSV estructurado para análisis forense por IA.
    pub async fn export_forensic_incidents(
        &self,
        format: crate::modules::pie::exporter::ForensicExportFormat,
        path: &std::path::Path,
        status_filter: Option<IncidentStatus>,
    ) -> Result<()> {
        let db = self.db.lock().await;
        crate::modules::pie::exporter::ForensicExporter::export_from_db(
            &db,
            format,
            path,
            status_filter,
        )
    }

    /// Consulta todos los incidentes persistidos en la base de datos (con o sin filtro de estado) y sus evidencias asociadas.
    pub async fn get_all_incidents(
        &self,
        status_filter: Option<IncidentStatus>,
    ) -> Result<Vec<Incident>> {
        let db = self.db.lock().await;
        crate::modules::pie::exporter::ForensicExporter::query_incidents(&db, status_filter)
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Métodos de Persistencia Network Guardian (net_devices & net_metrics)
    // ─────────────────────────────────────────────────────────────────────────────

    /// Inserta o actualiza un dispositivo de red descubierto en un contexto de red específico.
    pub async fn upsert_net_device(&self, dev: &PersistedNetDevice) -> Result<()> {
        let db = self.db.lock().await;
        db.execute(
            "INSERT INTO net_devices (
                network_id, mac, ip, hostname, vendor, is_trusted, custom_alias, first_seen, last_seen
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(network_id, mac) DO UPDATE SET
                ip = excluded.ip,
                hostname = CASE 
                    WHEN excluded.hostname IS NOT NULL AND excluded.hostname != '' THEN excluded.hostname 
                    ELSE net_devices.hostname 
                END,
                vendor = CASE 
                    WHEN excluded.vendor IS NOT NULL AND excluded.vendor != '' THEN excluded.vendor 
                    ELSE net_devices.vendor 
                END,
                last_seen = excluded.last_seen",
            params![
                dev.network_id,
                dev.mac,
                dev.ip,
                dev.hostname,
                dev.vendor,
                if dev.is_trusted { 1 } else { 0 },
                dev.custom_alias,
                dev.first_seen.to_rfc3339(),
                dev.last_seen.to_rfc3339(),
            ],
        ).context("Failed to upsert net_device")?;

        Ok(())
    }

    /// Obtiene todos los dispositivos de red registrados en todas las redes.
    pub async fn get_persisted_devices(&self) -> Result<Vec<PersistedNetDevice>> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT network_id, mac, ip, hostname, vendor, is_trusted, custom_alias, first_seen, last_seen
             FROM net_devices
             ORDER BY last_seen DESC"
        )?;

        let rows = stmt.query_map([], Self::map_device_row)?;
        let mut devices = Vec::new();
        for d in rows {
            devices.push(d?);
        }
        Ok(devices)
    }

    /// Obtiene los dispositivos registrados para un contexto de red específico.
    pub async fn get_devices_by_network(&self, network_id: &str) -> Result<Vec<PersistedNetDevice>> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT network_id, mac, ip, hostname, vendor, is_trusted, custom_alias, first_seen, last_seen
             FROM net_devices
             WHERE network_id = ?1
             ORDER BY last_seen DESC"
        )?;

        let rows = stmt.query_map(params![network_id], Self::map_device_row)?;
        let mut devices = Vec::new();
        for d in rows {
            devices.push(d?);
        }
        Ok(devices)
    }

    /// Obtiene un dispositivo específico por su clave compuesta (network_id, mac).
    pub async fn get_device_by_mac_and_network(&self, network_id: &str, mac: &str) -> Result<Option<PersistedNetDevice>> {
        let db = self.db.lock().await;
        let mut stmt = db.prepare(
            "SELECT network_id, mac, ip, hostname, vendor, is_trusted, custom_alias, first_seen, last_seen
             FROM net_devices
             WHERE network_id = ?1 AND mac = ?2"
        )?;

        let mut rows = stmt.query_map(params![network_id, mac], Self::map_device_row)?;
        if let Some(res) = rows.next() {
            Ok(Some(res?))
        } else {
            Ok(None)
        }
    }

    fn map_device_row(row: &rusqlite::Row) -> rusqlite::Result<PersistedNetDevice> {
        let network_id: String = row.get(0)?;
        let mac: String = row.get(1)?;
        let ip: String = row.get(2)?;
        let hostname: Option<String> = row.get(3)?;
        let vendor: Option<String> = row.get(4)?;
        let is_trusted_num: i32 = row.get(5)?;
        let custom_alias: Option<String> = row.get(6)?;
        let first_seen_str: String = row.get(7)?;
        let last_seen_str: String = row.get(8)?;

        let first_seen = DateTime::parse_from_rfc3339(&first_seen_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        let last_seen = DateTime::parse_from_rfc3339(&last_seen_str)
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
    }

    pub async fn update_device_alias(&self, network_id: &str, mac: &str, alias: Option<&str>) -> Result<()> {
        let db = self.db.lock().await;
        db.execute(
            "UPDATE net_devices SET custom_alias = ?1 WHERE network_id = ?2 AND mac = ?3",
            params![alias, network_id, mac],
        ).context("Failed to update device alias")?;
        Ok(())
    }

    pub async fn set_device_trusted(&self, network_id: &str, mac: &str, trusted: bool) -> Result<()> {
        let db = self.db.lock().await;
        db.execute(
            "UPDATE net_devices SET is_trusted = ?1 WHERE network_id = ?2 AND mac = ?3",
            params![if trusted { 1 } else { 0 }, network_id, mac],
        ).context("Failed to update device trusted status")?;
        Ok(())
    }

    pub async fn record_net_metrics(&self, metric: &PersistedNetMetric) -> Result<i64> {
        let db = self.db.lock().await;
        let id = db.query_row(
            "INSERT INTO net_metrics_history (
                network_id, interface_name, timestamp, gateway_rtt_ms, internet_rtt_ms, jitter_ms, packet_loss_percent
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            RETURNING id",
            params![
                metric.network_id,
                metric.interface_name,
                metric.timestamp.to_rfc3339(),
                metric.gateway_rtt_ms,
                metric.internet_rtt_ms,
                metric.jitter_ms,
                metric.packet_loss_percent,
            ],
            |row| row.get(0),
        ).context("Failed to insert into net_metrics_history")?;

        Ok(id)
    }

    pub async fn get_metrics_history(
        &self,
        network_id: Option<&str>,
        since: DateTime<Utc>,
    ) -> Result<Vec<PersistedNetMetric>> {
        let db = self.db.lock().await;
        let mut metrics = Vec::new();

        if let Some(net_id) = network_id {
            let mut stmt = db.prepare(
                "SELECT id, network_id, interface_name, timestamp, gateway_rtt_ms, internet_rtt_ms, jitter_ms, packet_loss_percent
                 FROM net_metrics_history
                 WHERE network_id = ?1 AND timestamp >= ?2
                 ORDER BY timestamp ASC"
            )?;
            let rows = stmt.query_map(params![net_id, since.to_rfc3339()], Self::map_metric_row)?;
            for m in rows {
                metrics.push(m?);
            }
        } else {
            let mut stmt = db.prepare(
                "SELECT id, network_id, interface_name, timestamp, gateway_rtt_ms, internet_rtt_ms, jitter_ms, packet_loss_percent
                 FROM net_metrics_history
                 WHERE timestamp >= ?1
                 ORDER BY timestamp ASC"
            )?;
            let rows = stmt.query_map(params![since.to_rfc3339()], Self::map_metric_row)?;
            for m in rows {
                metrics.push(m?);
            }
        }

        Ok(metrics)
    }

    fn map_metric_row(row: &rusqlite::Row) -> rusqlite::Result<PersistedNetMetric> {
        let id: i64 = row.get(0)?;
        let network_id: String = row.get(1)?;
        let interface_name: Option<String> = row.get(2)?;
        let ts_str: String = row.get(3)?;
        let gateway_rtt_ms: Option<f32> = row.get(4)?;
        let internet_rtt_ms: Option<f32> = row.get(5)?;
        let jitter_ms: Option<f32> = row.get(6)?;
        let packet_loss_percent: Option<f32> = row.get(7)?;

        let timestamp = DateTime::parse_from_rfc3339(&ts_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        Ok(PersistedNetMetric {
            id: Some(id),
            network_id,
            interface_name,
            timestamp,
            gateway_rtt_ms,
            internet_rtt_ms,
            jitter_ms,
            packet_loss_percent,
        })
    }

    pub async fn purge_old_metrics(&self, retention_days: u32) -> Result<usize> {
        let db = self.db.lock().await;
        let cutoff = Utc::now() - chrono::Duration::days(retention_days as i64);
        let deleted = db.execute(
            "DELETE FROM net_metrics_history WHERE timestamp < ?1",
            params![cutoff.to_rfc3339()],
        ).context("Failed to purge old net metrics")?;

        tracing::info!(
            target: "pie::engine",
            "Purged {} historical network metric records older than {} days",
            deleted,
            retention_days
        );
        Ok(deleted)
    }
}
