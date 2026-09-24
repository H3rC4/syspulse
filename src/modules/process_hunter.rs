use crate::models::ProcessEvent;
use anyhow::{Context, Result};
use chrono::{Local, TimeZone};
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::sync::Arc;
use sysinfo::{ProcessRefreshKind, System};
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, Duration};

const POLL_INTERVAL_MS: u64 = 500;
const TRANSIENT_THRESHOLD_SECS: u64 = 5;

#[derive(Debug, Clone)]
pub enum ProcessHunterCommand {
    Pause,
    Resume,
    ExportSelected(i64, ExportFormat, std::path::PathBuf),
}

#[derive(Debug, Clone)]
pub enum ExportFormat {
    Json,
    Csv,
}

impl ExportFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExportFormat::Json => "json",
            ExportFormat::Csv => "csv",
        }
    }
}

pub struct ProcessHunter {
    db: Arc<Mutex<Connection>>,
    command_tx: mpsc::UnboundedSender<ProcessHunterCommand>,
}

impl ProcessHunter {
    pub fn new() -> Result<(Self, mpsc::UnboundedReceiver<ProcessHunterCommand>)> {
        let db_path = crate::modules::config::Settings::db_path()?;
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create DB dir {:?}", parent))?;
        }

        let conn = Connection::open(&db_path)
            .with_context(|| format!("Failed to open DB {:?}", db_path))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS process_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                pid INTEGER NOT NULL,
                parent_pid INTEGER,
                name TEXT NOT NULL,
                executable_path TEXT NOT NULL,
                command_line TEXT NOT NULL,
                lifetime_seconds INTEGER
            )",
            [],
        )
        .context("Failed to create process_events table")?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_process_events_timestamp ON process_events(timestamp)",
            [],
        )
        .context("Failed to create timestamp index")?;

        let (tx, rx) = mpsc::unbounded_channel();

        Ok((
            Self {
                db: Arc::new(Mutex::new(conn)),
                command_tx: tx,
            },
            rx,
        ))
    }

    pub fn command_sender(&self) -> mpsc::UnboundedSender<ProcessHunterCommand> {
        self.command_tx.clone()
    }

    pub async fn start(
        &self,
        mut command_rx: mpsc::UnboundedReceiver<ProcessHunterCommand>,
        history_days: u32,
    ) {
        tracing::info!("Process Hunter starting");

        let mut system = System::new_all();
        let mut known_processes: HashMap<u32, (String, std::time::Instant)> = HashMap::new();

        let mut paused = false;
        let mut ticker = interval(Duration::from_millis(POLL_INTERVAL_MS));

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if paused {
                        continue;
                    }

                    system.refresh_processes_specifics(ProcessRefreshKind::everything());

                    let mut events = Vec::new();
                    let now = std::time::Instant::now();

                    for (pid, process) in system.processes() {
                        let pid_u32 = pid.as_u32();

                        if !known_processes.contains_key(&pid_u32) {
                            let name = process.name().to_string();
                            let exe = process
                                .exe()
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_default();
                            let cmd = process
                                .cmd()
                                .join(" ");

                            known_processes.insert(pid_u32, (name.clone(), now));

                            events.push(ProcessEvent {
                                id: None,
                                timestamp: Local::now(),
                                pid: pid_u32,
                                parent_pid: process.parent().map(|p| p.as_u32()),
                                name,
                                executable_path: exe,
                                command_line: cmd,
                                lifetime_seconds: None,
                            });
                        }
                    }

                    // Detect exited transient processes and remove stale entries.
                    let current_pids: Vec<u32> = system.processes().keys().map(|p| p.as_u32()).collect();
                    let mut exited = Vec::new();
                    known_processes.retain(|pid, (name, start)| {
                        if current_pids.contains(pid) {
                            true
                        } else {
                            let lifetime = now.duration_since(*start).as_secs();
                            if lifetime < TRANSIENT_THRESHOLD_SECS {
                                exited.push((*pid, name.clone(), lifetime));
                            }
                            false
                        }
                    });

                    if !events.is_empty() {
                        if let Err(e) = self.persist_events(&events).await {
                            tracing::error!("Failed to persist process events: {}", e);
                        }
                    }

                    if !exited.is_empty() {
                        tracing::debug!("Detected {} transient process exits", exited.len());
                    }

                    if let Err(e) = self.trim_history(history_days).await {
                        tracing::error!("Failed to trim process history: {}", e);
                    }
                }

                cmd = command_rx.recv() => {
                    match cmd {
                        Some(ProcessHunterCommand::Pause) => {
                            paused = true;
                            tracing::info!("Process Hunter paused");
                        }
                        Some(ProcessHunterCommand::Resume) => {
                            paused = false;
                            tracing::info!("Process Hunter resumed");
                        }
                        Some(ProcessHunterCommand::ExportSelected(id, format, path)) => {
                            if let Err(e) = self.export_event(id, format, &path).await {
                                tracing::error!("Failed to export process event: {}", e);
                            }
                        }
                        None => break,
                    }
                }
            }
        }

        tracing::info!("Process Hunter stopped");
    }

    async fn persist_events(&self, events: &[ProcessEvent]) -> Result<()> {
        let db = self.db.clone();
        let events = events.to_vec();

        tokio::task::spawn_blocking(move || {
            let conn = db.blocking_lock();
            let tx = conn.unchecked_transaction()?;

            for event in events {
                tx.execute(
                    "INSERT INTO process_events (timestamp, pid, parent_pid, name, executable_path, command_line, lifetime_seconds)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        event.timestamp.to_rfc3339(),
                        event.pid,
                        event.parent_pid,
                        event.name,
                        event.executable_path,
                        event.command_line,
                        event.lifetime_seconds,
                    ],
                )?;
            }

            tx.commit()?;
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("Failed to spawn DB write task")??;

        Ok(())
    }

    async fn trim_history(&self, history_days: u32) -> Result<()> {
        if history_days == 0 {
            return Ok(());
        }

        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let conn = db.blocking_lock();
            let cutoff = Local::now() - chrono::Duration::days(history_days as i64);
            conn.execute(
                "DELETE FROM process_events WHERE timestamp < ?1",
                [cutoff.to_rfc3339()],
            )?;
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("Failed to spawn trim task")??;

        Ok(())
    }

    pub async fn list_events(&self, limit: usize) -> Result<Vec<ProcessEvent>> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let conn = db.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT id, timestamp, pid, parent_pid, name, executable_path, command_line, lifetime_seconds
                 FROM process_events
                 ORDER BY timestamp DESC
                 LIMIT ?1"
            )?;

            let rows = stmt.query_map([limit], |row| {
                let ts_str: String = row.get(1)?;
                let timestamp = chrono::DateTime::parse_from_rfc3339(&ts_str)
                    .unwrap_or_else(|_| chrono::Utc.timestamp_opt(0, 0).unwrap().into())
                    .with_timezone(&Local);

                Ok(ProcessEvent {
                    id: row.get(0)?,
                    timestamp,
                    pid: row.get(2)?,
                    parent_pid: row.get(3)?,
                    name: row.get(4)?,
                    executable_path: row.get(5)?,
                    command_line: row.get(6)?,
                    lifetime_seconds: row.get(7)?,
                })
            })?;

            let mut events = Vec::new();
            for row in rows {
                events.push(row?);
            }

            Ok::<Vec<ProcessEvent>, anyhow::Error>(events)
        })
        .await
        .context("Failed to spawn list task")?
    }

    async fn export_event(
        &self,
        id: i64,
        format: ExportFormat,
        path: &std::path::Path,
    ) -> Result<()> {
        let db = self.db.clone();
        let path = path.to_path_buf();

        tokio::task::spawn_blocking(move || {
            let conn = db.blocking_lock();
            let mut stmt = conn.prepare(
                "SELECT id, timestamp, pid, parent_pid, name, executable_path, command_line, lifetime_seconds
                 FROM process_events WHERE id = ?1"
            )?;

            let event = stmt.query_row([id], |row| {
                let ts_str: String = row.get(1)?;
                let timestamp = chrono::DateTime::parse_from_rfc3339(&ts_str)
                    .unwrap_or_else(|_| chrono::Utc.timestamp_opt(0, 0).unwrap().into())
                    .with_timezone(&Local);

                Ok(ProcessEvent {
                    id: row.get(0)?,
                    timestamp,
                    pid: row.get(2)?,
                    parent_pid: row.get(3)?,
                    name: row.get(4)?,
                    executable_path: row.get(5)?,
                    command_line: row.get(6)?,
                    lifetime_seconds: row.get(7)?,
                })
            })?;

            match format {
                ExportFormat::Json => {
                    let content = serde_json::to_string_pretty(&event)
                        .context("Failed to serialize event to JSON")?;
                    std::fs::write(&path, content)
                        .with_context(|| format!("Failed to write JSON to {:?}", path))?;
                }
                ExportFormat::Csv => {
                    let mut writer = csv::Writer::from_path(&path)
                        .with_context(|| format!("Failed to create CSV writer at {:?}", path))?;
                    writer.write_record([
                        "id",
                        "timestamp",
                        "pid",
                        "parent_pid",
                        "name",
                        "executable_path",
                        "command_line",
                        "lifetime_seconds",
                    ])?;
                    writer.write_record([
                        event.id.map(|i| i.to_string()).unwrap_or_default(),
                        event.timestamp.to_rfc3339(),
                        event.pid.to_string(),
                        event.parent_pid.map(|p| p.to_string()).unwrap_or_default(),
                        event.name,
                        event.executable_path,
                        event.command_line,
                        event.lifetime_seconds.map(|s| s.to_string()).unwrap_or_default(),
                    ])?;
                    writer.flush()?;
                }
            }

            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("Failed to spawn export task")??;

        Ok(())
    }
}
