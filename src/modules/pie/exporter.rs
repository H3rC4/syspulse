use crate::modules::pie::models::{Incident, IncidentCategory, IncidentEvidence, IncidentSeverity, IncidentStatus};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Formato de exportación forense para análisis por modelos de inteligencia artificial o analistas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForensicExportFormat {
    Json,
    Csv,
}

impl ForensicExportFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            ForensicExportFormat::Json => "json",
            ForensicExportFormat::Csv => "csv",
        }
    }
}

/// Contenedor estructurado de reporte forense en JSON para análisis por IA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicReport {
    pub schema_version: String,
    pub exported_at_utc: DateTime<Utc>,
    pub total_incidents: usize,
    pub total_evidences: usize,
    pub incidents: Vec<Incident>,
}

/// Encabezados canónicos para exportación tabular en CSV.
pub const CSV_HEADERS: &[&str] = &[
    "incident_id",
    "timestamp_utc",
    "last_updated_utc",
    "correlation_key",
    "category",
    "severity",
    "risk_score",
    "confidence",
    "status",
    "title",
    "simple_summary",
    "simple_recommendation",
    "technical_rule_id",
    "technical_impact",
    "technical_mitigation",
    "diagnostic_limitations",
    "evidence_id",
    "evidence_timestamp_utc",
    "evidence_source_module",
    "evidence_event_type",
    "evidence_observable_json",
];

/// Exportador forense unificado de incidentes y evidencias de PIE.
pub struct ForensicExporter;

impl ForensicExporter {
    /// Consulta los incidentes persistidos en la base de datos y sus evidencias asociadas en orden determinista.
    /// Operación 100% de sólo lectura (SELECT).
    pub fn query_incidents(
        conn: &Connection,
        status_filter: Option<IncidentStatus>,
    ) -> Result<Vec<Incident>> {
        let (sql, params_vec): (&str, Vec<String>) = match status_filter {
            Some(status) => (
                "SELECT id, timestamp, last_updated, correlation_key, category, severity, risk_score, confidence, status,
                        title, simple_summary, simple_recommendation, technical_rule_id, technical_impact,
                        technical_mitigation, diagnostic_limitations
                 FROM pie_incidents
                 WHERE status = ?1
                 ORDER BY id ASC",
                vec![status.as_str().to_string()],
            ),
            None => (
                "SELECT id, timestamp, last_updated, correlation_key, category, severity, risk_score, confidence, status,
                        title, simple_summary, simple_recommendation, technical_rule_id, technical_impact,
                        technical_mitigation, diagnostic_limitations
                 FROM pie_incidents
                 ORDER BY id ASC",
                Vec::new(),
            ),
        };

        let mut stmt = conn.prepare(sql).context("Failed to prepare incidents query")?;

        let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
        let incident_rows = stmt.query_map(params_refs.as_slice(), |row| {
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
        }).context("Failed to execute query on pie_incidents")?;

        let mut incidents = Vec::new();
        for inc_res in incident_rows {
            let mut inc = inc_res.context("Failed to read incident row")?;
            if let Some(inc_id) = inc.id {
                let mut ev_stmt = conn.prepare(
                    "SELECT id, timestamp, source_module, event_type, observable_json
                     FROM pie_incident_evidences
                     WHERE incident_id = ?1
                     ORDER BY timestamp ASC, id ASC"
                ).context("Failed to prepare evidences query")?;

                let ev_rows = ev_stmt.query_map([inc_id], |row| {
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
                }).context("Failed to query pie_incident_evidences")?;

                for ev in ev_rows {
                    inc.evidences.push(ev.context("Failed to read evidence row")?);
                }
            }
            incidents.push(inc);
        }

        Ok(incidents)
    }

    /// Construye un reporte estructurado `ForensicReport` a partir de una lista de incidentes.
    pub fn build_report(incidents: &[Incident]) -> ForensicReport {
        let total_evidences = incidents.iter().map(|i| i.evidences.len()).sum();
        ForensicReport {
            schema_version: "1.0".to_string(),
            exported_at_utc: Utc::now(),
            total_incidents: incidents.len(),
            total_evidences,
            incidents: incidents.to_vec(),
        }
    }

    /// Genera la cadena de texto JSON estructurada con sangría reproducible y completa.
    pub fn to_json_string(incidents: &[Incident]) -> Result<String> {
        let report = Self::build_report(incidents);
        serde_json::to_string_pretty(&report).context("Failed to serialize forensic report to JSON")
    }

    /// Genera la cadena de texto CSV con escape estricto de campos RFC 4180.
    pub fn to_csv_string(incidents: &[Incident]) -> Result<String> {
        let mut wtr = csv::WriterBuilder::new().from_writer(Vec::new());
        wtr.write_record(CSV_HEADERS)
            .context("Failed to write CSV headers")?;

        for inc in incidents {
            if inc.evidences.is_empty() {
                wtr.write_record(&[
                    inc.id.map(|i| i.to_string()).unwrap_or_default(),
                    inc.timestamp_utc.to_rfc3339(),
                    inc.last_updated_utc.to_rfc3339(),
                    inc.correlation_key.clone().unwrap_or_default(),
                    inc.category.as_str().to_string(),
                    inc.severity.as_str().to_string(),
                    inc.risk_score.to_string(),
                    format!("{:.4}", inc.confidence),
                    inc.status.as_str().to_string(),
                    inc.title.clone(),
                    inc.simple_summary.clone(),
                    inc.simple_recommendation.clone(),
                    inc.technical_rule_id.clone(),
                    inc.technical_impact.clone(),
                    inc.technical_mitigation.clone(),
                    inc.diagnostic_limitations.clone(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                ]).context("Failed to write incident record to CSV")?;
            } else {
                for ev in &inc.evidences {
                    wtr.write_record(&[
                        inc.id.map(|i| i.to_string()).unwrap_or_default(),
                        inc.timestamp_utc.to_rfc3339(),
                        inc.last_updated_utc.to_rfc3339(),
                        inc.correlation_key.clone().unwrap_or_default(),
                        inc.category.as_str().to_string(),
                        inc.severity.as_str().to_string(),
                        inc.risk_score.to_string(),
                        format!("{:.4}", inc.confidence),
                        inc.status.as_str().to_string(),
                        inc.title.clone(),
                        inc.simple_summary.clone(),
                        inc.simple_recommendation.clone(),
                        inc.technical_rule_id.clone(),
                        inc.technical_impact.clone(),
                        inc.technical_mitigation.clone(),
                        inc.diagnostic_limitations.clone(),
                        ev.id.map(|i| i.to_string()).unwrap_or_default(),
                        ev.timestamp_utc.to_rfc3339(),
                        ev.source_module.clone(),
                        ev.event_type.clone(),
                        ev.observable_json.clone(),
                    ]).context("Failed to write incident evidence record to CSV")?;
                }
            }
        }

        wtr.flush().context("Failed to flush CSV writer")?;
        let bytes = wtr.into_inner().context("Failed to finalize CSV output")?;
        String::from_utf8(bytes).context("CSV output was not valid UTF-8")
    }

    /// Exporta incidentes a un archivo JSON en disco de forma atómica y local.
    pub fn export_to_json(incidents: &[Incident], path: &Path) -> Result<()> {
        let json_content = Self::to_json_string(incidents)?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create parent directory {:?}", parent))?;
            }
        }
        std::fs::write(path, json_content)
            .with_context(|| format!("Failed to write forensic JSON export to {:?}", path))?;
        Ok(())
    }

    /// Exporta incidentes a un archivo CSV en disco de forma local.
    pub fn export_to_csv(incidents: &[Incident], path: &Path) -> Result<()> {
        let csv_content = Self::to_csv_string(incidents)?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create parent directory {:?}", parent))?;
            }
        }
        std::fs::write(path, csv_content)
            .with_context(|| format!("Failed to write forensic CSV export to {:?}", path))?;
        Ok(())
    }

    /// Método integral: consulta la base de datos y escribe el reporte forense en el formato solicitado.
    pub fn export_from_db(
        conn: &Connection,
        format: ForensicExportFormat,
        path: &Path,
        status_filter: Option<IncidentStatus>,
    ) -> Result<()> {
        let incidents = Self::query_incidents(conn, status_filter)?;
        match format {
            ForensicExportFormat::Json => Self::export_to_json(&incidents, path),
            ForensicExportFormat::Csv => Self::export_to_csv(&incidents, path),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::pie::engine::PulseIntelligenceEngine;
    use rusqlite::Connection;

    fn test_temp_dir(prefix: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("syspulse_forensic_test_{}_{}_{}", prefix, std::process::id(), unique));
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    fn create_test_incident(
        id: i64,
        key: &str,
        severity: IncidentSeverity,
        status: IncidentStatus,
        evidences: Vec<IncidentEvidence>,
    ) -> Incident {
        let now = Utc::now();
        Incident {
            id: Some(id),
            timestamp_utc: now,
            last_updated_utc: now,
            correlation_key: Some(key.to_string()),
            category: IncidentCategory::Network,
            severity,
            risk_score: 75,
            confidence: 0.90,
            status,
            title: "Test Incident with Special Chars: \"Quotes\", Commas, & Newlines\n".to_string(),
            simple_summary: "Simple user summary with \"escaped\" text".to_string(),
            simple_recommendation: "Reboot router or check cable".to_string(),
            technical_rule_id: "PIE-R-WIFI-DEG".to_string(),
            technical_impact: "High packet loss: > 10%".to_string(),
            technical_mitigation: "Switch to 5 GHz band".to_string(),
            diagnostic_limitations: "Signal measured at single point".to_string(),
            evidences,
        }
    }

    #[tokio::test]
    async fn test_forensic_export_json_structure_and_evidence_association() {
        let mut conn = Connection::open_in_memory().unwrap();
        PulseIntelligenceEngine::migrate_schema(&mut conn).unwrap();
        let pie = PulseIntelligenceEngine::with_connection(conn).unwrap();

        let now = Utc::now();
        let ev1 = IncidentEvidence {
            id: None,
            incident_id: None,
            timestamp_utc: now,
            source_module: "network_guardian".to_string(),
            event_type: "wifi_signal_sample".to_string(),
            observable_json: "{\"rssi\":-85,\"channel\":6}".to_string(),
        };
        let ev2 = IncidentEvidence {
            id: None,
            incident_id: None,
            timestamp_utc: now + chrono::Duration::seconds(5),
            source_module: "sys_monitor".to_string(),
            event_type: "latency_spike".to_string(),
            observable_json: "{\"rtt_ms\":145.5}".to_string(),
        };

        let inc1 = create_test_incident(1, "key_net_1", IncidentSeverity::High, IncidentStatus::Active, vec![ev1, ev2]);
        let inc2 = create_test_incident(2, "key_net_2", IncidentSeverity::Low, IncidentStatus::Resolved, vec![]);

        pie.persist_incident(&inc1).await.unwrap();
        pie.persist_incident(&inc2).await.unwrap();

        let dir = test_temp_dir("json_struct");
        let json_path = dir.join("forensic_report.json");

        pie.export_forensic_incidents(ForensicExportFormat::Json, &json_path, None).await.unwrap();

        assert!(json_path.exists());
        let file_content = std::fs::read_to_string(&json_path).unwrap();

        let report: ForensicReport = serde_json::from_str(&file_content).expect("Must deserialize valid ForensicReport");
        assert_eq!(report.schema_version, "1.0");
        assert_eq!(report.total_incidents, 2);
        assert_eq!(report.total_evidences, 2);
        assert_eq!(report.incidents.len(), 2);

        // Deterministic ordering: ID 1 then ID 2
        assert_eq!(report.incidents[0].id, Some(1));
        assert_eq!(report.incidents[0].correlation_key.as_deref(), Some("key_net_1"));
        assert_eq!(report.incidents[0].evidences.len(), 2);
        assert_eq!(report.incidents[0].evidences[0].source_module, "network_guardian");
        assert_eq!(report.incidents[0].evidences[1].source_module, "sys_monitor");

        assert_eq!(report.incidents[1].id, Some(2));
        assert_eq!(report.incidents[1].correlation_key.as_deref(), Some("key_net_2"));
        assert_eq!(report.incidents[1].evidences.len(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_forensic_export_csv_escaping_and_deterministic_order() {
        let mut conn = Connection::open_in_memory().unwrap();
        PulseIntelligenceEngine::migrate_schema(&mut conn).unwrap();
        let pie = PulseIntelligenceEngine::with_connection(conn).unwrap();

        let now = Utc::now();
        let ev1 = IncidentEvidence {
            id: None,
            incident_id: None,
            timestamp_utc: now,
            source_module: "network_guardian".to_string(),
            event_type: "packet_loss".to_string(),
            observable_json: "{\"loss_pct\":15.5,\"note\":\"commas, quotes \\\"test\\\" & newlines\\n\"}".to_string(),
        };

        let inc1 = create_test_incident(1, "key_csv_1", IncidentSeverity::Critical, IncidentStatus::Active, vec![ev1]);
        let inc2 = create_test_incident(2, "key_csv_2", IncidentSeverity::Info, IncidentStatus::Active, vec![]);

        pie.persist_incident(&inc1).await.unwrap();
        pie.persist_incident(&inc2).await.unwrap();

        let dir = test_temp_dir("csv_escape");
        let csv_path = dir.join("forensic_report.csv");

        pie.export_forensic_incidents(ForensicExportFormat::Csv, &csv_path, None).await.unwrap();

        assert!(csv_path.exists());
        let csv_content = std::fs::read_to_string(&csv_path).unwrap();

        // Validar lectura estricta con csv::Reader
        let mut rdr = csv::Reader::from_reader(csv_content.as_bytes());
        let headers = rdr.headers().unwrap();
        assert_eq!(headers.get(0), Some("incident_id"));
        assert_eq!(headers.get(9), Some("title"));
        assert_eq!(headers.get(20), Some("evidence_observable_json"));

        let records: Vec<csv::StringRecord> = rdr.records().map(|r| r.unwrap()).collect();
        // 2 filas: 1 fila para inc1 con su evidencia, 1 fila para inc2 sin evidencia
        assert_eq!(records.len(), 2);

        // Fila 1: inc1 con evidencia
        assert_eq!(records[0].get(0), Some("1"));
        assert_eq!(records[0].get(3), Some("key_csv_1"));
        assert_eq!(records[0].get(5), Some("critical"));
        assert!(records[0].get(9).unwrap().contains("\"Quotes\", Commas, & Newlines"));
        assert_eq!(records[0].get(18), Some("network_guardian"));
        assert!(records[0].get(20).unwrap().contains("loss_pct"));

        // Fila 2: inc2 sin evidencia (campos de evidencia vacíos)
        assert_eq!(records[1].get(0), Some("2"));
        assert_eq!(records[1].get(3), Some("key_csv_2"));
        assert_eq!(records[1].get(16), Some("")); // evidence_id
        assert_eq!(records[1].get(18), Some("")); // evidence_source_module
        assert_eq!(records[1].get(20), Some("")); // evidence_observable_json

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_forensic_export_empty_database_graceful() {
        let json_str = ForensicExporter::to_json_string(&[]).unwrap();
        let report: ForensicReport = serde_json::from_str(&json_str).unwrap();
        assert_eq!(report.total_incidents, 0);
        assert_eq!(report.total_evidences, 0);
        assert!(report.incidents.is_empty());

        let csv_str = ForensicExporter::to_csv_string(&[]).unwrap();
        let mut rdr = csv::Reader::from_reader(csv_str.as_bytes());
        assert_eq!(rdr.headers().unwrap().len(), CSV_HEADERS.len());
        assert_eq!(rdr.records().count(), 0);
    }

    #[tokio::test]
    async fn test_forensic_export_status_filter() {
        let mut conn = Connection::open_in_memory().unwrap();
        PulseIntelligenceEngine::migrate_schema(&mut conn).unwrap();
        let pie = PulseIntelligenceEngine::with_connection(conn).unwrap();

        let inc1 = create_test_incident(1, "k1", IncidentSeverity::High, IncidentStatus::Active, vec![]);
        let inc2 = create_test_incident(2, "k2", IncidentSeverity::Low, IncidentStatus::Resolved, vec![]);
        let inc3 = create_test_incident(3, "k3", IncidentSeverity::Medium, IncidentStatus::Acknowledged, vec![]);

        pie.persist_incident(&inc1).await.unwrap();
        pie.persist_incident(&inc2).await.unwrap();
        pie.persist_incident(&inc3).await.unwrap();

        let active = pie.get_all_incidents(Some(IncidentStatus::Active)).await.unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, Some(1));

        let resolved = pie.get_all_incidents(Some(IncidentStatus::Resolved)).await.unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].id, Some(2));

        let all = pie.get_all_incidents(None).await.unwrap();
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn test_forensic_export_evidence_ordering() {
        let mut conn = Connection::open_in_memory().unwrap();
        PulseIntelligenceEngine::migrate_schema(&mut conn).unwrap();
        let pie = PulseIntelligenceEngine::with_connection(conn).unwrap();

        let t0 = Utc::now();
        let ev_later = IncidentEvidence {
            id: None,
            incident_id: None,
            timestamp_utc: t0 + chrono::Duration::seconds(60),
            source_module: "network_guardian".to_string(),
            event_type: "ev_later".to_string(),
            observable_json: "{\"t\":60}".to_string(),
        };
        let ev_earlier = IncidentEvidence {
            id: None,
            incident_id: None,
            timestamp_utc: t0,
            source_module: "sys_monitor".to_string(),
            event_type: "ev_earlier".to_string(),
            observable_json: "{\"t\":0}".to_string(),
        };

        let inc = create_test_incident(1, "k_order", IncidentSeverity::Medium, IncidentStatus::Active, vec![ev_later, ev_earlier]);
        pie.persist_incident(&inc).await.unwrap();

        let all = pie.get_all_incidents(None).await.unwrap();
        assert_eq!(all.len(), 1);
        let evs = &all[0].evidences;
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].event_type, "ev_earlier", "Evidences must be ordered chronologically ascending");
        assert_eq!(evs[1].event_type, "ev_later");
    }

    #[test]
    fn test_forensic_export_file_io_error_handling() {
        let invalid_path = Path::new("");
        let res = ForensicExporter::export_to_json(&[], invalid_path);
        assert!(res.is_err(), "Exporting to empty path must fail gracefully");

        let res_csv = ForensicExporter::export_to_csv(&[], invalid_path);
        assert!(res_csv.is_err(), "Exporting CSV to empty path must fail gracefully");
    }
}
