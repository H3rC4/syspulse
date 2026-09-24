use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Supported application languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Language {
    #[serde(rename = "en")]
    English,
    #[serde(rename = "es-AR")]
    SpanishArgentina,
}

impl Default for Language {
    fn default() -> Self {
        Language::English
    }
}

impl Language {
    pub fn as_str(&self) -> &'static str {
        match self {
            Language::English => "en",
            Language::SpanishArgentina => "es-AR",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "es-AR" | "es" => Language::SpanishArgentina,
            _ => Language::English,
        }
    }
}

/// A single process event captured by Process Hunter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub id: Option<i64>,
    pub timestamp: chrono::DateTime<chrono::Local>,
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub name: String,
    pub executable_path: String,
    pub command_line: String,
    pub lifetime_seconds: Option<u64>,
}

/// A process entry shown in the CPU Focus list.
#[derive(Debug, Clone, Default)]
pub struct ProcessEntry {
    pub pid: u32,
    pub name: String,
    pub executable_path: String,
    pub cpu_percent: f32,
    pub memory_mb: u64,
    pub focused: bool,
}

/// A group of duplicate files sharing the same hash.
#[derive(Debug, Clone, Default)]
pub struct DuplicateGroup {
    pub hash: String,
    pub size: u64,
    pub files: Vec<DuplicateFile>,
}

#[derive(Debug, Clone, Default)]
pub struct DuplicateFile {
    pub path: PathBuf,
    pub created: Option<chrono::DateTime<chrono::Local>>,
    pub selected: bool,
}

/// A quarantined file entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: Option<i64>,
    pub quarantined_at: chrono::DateTime<chrono::Local>,
    pub original_path: PathBuf,
    pub quarantine_path: PathBuf,
    pub size: u64,
}

/// Cleaner scan result.
#[derive(Debug, Clone, Default)]
pub struct CleanerResult {
    pub files_found: usize,
    pub bytes_reclaimable: u64,
    pub errors: Vec<String>,
}

// ── System Monitor Dashboard Structs ──

#[derive(Debug, Clone, Default)]
pub struct CoreUsage {
    pub name: String,
    pub usage: f32,
}

#[derive(Debug, Clone, Default)]
pub struct DiskInfo {
    pub name: String,
    pub mount_point: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Debug, Clone, Default)]
pub struct TempInfo {
    pub label: String,
    pub temperature: f32,
}

#[derive(Debug, Clone, Default)]
pub struct TopProcess {
    pub name: String,
    pub pid: u32,
    pub value: f32,
    pub memory_mb: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SystemStats {
    pub cpu_usage: f32,
    pub cores: Vec<CoreUsage>,
    pub total_memory: u64,
    pub used_memory: u64,
    pub total_swap: u64,
    pub used_swap: u64,
    pub load_avg_1: f64,
    pub load_avg_5: f64,
    pub load_avg_15: f64,
    pub disks: Vec<DiskInfo>,
    pub network_up_bps: f64,
    pub network_down_bps: f64,
    pub temperatures: Vec<TempInfo>,
    pub uptime_seconds: u64,
    pub top_cpu: Vec<TopProcess>,
    pub top_ram: Vec<TopProcess>,
}
