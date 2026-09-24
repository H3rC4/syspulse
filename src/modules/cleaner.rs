use crate::models::{CleanerResult, DuplicateFile, DuplicateGroup, QuarantineEntry};
use anyhow::{Context, Result};
use chrono::Local;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;
use walkdir::WalkDir;

const BUFFER_SIZE: usize = 8192;
const CHUNK_SIZE: usize = 1000; // Process files in batches to avoid memory bloat

#[derive(Debug, Clone)]
pub enum ScanTarget {
    SystemTemp,
    UserSelected(PathBuf),
}

#[derive(Debug, Serialize, Deserialize)]
struct QuarantineManifest {
    entries: HashMap<String, String>, // id -> original_path
}

impl QuarantineManifest {
    fn load(path: &Path) -> Self {
        if path.exists() {
            if let Ok(data) = std::fs::read_to_string(path) {
                if let Ok(manifest) = serde_json::from_str(&data) {
                    return manifest;
                }
            }
        }
        Self { entries: HashMap::new() }
    }

    fn save(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(path, data)?;
        Ok(())
    }
}

pub struct Cleaner {
    quarantine_dir: PathBuf,
    manifest_path: PathBuf,
    manifest: Arc<Mutex<QuarantineManifest>>,
}

impl Cleaner {
    pub fn new() -> Result<Self> {
        let quarantine_dir = crate::modules::config::Settings::quarantine_dir()?;
        std::fs::create_dir_all(&quarantine_dir)
            .with_context(|| format!("Failed to create quarantine dir {:?}", quarantine_dir))?;

        let manifest_path = quarantine_dir.join("manifest.json");
        let manifest = QuarantineManifest::load(&manifest_path);

        Ok(Self {
            quarantine_dir,
            manifest_path,
            manifest: Arc::new(Mutex::new(manifest)),
        })
    }

    pub fn default_temp_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        #[cfg(target_os = "windows")]
        {
            if let Some(temp) = std::env::var_os("TEMP") {
                paths.push(PathBuf::from(temp));
            }
            if let Some(local_app_data) = dirs::data_local_dir() {
                paths.push(local_app_data.join("Temp"));
                paths.push(local_app_data.join("npm-cache"));
                paths.push(local_app_data.join("pip").join("cache"));
                paths.push(local_app_data.join("Cargo").join("registry").join("cache"));
            }
        }

        #[cfg(target_os = "macos")]
        {
            paths.push(PathBuf::from("/tmp"));
            if let Some(home) = dirs::home_dir() {
                paths.push(home.join("Library/Caches"));
                paths.push(home.join("Library/Caches/pip"));
                paths.push(home.join("Library/Caches/npm"));
                paths.push(home.join(".cargo/registry/cache"));
            }
        }

        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            paths.push(PathBuf::from("/tmp"));
            if let Some(home) = dirs::home_dir() {
                paths.push(home.join(".cache"));
            }
        }

        paths
    }

    pub async fn scan_system_temp(
        &self,
        token: CancellationToken,
        pause_flag: Arc<AtomicBool>,
        cancel_flag: Arc<AtomicBool>,
        progress_callback: impl Fn(usize, u64) + Send + 'static,
    ) -> Result<CleanerResult> {
        let paths = Self::default_temp_paths();
        self.scan_paths(paths, token, pause_flag, cancel_flag, progress_callback).await
    }

    pub async fn scan_paths(
        &self,
        paths: Vec<PathBuf>,
        token: CancellationToken,
        pause_flag: Arc<AtomicBool>,
        cancel_flag: Arc<AtomicBool>,
        progress_callback: impl Fn(usize, u64) + Send + 'static,
    ) -> Result<CleanerResult> {
        let mut result = CleanerResult::default();

        for base in paths {
            if !base.exists() || !base.is_dir() {
                continue;
            }

            // Process in chunks to avoid memory bloat
            let mut chunk_count = 0;

            for entry in WalkDir::new(&base).into_iter().filter_map(|e| e.ok()) {
                if token.is_cancelled() || cancel_flag.load(Ordering::Relaxed) {
                    return Ok(result);
                }

                // Check pause flag
                while pause_flag.load(Ordering::Relaxed) {
                    if token.is_cancelled() || cancel_flag.load(Ordering::Relaxed) {
                        return Ok(result);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }

                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                match entry.metadata() {
                    Ok(meta) => {
                        result.files_found += 1;
                        result.bytes_reclaimable += meta.len();
                        chunk_count += 1;
                        
                        // Update progress every CHUNK_SIZE files
                        if chunk_count >= CHUNK_SIZE {
                            progress_callback(result.files_found, result.bytes_reclaimable);
                            chunk_count = 0;
                            tokio::task::yield_now().await;
                        }
                    }
                    Err(e) => {
                        result.errors.push(format!("{}: {}", path.display(), e));
                    }
                }
            }

            // Final progress update
            if chunk_count > 0 {
                progress_callback(result.files_found, result.bytes_reclaimable);
            }
        }

        Ok(result)
    }

    pub async fn clean_system_temp(
        &self,
        token: CancellationToken,
        pause_flag: Arc<AtomicBool>,
        cancel_flag: Arc<AtomicBool>,
        progress_callback: impl Fn(usize, u64) + Send + 'static,
        permanent_delete: bool,  // NUEVO
    ) -> Result<CleanerResult> {
        let paths = Self::default_temp_paths();
        self.clean_paths(paths, token, pause_flag, cancel_flag, progress_callback, permanent_delete).await
    }

    pub async fn clean_paths(
        &self,
        paths: Vec<PathBuf>,
        token: CancellationToken,
        pause_flag: Arc<AtomicBool>,
        cancel_flag: Arc<AtomicBool>,
        progress_callback: impl Fn(usize, u64) + Send + 'static,
        permanent_delete: bool,  // NUEVO: true = eliminar directo, false = papelera
    ) -> Result<CleanerResult> {
        let mut result = CleanerResult::default();
        let mut moved_bytes: u64 = 0;

        for base in paths {
            if !base.exists() || !base.is_dir() {
                tracing::debug!("Path does not exist or is not a directory: {:?}", base);
                continue;
            }

            tracing::info!("Cleaning path: {:?}", base);

            // Collect files in chunks to avoid memory bloat
            let mut chunk: Vec<(PathBuf, u64)> = Vec::with_capacity(CHUNK_SIZE);

            for entry in WalkDir::new(&base).into_iter().filter_map(|e| e.ok()) {
                if token.is_cancelled() || cancel_flag.load(Ordering::Relaxed) {
                    return Ok(result);
                }

                let path = entry.path();
                if !path.is_file() {
                    continue;
                }

                if let Ok(meta) = entry.metadata() {
                    chunk.push((path.to_path_buf(), meta.len()));

                    // Process chunk when full
                    if chunk.len() >= CHUNK_SIZE {
                        tracing::debug!("Processing chunk of {} files", chunk.len());
                        for (file_path, size) in chunk.drain(..) {
                            if token.is_cancelled() || cancel_flag.load(Ordering::Relaxed) {
                                return Ok(result);
                            }

                            // Check pause flag
                            while pause_flag.load(Ordering::Relaxed) {
                                if token.is_cancelled() || cancel_flag.load(Ordering::Relaxed) {
                                    return Ok(result);
                                }
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            }

                            // Eliminar según configuración: directo o papelera
                            let path_clone = file_path.clone();
                            let delete_result = if permanent_delete {
                                // Eliminación directa - sin papelera, instantáneo
                                tokio::task::spawn_blocking(move || {
                                    std::fs::remove_file(&path_clone)
                                }).await
                            } else {
                                // A papelera (comportamiento original)
                                tokio::task::spawn_blocking(move || {
                                    trash::delete(&path_clone)
                                }).await
                            };

                            match delete_result {
                                Ok(Ok(_)) => {
                                    result.files_found += 1;
                                    moved_bytes += size;
                                    result.bytes_reclaimable = moved_bytes;
                                    progress_callback(result.files_found, moved_bytes);
                                    tracing::debug!("Deleted: {:?}", file_path);
                                }
                                Ok(Err(e)) => {
                                    let error_msg = format!("{}: {}", file_path.display(), e);
                                    tracing::warn!("Failed to delete: {}", error_msg);
                                    result.errors.push(error_msg);
                                }
                                Err(e) => {
                                    let error_msg = format!("{}: spawn_blocking failed: {}", file_path.display(), e);
                                    tracing::warn!("Failed to delete: {}", error_msg);
                                    result.errors.push(error_msg);
                                }
                            }
                        }
                        // Yield to runtime between chunks
                        tokio::task::yield_now().await;
                    }
                }
            }

            // Process remaining files in last chunk
            if !chunk.is_empty() {
                tracing::debug!("Processing final chunk of {} files", chunk.len());
                for (file_path, size) in chunk.drain(..) {
                    if token.is_cancelled() || cancel_flag.load(Ordering::Relaxed) {
                        return Ok(result);
                    }

                    while pause_flag.load(Ordering::Relaxed) {
                        if token.is_cancelled() || cancel_flag.load(Ordering::Relaxed) {
                            return Ok(result);
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }

                    let path_clone = file_path.clone();
                    let delete_result = if permanent_delete {
                        tokio::task::spawn_blocking(move || {
                            std::fs::remove_file(&path_clone)
                        }).await
                    } else {
                        tokio::task::spawn_blocking(move || {
                            trash::delete(&path_clone)
                        }).await
                    };

                    match delete_result {
                        Ok(Ok(_)) => {
                            result.files_found += 1;
                            moved_bytes += size;
                            result.bytes_reclaimable = moved_bytes;
                            progress_callback(result.files_found, moved_bytes);
                        }
                        Ok(Err(e)) => {
                            let error_msg = format!("{}: {}", file_path.display(), e);
                            tracing::warn!("Failed to delete: {}", error_msg);
                            result.errors.push(error_msg);
                        }
                        Err(e) => {
                            let error_msg = format!("{}: spawn_blocking failed: {}", file_path.display(), e);
                            tracing::warn!("Failed to delete: {}", error_msg);
                            result.errors.push(error_msg);
                        }
                    }
                }
            }
        }

        tracing::info!("Clean complete: {} files, {} errors", result.files_found, result.errors.len());
        Ok(result)
    }

    pub async fn find_duplicates(
        &self,
        target: PathBuf,
        token: CancellationToken,
        pause_flag: Arc<AtomicBool>,
        progress_callback: impl Fn(usize, u64) + Send + 'static,
    ) -> Result<Vec<DuplicateGroup>> {
        let mut by_size: HashMap<u64, Vec<PathBuf>> = HashMap::new();
        let mut chunk_count = 0;

        for entry in WalkDir::new(&target).into_iter().filter_map(|e| e.ok()) {
            if token.is_cancelled() {
                return Ok(Vec::new());
            }

            // Check pause flag
            while pause_flag.load(Ordering::Relaxed) {
                if token.is_cancelled() {
                    return Ok(Vec::new());
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }

            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            match entry.metadata() {
                Ok(meta) => {
                    let size = meta.len();
                    if size == 0 {
                        continue;
                    }
                    by_size.entry(size).or_default().push(path.to_path_buf());
                    chunk_count += 1;
                    
                    // Yield periodically to keep UI responsive
                    if chunk_count >= CHUNK_SIZE {
                        progress_callback(chunk_count, 0);
                        chunk_count = 0;
                        tokio::task::yield_now().await;
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to read metadata for {}: {}", path.display(), e);
                }
            }
        }

        let mut groups: Vec<DuplicateGroup> = Vec::new();
        let mut scanned_files: usize = 0;

        for (size, paths) in by_size {
            if paths.len() < 2 {
                continue;
            }

            let mut by_hash: HashMap<String, Vec<(PathBuf, Option<chrono::DateTime<Local>>)>> = HashMap::new();

            for path in paths {
                if token.is_cancelled() {
                    return Ok(Vec::new());
                }

                // Check pause flag
                while pause_flag.load(Ordering::Relaxed) {
                    if token.is_cancelled() {
                        return Ok(Vec::new());
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }

                match compute_file_hash(&path).await {
                    Ok(hash) => {
                        let created = std::fs::metadata(&path)
                            .and_then(|m| m.created())
                            .ok()
                            .map(|t| chrono::DateTime::<Local>::from(t));

                        by_hash.entry(hash).or_default().push((path, created));
                        scanned_files += 1;
                        progress_callback(scanned_files, size);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to hash {}: {}", path.display(), e);
                    }
                }
            }

            for (hash, mut files) in by_hash {
                if files.len() < 2 {
                    continue;
                }

                // Sort by created date (oldest first), then by filename as tiebreaker
                files.sort_by(|a, b| {
                    let date_cmp = a.1.unwrap_or_else(Local::now).cmp(&b.1.unwrap_or_else(Local::now));
                    if date_cmp == std::cmp::Ordering::Equal {
                        // If dates are equal, sort by filename
                        a.0.file_name().unwrap_or_default().cmp(&b.0.file_name().unwrap_or_default())
                    } else {
                        date_cmp
                    }
                });

                let duplicate_files: Vec<DuplicateFile> = files
                    .iter()
                    .enumerate()
                    .map(|(idx, (path, created))| DuplicateFile {
                        path: path.clone(),
                        created: *created,
                        selected: idx > 0,
                    })
                    .collect();

                groups.push(DuplicateGroup {
                    hash: hash.clone(),
                    size,
                    files: duplicate_files,
                });
            }
        }

        groups.sort_by(|a, b| b.size.cmp(&a.size));
        Ok(groups)
    }

    pub async fn quarantine_selected_duplicates(
        &self,
        groups: &[DuplicateGroup],
        token: CancellationToken,
    ) -> Result<Vec<QuarantineEntry>> {
        let mut entries = Vec::new();

        for group in groups {
            for file in &group.files {
                if !file.selected {
                    continue;
                }

                if token.is_cancelled() {
                    return Ok(entries);
                }

                match self.quarantine_file(&file.path).await {
                    Ok(size) => {
                        let quarantine_filename = {
                            let path_hash = {
                                let mut hasher = Sha256::new();
                                hasher.update(file.path.to_string_lossy().as_bytes());
                                let result = hasher.finalize();
                                format!("{:x}", result)[..16].to_string()
                            };
                            let extension = file.path.extension()
                                .map(|e| format!(".{}", e.to_string_lossy()))
                                .unwrap_or_default();
                            format!("{}_{}{}", path_hash, std::process::id(), extension)
                        };
                        
                        entries.push(QuarantineEntry {
                            id: None,
                            quarantined_at: Local::now(),
                            original_path: file.path.clone(),
                            quarantine_path: self.quarantine_dir.join(&quarantine_filename),
                            size,
                        });
                    }
                    Err(e) => {
                        tracing::error!("Failed to quarantine {}: {}", file.path.display(), e);
                    }
                }
            }
        }

        Ok(entries)
    }

    pub fn list_quarantine(&self) -> Result<Vec<QuarantineEntry>> {
        let manifest = QuarantineManifest::load(&self.manifest_path);
        let mut entries = Vec::new();

        for entry in WalkDir::new(&self.quarantine_dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            // Skip manifest file
            if path.file_name().map(|f| f == "manifest.json").unwrap_or(false) {
                continue;
            }

            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };

            let original_path = self.original_path_from_quarantine(path);

            entries.push(QuarantineEntry {
                id: None,
                quarantined_at: chrono::DateTime::<Local>::from(meta.modified().unwrap_or(std::time::UNIX_EPOCH)),
                original_path,
                quarantine_path: path.to_path_buf(),
                size: meta.len(),
            });
        }

        entries.sort_by(|a, b| b.quarantined_at.cmp(&a.quarantined_at));
        Ok(entries)
    }

    pub fn restore_from_quarantine(&self, entry: &QuarantineEntry) -> Result<()> {
        if let Some(parent) = entry.original_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to recreate original dir {:?}", parent))?;
        }

        std::fs::rename(&entry.quarantine_path, &entry.original_path)
            .with_context(|| format!("Failed to restore {:?}", entry.quarantine_path))?;

        // Remove from manifest
        if let Some(file_name) = entry.quarantine_path.file_name() {
            let mut manifest = self.manifest.lock().unwrap();
            manifest.entries.remove(file_name.to_string_lossy().as_ref());
            manifest.save(&self.manifest_path)?;
        }

        Ok(())
    }

    pub fn delete_quarantine_permanently(&self, entry: &QuarantineEntry) -> Result<()> {
        trash::delete(&entry.quarantine_path)
            .with_context(|| format!("Failed to move {:?} to trash", entry.quarantine_path))?;

        // Remove from manifest
        if let Some(file_name) = entry.quarantine_path.file_name() {
            let mut manifest = self.manifest.lock().unwrap();
            manifest.entries.remove(file_name.to_string_lossy().as_ref());
            manifest.save(&self.manifest_path)?;
        }

        Ok(())
    }

    pub fn purge_old_quarantine(&self, days: u32) -> Result<usize> {
        if days == 0 {
            return Ok(0);
        }

        let cutoff = Local::now() - chrono::Duration::days(days as i64);
        let mut count = 0;

        // Don't lock manifest during iteration to avoid deadlocks
        let mut manifest = self.manifest.lock().unwrap();
        let mut entries_to_remove = Vec::new();

        for entry in WalkDir::new(&self.quarantine_dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            // Skip manifest file
            if path.file_name().map(|f| f == "manifest.json").unwrap_or(false) {
                continue;
            }

            let modified = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .map(|t| chrono::DateTime::<Local>::from(t));

            if let Some(modified) = modified {
                if modified < cutoff {
                    // Just remove the file directly, don't use trash
                    if std::fs::remove_file(path).is_ok() {
                        if let Some(file_name) = path.file_name() {
                            entries_to_remove.push(file_name.to_string_lossy().to_string());
                        }
                        count += 1;
                    }
                }
            }
        }

        // Remove entries from manifest
        for entry_name in entries_to_remove {
            manifest.entries.remove(&entry_name);
        }

        manifest.save(&self.manifest_path)?;
        tracing::info!("Purged {} old quarantine entries", count);
        Ok(count)
    }

    async fn quarantine_file(&self, source: &Path) -> Result<u64> {
        let meta = std::fs::metadata(source)
            .with_context(|| format!("Failed to read metadata for {:?}", source))?;

        let size = meta.len();
        
        // Generate short ID from hash of path
        let path_hash = {
            let mut hasher = Sha256::new();
            hasher.update(source.to_string_lossy().as_bytes());
            let result = hasher.finalize();
            format!("{:x}", result)[..16].to_string()
        };
        
        let extension = source.extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();
        
        let safe_filename = format!("{}_{}{}", path_hash, std::process::id(), extension);
        let dest = self.quarantine_dir.join(&safe_filename);

        // Update manifest
        {
            let mut manifest = self.manifest.lock().unwrap();
            manifest.entries.insert(safe_filename, source.to_string_lossy().to_string());
            manifest.save(&self.manifest_path)?;
        }

        // Try rename first, if it fails (cross-device), copy then delete
        match std::fs::rename(source, &dest) {
            Ok(_) => {
                tracing::debug!("Quarantined (rename): {:?}", source);
            }
            Err(e) => {
                tracing::debug!("Rename failed for {:?}: {}, trying copy+delete", source, e);
                std::fs::copy(source, &dest)
                    .with_context(|| format!("Failed to copy {:?} to quarantine {:?}", source, dest))?;
                std::fs::remove_file(source)
                    .with_context(|| format!("Failed to remove original {:?}", source))?;
                tracing::debug!("Quarantined (copy+delete): {:?}", source);
            }
        }

        Ok(size)
    }

    fn quarantine_path_for(&self, original: &Path) -> PathBuf {
        let canonical = original.canonicalize().unwrap_or_else(|_| original.to_path_buf());
        let safe_name = canonical
            .to_string_lossy()
            .replace([':', '/', '\\'], "_");

        self.quarantine_dir.join(format!(
            "{}_{}_{}",
            safe_name,
            std::process::id(),
            chrono::Local::now().timestamp_millis()
        ))
    }

    fn original_path_from_quarantine(&self, quarantine_path: &Path) -> PathBuf {
        // Try to read from manifest first
        if let Some(file_name) = quarantine_path.file_name() {
        let manifest = QuarantineManifest::load(&self.manifest_path);
            if let Some(original) = manifest.entries.get(file_name.to_string_lossy().as_ref()) {
                return PathBuf::from(original);
            }
        }
        
        // Fallback to old method
        if let Some(file_name) = quarantine_path.file_stem() {
            let name = file_name.to_string_lossy();
            if let Some(base) = name.split("_0_").next() {
                return PathBuf::from(base.replace('_', std::path::MAIN_SEPARATOR.to_string().as_str()));
            }
        }
        quarantine_path.to_path_buf()
    }
}

async fn compute_file_hash(path: &Path) -> Result<String> {
    let path = path.to_path_buf();

    tokio::task::spawn_blocking(move || {
        let mut file = std::fs::File::open(&path)
            .with_context(|| format!("Failed to open {:?}", path))?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; BUFFER_SIZE];

        loop {
            let n = std::io::Read::read(&mut file, &mut buffer)
                .with_context(|| format!("Failed to read {:?}", path))?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }

        Ok::<String, anyhow::Error>(format!("{:x}", hasher.finalize()))
    })
    .await
    .context("Failed to spawn hash task")?
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    if bytes == 0 {
        return "0 B".to_string();
    }

    let exp = (bytes as f64).log(1024.0).min(UNITS.len() as f64 - 1.0) as usize;
    let value = bytes as f64 / 1024f64.powi(exp as i32);
    format!("{:.2} {}", value, UNITS[exp])
}
