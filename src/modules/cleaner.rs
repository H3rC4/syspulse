use crate::models::{CleanerResult, DuplicateFile, DuplicateGroup, QuarantineEntry};
use anyhow::{Context, Result};
use chrono::{Local, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
#[cfg(not(windows))]
use std::time::SystemTime;
use tokio_util::sync::CancellationToken;
use walkdir::WalkDir;

#[cfg(windows)]
use std::os::windows::fs::MetadataExt as WindowsMetadataExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::Foundation::{FILETIME, HANDLE};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    LockFileEx, MoveFileExW, SetFileAttributesW, SetFileTime, UnlockFileEx,
    FILE_FLAGS_AND_ATTRIBUTES, LOCKFILE_EXCLUSIVE_LOCK, MOVE_FILE_FLAGS,
};
#[cfg(windows)]
use windows::Win32::System::IO::OVERLAPPED;

const BUFFER_SIZE: usize = 65536; // 64 KB buffer for high I/O throughput
const PRE_HASH_SIZE: usize = 16384; // 16 KB for duplicate pre-hashing
const CHUNK_SIZE: usize = 1000; // Process files in batches to avoid memory bloat
const QUARANTINE_LOCK_FILE: &str = ".syspulse-quarantine.lock";
const QUARANTINE_STAGING_SUFFIX: &str = ".syspulse-staging";
const RESTORE_STAGING_PREFIX: &str = ".syspulse-restore-";
const FILE_ATTRIBUTE_REPARSE_POINT_FLAG: u32 = 0x400;

#[cfg(test)]
mod fault_injection {
    use std::cell::{Cell, RefCell};

    thread_local! {
        static POINT: RefCell<Option<&'static str>> = const { RefCell::new(None) };
        static FORCE_CROSS_VOLUME: Cell<bool> = const { Cell::new(false) };
    }

    pub fn set_point(point: &'static str) {
        POINT.with(|slot| *slot.borrow_mut() = Some(point));
    }

    pub fn set_force_cross_volume(force: bool) {
        FORCE_CROSS_VOLUME.with(|slot| slot.set(force));
    }

    pub fn force_cross_volume() -> bool {
        FORCE_CROSS_VOLUME.with(Cell::get)
    }

    pub fn reset() {
        POINT.with(|slot| *slot.borrow_mut() = None);
        FORCE_CROSS_VOLUME.with(|slot| slot.set(false));
    }

    pub fn check(point: &str) -> anyhow::Result<()> {
        let hit = POINT.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.as_deref() == Some(point) {
                *slot = None;
                true
            } else {
                false
            }
        });
        if hit {
            anyhow::bail!("injected fault at {}", point);
        }
        Ok(())
    }
}

#[cfg(not(test))]
mod fault_injection {
    pub fn check(_point: &str) -> anyhow::Result<()> {
        Ok(())
    }

    pub fn force_cross_volume() -> bool {
        false
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum ScanTarget {
    SystemTemp,
    UserSelected(PathBuf),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum QuarantineState {
    #[default]
    Quarantined,
    Restored,
    Deleted,
    Staged,
    Restoring,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineRecordV2 {
    pub original_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantined_at_utc: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(default)]
    pub state: QuarantineState,
}

fn validate_windows_component(name: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("Windows file name cannot be empty");
    }
    if name.ends_with(' ') || name.ends_with('.') {
        anyhow::bail!("Windows file name {:?} cannot end with a space or dot", name);
    }
    if name.chars().any(char::is_control) {
        anyhow::bail!("Windows file name {:?} contains control characters", name);
    }

    let stem = name
        .split('.')
        .next()
        .unwrap_or(name)
        .trim_end_matches([' ', '.'])
        .to_ascii_uppercase();

    const RESERVED: &[&str] = &["CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"];
    if RESERVED.contains(&stem.as_str()) {
        anyhow::bail!("Windows file name {:?} is reserved", name);
    }
    if let Some(number) = stem.strip_prefix("COM") {
        if number.len() == 1 && "123456789".contains(number) {
            anyhow::bail!("Windows file name {:?} is reserved", name);
        }
    }
    if let Some(number) = stem.strip_prefix("LPT") {
        if number.len() == 1 && "123456789".contains(number) {
            anyhow::bail!("Windows file name {:?} is reserved", name);
        }
    }
    Ok(())
}

fn is_reparse_or_symlink(path: &Path) -> Result<bool> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).with_context(|| format!("Failed to inspect {:?}", path)),
    };

    #[cfg(windows)]
    {
        Ok(metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT_FLAG != 0)
    }
    #[cfg(not(windows))]
    {
        Ok(metadata.file_type().is_symlink())
    }
}

fn ensure_not_reparse(path: &Path, label: &str) -> Result<()> {
    if is_reparse_or_symlink(path)? {
        anyhow::bail!("{} {:?} is a reparse point or symbolic link", label, path);
    }
    Ok(())
}

impl QuarantineRecordV2 {
    pub fn validate(&self, key: &str, quarantine_dir: &Path) -> Result<()> {
        Self::validate_key(key)?;
        Self::validate_original_path(&self.original_path, quarantine_dir)?;
        Ok(())
    }

    pub fn validate_key(key: &str) -> Result<()> {
        if key.is_empty() {
            anyhow::bail!("Quarantine manifest key cannot be empty");
        }
        if key.contains('/') || key.contains('\\') || key.contains(':') {
            anyhow::bail!("Quarantine manifest key {:?} contains illegal path separators", key);
        }
        if key == ".." || key == "." {
            anyhow::bail!("Quarantine manifest key {:?} is an invalid relative path component", key);
        }
        if key == "manifest.json" || key == "manifest.v1.bak" || key.starts_with("manifest.") {
            anyhow::bail!("Quarantine manifest key {:?} collides with manifest control files", key);
        }
        validate_windows_component(key)?;
        Ok(())
    }

    pub fn validate_original_path(original_path: &Path, quarantine_dir: &Path) -> Result<()> {
        if original_path.as_os_str().is_empty() {
            anyhow::bail!("Original path cannot be empty");
        }
        if !original_path.is_absolute() {
            anyhow::bail!("Original path {:?} is not absolute", original_path);
        }
        if original_path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir | std::path::Component::CurDir))
        {
            anyhow::bail!("Original path {:?} contains relative path components", original_path);
        }
        let file_name = original_path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default();
        validate_windows_component(&file_name)?;
        ensure_not_reparse(original_path, "Original path")?;
        ensure_not_reparse(quarantine_dir, "Quarantine directory")?;
        if let (Ok(orig_canon), Ok(quar_canon)) = (original_path.canonicalize(), quarantine_dir.canonicalize()) {
            if orig_canon.starts_with(&quar_canon) {
                anyhow::bail!("Original path {:?} points inside quarantine directory {:?}", original_path, quarantine_dir);
            }
        } else if original_path.starts_with(quarantine_dir) {
            anyhow::bail!("Original path {:?} points inside quarantine directory {:?}", original_path, quarantine_dir);
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct QuarantineManifestV1 {
    entries: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineManifestV2 {
    pub version: u32,
    pub entries: HashMap<String, QuarantineRecordV2>,
}

impl QuarantineManifestV2 {
    pub fn new() -> Self {
        Self {
            version: 2,
            entries: HashMap::new(),
        }
    }

    /// Loads manifest v2, or migrates non-destructively from v1 with a backup.
    /// In case of corruption or orphan temp ambiguity, returns an Err to block
    /// destructive operations and avoid wiping data silently.
    pub fn load_or_recover(path: &Path) -> Result<Self> {
        let parent = path.parent().context("Manifest path has no parent directory")?;

        if !path.exists() {
            let orphan_temps = Self::find_orphan_temps(parent);
            let existing_files = Self::find_existing_state_files(parent);
            if !orphan_temps.is_empty() || !existing_files.is_empty() {
                anyhow::bail!(
                    "Ambiguous quarantine state: manifest.json is missing but {} orphan temporary file(s) and {} existing file(s) remain. Refusing to initialize empty manifest to avoid data loss.",
                    orphan_temps.len(),
                    existing_files.len()
                );
            }
            return Ok(Self::new());
        }

        ensure_not_reparse(path, "Quarantine manifest")?;

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read quarantine manifest at {:?}", path))?;

        if content.trim().is_empty() {
            anyhow::bail!(
                "Quarantine manifest at {:?} is empty/truncated. Refusing to initialize empty manifest to prevent data loss.",
                path
            );
        }

        let value: serde_json::Value = serde_json::from_str(&content)
            .with_context(|| format!("Quarantine manifest at {:?} is corrupt or unparseable", path))?;

        if let Some(version_value) = value.get("version") {
            let version = version_value.as_u64().with_context(|| {
                format!("Quarantine manifest at {:?} has a non-numeric schema version", path)
            })?;
            if version != 2 {
                anyhow::bail!(
                    "Unsupported quarantine manifest schema version {} at {:?}. Refusing to proceed.",
                    version,
                    path
                );
            }

            let manifest_v2: QuarantineManifestV2 = serde_json::from_value(value)
                .with_context(|| format!("Quarantine manifest v2 at {:?} is corrupt", path))?;
            for (k, v) in &manifest_v2.entries {
                v.validate(k, parent)?;
            }
            Self::cleanup_stale_temps_if_safe(parent);
            return Ok(manifest_v2);
        }

        let manifest_v1: QuarantineManifestV1 = serde_json::from_value(value)
            .with_context(|| format!("Quarantine manifest at {:?} is corrupt or unparseable", path))?;
        tracing::info!("Detected v1 quarantine manifest at {:?}. Starting non-destructive migration...", path);
        let backup_path = parent.join("manifest.v1.bak");
        std::fs::copy(path, &backup_path)
            .with_context(|| format!("Failed to create non-destructive v1 backup at {:?}", backup_path))?;

        let mut v2_entries = HashMap::new();
        for (k, orig_path_str) in manifest_v1.entries {
            let record = QuarantineRecordV2 {
                original_path: PathBuf::from(orig_path_str),
                quarantined_at_utc: None,
                original_sha256: None,
                size_bytes: None,
                state: QuarantineState::Quarantined,
            };
            record.validate(&k, parent)?;
            v2_entries.insert(k, record);
        }

        let v2_manifest = Self {
            version: 2,
            entries: v2_entries,
        };

        v2_manifest.save_atomic(path)
            .with_context(|| format!("Failed to save migrated v2 manifest to {:?}", path))?;
        tracing::info!("Quarantine manifest migrated to v2 with {} entries. Backup preserved at {:?}", v2_manifest.entries.len(), backup_path);
        Self::cleanup_stale_temps_if_safe(parent);
        Ok(v2_manifest)
    }

    /// Atomically persists the manifest using an exclusive temp file and sync_all.
    pub fn save_atomic(&self, path: &Path) -> Result<()> {
        let parent = path.parent().context("Manifest path has no parent directory")?;
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create manifest parent directory {:?}", parent))?;

        for (k, v) in &self.entries {
            v.validate(k, parent)?;
        }

        let serialized = serde_json::to_string_pretty(self)
            .context("Failed to serialize quarantine manifest v2")?;

        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temp_filename = format!("manifest.json.tmp.{}.{}", std::process::id(), unique_id);
        let temp_path = parent.join(temp_filename);

        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
                .with_context(|| format!("Failed to create exclusive temporary manifest at {:?}", temp_path))?;

            file.write_all(serialized.as_bytes())
                .with_context(|| format!("Failed to write manifest payload to {:?}", temp_path))?;
            file.sync_all()
                .with_context(|| format!("Failed to sync_all manifest payload to disk for {:?}", temp_path))?;
        }

        if let Err(e) = std::fs::rename(&temp_path, path) {
            let _ = std::fs::remove_file(&temp_path);
            return Err(e).with_context(|| format!("Failed atomic replacement from {:?} to {:?}", temp_path, path));
        }

        Ok(())
    }

    fn find_orphan_temps(dir: &Path) -> Vec<PathBuf> {
        let mut temps = Vec::new();
        if let Ok(read_dir) = std::fs::read_dir(dir) {
            for entry in read_dir.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with("manifest.json.tmp.") {
                    temps.push(entry.path());
                }
            }
        }
        temps
    }

    fn find_existing_state_files(dir: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();
        if let Ok(read_dir) = std::fs::read_dir(dir) {
            for entry in read_dir.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str == QUARANTINE_LOCK_FILE || name_str.starts_with("manifest.json.tmp.") {
                    continue;
                }
                files.push(entry.path());
            }
        }
        files
    }

    fn cleanup_stale_temps_if_safe(dir: &Path) {
        for temp in Self::find_orphan_temps(dir) {
            let _ = std::fs::remove_file(temp);
        }
    }
}

#[cfg(windows)]
struct QuarantineProcessLock {
    file: std::fs::File,
}

#[cfg(windows)]
impl QuarantineProcessLock {
    fn acquire(path: &Path) -> Result<Self> {
        ensure_not_reparse(path, "Quarantine lock file")?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("Failed to open quarantine lock {:?}", path))?;
        let handle = HANDLE(file.as_raw_handle() as isize);
        let mut overlapped = OVERLAPPED::default();
        unsafe {
            LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK, 0, u32::MAX, u32::MAX, &mut overlapped)
                .map_err(|error| anyhow::anyhow!("Failed to acquire cross-process quarantine lock: {}", error))?;
        }
        Ok(Self { file })
    }
}

#[cfg(windows)]
impl Drop for QuarantineProcessLock {
    fn drop(&mut self) {
        let handle = HANDLE(self.file.as_raw_handle() as isize);
        let mut overlapped = OVERLAPPED::default();
        unsafe {
            let _ = UnlockFileEx(handle, 0, u32::MAX, u32::MAX, &mut overlapped);
        }
    }
}

#[cfg(all(unix, not(windows)))]
struct QuarantineProcessLock {
    file: std::fs::File,
}

#[cfg(all(unix, not(windows)))]
impl QuarantineProcessLock {
    fn acquire(path: &Path) -> Result<Self> {
        ensure_not_reparse(path, "Quarantine lock file")?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("Failed to open quarantine lock {:?}", path))?;
        let result = unsafe { libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(&file), libc::LOCK_EX) };
        if result != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("Failed to acquire cross-process quarantine lock {:?}", path));
        }
        Ok(Self { file })
    }
}

#[cfg(all(unix, not(windows)))]
impl Drop for QuarantineProcessLock {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(&self.file), libc::LOCK_UN);
        }
    }
}

#[derive(Debug)]
struct CrossDeviceMoveError;

impl std::fmt::Display for CrossDeviceMoveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("source and destination are on different volumes")
    }
}

impl std::error::Error for CrossDeviceMoveError {}

#[cfg(windows)]
fn wide_path(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

fn atomic_move_no_replace(source: &Path, destination: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        let source_wide = wide_path(source);
        let destination_wide = wide_path(destination);
        unsafe {
            MoveFileExW(
                PCWSTR(source_wide.as_ptr()),
                PCWSTR(destination_wide.as_ptr()),
                MOVE_FILE_FLAGS(0),
            )
        }
        .map_err(|error| {
            let code = error.code().0 as u32 & 0xFFFF;
            if code == 17 {
                anyhow::Error::new(CrossDeviceMoveError)
            } else {
                anyhow::anyhow!(
                    "Failed atomic move from {:?} to {:?}: {}",
                    source,
                    destination,
                    error
                )
            }
        })
    }

    #[cfg(all(unix, not(windows)))]
    {
        match std::fs::hard_link(source, destination) {
            Ok(()) => std::fs::remove_file(source)
                .with_context(|| format!("Moved {:?} but failed to remove source {:?}", source, destination)),
            Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {
                Err(anyhow::Error::new(CrossDeviceMoveError))
            }
            Err(error) => Err(error)
                .with_context(|| format!("Failed atomic move from {:?} to {:?}", source, destination)),
        }
    }

    #[cfg(not(any(windows, unix)))]
    {
        if destination.exists() {
            anyhow::bail!("Destination {:?} already exists", destination);
        }
        std::fs::rename(source, destination)
            .with_context(|| format!("Failed atomic move from {:?} to {:?}", source, destination))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    len: u64,
    #[cfg(not(windows))]
    modified: Option<SystemTime>,
    #[cfg(not(windows))]
    created: Option<SystemTime>,
    #[cfg(windows)]
    creation_time: u64,
    #[cfg(windows)]
    last_write_time: u64,
    #[cfg(windows)]
    attributes: u32,
}

fn file_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        len: metadata.len(),
        #[cfg(not(windows))]
        modified: metadata.modified().ok(),
        #[cfg(not(windows))]
        created: metadata.created().ok(),
        #[cfg(windows)]
        creation_time: metadata.creation_time(),
        #[cfg(windows)]
        last_write_time: metadata.last_write_time(),
        #[cfg(windows)]
        attributes: metadata.file_attributes(),
    }
}

fn compute_file_hash_sync(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open {:?}", path))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; BUFFER_SIZE];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("Failed to read {:?}", path))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn verify_file(path: &Path, expected_hash: &str, expected_size: u64) -> Result<()> {
    ensure_not_reparse(path, "Verification target")?;
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Failed to read metadata for {:?}", path))?;
    if metadata.len() != expected_size {
        anyhow::bail!(
            "Size verification failed for {:?}: expected {}, found {}",
            path,
            expected_size,
            metadata.len()
        );
    }
    let actual_hash = compute_file_hash_sync(path)?;
    if actual_hash != expected_hash {
        anyhow::bail!(
            "SHA-256 verification failed for {:?}: expected {}, found {}",
            path,
            expected_hash,
            actual_hash
        );
    }
    Ok(())
}

fn revalidate_source(path: &Path, identity: &FileIdentity, expected_hash: &str) -> Result<()> {
    ensure_not_reparse(path, "Source")?;
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("Failed to revalidate source {:?}", path))?;
    if file_identity(&metadata) != *identity {
        anyhow::bail!("Source identity changed for {:?}; preserving all copies", path);
    }
    let actual_hash = compute_file_hash_sync(path)?;
    if actual_hash != expected_hash {
        anyhow::bail!("Source content changed for {:?}; preserving all copies", path);
    }
    Ok(())
}

#[cfg(windows)]
fn preserve_metadata(source_metadata: &std::fs::Metadata, destination: &Path) -> Result<()> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(destination)
        .with_context(|| format!("Failed to open {:?} for metadata preservation", destination))?;
    let handle = HANDLE(file.as_raw_handle() as isize);
    let creation = FILETIME {
        dwLowDateTime: source_metadata.creation_time() as u32,
        dwHighDateTime: (source_metadata.creation_time() >> 32) as u32,
    };
    let access = FILETIME {
        dwLowDateTime: source_metadata.last_access_time() as u32,
        dwHighDateTime: (source_metadata.last_access_time() >> 32) as u32,
    };
    let write = FILETIME {
        dwLowDateTime: source_metadata.last_write_time() as u32,
        dwHighDateTime: (source_metadata.last_write_time() >> 32) as u32,
    };
    unsafe {
        SetFileTime(handle, Some(&creation), Some(&access), Some(&write))
            .map_err(|error| anyhow::anyhow!("Failed to preserve timestamps for {:?}: {}", destination, error))?;
    }
    drop(file);
    let destination_wide = wide_path(destination);
    unsafe {
        SetFileAttributesW(
            PCWSTR(destination_wide.as_ptr()),
            FILE_FLAGS_AND_ATTRIBUTES(source_metadata.file_attributes()),
        )
        .map_err(|error| anyhow::anyhow!("Failed to preserve attributes for {:?}: {}", destination, error))?;
    }
    Ok(())
}

#[cfg(not(windows))]
fn preserve_metadata(source_metadata: &std::fs::Metadata, destination: &Path) -> Result<()> {
    std::fs::set_permissions(destination, source_metadata.permissions())
        .with_context(|| format!("Failed to preserve permissions for {:?}", destination))
}

fn copy_file_exclusive(source: &Path, destination: &Path) -> Result<()> {
    ensure_not_reparse(source, "Copy source")?;
    ensure_not_reparse(destination, "Staging destination")?;
    let source_metadata = std::fs::metadata(source)
        .with_context(|| format!("Failed to read metadata for {:?}", source))?;
    let mut source_file = std::fs::File::open(source)
        .with_context(|| format!("Failed to open {:?}", source))?;
    let mut destination_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .with_context(|| format!("Failed to create exclusive staging file {:?}", destination))?;

    let copy_result = (|| -> Result<()> {
        std::io::copy(&mut source_file, &mut destination_file)
            .with_context(|| format!("Failed to copy {:?} to {:?}", source, destination))?;
        destination_file
            .sync_all()
            .with_context(|| format!("Failed to sync staging file {:?}", destination))?;
        Ok(())
    })();

    if let Err(error) = copy_result {
        drop(destination_file);
        let _ = std::fs::remove_file(destination);
        return Err(error);
    }
    drop(destination_file);
    preserve_metadata(&source_metadata, destination)?;
    Ok(())
}

fn quarantine_staging_path_for(dir: &Path, key: &str) -> PathBuf {
    dir.join(format!("{}{}", key, QUARANTINE_STAGING_SUFFIX))
}

fn restore_staging_path_for(destination: &Path, key: &str) -> Result<PathBuf> {
    let parent = destination
        .parent()
        .context("Restore destination has no parent directory")?;
    Ok(parent.join(format!("{}{}", RESTORE_STAGING_PREFIX, key)))
}

enum RecoveryAction {
    Keep,
    RemoveEntry,
    MarkQuarantined,
    RollbackRestore,
}

fn recover_staged_quarantine(
    quarantine_dir: &Path,
    key: &str,
    record: &QuarantineRecordV2,
) -> Result<RecoveryAction> {
    let expected_hash = record
        .original_sha256
        .as_deref()
        .context("Staged quarantine record has no SHA-256")?;
    let expected_size = record
        .size_bytes
        .context("Staged quarantine record has no size")?;
    let source = &record.original_path;
    let destination = quarantine_dir.join(key);
    let staging = quarantine_staging_path_for(quarantine_dir, key);

    let source_exists = source.exists();
    let destination_exists = destination.exists();
    let staging_exists = staging.exists();

    if destination_exists {
        verify_file(&destination, expected_hash, expected_size)?;
        if source_exists {
            verify_file(source, expected_hash, expected_size)?;
            std::fs::remove_file(source)
                .with_context(|| format!("Failed to finalize quarantine by removing {:?}", source))?;
        }
        if staging_exists {
            std::fs::remove_file(&staging)
                .with_context(|| format!("Failed to remove redundant staging file {:?}", staging))?;
        }
        return Ok(RecoveryAction::MarkQuarantined);
    }

    if source_exists {
        if staging_exists {
            std::fs::remove_file(&staging)
                .with_context(|| format!("Failed to roll back staging file {:?}", staging))?;
        }
        return Ok(RecoveryAction::RemoveEntry);
    }

    if staging_exists {
        verify_file(&staging, expected_hash, expected_size)?;
        atomic_move_no_replace(&staging, &destination)?;
        verify_file(&destination, expected_hash, expected_size)?;
        return Ok(RecoveryAction::MarkQuarantined);
    }

    anyhow::bail!(
        "Unresolved quarantine transaction for {:?}: source, destination and staging are all missing",
        key
    )
}

fn recover_staged_restore(
    quarantine_dir: &Path,
    key: &str,
    record: &QuarantineRecordV2,
) -> Result<RecoveryAction> {
    let expected_hash = record
        .original_sha256
        .as_deref()
        .context("Restoring record has no SHA-256")?;
    let expected_size = record
        .size_bytes
        .context("Restoring record has no size")?;
    let source = quarantine_dir.join(key);
    let destination = &record.original_path;
    let staging = restore_staging_path_for(destination, key)?;

    let source_exists = source.exists();
    let destination_exists = destination.exists();
    let staging_exists = staging.exists();

    if destination_exists {
        verify_file(destination, expected_hash, expected_size)?;
        if source_exists {
            verify_file(&source, expected_hash, expected_size)?;
            std::fs::remove_file(&source)
                .with_context(|| format!("Failed to finalize restore by removing {:?}", source))?;
        }
        if staging_exists {
            std::fs::remove_file(&staging)
                .with_context(|| format!("Failed to remove redundant restore staging {:?}", staging))?;
        }
        return Ok(RecoveryAction::RemoveEntry);
    }

    if source_exists {
        if staging_exists {
            std::fs::remove_file(&staging)
                .with_context(|| format!("Failed to roll back restore staging {:?}", staging))?;
        }
        return Ok(RecoveryAction::RollbackRestore);
    }

    if staging_exists {
        verify_file(&staging, expected_hash, expected_size)?;
        atomic_move_no_replace(&staging, destination)?;
        verify_file(destination, expected_hash, expected_size)?;
        return Ok(RecoveryAction::RemoveEntry);
    }

    anyhow::bail!(
        "Unresolved restore transaction for {:?}: source, destination and staging are all missing",
        key
    )
}

fn recover_pending_transactions(
    quarantine_dir: &Path,
    manifest_path: &Path,
    manifest: &mut QuarantineManifestV2,
) -> Result<()> {
    let pending: Vec<(String, QuarantineRecordV2)> = manifest
        .entries
        .iter()
        .filter(|(_, record)| matches!(record.state, QuarantineState::Staged | QuarantineState::Restoring))
        .map(|(key, record)| (key.clone(), record.clone()))
        .collect();

    if pending.is_empty() {
        return Ok(());
    }

    let mut next = manifest.clone();
    let mut changed = false;
    let mut first_error: Option<anyhow::Error> = None;

    for (key, record) in pending {
        let result = match record.state {
            QuarantineState::Staged => recover_staged_quarantine(quarantine_dir, &key, &record),
            QuarantineState::Restoring => recover_staged_restore(quarantine_dir, &key, &record),
            _ => Ok(RecoveryAction::Keep),
        };

        match result {
            Ok(RecoveryAction::Keep) => {}
            Ok(RecoveryAction::RemoveEntry) => {
                next.entries.remove(&key);
                changed = true;
            }
            Ok(RecoveryAction::MarkQuarantined) => {
                if let Some(record) = next.entries.get_mut(&key) {
                    record.state = QuarantineState::Quarantined;
                    if record.quarantined_at_utc.is_none() {
                        record.quarantined_at_utc = Some(Utc::now());
                    }
                    changed = true;
                }
            }
            Ok(RecoveryAction::RollbackRestore) => {
                if let Some(record) = next.entries.get_mut(&key) {
                    record.state = QuarantineState::Quarantined;
                    changed = true;
                }
            }
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(error.context(format!("Failed recovery for {:?}", key)));
                }
            }
        }
    }

    if changed {
        next.save_atomic(manifest_path)?;
        *manifest = next;
    }

    if let Some(error) = first_error {
        return Err(error);
    }
    Ok(())
}

pub struct Cleaner {
    quarantine_dir: PathBuf,
    manifest_path: PathBuf,
    lock_path: PathBuf,
    manifest: Arc<Mutex<QuarantineManifestV2>>,
}

impl Cleaner {
    pub fn new() -> Result<Self> {
        let quarantine_dir = crate::modules::config::Settings::quarantine_dir()?;
        Self::new_with_dir(quarantine_dir)
    }

    pub fn new_with_dir(quarantine_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&quarantine_dir)
            .with_context(|| format!("Failed to create quarantine dir {:?}", quarantine_dir))?;
        ensure_not_reparse(&quarantine_dir, "Quarantine directory")?;

        let manifest_path = quarantine_dir.join("manifest.json");
        let lock_path = quarantine_dir.join(QUARANTINE_LOCK_FILE);
        let _lock = QuarantineProcessLock::acquire(&lock_path)?;
        let mut manifest = QuarantineManifestV2::load_or_recover(&manifest_path)?;
        recover_pending_transactions(&quarantine_dir, &manifest_path, &mut manifest)?;

        Ok(Self {
            quarantine_dir,
            manifest_path,
            lock_path,
            manifest: Arc::new(Mutex::new(manifest)),
        })
    }

    fn prepare_locked(&self) -> Result<(QuarantineProcessLock, MutexGuard<'_, QuarantineManifestV2>)> {
        let lock = QuarantineProcessLock::acquire(&self.lock_path)?;
        let mut guard = self.manifest.lock().unwrap();
        let mut manifest = QuarantineManifestV2::load_or_recover(&self.manifest_path)?;
        let recovery_result = recover_pending_transactions(&self.quarantine_dir, &self.manifest_path, &mut manifest);
        *guard = manifest;
        recovery_result?;
        Ok((lock, guard))
    }

    fn persist_manifest(
        &self,
        guard: &mut MutexGuard<'_, QuarantineManifestV2>,
        next: QuarantineManifestV2,
    ) -> Result<()> {
        next.save_atomic(&self.manifest_path)?;
        **guard = next;
        Ok(())
    }

    fn quarantine_staging_path(&self, key: &str) -> PathBuf {
        self.quarantine_dir.join(format!("{}{}", key, QUARANTINE_STAGING_SUFFIX))
    }

    pub fn default_temp_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        #[cfg(target_os = "windows")]
        {
            if let Some(temp) = std::env::var_os("TEMP") {
                paths.push(PathBuf::from(temp));
            }
            if let Some(local_app_data) = dirs::data_local_dir() {
                let temp_dir = local_app_data.join("Temp");
                if !paths.contains(&temp_dir) {
                    paths.push(temp_dir);
                }
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
                            let delete_result: Result<(), String> = if permanent_delete {
                                // Eliminación directa - sin papelera, instantáneo
                                tokio::task::spawn_blocking(move || {
                                    std::fs::remove_file(&path_clone).map_err(|e| e.to_string())
                                }).await.map_err(|e| e.to_string()).and_then(|r| r)
                            } else {
                                // A papelera (comportamiento original)
                                tokio::task::spawn_blocking(move || {
                                    trash::delete(&path_clone).map_err(|e| e.to_string())
                                }).await.map_err(|e| e.to_string()).and_then(|r| r)
                            };

                            match delete_result {
                                Ok(_) => {
                                    result.files_found += 1;
                                    moved_bytes += size;
                                    result.bytes_reclaimable = moved_bytes;
                                    progress_callback(result.files_found, moved_bytes);
                                    tracing::debug!("Deleted: {:?}", file_path);
                                }
                                Err(e) => {
                                    let error_msg = format!("{}: {}", file_path.display(), e);
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
                    let delete_result: Result<(), String> = if permanent_delete {
                        tokio::task::spawn_blocking(move || {
                            std::fs::remove_file(&path_clone).map_err(|e| e.to_string())
                        }).await.map_err(|e| e.to_string()).and_then(|r| r)
                    } else {
                        tokio::task::spawn_blocking(move || {
                            trash::delete(&path_clone).map_err(|e| e.to_string())
                        }).await.map_err(|e| e.to_string()).and_then(|r| r)
                    };

                    match delete_result {
                        Ok(_) => {
                            result.files_found += 1;
                            moved_bytes += size;
                            result.bytes_reclaimable = moved_bytes;
                            progress_callback(result.files_found, moved_bytes);
                        }
                        Err(e) => {
                            let error_msg = format!("{}: {}", file_path.display(), e);
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

            // Two-stage hashing optimization:
            // 1. If files are larger than 16 KB, compute a fast pre-hash of the first 16 KB.
            // 2. Only compute the full SHA-256 for files whose pre-hash matches.
            let candidate_paths = if size > PRE_HASH_SIZE as u64 {
                let mut by_pre_hash: HashMap<String, Vec<PathBuf>> = HashMap::new();
                for path in paths {
                    if token.is_cancelled() {
                        return Ok(Vec::new());
                    }
                    while pause_flag.load(Ordering::Relaxed) {
                        if token.is_cancelled() {
                            return Ok(Vec::new());
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }

                    match compute_file_pre_hash(&path).await {
                        Ok(pre_hash) => {
                            by_pre_hash.entry(pre_hash).or_default().push(path);
                        }
                        Err(e) => {
                            tracing::warn!("Failed to pre-hash {}: {}", path.display(), e);
                        }
                    }
                }

                let mut matching = Vec::new();
                for (_, pre_paths) in by_pre_hash {
                    if pre_paths.len() >= 2 {
                        matching.extend(pre_paths);
                    }
                }
                matching
            } else {
                paths
            };

            if candidate_paths.len() < 2 {
                continue;
            }

            let mut by_hash: HashMap<String, Vec<(PathBuf, Option<chrono::DateTime<Local>>)>> = HashMap::new();

            for path in candidate_paths {
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
                    Ok((key, size, quarantined_at)) => {
                        entries.push(QuarantineEntry {
                            id: None,
                            quarantined_at: Some(quarantined_at.with_timezone(&Local)),
                            original_path: file.path.clone(),
                            quarantine_path: self.quarantine_dir.join(key),
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
        let (_lock, manifest_guard) = self.prepare_locked()?;
        let manifest = manifest_guard.clone();
        let mut entries = Vec::new();

        for entry in WalkDir::new(&self.quarantine_dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            if let Some(name) = path.file_name() {
                let name_str = name.to_string_lossy();
                if name_str == "manifest.json"
                    || name_str.starts_with("manifest.")
                    || name_str == QUARANTINE_LOCK_FILE
                    || name_str.ends_with(QUARANTINE_STAGING_SUFFIX)
                {
                    continue;
                }
            }

            ensure_not_reparse(path, "Quarantined file")?;
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };

            let (original_path, quarantined_at) = if let Some(file_name) = path.file_name() {
                let key = file_name.to_string_lossy();
                if let Some(record) = manifest.entries.get(key.as_ref()) {
                    (
                        record.original_path.clone(),
                        record.quarantined_at_utc.map(|utc| utc.with_timezone(&Local)),
                    )
                } else {
                    (self.original_path_from_quarantine_fallback(path), None)
                }
            } else {
                (path.to_path_buf(), None)
            };

            entries.push(QuarantineEntry {
                id: None,
                quarantined_at,
                original_path,
                quarantine_path: path.to_path_buf(),
                size: meta.len(),
            });
        }

        entries.sort_by_key(|entry| std::cmp::Reverse(entry.quarantined_at));
        Ok(entries)
    }

    pub fn restore_from_quarantine(&self, entry: &QuarantineEntry) -> Result<()> {
        let key = entry
            .quarantine_path
            .file_name()
            .context("Quarantine entry has no file name")?
            .to_string_lossy()
            .to_string();
        QuarantineRecordV2::validate_key(&key)?;

        let (_lock, mut guard) = self.prepare_locked()?;
        let record = guard
            .entries
            .get(&key)
            .cloned()
            .context("Quarantine manifest record not found; refusing to infer restoration")?;
        if !matches!(record.state, QuarantineState::Quarantined) {
            anyhow::bail!("Quarantine entry {:?} is not in a restorable state", key);
        }

        let source = self.quarantine_dir.join(&key);
        ensure_not_reparse(&source, "Quarantine source")?;
        if !source.exists() {
            anyhow::bail!("Quarantine source {:?} is missing", source);
        }

        let destination = record.original_path.clone();
        QuarantineRecordV2::validate_original_path(&destination, &self.quarantine_dir)?;
        ensure_not_reparse(&destination, "Restore destination")?;
        if destination.exists() {
            anyhow::bail!(
                "Restore destination {:?} already exists; preserving both copies",
                destination
            );
        }
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to recreate original dir {:?}", parent))?;
            ensure_not_reparse(parent, "Restore destination parent")?;
        }

        let source_metadata = std::fs::metadata(&source)
            .with_context(|| format!("Failed to read quarantine metadata {:?}", source))?;
        let source_identity = file_identity(&source_metadata);
        let size = source_metadata.len();
        let hash = compute_file_hash_sync(&source)?;
        if let Some(expected_hash) = record.original_sha256.as_deref() {
            if expected_hash != hash {
                anyhow::bail!("Quarantine content changed for {:?}; preserving both copies", key);
            }
        }
        if let Some(expected_size) = record.size_bytes {
            if expected_size != size {
                anyhow::bail!("Quarantine size changed for {:?}; preserving both copies", key);
            }
        }

        let staging = restore_staging_path_for(&destination, &key)?;
        let mut next = guard.clone();
        if let Some(record) = next.entries.get_mut(&key) {
            record.state = QuarantineState::Restoring;
            record.original_sha256 = Some(hash.clone());
            record.size_bytes = Some(size);
        }
        fault_injection::check("restore_before_staged_save")?;
        self.persist_manifest(&mut guard, next)?;
        fault_injection::check("restore_after_staged_persist")?;

        let mut cross_volume = fault_injection::force_cross_volume();
        if !cross_volume {
            match atomic_move_no_replace(&source, &destination) {
                Ok(()) => {
                    fault_injection::check("restore_after_final_move")?;
                    verify_file(&destination, &hash, size)?;
                }
                Err(error) if error.downcast_ref::<CrossDeviceMoveError>().is_some() => {
                    cross_volume = true;
                }
                Err(error) => {
                    let mut rollback = guard.clone();
                    if let Some(record) = rollback.entries.get_mut(&key) {
                        record.state = QuarantineState::Quarantined;
                    }
                    self.persist_manifest(&mut guard, rollback)?;
                    return Err(error);
                }
            }
        }

        if cross_volume {
            copy_file_exclusive(&source, &staging)?;
            fault_injection::check("restore_after_stage_copy")?;
            verify_file(&staging, &hash, size)?;
            fault_injection::check("restore_after_stage_verify")?;
            if let Err(error) = atomic_move_no_replace(&staging, &destination) {
                if let Err(cleanup_error) = std::fs::remove_file(&staging) {
                    return Err(error.context(format!(
                        "Also failed to remove restore staging {:?}: {}",
                        staging, cleanup_error
                    )));
                }
                let mut rollback = guard.clone();
                if let Some(record) = rollback.entries.get_mut(&key) {
                    record.state = QuarantineState::Quarantined;
                }
                self.persist_manifest(&mut guard, rollback)?;
                return Err(error);
            }
            fault_injection::check("restore_after_final_move")?;
            verify_file(&destination, &hash, size)?;
            fault_injection::check("restore_before_source_delete")?;
            revalidate_source(&source, &source_identity, &hash)?;
            std::fs::remove_file(&source)
                .with_context(|| format!("Failed to finalize restore by removing {:?}", source))?;
            fault_injection::check("restore_after_source_delete")?;
        }

        fault_injection::check("restore_before_commit")?;
        let mut done = guard.clone();
        done.entries.remove(&key);
        self.persist_manifest(&mut guard, done)?;
        Ok(())
    }

    pub fn delete_quarantine_permanently(&self, entry: &QuarantineEntry) -> Result<()> {
        let key = entry
            .quarantine_path
            .file_name()
            .context("Quarantine entry has no file name")?
            .to_string_lossy()
            .to_string();
        QuarantineRecordV2::validate_key(&key)?;

        let (_lock, mut guard) = self.prepare_locked()?;
        let source = self.quarantine_dir.join(&key);
        ensure_not_reparse(&source, "Quarantine source")?;
        if !source.exists() {
            anyhow::bail!("Quarantine source {:?} is missing", source);
        }

        trash::delete(&source)
            .with_context(|| format!("Failed to move {:?} to trash", source))?;

        let mut next = guard.clone();
        next.entries.remove(&key);
        self.persist_manifest(&mut guard, next)?;
        Ok(())
    }

    /// Temporarily suspended by security audit (A11.09): Automatic deletion of
    /// quarantined files is disabled to prevent permanent, unintended data loss.
    ///
    /// Root cause: The legacy purge mechanism evaluated filesystem `mtime` (`metadata.modified()`),
    /// which reflects original file creation/modification timestamps rather than the actual
    /// quarantine ingestion timestamp. This caused any quarantined files with original modification
    /// dates older than the retention threshold (default: 7 days) to be permanently destroyed
    /// immediately upon SysPulse startup.
    ///
    /// Containment implementation:
    /// - Automatic deletion is completely suspended.
    /// - No physical files are removed (`std::fs::remove_file` is not invoked).
    /// - The manifest entries are preserved intact without modification.
    /// - No heuristic or estimated quarantine dates are fabricated for historical entries.
    /// - Compatibility with `settings.toml` (`quarantine_days`) is maintained.
    /// - Bloque 2B provides recoverable transactions and trusted `quarantined_at` metadata,
    ///   but automatic purge remains disabled until explicit authorization.
    pub fn purge_old_quarantine(&self, days: u32) -> Result<usize> {
        let _ = days;
        tracing::warn!(
            "Quarantine automatic purge is temporarily suspended due to security audit A11.09 (preventing automated data loss). Existing quarantine files and manifest are preserved intact."
        );
        Ok(0)
    }

    async fn quarantine_file(&self, source: &Path) -> Result<(String, u64, chrono::DateTime<Utc>)> {
        QuarantineRecordV2::validate_original_path(source, &self.quarantine_dir)?;
        let (_lock, mut guard) = self.prepare_locked()?;

        let metadata = std::fs::metadata(source)
            .with_context(|| format!("Failed to read metadata for {:?}", source))?;
        let identity = file_identity(&metadata);
        let size = metadata.len();
        let hash = compute_file_hash_sync(source)?;

        let path_hash = {
            let mut hasher = Sha256::new();
            hasher.update(source.to_string_lossy().as_bytes());
            let result = hasher.finalize();
            format!("{:x}", result)[..16].to_string()
        };
        let extension = source.extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();
        let key = format!("{}_{}{}", path_hash, std::process::id(), extension);
        QuarantineRecordV2::validate_key(&key)?;

        let destination = self.quarantine_dir.join(&key);
        let staging = self.quarantine_staging_path(&key);

        if guard.entries.contains_key(&key) || destination.exists() || staging.exists() {
            anyhow::bail!("Quarantine key {:?} already exists; refusing to overwrite", key);
        }

        let mut next = guard.clone();
        next.entries.insert(
            key.clone(),
            QuarantineRecordV2 {
                original_path: source.to_path_buf(),
                quarantined_at_utc: None,
                original_sha256: Some(hash.clone()),
                size_bytes: Some(size),
                state: QuarantineState::Staged,
            },
        );
        fault_injection::check("quarantine_before_staged_save")?;
        self.persist_manifest(&mut guard, next)?;
        fault_injection::check("quarantine_after_staged_persist")?;

        let mut cross_volume = fault_injection::force_cross_volume();
        if !cross_volume {
            match atomic_move_no_replace(source, &destination) {
                Ok(()) => {
                    fault_injection::check("quarantine_after_final_move")?;
                    verify_file(&destination, &hash, size)?;
                }
                Err(error) if error.downcast_ref::<CrossDeviceMoveError>().is_some() => {
                    cross_volume = true;
                }
                Err(error) => {
                    let mut rollback = guard.clone();
                    rollback.entries.remove(&key);
                    self.persist_manifest(&mut guard, rollback)?;
                    return Err(error);
                }
            }
        }

        if cross_volume {
            copy_file_exclusive(source, &staging)?;
            fault_injection::check("quarantine_after_stage_copy")?;
            verify_file(&staging, &hash, size)?;
            fault_injection::check("quarantine_after_stage_verify")?;
            atomic_move_no_replace(&staging, &destination)?;
            fault_injection::check("quarantine_after_final_move")?;
            verify_file(&destination, &hash, size)?;
            fault_injection::check("quarantine_before_source_delete")?;
            revalidate_source(source, &identity, &hash)?;
            std::fs::remove_file(source)
                .with_context(|| format!("Failed to finalize quarantine by removing {:?}", source))?;
            fault_injection::check("quarantine_after_source_delete")?;
        }

        fault_injection::check("quarantine_before_commit")?;
        let quarantined_at = Utc::now();
        let mut done = guard.clone();
        if let Some(record) = done.entries.get_mut(&key) {
            record.state = QuarantineState::Quarantined;
            record.quarantined_at_utc = Some(quarantined_at);
            record.original_sha256 = Some(hash);
            record.size_bytes = Some(size);
        }
        self.persist_manifest(&mut guard, done)?;
        Ok((key, size, quarantined_at))
    }

    #[allow(dead_code)]
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

    fn original_path_from_quarantine_fallback(&self, quarantine_path: &Path) -> PathBuf {
        if let Some(file_name) = quarantine_path.file_stem() {
            let name = file_name.to_string_lossy();
            if let Some(base) = name.split("_0_").next() {
                return PathBuf::from(base.replace('_', std::path::MAIN_SEPARATOR.to_string().as_str()));
            }
        }
        quarantine_path.to_path_buf()
    }
}

pub fn format_quarantined_date(date: Option<chrono::DateTime<chrono::Local>>) -> String {
    date.map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "-".to_string())
}

async fn compute_file_pre_hash(path: &Path) -> Result<String> {
    let path = path.to_path_buf();

    tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut file = std::fs::File::open(&path)
            .with_context(|| format!("Failed to open {:?}", path))?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; PRE_HASH_SIZE];

        let n = file
            .read(&mut buffer)
            .with_context(|| format!("Failed to read pre-hash for {:?}", path))?;
        hasher.update(&buffer[..n]);

        Ok::<String, anyhow::Error>(format!("{:x}", hasher.finalize()))
    })
    .await
    .context("Failed to spawn pre-hash task")?
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

#[cfg(test)]
mod tests {
    use super::*;

    struct TestQuarantineDir {
        path: PathBuf,
    }

    impl TestQuarantineDir {
        fn new(prefix: &str) -> Self {
            let unique_id = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "syspulse_cleaner_test_{}_{}_{}",
                prefix,
                std::process::id(),
                unique_id
            ));
            std::fs::create_dir_all(&path).expect("Failed to create isolated test dir");
            Self { path }
        }
    }

    impl Drop for TestQuarantineDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    struct TestWorkspace {
        root: PathBuf,
        quarantine: PathBuf,
        source: PathBuf,
    }

    impl TestWorkspace {
        fn new(prefix: &str) -> Self {
            let unique_id = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "syspulse_transaction_test_{}_{}_{}",
                prefix,
                std::process::id(),
                unique_id
            ));
            let quarantine = root.join("quarantine");
            let source = root.join("source");
            std::fs::create_dir_all(&quarantine).unwrap();
            std::fs::create_dir_all(&source).unwrap();
            Self { root, quarantine, source }
        }

        fn source_file(&self, name: &str, content: &[u8]) -> PathBuf {
            let path = self.source.join(name);
            std::fs::write(&path, content).unwrap();
            path
        }

        fn cleaner(&self) -> Cleaner {
            Cleaner::new_with_dir(self.quarantine.clone()).unwrap()
        }
    }

    impl Drop for TestWorkspace {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn test_a11_09_quarantine_old_files_not_purged() {
        let test_dir = TestQuarantineDir::new("containment_old_files");
        let file1 = test_dir.path.join("file1_test.dat");
        let file2 = test_dir.path.join("file2_test.dat");
        std::fs::write(&file1, b"quarantined payload 1").unwrap();
        std::fs::write(&file2, b"quarantined payload 2").unwrap();

        let manifest_file = test_dir.path.join("manifest.json");
        let mut initial_manifest = QuarantineManifestV2::new();
        initial_manifest.entries.insert(
            "file1_test.dat".to_string(),
            QuarantineRecordV2 {
                original_path: PathBuf::from("C:\\original\\file1.dat"),
                quarantined_at_utc: None,
                original_sha256: None,
                size_bytes: Some(21),
                state: QuarantineState::Quarantined,
            },
        );
        initial_manifest.entries.insert(
            "file2_test.dat".to_string(),
            QuarantineRecordV2 {
                original_path: PathBuf::from("C:\\original\\file2.dat"),
                quarantined_at_utc: None,
                original_sha256: None,
                size_bytes: Some(21),
                state: QuarantineState::Quarantined,
            },
        );
        initial_manifest
            .save_atomic(&manifest_file)
            .expect("Failed to save initial manifest");

        let cleaner = Cleaner::new_with_dir(test_dir.path.clone()).expect("Failed to reload cleaner");

        let purged = cleaner
            .purge_old_quarantine(1)
            .expect("Purge should succeed safely");
        assert_eq!(purged, 0, "Suspended purge must report 0 files deleted");

        assert!(file1.exists(), "file1_test.dat must not be deleted");
        assert!(file2.exists(), "file2_test.dat must not be deleted");

        let loaded_manifest = QuarantineManifestV2::load_or_recover(&manifest_file).unwrap();
        assert_eq!(
            loaded_manifest.entries.len(),
            2,
            "Manifest entries must remain intact"
        );
        assert!(loaded_manifest.entries.contains_key("file1_test.dat"));
        assert!(loaded_manifest.entries.contains_key("file2_test.dat"));
    }

    #[test]
    fn test_a11_09_historical_records_without_quarantine_date_remain_intact() {
        let test_dir = TestQuarantineDir::new("historical_records");

        let manifest_file = test_dir.path.join("manifest.json");
        let manifest_content = r#"{
  "entries": {
    "legacy_doc_1234.docx": "D:\\docs\\report.docx",
    "legacy_img_5678.png": "D:\\images\\photo.png"
  }
}"#;
        std::fs::write(&manifest_file, manifest_content).expect("Failed to write legacy manifest");

        let doc_path = test_dir.path.join("legacy_doc_1234.docx");
        let img_path = test_dir.path.join("legacy_img_5678.png");
        std::fs::write(&doc_path, b"historical doc content").unwrap();
        std::fs::write(&img_path, b"historical img content").unwrap();

        let cleaner = Cleaner::new_with_dir(test_dir.path.clone()).expect("Failed to create cleaner");

        let result = cleaner
            .purge_old_quarantine(7)
            .expect("Purge must succeed without error");
        assert_eq!(result, 0);

        assert!(doc_path.exists(), "Historical doc must exist");
        assert!(img_path.exists(), "Historical img must exist");

        let reloaded = QuarantineManifestV2::load_or_recover(&manifest_file).unwrap();
        assert_eq!(reloaded.entries.len(), 2);
        assert_eq!(
            reloaded.entries.get("legacy_doc_1234.docx").unwrap().original_path,
            PathBuf::from("D:\\docs\\report.docx")
        );
        assert_eq!(
            reloaded.entries.get("legacy_doc_1234.docx").unwrap().quarantined_at_utc,
            None
        );
    }

    #[test]
    fn test_a11_09_manifest_unaltered_during_maintenance_flow() {
        let test_dir = TestQuarantineDir::new("manifest_unaltered");
        let manifest_file = test_dir.path.join("manifest.json");

        let raw_json = r#"{
  "version": 2,
  "entries": {
    "sample_a.tmp": {
      "original_path": "C:\\temp\\sample_a.tmp",
      "state": "Quarantined"
    },
    "sample_b.tmp": {
      "original_path": "C:\\temp\\sample_b.tmp",
      "state": "Quarantined"
    }
  }
}"#;
        std::fs::write(&manifest_file, raw_json).unwrap();
        std::fs::write(test_dir.path.join("sample_a.tmp"), b"aaa").unwrap();
        std::fs::write(test_dir.path.join("sample_b.tmp"), b"bbb").unwrap();

        let cleaner = Cleaner::new_with_dir(test_dir.path.clone()).unwrap();

        let count = cleaner.purge_old_quarantine(30).unwrap();
        assert_eq!(count, 0);

        let current_manifest = QuarantineManifestV2::load_or_recover(&manifest_file).unwrap();
        assert_eq!(current_manifest.entries.len(), 2);
        assert!(current_manifest.entries.contains_key("sample_a.tmp"));
        assert!(current_manifest.entries.contains_key("sample_b.tmp"));
    }

    #[test]
    fn test_a11_09_no_alternative_insecure_auto_purge_paths() {
        let test_dir = TestQuarantineDir::new("no_alt_paths");
        let cleaner = Cleaner::new_with_dir(test_dir.path.clone()).unwrap();

        let sample_file = test_dir.path.join("guarded.bin");
        std::fs::write(&sample_file, b"secure data").unwrap();

        for days in [0, 1, 7, 30, 90] {
            let res = cleaner.purge_old_quarantine(days).unwrap();
            assert_eq!(res, 0, "No day parameter should trigger deletion in contained state");
            assert!(sample_file.exists(), "File must survive for days = {}", days);
        }

        assert!(
            cleaner.list_quarantine().is_err(),
            "An unmanifested quarantine file must fail closed"
        );
        assert!(sample_file.exists());
    }

    #[test]
    fn test_b2a_migration_v1_to_v2_with_backup() {
        let test_dir = TestQuarantineDir::new("migration_v1_v2");
        let manifest_file = test_dir.path.join("manifest.json");

        let v1_content = r#"{
  "entries": {
    "archived_doc.pdf": "C:\\Users\\User\\Documents\\archived_doc.pdf",
    "photo.jpg": "D:\\Photos\\photo.jpg"
  }
}"#;
        std::fs::write(&manifest_file, v1_content).unwrap();

        // Load & migrate
        let manifest_v2 = QuarantineManifestV2::load_or_recover(&manifest_file)
            .expect("Migration from v1 to v2 must succeed");

        assert_eq!(manifest_v2.version, 2);
        assert_eq!(manifest_v2.entries.len(), 2);

        let doc_record = manifest_v2.entries.get("archived_doc.pdf").unwrap();
        assert_eq!(doc_record.original_path, PathBuf::from("C:\\Users\\User\\Documents\\archived_doc.pdf"));
        assert_eq!(doc_record.quarantined_at_utc, None, "Must not fabricate quarantine date");
        assert_eq!(doc_record.original_sha256, None, "Must not fabricate sha256");
        assert_eq!(doc_record.size_bytes, None, "Must not fabricate size");
        assert_eq!(doc_record.state, QuarantineState::Quarantined);

        // Verify non-destructive backup
        let backup_file = test_dir.path.join("manifest.v1.bak");
        assert!(backup_file.exists(), "manifest.v1.bak must be preserved");
        let backup_content = std::fs::read_to_string(&backup_file).unwrap();
        assert_eq!(backup_content, v1_content, "Backup content must match original exactly");

        // Verify manifest.json on disk is valid v2
        let on_disk = std::fs::read_to_string(&manifest_file).unwrap();
        assert!(on_disk.contains("\"version\": 2"));
    }

    #[test]
    fn test_b2a_corruption_blocks_destructive_operations_never_empty() {
        let test_dir = TestQuarantineDir::new("corruption_blocks");
        let manifest_file = test_dir.path.join("manifest.json");

        let corrupt_payload = "{\"entries\": {\"broken\": ";
        std::fs::write(&manifest_file, corrupt_payload).unwrap();

        // load_or_recover must fail with error, never return empty manifest
        let result = QuarantineManifestV2::load_or_recover(&manifest_file);
        assert!(result.is_err(), "Corrupt manifest must return Err");

        // Cleaner initialization must fail
        let cleaner_res = Cleaner::new_with_dir(test_dir.path.clone());
        assert!(cleaner_res.is_err(), "Cleaner init must fail on corrupt manifest");

        // Verify disk content was not wiped or replaced with empty json
        let content_after = std::fs::read_to_string(&manifest_file).unwrap();
        assert_eq!(content_after, corrupt_payload, "Corrupted file must remain untouched to prevent data loss");
    }

    #[test]
    fn test_b2a_orphan_temp_ambiguity_handling() {
        let test_dir = TestQuarantineDir::new("orphan_temp");
        // manifest.json does NOT exist, but orphan temp exists
        let orphan_temp = test_dir.path.join("manifest.json.tmp.9999.123456");
        std::fs::write(&orphan_temp, b"interrupted temp payload").unwrap();

        let manifest_file = test_dir.path.join("manifest.json");
        let res = QuarantineManifestV2::load_or_recover(&manifest_file);
        assert!(res.is_err(), "Ambiguity with orphan temp must return Err instead of initializing empty");
    }

    #[test]
    fn test_b2a_atomic_write_sync_and_exclusive_temp() {
        let test_dir = TestQuarantineDir::new("atomic_write");
        let manifest_file = test_dir.path.join("manifest.json");

        let mut manifest = QuarantineManifestV2::new();
        manifest.entries.insert(
            "test_key.dat".to_string(),
            QuarantineRecordV2 {
                original_path: PathBuf::from("C:\\safe\\file.dat"),
                quarantined_at_utc: Some(chrono::Utc::now()),
                original_sha256: Some("abcdef1234567890".to_string()),
                size_bytes: Some(1024),
                state: QuarantineState::Quarantined,
            },
        );

        manifest.save_atomic(&manifest_file).expect("Atomic save must succeed");
        assert!(manifest_file.exists());

        // Verify no leftover .tmp files
        let orphan_temps = QuarantineManifestV2::find_orphan_temps(&test_dir.path);
        assert!(orphan_temps.is_empty(), "No temporary files should be left behind");

        // Verify content reloaded matches
        let reloaded = QuarantineManifestV2::load_or_recover(&manifest_file).unwrap();
        assert_eq!(reloaded.entries.len(), 1);
        assert_eq!(reloaded.entries.get("test_key.dat").unwrap().size_bytes, Some(1024));
    }

    #[test]
    fn test_b2a_key_and_path_validation() {
        let test_dir = TestQuarantineDir::new("key_validation");

        // Key validation tests
        assert!(QuarantineRecordV2::validate_key("").is_err(), "Empty key must fail");
        assert!(QuarantineRecordV2::validate_key("../escape").is_err(), "Path traversal must fail");
        assert!(QuarantineRecordV2::validate_key("sub/folder").is_err(), "Slash must fail");
        assert!(QuarantineRecordV2::validate_key("sub\\folder").is_err(), "Backslash must fail");
        assert!(QuarantineRecordV2::validate_key("manifest.json").is_err(), "manifest.json must fail");
        assert!(QuarantineRecordV2::validate_key("manifest.v1.bak").is_err(), "manifest.v1.bak must fail");
        assert!(QuarantineRecordV2::validate_key("valid_hash_1234.bin").is_ok(), "Valid filename must pass");

        // Original path validation tests
        assert!(QuarantineRecordV2::validate_original_path(Path::new(""), &test_dir.path).is_err(), "Empty original path must fail");
        let inside_path = test_dir.path.join("nested.dat");
        assert!(QuarantineRecordV2::validate_original_path(&inside_path, &test_dir.path).is_err(), "Path inside quarantine dir must fail");
        assert!(QuarantineRecordV2::validate_original_path(Path::new("relative\\file.txt"), &test_dir.path).is_err(), "Relative original path must fail");
        assert!(QuarantineRecordV2::validate_original_path(Path::new("C:\\external\\..\\file.txt"), &test_dir.path).is_err(), "Parent traversal must fail");
        assert!(QuarantineRecordV2::validate_original_path(Path::new("C:\\external\\file.txt"), &test_dir.path).is_ok(), "External path must pass");
    }

    #[test]
    fn test_b2a_concurrent_manifest_writes() {
        let test_dir = TestQuarantineDir::new("concurrent_writes");
        let manifest_file = test_dir.path.join("manifest.json");

        let initial = QuarantineManifestV2::new();
        initial.save_atomic(&manifest_file).unwrap();

        let shared_manifest = Arc::new(Mutex::new(initial));
        let manifest_path = manifest_file.clone();

        let mut handles = Vec::new();
        for i in 0..10 {
            let manifest_clone = shared_manifest.clone();
            let path_clone = manifest_path.clone();
            handles.push(std::thread::spawn(move || {
                let key = format!("concurrent_file_{}.bin", i);
                let record = QuarantineRecordV2 {
                    original_path: PathBuf::from(format!("C:\\orig\\concurrent_{}.bin", i)),
                    quarantined_at_utc: Some(chrono::Utc::now()),
                    original_sha256: None,
                    size_bytes: Some(100 + i as u64),
                    state: QuarantineState::Quarantined,
                };
                let mut guard = manifest_clone.lock().unwrap();
                guard.entries.insert(key, record);
                guard.save_atomic(&path_clone).expect("Concurrent atomic save must succeed");
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let reloaded = QuarantineManifestV2::load_or_recover(&manifest_file).unwrap();
        assert_eq!(reloaded.entries.len(), 10, "All 10 concurrent writes must be safely preserved");
    }

    fn payload_files(workspace: &TestWorkspace) -> Vec<PathBuf> {
        std::fs::read_dir(&workspace.quarantine)
            .unwrap()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                let name = path.file_name().unwrap().to_string_lossy();
                name != "manifest.json"
                    && name != QUARANTINE_LOCK_FILE
                    && !name.starts_with("manifest.")
                    && !name.ends_with(QUARANTINE_STAGING_SUFFIX)
            })
            .collect()
    }

    fn entry_for(workspace: &TestWorkspace, original_path: &Path) -> QuarantineEntry {
        let quarantine_path = payload_files(workspace).into_iter().next().unwrap();
        let size = std::fs::metadata(&quarantine_path).unwrap().len();
        QuarantineEntry {
            id: None,
            quarantined_at: None,
            original_path: original_path.to_path_buf(),
            quarantine_path,
            size,
        }
    }

    #[test]
    fn test_b2a_missing_manifest_with_existing_files_fails_closed() {
        let workspace = TestWorkspace::new("missing_manifest");
        let stray = workspace.quarantine.join("orphan.bin");
        std::fs::write(&stray, b"orphan payload").unwrap();

        let manifest_path = workspace.quarantine.join("manifest.json");
        assert!(QuarantineManifestV2::load_or_recover(&manifest_path).is_err());
        assert!(Cleaner::new_with_dir(workspace.quarantine.clone()).is_err());
        assert!(stray.exists());
        assert!(workspace.quarantine.join(QUARANTINE_LOCK_FILE).exists());
    }

    #[test]
    fn test_b2a_unknown_schema_version_fails_closed() {
        let workspace = TestWorkspace::new("unknown_schema");
        let manifest_path = workspace.quarantine.join("manifest.json");
        let content = r#"{"version":99,"entries":{}}"#;
        std::fs::write(&manifest_path, content).unwrap();

        assert!(QuarantineManifestV2::load_or_recover(&manifest_path).is_err());
        assert_eq!(std::fs::read_to_string(&manifest_path).unwrap(), content);
    }

    #[test]
    fn test_b2a_reserved_windows_names_rejected() {
        for name in ["CON", "con.txt", "PRN.log", "AUX", "NUL", "COM1.bin", "LPT9.tar.gz", "name.", "name "] {
            assert!(QuarantineRecordV2::validate_key(name).is_err(), "{:?} must be rejected", name);
        }
        assert!(QuarantineRecordV2::validate_key("valid_hash_1234.bin").is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn test_b2a_reparse_source_rejected_when_symlink_available() {
        let workspace = TestWorkspace::new("reparse_source");
        let target = workspace.source_file("target.bin", b"target");
        let link = workspace.source.join("link.bin");
        if std::os::windows::fs::symlink_file(&target, &link).is_err() {
            return;
        }
        assert!(ensure_not_reparse(&link, "Source").is_err());
        assert!(QuarantineRecordV2::validate_original_path(&link, &workspace.quarantine).is_err());
    }

    #[tokio::test]
    async fn test_b2a_failed_staged_save_leaves_source_and_memory_unchanged() {
        fault_injection::reset();
        let workspace = TestWorkspace::new("staged_save_failure");
        let source = workspace.source_file("doc.bin", b"payload");
        let cleaner = workspace.cleaner();

        fault_injection::set_point("quarantine_before_staged_save");
        assert!(cleaner.quarantine_file(&source).await.is_err());
        assert!(source.exists());
        assert!(cleaner.manifest.lock().unwrap().entries.is_empty());
    }

    #[tokio::test]
    async fn test_b2b_quarantine_after_staged_persist_recovers_to_source() {
        fault_injection::reset();
        let workspace = TestWorkspace::new("quarantine_staged_recovery");
        let source = workspace.source_file("doc.bin", b"payload");
        let cleaner = workspace.cleaner();

        fault_injection::set_point("quarantine_after_staged_persist");
        assert!(cleaner.quarantine_file(&source).await.is_err());
        assert!(source.exists());

        let recovered = workspace.cleaner();
        assert!(recovered.list_quarantine().unwrap().is_empty());
        assert!(source.exists());
    }

    #[tokio::test]
    async fn test_b2b_quarantine_after_final_move_recovers_to_quarantined() {
        fault_injection::reset();
        let workspace = TestWorkspace::new("quarantine_final_move_recovery");
        let source = workspace.source_file("doc.bin", b"payload");
        let cleaner = workspace.cleaner();

        fault_injection::set_point("quarantine_after_final_move");
        assert!(cleaner.quarantine_file(&source).await.is_err());
        assert!(!source.exists());

        let recovered = workspace.cleaner();
        let entries = recovered.list_quarantine().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(std::fs::read(&entries[0].quarantine_path).unwrap(), b"payload");
        assert!(entries[0].quarantined_at.is_some());
    }

    #[tokio::test]
    async fn test_b2b_quarantine_cross_volume_stage_copy_failure_rolls_back() {
        fault_injection::reset();
        fault_injection::set_force_cross_volume(true);
        let workspace = TestWorkspace::new("quarantine_stage_copy");
        let source = workspace.source_file("doc.bin", b"payload");
        let cleaner = workspace.cleaner();

        fault_injection::set_point("quarantine_after_stage_copy");
        assert!(cleaner.quarantine_file(&source).await.is_err());
        assert!(source.exists());
        assert!(std::fs::read_dir(&workspace.quarantine).unwrap().flatten().any(|entry| {
            entry.file_name().to_string_lossy().ends_with(QUARANTINE_STAGING_SUFFIX)
        }));

        let recovered = workspace.cleaner();
        assert!(recovered.list_quarantine().unwrap().is_empty());
        assert!(source.exists());
        assert!(!std::fs::read_dir(&workspace.quarantine).unwrap().flatten().any(|entry| {
            entry.file_name().to_string_lossy().ends_with(QUARANTINE_STAGING_SUFFIX)
        }));
    }

    #[tokio::test]
    async fn test_b2b_quarantine_cross_volume_before_source_delete_finalizes_both_copies() {
        fault_injection::reset();
        fault_injection::set_force_cross_volume(true);
        let workspace = TestWorkspace::new("quarantine_before_delete");
        let source = workspace.source_file("doc.bin", b"payload");
        let cleaner = workspace.cleaner();

        fault_injection::set_point("quarantine_before_source_delete");
        assert!(cleaner.quarantine_file(&source).await.is_err());
        assert!(source.exists());
        assert_eq!(payload_files(&workspace).len(), 1);

        let recovered = workspace.cleaner();
        let entries = recovered.list_quarantine().unwrap();
        assert_eq!(entries.len(), 1);
        assert!(!source.exists());
        assert_eq!(std::fs::read(&entries[0].quarantine_path).unwrap(), b"payload");
    }

    #[tokio::test]
    async fn test_b2b_quarantine_uncertain_source_change_preserves_both_copies() {
        fault_injection::reset();
        fault_injection::set_force_cross_volume(true);
        let workspace = TestWorkspace::new("quarantine_uncertain");
        let source = workspace.source_file("doc.bin", b"payload");
        let cleaner = workspace.cleaner();

        fault_injection::set_point("quarantine_before_source_delete");
        assert!(cleaner.quarantine_file(&source).await.is_err());
        std::fs::write(&source, b"changed after staging").unwrap();

        assert!(Cleaner::new_with_dir(workspace.quarantine.clone()).is_err());
        assert!(source.exists());
        assert_eq!(std::fs::read(&source).unwrap(), b"changed after staging");
        assert_eq!(payload_files(&workspace).len(), 1);
    }

    #[tokio::test]
    async fn test_b2b_quarantine_before_commit_recovers_to_quarantined() {
        fault_injection::reset();
        let workspace = TestWorkspace::new("quarantine_before_commit");
        let source = workspace.source_file("doc.bin", b"payload");
        let cleaner = workspace.cleaner();

        fault_injection::set_point("quarantine_before_commit");
        assert!(cleaner.quarantine_file(&source).await.is_err());
        assert!(!source.exists());

        let recovered = workspace.cleaner();
        assert_eq!(recovered.list_quarantine().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_b2b_restore_before_staged_save_leaves_quarantine_intact() {
        fault_injection::reset();
        let workspace = TestWorkspace::new("restore_staged_save");
        let source = workspace.source_file("doc.bin", b"payload");
        let cleaner = workspace.cleaner();
        cleaner.quarantine_file(&source).await.unwrap();
        let entry = entry_for(&workspace, &source);

        fault_injection::set_point("restore_before_staged_save");
        assert!(cleaner.restore_from_quarantine(&entry).is_err());
        assert!(!source.exists());
        assert!(entry.quarantine_path.exists());

        let recovered = workspace.cleaner();
        assert_eq!(recovered.list_quarantine().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_b2b_restore_after_staged_persist_rolls_back() {
        fault_injection::reset();
        let workspace = TestWorkspace::new("restore_staged_persist");
        let source = workspace.source_file("doc.bin", b"payload");
        let cleaner = workspace.cleaner();
        cleaner.quarantine_file(&source).await.unwrap();
        let entry = entry_for(&workspace, &source);

        fault_injection::set_point("restore_after_staged_persist");
        assert!(cleaner.restore_from_quarantine(&entry).is_err());
        assert!(!source.exists());
        assert!(entry.quarantine_path.exists());

        let recovered = workspace.cleaner();
        assert_eq!(recovered.list_quarantine().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_b2b_restore_after_final_move_recovers_destination() {
        fault_injection::reset();
        let workspace = TestWorkspace::new("restore_final_move");
        let source = workspace.source_file("doc.bin", b"payload");
        let cleaner = workspace.cleaner();
        cleaner.quarantine_file(&source).await.unwrap();
        let entry = entry_for(&workspace, &source);

        fault_injection::set_point("restore_after_final_move");
        assert!(cleaner.restore_from_quarantine(&entry).is_err());
        assert!(source.exists());
        assert!(!entry.quarantine_path.exists());

        let recovered = workspace.cleaner();
        assert!(recovered.list_quarantine().unwrap().is_empty());
        assert_eq!(std::fs::read(&source).unwrap(), b"payload");
    }

    #[tokio::test]
    async fn test_b2b_restore_cross_volume_stage_copy_failure_rolls_back() {
        fault_injection::reset();
        fault_injection::set_force_cross_volume(true);
        let workspace = TestWorkspace::new("restore_stage_copy");
        let source = workspace.source_file("doc.bin", b"payload");
        let cleaner = workspace.cleaner();
        cleaner.quarantine_file(&source).await.unwrap();
        let entry = entry_for(&workspace, &source);

        fault_injection::set_point("restore_after_stage_copy");
        assert!(cleaner.restore_from_quarantine(&entry).is_err());
        assert!(!source.exists());
        assert!(entry.quarantine_path.exists());
        assert!(workspace.source.read_dir().unwrap().flatten().any(|item| {
            item.file_name().to_string_lossy().starts_with(RESTORE_STAGING_PREFIX)
        }));

        let recovered = workspace.cleaner();
        assert_eq!(recovered.list_quarantine().unwrap().len(), 1);
        assert!(entry.quarantine_path.exists());
    }

    #[tokio::test]
    async fn test_b2b_restore_cross_volume_before_source_delete_finalizes() {
        fault_injection::reset();
        fault_injection::set_force_cross_volume(true);
        let workspace = TestWorkspace::new("restore_before_delete");
        let source = workspace.source_file("doc.bin", b"payload");
        let cleaner = workspace.cleaner();
        cleaner.quarantine_file(&source).await.unwrap();
        let entry = entry_for(&workspace, &source);

        fault_injection::set_point("restore_before_source_delete");
        assert!(cleaner.restore_from_quarantine(&entry).is_err());
        assert!(source.exists());
        assert!(entry.quarantine_path.exists());

        let recovered = workspace.cleaner();
        assert!(recovered.list_quarantine().unwrap().is_empty());
        assert_eq!(std::fs::read(&source).unwrap(), b"payload");
        assert!(!entry.quarantine_path.exists());
    }

    #[tokio::test]
    async fn test_b2b_restore_before_commit_recovers_destination() {
        fault_injection::reset();
        let workspace = TestWorkspace::new("restore_before_commit");
        let source = workspace.source_file("doc.bin", b"payload");
        let cleaner = workspace.cleaner();
        cleaner.quarantine_file(&source).await.unwrap();
        let entry = entry_for(&workspace, &source);

        fault_injection::set_point("restore_before_commit");
        assert!(cleaner.restore_from_quarantine(&entry).is_err());
        assert!(source.exists());
        assert!(!entry.quarantine_path.exists());

        let recovered = workspace.cleaner();
        assert!(recovered.list_quarantine().unwrap().is_empty());
        assert_eq!(std::fs::read(&source).unwrap(), b"payload");
    }

    #[tokio::test]
    async fn test_b2b_restore_never_overwrites_existing_destination() {
        fault_injection::reset();
        let workspace = TestWorkspace::new("restore_no_overwrite");
        let source = workspace.source_file("doc.bin", b"payload");
        let cleaner = workspace.cleaner();
        cleaner.quarantine_file(&source).await.unwrap();
        let entry = entry_for(&workspace, &source);
        std::fs::write(&source, b"existing destination").unwrap();

        assert!(cleaner.restore_from_quarantine(&entry).is_err());
        assert_eq!(std::fs::read(&source).unwrap(), b"existing destination");
        assert!(entry.quarantine_path.exists());
        assert_eq!(cleaner.list_quarantine().unwrap().len(), 1);
    }
}
