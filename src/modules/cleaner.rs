use crate::models::{CleanerResult, DuplicateFile, DuplicateGroup, QuarantineEntry};
use anyhow::{Context, Result};
use chrono::{Local, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use tokio_util::sync::CancellationToken;
use walkdir::WalkDir;

#[cfg(windows)]
use std::os::windows::fs::MetadataExt as WindowsMetadataExt;
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::Foundation::{
    BOOLEAN, FILETIME, GENERIC_READ, GENERIC_WRITE, HANDLE, ERROR_HANDLE_EOF,
};
#[cfg(windows)]
use windows::Win32::Security::{
    GetFileSecurityW, SetFileSecurityW, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
    OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FileBasicInfo, FileDispositionInfoEx, FileRenameInfo, FindClose,
    FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard, GetFileInformationByHandle,
    LockFileEx, SetFileInformationByHandle, UnlockFileEx, BY_HANDLE_FILE_INFORMATION, CREATE_NEW,
    DELETE, FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_ENCRYPTED,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_SPARSE_FILE, FILE_BASIC_INFO, FILE_CREATION_DISPOSITION,
    FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    FILE_DISPOSITION_INFO_EX, FILE_DISPOSITION_INFO_EX_FLAGS, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_MODE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    OPEN_EXISTING,
    WIN32_FIND_STREAM_DATA,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct QuarantineTransaction {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_identity: Option<FileIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staging_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staging_identity: Option<FileIdentity>,
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
    #[serde(default, skip_serializing_if = "QuarantineTransaction::is_empty")]
    pub transaction: QuarantineTransaction,
}

impl QuarantineTransaction {
    fn is_empty(&self) -> bool {
        self.source_identity.is_none() && self.staging_path.is_none() && self.staging_identity.is_none()
    }
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
        if number.chars().count() == 1 && "123456789¹²³".contains(number) {
            anyhow::bail!("Windows file name {:?} is reserved", name);
        }
    }
    if let Some(number) = stem.strip_prefix("LPT") {
        if number.chars().count() == 1 && "123456789¹²³".contains(number) {
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
            let orphan_temps = Self::find_orphan_temps(parent)?;
            let existing_files = Self::find_existing_state_files(parent)?;
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
            Self::cleanup_stale_temps_if_safe(parent)?;
            return Ok(manifest_v2);
        }

        let manifest_v1: QuarantineManifestV1 = serde_json::from_value(value)
            .with_context(|| format!("Quarantine manifest at {:?} is corrupt or unparseable", path))?;
        tracing::info!("Detected v1 quarantine manifest at {:?}. Starting non-destructive migration...", path);
        let backup_path = parent.join("manifest.v1.bak");
        Self::preserve_v1_backup(path, &backup_path)?;

        let mut v2_entries = HashMap::new();
        for (k, orig_path_str) in manifest_v1.entries {
            let record = QuarantineRecordV2 {
                original_path: PathBuf::from(orig_path_str),
                quarantined_at_utc: None,
                original_sha256: None,
                size_bytes: None,
                state: QuarantineState::Quarantined,
                transaction: QuarantineTransaction::default(),
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
        Self::cleanup_stale_temps_if_safe(parent)?;
        Ok(v2_manifest)
    }

    fn preserve_v1_backup(source: &Path, backup_path: &Path) -> Result<()> {
        use std::io::Write;

        ensure_not_reparse(source, "v1 quarantine manifest")?;
        ensure_not_reparse(backup_path, "v1 quarantine backup")?;
        let content = std::fs::read(source)
            .with_context(|| format!("Failed to read v1 quarantine manifest at {:?}", source))?;

        if backup_path.exists() {
            let existing = std::fs::read(backup_path)
                .with_context(|| format!("Failed to read existing v1 backup at {:?}", backup_path))?;
            if existing != content {
                anyhow::bail!(
                    "Existing v1 backup at {:?} differs from the current manifest; refusing to overwrite",
                    backup_path
                );
            }
            return Ok(());
        }

        let mut backup = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(backup_path)
            .with_context(|| format!("Failed to create exclusive v1 backup at {:?}", backup_path))?;
        backup
            .write_all(&content)
            .with_context(|| format!("Failed to write v1 backup at {:?}", backup_path))?;
        backup
            .sync_all()
            .with_context(|| format!("Failed to sync v1 backup at {:?}", backup_path))?;
        Ok(())
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

    fn find_orphan_temps(dir: &Path) -> Result<Vec<PathBuf>> {
        let mut temps = Vec::new();
        let read_dir = std::fs::read_dir(dir)
            .with_context(|| format!("Failed to enumerate quarantine directory {:?}", dir))?;
        for entry in read_dir {
            let entry = entry
                .with_context(|| format!("Failed to enumerate quarantine directory {:?}", dir))?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("manifest.json.tmp.") {
                temps.push(entry.path());
            }
        }
        Ok(temps)
    }

    fn find_existing_state_files(dir: &Path) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        let read_dir = std::fs::read_dir(dir)
            .with_context(|| format!("Failed to enumerate quarantine directory {:?}", dir))?;
        for entry in read_dir {
            let entry = entry
                .with_context(|| format!("Failed to enumerate quarantine directory {:?}", dir))?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str == QUARANTINE_LOCK_FILE || name_str.starts_with("manifest.json.tmp.") {
                continue;
            }
            files.push(entry.path());
        }
        Ok(files)
    }

    fn cleanup_stale_temps_if_safe(dir: &Path) -> Result<()> {
        for temp in Self::find_orphan_temps(dir)? {
            std::fs::remove_file(&temp)
                .with_context(|| format!("Failed to remove stale manifest temp {:?}", temp))?;
        }
        Ok(())
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
            LockFileEx(
                handle,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
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

    let raw: Vec<u16> = path.as_os_str().encode_wide().collect();
    let mut prefixed = Vec::with_capacity(raw.len() + 8);
    if raw.starts_with(&[b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16]) {
        prefixed.extend_from_slice(&raw);
    } else if raw.starts_with(&[b'\\' as u16, b'\\' as u16]) {
        prefixed.extend("\\\\?\\UNC\\".encode_utf16());
        prefixed.extend_from_slice(&raw[2..]);
    } else {
        prefixed.extend("\\\\?\\".encode_utf16());
        prefixed.extend_from_slice(&raw);
    }
    prefixed.push(0);
    prefixed
}

#[cfg(all(unix, not(windows)))]
fn atomic_move_no_replace(source: &Path, destination: &Path) -> Result<()> {
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
fn atomic_move_no_replace(source: &Path, destination: &Path) -> Result<()> {
    if destination.exists() {
        anyhow::bail!("Destination {:?} already exists", destination);
    }
    std::fs::rename(source, destination)
        .with_context(|| format!("Failed atomic move from {:?} to {:?}", source, destination))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FileIdentity {
    pub volume_id: u64,
    pub file_id: u64,
    pub len: u64,
    #[serde(default)]
    pub creation_time: u64,
    #[serde(default)]
    pub last_access_time: u64,
    #[serde(default)]
    pub last_write_time: u64,
    #[serde(default)]
    pub attributes: u32,
}

impl FileIdentity {
    fn same_object(&self, other: &Self) -> bool {
        self.volume_id == other.volume_id && self.file_id == other.file_id
    }

    fn same_file(&self, other: &Self) -> bool {
        self.same_object(other) && self.len == other.len
    }
}

#[cfg(windows)]
fn filetime_to_u64(value: FILETIME) -> u64 {
    ((value.dwHighDateTime as u64) << 32) | value.dwLowDateTime as u64
}

#[cfg(windows)]
fn identity_from_file(file: &std::fs::File) -> Result<FileIdentity> {
    let handle = HANDLE(file.as_raw_handle() as isize);
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe {
        GetFileInformationByHandle(handle, &mut info)
            .map_err(|error| anyhow::anyhow!("Failed to read file identity: {}", error))?;
    }
    Ok(FileIdentity {
        volume_id: info.dwVolumeSerialNumber as u64,
        file_id: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
        len: ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64,
        creation_time: filetime_to_u64(info.ftCreationTime),
        last_access_time: filetime_to_u64(info.ftLastAccessTime),
        last_write_time: filetime_to_u64(info.ftLastWriteTime),
        attributes: info.dwFileAttributes,
    })
}

#[cfg(not(windows))]
fn system_time_to_u64(value: Option<std::time::SystemTime>) -> u64 {
    value
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(not(windows))]
fn identity_from_file(file: &std::fs::File) -> Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file
        .metadata()
        .context("Failed to read file identity metadata")?;
    Ok(FileIdentity {
        volume_id: metadata.dev(),
        file_id: metadata.ino(),
        len: metadata.len(),
        creation_time: system_time_to_u64(metadata.created().ok()),
        last_access_time: system_time_to_u64(metadata.accessed().ok()),
        last_write_time: system_time_to_u64(metadata.modified().ok()),
        attributes: metadata.mode(),
    })
}

#[cfg(windows)]
fn open_windows_file(
    path: &Path,
    access: u32,
    share: u32,
    creation: FILE_CREATION_DISPOSITION,
    flags: FILE_FLAGS_AND_ATTRIBUTES,
) -> Result<std::fs::File> {
    let wide = wide_path(path);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            access,
            FILE_SHARE_MODE(share),
            None,
            creation,
            flags,
            HANDLE::default(),
        )
    }
    .map_err(|error| anyhow::anyhow!("Failed to open {:?}: {}", path, error))?;
    let file = unsafe { std::fs::File::from_raw_handle(handle.0 as RawHandle) };
    Ok(file)
}

struct LockedFile {
    file: std::fs::File,
    path: PathBuf,
    identity: FileIdentity,
}

impl LockedFile {
    fn open_source(path: &Path) -> Result<Self> {
        ensure_not_reparse(path, "Source")?;
        #[cfg(windows)]
        let file = open_windows_file(
            path,
            GENERIC_READ.0 | DELETE.0,
            FILE_SHARE_READ.0,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )?;
        #[cfg(not(windows))]
        let file = std::fs::File::open(path)
            .with_context(|| format!("Failed to open {:?}", path))?;
        let identity = identity_from_file(&file)?;
        Self::from_parts(file, path, identity)
    }

    fn open_read(path: &Path) -> Result<Self> {
        ensure_not_reparse(path, "Verification target")?;
        #[cfg(windows)]
        let file = open_windows_file(
            path,
            GENERIC_READ.0,
            FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )?;
        #[cfg(not(windows))]
        let file = std::fs::File::open(path)
            .with_context(|| format!("Failed to open {:?}", path))?;
        let identity = identity_from_file(&file)?;
        Self::from_parts(file, path, identity)
    }

    fn create_staging(path: &Path) -> Result<Self> {
        ensure_not_reparse(path, "Staging file")?;
        #[cfg(windows)]
        let file = open_windows_file(
            path,
            GENERIC_READ.0 | GENERIC_WRITE.0 | DELETE.0,
            FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
        )?;
        #[cfg(not(windows))]
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("Failed to create exclusive staging file {:?}", path))?;
        let identity = identity_from_file(&file)?;
        Self::from_parts(file, path, identity)
    }

    fn from_parts(file: std::fs::File, path: &Path, identity: FileIdentity) -> Result<Self> {
        #[cfg(windows)]
        if identity.attributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            anyhow::bail!("Source {:?} is a reparse point or symbolic link", path);
        }
        Ok(Self {
            file,
            path: path.to_path_buf(),
            identity,
        })
    }

    fn current_identity(&self) -> Result<FileIdentity> {
        identity_from_file(&self.file)
    }

    fn rewind(&mut self) -> Result<()> {
        self.file
            .seek(SeekFrom::Start(0))
            .with_context(|| format!("Failed to rewind {:?}", self.path))?;
        Ok(())
    }

    fn hash(&mut self) -> Result<String> {
        self.rewind()?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; BUFFER_SIZE];
        loop {
            let read = self
                .file
                .read(&mut buffer)
                .with_context(|| format!("Failed to read {:?}", self.path))?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }

    fn verify_hash(&mut self, expected_hash: &str, expected_size: u64) -> Result<()> {
        if self.current_identity()?.len != expected_size {
            anyhow::bail!(
                "Size verification failed for {:?}: expected {}, found {}",
                self.path,
                expected_size,
                self.current_identity()?.len
            );
        }
        let actual_hash = self.hash()?;
        if actual_hash != expected_hash {
            anyhow::bail!(
                "SHA-256 verification failed for {:?}: expected {}, found {}",
                self.path,
                expected_hash,
                actual_hash
            );
        }
        Ok(())
    }

    fn revalidate_source(&mut self, expected_hash: &str) -> Result<()> {
        if !self.current_identity()?.same_file(&self.identity) {
            anyhow::bail!("Source identity changed for {:?}; preserving all copies", self.path);
        }
        self.verify_hash(expected_hash, self.identity.len)
    }

    fn move_no_replace(&mut self, destination: &Path) -> Result<()> {
        #[cfg(windows)]
        {
            let destination_wide = wide_path(destination);
            let name = &destination_wide[..destination_wide.len().saturating_sub(1)];
            let buffer_size = std::mem::size_of::<FILE_RENAME_INFO>()
                + name.len().saturating_sub(1) * std::mem::size_of::<u16>();
            let mut buffer = vec![0u64; buffer_size.div_ceil(8)];
            let info = buffer.as_mut_ptr() as *mut FILE_RENAME_INFO;
            unsafe {
                (*info).Anonymous.ReplaceIfExists = BOOLEAN(0);
                (*info).RootDirectory = HANDLE::default();
                (*info).FileNameLength = std::mem::size_of_val(name) as u32;
                std::ptr::copy_nonoverlapping(
                    name.as_ptr(),
                    (*info).FileName.as_mut_ptr(),
                    name.len(),
                );
                let result = SetFileInformationByHandle(
                    HANDLE(self.file.as_raw_handle() as isize),
                    FileRenameInfo,
                    info as *const _ as *const _,
                    buffer_size as u32,
                );
                if let Err(error) = result {
                    let code = error.code().0 as u32 & 0xFFFF;
                    if code == 17 {
                        return Err(anyhow::Error::new(CrossDeviceMoveError));
                    }
                    return Err(anyhow::anyhow!(
                        "Failed handle-based move from {:?} to {:?}: {}",
                        self.path,
                        destination,
                        error
                    ));
                }
            }
        }
        #[cfg(not(windows))]
        {
            if !self.current_identity()?.same_object(&self.identity) {
                anyhow::bail!("Source identity changed for {:?}; refusing to move", self.path);
            }
            atomic_move_no_replace(&self.path, destination)?;
        }
        self.path = destination.to_path_buf();
        Ok(())
    }

    fn delete(self) -> Result<()> {
        #[cfg(windows)]
        {
            let info = FILE_DISPOSITION_INFO_EX {
                Flags: FILE_DISPOSITION_INFO_EX_FLAGS(
                    FILE_DISPOSITION_FLAG_DELETE.0 | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE.0,
                ),
            };
            unsafe {
                SetFileInformationByHandle(
                    HANDLE(self.file.as_raw_handle() as isize),
                    FileDispositionInfoEx,
                    &info as *const _ as *const _,
                    std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
                )
                .map_err(|error| {
                    anyhow::anyhow!("Failed handle-based delete for {:?}: {}", self.path, error)
                })?;
            }
        }
        #[cfg(not(windows))]
        {
            if !self.current_identity()?.same_object(&self.identity) {
                anyhow::bail!("Source identity changed for {:?}; refusing to delete", self.path);
            }
            std::fs::remove_file(&self.path)
                .with_context(|| format!("Failed to delete {:?}", self.path))?;
        }
        Ok(())
    }
}

fn stream_path(path: &Path, stream_name: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(stream_name);
    PathBuf::from(value)
}

#[cfg(windows)]
fn enumerate_streams(path: &Path) -> Result<Vec<(String, i64)>> {
    let wide = wide_path(path);
    let mut data = WIN32_FIND_STREAM_DATA::default();
    let handle = match unsafe {
        FindFirstStreamW(
            PCWSTR(wide.as_ptr()),
            FindStreamInfoStandard,
            &mut data as *mut _ as *mut _,
            0,
        )
    } {
        Ok(handle) => handle,
        Err(error) if error.code().0 as u32 & 0xFFFF == ERROR_HANDLE_EOF.0 => return Ok(Vec::new()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Failed to enumerate NTFS streams for {:?}", path))
        }
    };

    let mut streams = Vec::new();
    loop {
        let length = data
            .cStreamName
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(data.cStreamName.len());
        streams.push((
            String::from_utf16_lossy(&data.cStreamName[..length]),
            data.StreamSize,
        ));
        match unsafe { FindNextStreamW(handle, &mut data as *mut _ as *mut _) } {
            Ok(()) => {}
            Err(error) if error.code().0 as u32 & 0xFFFF == ERROR_HANDLE_EOF.0 => break,
            Err(error) => {
                let _ = unsafe { FindClose(handle) };
                return Err(error)
                    .with_context(|| format!("Failed to enumerate NTFS streams for {:?}", path));
            }
        }
    }
    unsafe { FindClose(handle) }.map_err(|error| anyhow::anyhow!("Failed to close stream search: {}", error))?;
    Ok(streams)
}

#[cfg(windows)]
fn preserve_streams(source: &Path, destination: &Path) -> Result<()> {
    for (stream_name, _) in enumerate_streams(source)? {
        if stream_name == "::$DATA" {
            continue;
        }
        let source_stream = stream_path(source, &stream_name);
        let destination_stream = stream_path(destination, &stream_name);
        let mut input = std::fs::File::open(&source_stream)
            .with_context(|| format!("Failed to open NTFS stream {:?}", source_stream))?;
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&destination_stream)
            .with_context(|| format!("Failed to create NTFS stream {:?}", destination_stream))?;
        std::io::copy(&mut input, &mut output)
            .with_context(|| format!("Failed to copy NTFS stream {:?}", source_stream))?;
        output
            .sync_all()
            .with_context(|| format!("Failed to sync NTFS stream {:?}", destination_stream))?;
    }
    Ok(())
}

#[cfg(windows)]
fn preserve_security(source: &Path, destination: &Path) -> Result<()> {
    let information = OBJECT_SECURITY_INFORMATION(
        OWNER_SECURITY_INFORMATION.0 | GROUP_SECURITY_INFORMATION.0 | DACL_SECURITY_INFORMATION.0,
    );
    let source_wide = wide_path(source);
    let mut needed = 0u32;
    let mut buffer = Vec::<u64>::new();
    let first = unsafe {
        GetFileSecurityW(
            PCWSTR(source_wide.as_ptr()),
            information.0,
            PSECURITY_DESCRIPTOR::default(),
            0,
            &mut needed,
        )
    };
    if !first.as_bool() && needed == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("Failed to read security descriptor for {:?}", source));
    }
    if needed == 0 {
        anyhow::bail!("Security descriptor for {:?} is empty", source);
    }
    buffer.resize((needed as usize).div_ceil(8), 0);
    let descriptor = PSECURITY_DESCRIPTOR(buffer.as_mut_ptr() as *mut _);
    let second = unsafe {
        GetFileSecurityW(
            PCWSTR(source_wide.as_ptr()),
            information.0,
            descriptor,
            needed,
            &mut needed,
        )
    };
    if !second.as_bool() {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("Failed to read security descriptor for {:?}", source));
    }

    let destination_wide = wide_path(destination);
    let applied = unsafe {
        SetFileSecurityW(PCWSTR(destination_wide.as_ptr()), information, descriptor)
    };
    if !applied.as_bool() {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("Failed to preserve security descriptor for {:?}", destination));
    }
    Ok(())
}

#[cfg(windows)]
fn preserve_basic_info(destination: &Path, identity: &FileIdentity) -> Result<()> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(destination)
        .with_context(|| format!("Failed to open {:?} for metadata preservation", destination))?;
    let info = FILE_BASIC_INFO {
        CreationTime: identity.creation_time as i64,
        LastAccessTime: identity.last_access_time as i64,
        LastWriteTime: identity.last_write_time as i64,
        ChangeTime: 0,
        FileAttributes: identity.attributes,
    };
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle() as isize),
            FileBasicInfo,
            &info as *const _ as *const _,
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
        .map_err(|error| anyhow::anyhow!("Failed to preserve metadata for {:?}: {}", destination, error))?;
    }
    Ok(())
}

#[cfg(windows)]
fn preserve_windows_metadata(source: &Path, destination: &Path, identity: &FileIdentity) -> Result<()> {
    let unsupported = identity.attributes
        & (FILE_ATTRIBUTE_ENCRYPTED.0
            | FILE_ATTRIBUTE_COMPRESSED.0
            | FILE_ATTRIBUTE_OFFLINE.0
            | FILE_ATTRIBUTE_SPARSE_FILE.0
            | FILE_ATTRIBUTE_DIRECTORY.0
            | FILE_ATTRIBUTE_REPARSE_POINT.0);
    if unsupported != 0 {
        anyhow::bail!(
            "Source {:?} uses unsupported NTFS attributes 0x{:x}; retaining source",
            source,
            unsupported
        );
    }
    preserve_streams(source, destination)?;
    preserve_security(source, destination)?;
    preserve_basic_info(destination, identity)?;
    Ok(())
}

#[cfg(not(windows))]
fn preserve_metadata(source: &Path, destination: &Path) -> Result<()> {
    let metadata = std::fs::metadata(source)
        .with_context(|| format!("Failed to read metadata for {:?}", source))?;
    std::fs::set_permissions(destination, metadata.permissions())
        .with_context(|| format!("Failed to preserve permissions for {:?}", destination))
}

fn copy_to_staging(source: &mut LockedFile, staging: &mut LockedFile) -> Result<FileIdentity> {
    ensure_not_reparse(&source.path, "Copy source")?;
    ensure_not_reparse(&staging.path, "Staging destination")?;
    source.rewind()?;
    staging.rewind()?;
    std::io::copy(&mut source.file, &mut staging.file)
        .with_context(|| format!("Failed to copy {:?} to {:?}", source.path, staging.path))?;
    staging
        .file
        .sync_all()
        .with_context(|| format!("Failed to sync staging file {:?}", staging.path))?;

    if !source.current_identity()?.same_file(&source.identity) {
        anyhow::bail!("Source identity changed for {:?}; preserving all copies", source.path);
    }

    #[cfg(windows)]
    preserve_windows_metadata(&source.path, &staging.path, &source.identity)?;
    #[cfg(not(windows))]
    preserve_metadata(&source.path, &staging.path)?;

    let identity = staging.current_identity()?;
    if !identity.same_object(&staging.identity) {
        anyhow::bail!("Staging identity changed for {:?}; preserving all copies", staging.path);
    }
    Ok(identity)
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

fn path_present(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("Failed to inspect {:?}", path)),
    }
}

fn verify_source_at(
    path: &Path,
    identity: &FileIdentity,
    expected_hash: &str,
    expected_size: u64,
) -> Result<()> {
    let mut file = LockedFile::open_read(path)?;
    if !file.current_identity()?.same_file(identity) {
        anyhow::bail!("Source identity changed for {:?}; preserving all copies", path);
    }
    file.verify_hash(expected_hash, expected_size)
}

fn verify_destination_at(
    path: &Path,
    transaction: &QuarantineTransaction,
    expected_hash: &str,
    expected_size: u64,
) -> Result<()> {
    let mut file = LockedFile::open_read(path)?;
    let current = file.current_identity()?;
    if let Some(staging_identity) = transaction.staging_identity.as_ref() {
        if !current.same_object(staging_identity) {
            anyhow::bail!("Destination identity changed for {:?}; preserving all copies", path);
        }
    } else if let Some(source_identity) = transaction.source_identity.as_ref() {
        if !current.same_file(source_identity) {
            anyhow::bail!("Destination identity changed for {:?}; preserving all copies", path);
        }
    } else {
        anyhow::bail!("Destination {:?} has no recorded identity; preserving all copies", path);
    }
    file.verify_hash(expected_hash, expected_size)
}

fn delete_owned_staging(
    staging: &Path,
    transaction: &QuarantineTransaction,
    expected_hash: Option<(&str, u64)>,
) -> Result<()> {
    let recorded = transaction
        .staging_identity
        .as_ref()
        .context("Staging file has no recorded identity; preserving all copies")?;
    let mut file = LockedFile::open_source(staging)?;
    if !file.current_identity()?.same_object(recorded) {
        anyhow::bail!("Staging identity changed for {:?}; preserving all copies", staging);
    }
    if let Some((hash, size)) = expected_hash {
        file.verify_hash(hash, size)?;
    }
    file.delete()
}

fn verify_staging_at(
    staging: &Path,
    transaction: &QuarantineTransaction,
    expected_hash: &str,
    expected_size: u64,
) -> Result<LockedFile> {
    let recorded = transaction
        .staging_identity
        .as_ref()
        .context("Staging file has no recorded identity; preserving all copies")?;
    let mut file = LockedFile::open_source(staging)?;
    if !file.current_identity()?.same_object(recorded) {
        anyhow::bail!("Staging identity changed for {:?}; preserving all copies", staging);
    }
    file.verify_hash(expected_hash, expected_size)?;
    Ok(file)
}

fn validate_recorded_staging_path(record: &QuarantineRecordV2, derived: &Path) -> Result<()> {
    if let Some(recorded) = record.transaction.staging_path.as_ref() {
        if recorded != derived {
            anyhow::bail!(
                "Recorded staging path {:?} does not match expected {:?}; preserving all copies",
                recorded,
                derived
            );
        }
    }
    Ok(())
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
    validate_recorded_staging_path(record, &staging)?;

    let source_exists = path_present(source)?;
    let destination_exists = path_present(&destination)?;
    let staging_exists = path_present(&staging)?;

    if destination_exists {
        if source_exists || staging_exists {
            anyhow::bail!(
                "Ambiguous quarantine transaction for {:?}: multiple copies remain; preserving all copies",
                key
            );
        }
        verify_destination_at(&destination, &record.transaction, expected_hash, expected_size)?;
        return Ok(RecoveryAction::MarkQuarantined);
    }

    if source_exists {
        let source_identity = record
            .transaction
            .source_identity
            .as_ref()
            .context("Staged quarantine source has no recorded identity")?;
        verify_source_at(source, source_identity, expected_hash, expected_size)?;
        if staging_exists {
            delete_owned_staging(&staging, &record.transaction, None)?;
        }
        return Ok(RecoveryAction::RemoveEntry);
    }

    if staging_exists {
        let mut staging_file = verify_staging_at(
            &staging,
            &record.transaction,
            expected_hash,
            expected_size,
        )?;
        staging_file.move_no_replace(&destination)?;
        verify_destination_at(&destination, &record.transaction, expected_hash, expected_size)?;
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
    validate_recorded_staging_path(record, &staging)?;

    let source_exists = path_present(&source)?;
    let destination_exists = path_present(destination)?;
    let staging_exists = path_present(&staging)?;

    if destination_exists {
        if source_exists || staging_exists {
            anyhow::bail!(
                "Ambiguous restore transaction for {:?}: multiple copies remain; preserving all copies",
                key
            );
        }
        verify_destination_at(destination, &record.transaction, expected_hash, expected_size)?;
        return Ok(RecoveryAction::RemoveEntry);
    }

    if source_exists {
        let source_identity = record
            .transaction
            .source_identity
            .as_ref()
            .context("Restoring source has no recorded identity")?;
        verify_source_at(&source, source_identity, expected_hash, expected_size)?;
        if staging_exists {
            delete_owned_staging(&staging, &record.transaction, None)?;
        }
        return Ok(RecoveryAction::RollbackRestore);
    }

    if staging_exists {
        let mut staging_file = verify_staging_at(
            &staging,
            &record.transaction,
            expected_hash,
            expected_size,
        )?;
        staging_file.move_no_replace(destination)?;
        verify_destination_at(destination, &record.transaction, expected_hash, expected_size)?;
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
        let mut manifest = match QuarantineManifestV2::load_or_recover(&manifest_path) {
            Ok(manifest) => manifest,
            Err(error) => {
                tracing::error!(
                    "Quarantine manifest could not be loaded; destructive quarantine operations are disabled: {}",
                    error
                );
                QuarantineManifestV2::new()
            }
        };
        if let Err(error) = recover_pending_transactions(&quarantine_dir, &manifest_path, &mut manifest) {
            tracing::error!(
                "Quarantine transaction recovery failed; destructive quarantine operations remain disabled: {}",
                error
            );
        }

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

        for entry in WalkDir::new(&self.quarantine_dir).into_iter() {
            let entry = entry
                .with_context(|| format!("Failed to enumerate quarantine directory {:?}", self.quarantine_dir))?;
            let path = entry.path();
            if entry.file_type().is_dir() {
                continue;
            }
            if !entry.file_type().is_file() {
                anyhow::bail!("Unexpected non-file entry in quarantine directory: {:?}", path);
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
            let meta = entry
                .metadata()
                .with_context(|| format!("Failed to read metadata for quarantined file {:?}", path))?;

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
        let mut source_file = LockedFile::open_source(&source)?;
        let source_identity = source_file.identity.clone();
        let size = source_identity.len;
        let hash = source_file.hash()?;
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

        let destination = record.original_path.clone();
        QuarantineRecordV2::validate_original_path(&destination, &self.quarantine_dir)?;
        if path_present(&destination)? {
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

        let staging = restore_staging_path_for(&destination, &key)?;
        if path_present(&staging)? {
            anyhow::bail!(
                "Restore staging {:?} already exists; refusing to overwrite",
                staging
            );
        }

        let mut next = guard.clone();
        if let Some(record) = next.entries.get_mut(&key) {
            record.state = QuarantineState::Restoring;
            record.original_sha256 = Some(hash.clone());
            record.size_bytes = Some(size);
            record.transaction = QuarantineTransaction {
                source_identity: Some(source_identity.clone()),
                staging_path: None,
                staging_identity: None,
            };
        }
        fault_injection::check("restore_before_staged_save")?;
        self.persist_manifest(&mut guard, next)?;
        fault_injection::check("restore_after_staged_persist")?;

        let mut cross_volume = fault_injection::force_cross_volume();
        if !cross_volume {
            match source_file.move_no_replace(&destination) {
                Ok(()) => {
                    fault_injection::check("restore_after_final_move")?;
                    source_file.verify_hash(&hash, size)?;
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
            let mut staging_file = match LockedFile::create_staging(&staging) {
                Ok(file) => file,
                Err(error) => {
                    let mut rollback = guard.clone();
                    if let Some(record) = rollback.entries.get_mut(&key) {
                        record.state = QuarantineState::Quarantined;
                    }
                    self.persist_manifest(&mut guard, rollback)?;
                    return Err(error);
                }
            };

            let mut staged = guard.clone();
            if let Some(record) = staged.entries.get_mut(&key) {
                record.transaction.staging_path = Some(staging.clone());
                record.transaction.staging_identity = Some(staging_file.identity.clone());
            }
            if let Err(error) = self.persist_manifest(&mut guard, staged) {
                let _ = staging_file.delete();
                return Err(error);
            }

            if let Err(error) = copy_to_staging(&mut source_file, &mut staging_file) {
                let _ = staging_file.delete();
                let mut rollback = guard.clone();
                if let Some(record) = rollback.entries.get_mut(&key) {
                    record.state = QuarantineState::Quarantined;
                }
                let _ = self.persist_manifest(&mut guard, rollback);
                return Err(error);
            }
            fault_injection::check("restore_after_stage_copy")?;
            staging_file.verify_hash(&hash, size)?;
            fault_injection::check("restore_after_stage_verify")?;
            if let Err(error) = staging_file.move_no_replace(&destination) {
                let _ = staging_file.delete();
                let mut rollback = guard.clone();
                if let Some(record) = rollback.entries.get_mut(&key) {
                    record.state = QuarantineState::Quarantined;
                }
                self.persist_manifest(&mut guard, rollback)?;
                return Err(error);
            }
            fault_injection::check("restore_after_final_move")?;
            staging_file.verify_hash(&hash, size)?;
            fault_injection::check("restore_before_source_delete")?;
            source_file.revalidate_source(&hash)?;
            source_file.delete()?;
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
        if !guard.entries.contains_key(&key) {
            anyhow::bail!("Quarantine manifest record not found; refusing to delete");
        }
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

        let mut source_file = LockedFile::open_source(source)?;
        let identity = source_file.identity.clone();
        let size = identity.len;
        let hash = source_file.hash()?;

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

        if guard.entries.contains_key(&key)
            || path_present(&destination)?
            || path_present(&staging)?
        {
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
                transaction: QuarantineTransaction {
                    source_identity: Some(identity.clone()),
                    staging_path: None,
                    staging_identity: None,
                },
            },
        );
        fault_injection::check("quarantine_before_staged_save")?;
        self.persist_manifest(&mut guard, next)?;
        fault_injection::check("quarantine_after_staged_persist")?;

        let mut cross_volume = fault_injection::force_cross_volume();
        if !cross_volume {
            match source_file.move_no_replace(&destination) {
                Ok(()) => {
                    fault_injection::check("quarantine_after_final_move")?;
                    source_file.verify_hash(&hash, size)?;
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
            let mut staging_file = match LockedFile::create_staging(&staging) {
                Ok(file) => file,
                Err(error) => {
                    let mut rollback = guard.clone();
                    rollback.entries.remove(&key);
                    self.persist_manifest(&mut guard, rollback)?;
                    return Err(error);
                }
            };

            let mut staged = guard.clone();
            if let Some(record) = staged.entries.get_mut(&key) {
                record.transaction.staging_path = Some(staging.clone());
                record.transaction.staging_identity = Some(staging_file.identity.clone());
            }
            if let Err(error) = self.persist_manifest(&mut guard, staged) {
                let _ = staging_file.delete();
                return Err(error);
            }

            if let Err(error) = copy_to_staging(&mut source_file, &mut staging_file) {
                let _ = staging_file.delete();
                let mut rollback = guard.clone();
                rollback.entries.remove(&key);
                let _ = self.persist_manifest(&mut guard, rollback);
                return Err(error);
            }
            fault_injection::check("quarantine_after_stage_copy")?;
            staging_file.verify_hash(&hash, size)?;
            fault_injection::check("quarantine_after_stage_verify")?;
            if let Err(error) = staging_file.move_no_replace(&destination) {
                let _ = staging_file.delete();
                let mut rollback = guard.clone();
                rollback.entries.remove(&key);
                self.persist_manifest(&mut guard, rollback)?;
                return Err(error);
            }
            fault_injection::check("quarantine_after_final_move")?;
            staging_file.verify_hash(&hash, size)?;
            fault_injection::check("quarantine_before_source_delete")?;
            source_file.revalidate_source(&hash)?;
            source_file.delete()?;
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
                transaction: QuarantineTransaction::default(),
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
                transaction: QuarantineTransaction::default(),
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

        // Cleaner initialization must remain available but destructive operations must fail closed
        let cleaner = Cleaner::new_with_dir(test_dir.path.clone())
            .expect("Cleaner startup must not fail because of a corrupt quarantine manifest");
        assert!(cleaner.list_quarantine().is_err(), "Destructive operations must fail closed");

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
                transaction: QuarantineTransaction::default(),
            },
        );

        manifest.save_atomic(&manifest_file).expect("Atomic save must succeed");
        assert!(manifest_file.exists());

        // Verify no leftover .tmp files
        let orphan_temps = QuarantineManifestV2::find_orphan_temps(&test_dir.path)
            .expect("Temporary file enumeration must succeed");
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
                transaction: QuarantineTransaction::default(),
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
        let cleaner = Cleaner::new_with_dir(workspace.quarantine.clone())
            .expect("Cleaner startup must remain available");
        assert!(cleaner.list_quarantine().is_err(), "Destructive operations must fail closed");
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
        for name in [
            "CON", "con.txt", "PRN.log", "AUX", "NUL", "COM1.bin", "LPT9.tar.gz", "COM¹.txt",
            "LPT².log", "name.", "name ",
        ] {
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
    async fn test_b2b_quarantine_cross_volume_before_source_delete_preserves_both_copies() {
        fault_injection::reset();
        fault_injection::set_force_cross_volume(true);
        let workspace = TestWorkspace::new("quarantine_before_delete");
        let source = workspace.source_file("doc.bin", b"payload");
        let cleaner = workspace.cleaner();

        fault_injection::set_point("quarantine_before_source_delete");
        assert!(cleaner.quarantine_file(&source).await.is_err());
        assert!(source.exists());
        assert_eq!(payload_files(&workspace).len(), 1);

        let recovered = Cleaner::new_with_dir(workspace.quarantine.clone())
            .expect("Cleaner startup must remain available");
        assert!(recovered.list_quarantine().is_err(), "Ambiguous recovery must fail closed");
        assert!(source.exists());
        assert_eq!(std::fs::read(&source).unwrap(), b"payload");
        let copies = payload_files(&workspace);
        assert_eq!(copies.len(), 1);
        assert_eq!(std::fs::read(&copies[0]).unwrap(), b"payload");
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

        let recovered = Cleaner::new_with_dir(workspace.quarantine.clone())
            .expect("Cleaner startup must remain available");
        assert!(recovered.list_quarantine().is_err(), "Destructive operations must fail closed");
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
    async fn test_b2b_restore_cross_volume_before_source_delete_preserves_both_copies() {
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

        let recovered = Cleaner::new_with_dir(workspace.quarantine.clone())
            .expect("Cleaner startup must remain available");
        assert!(recovered.list_quarantine().is_err(), "Ambiguous recovery must fail closed");
        assert_eq!(std::fs::read(&source).unwrap(), b"payload");
        assert!(entry.quarantine_path.exists());
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

    #[tokio::test]
    async fn test_b2b_recovery_preserves_staging_without_recorded_identity() {
        fault_injection::reset();
        fault_injection::set_force_cross_volume(true);
        let workspace = TestWorkspace::new("unowned_staging");
        let source = workspace.source_file("doc.bin", b"payload");
        let cleaner = workspace.cleaner();

        fault_injection::set_point("quarantine_after_stage_copy");
        assert!(cleaner.quarantine_file(&source).await.is_err());
        assert!(source.exists());

        let manifest_path = workspace.quarantine.join("manifest.json");
        let mut manifest = QuarantineManifestV2::load_or_recover(&manifest_path).unwrap();
        let key = manifest.entries.keys().next().unwrap().clone();
        manifest
            .entries
            .get_mut(&key)
            .unwrap()
            .transaction
            .staging_identity = None;
        manifest.save_atomic(&manifest_path).unwrap();

        let recovered = Cleaner::new_with_dir(workspace.quarantine.clone())
            .expect("Cleaner startup must remain available");
        assert!(recovered.list_quarantine().is_err(), "Unowned staging must fail closed");
        assert!(source.exists());
        assert!(quarantine_staging_path_for(&workspace.quarantine, &key).exists());
    }

    #[test]
    fn test_b2b_handle_identity_and_no_replace_move() {
        let workspace = TestWorkspace::new("handle_identity");
        let source_path = workspace.source_file("source.bin", b"payload");
        let other_path = workspace.source_file("other.bin", b"payload");
        let mut source = LockedFile::open_source(&source_path).unwrap();
        let other = LockedFile::open_read(&other_path).unwrap();
        assert!(!source.identity.same_object(&other.identity));

        let destination = workspace.source.join("destination.bin");
        std::fs::write(&destination, b"existing destination").unwrap();
        assert!(source.move_no_replace(&destination).is_err());
        assert!(source_path.exists());
        assert_eq!(std::fs::read(&destination).unwrap(), b"existing destination");

        std::fs::remove_file(&destination).unwrap();
        source.move_no_replace(&destination).unwrap();
        assert!(!source_path.exists());
        assert_eq!(source.path, destination);

        let mut moved = LockedFile::open_read(&destination).unwrap();
        assert!(moved.identity.same_object(&source.identity));
        let expected_hash = {
            let mut hasher = Sha256::new();
            hasher.update(b"payload");
            format!("{:x}", hasher.finalize())
        };
        moved.verify_hash(&expected_hash, 7).unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn test_b2b_cross_volume_preserves_ntfs_streams_and_attributes() {
        use std::os::windows::fs::MetadataExt;
        use windows::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN};

        fault_injection::reset();
        fault_injection::set_force_cross_volume(true);
        let workspace = TestWorkspace::new("ntfs_metadata");
        let source = workspace.source_file("doc.bin", b"payload");
        let source_stream = stream_path(&source, ":syspulse_test");
        std::fs::write(&source_stream, b"alternate data").unwrap();
        let source_wide = wide_path(&source);
        unsafe {
            SetFileAttributesW(
                PCWSTR(source_wide.as_ptr()),
                FILE_FLAGS_AND_ATTRIBUTES(FILE_ATTRIBUTE_HIDDEN.0),
            )
            .unwrap();
        }

        let cleaner = workspace.cleaner();
        cleaner.quarantine_file(&source).await.unwrap();
        assert!(!source.exists());

        let destination = payload_files(&workspace).into_iter().next().unwrap();
        let destination_stream = stream_path(&destination, ":syspulse_test");
        assert_eq!(std::fs::read(destination_stream).unwrap(), b"alternate data");
        let attributes = std::fs::metadata(&destination).unwrap().file_attributes();
        assert_eq!(attributes & FILE_ATTRIBUTE_HIDDEN.0, FILE_ATTRIBUTE_HIDDEN.0);
    }

    #[test]
    fn test_b2b_v1_backup_is_never_overwritten() {
        let test_dir = TestQuarantineDir::new("v1_backup_conflict");
        let manifest_file = test_dir.path.join("manifest.json");
        let backup_file = test_dir.path.join("manifest.v1.bak");
        let v1_content = r#"{"entries":{"archived.pdf":"C:\\docs\\archived.pdf"}}"#;
        let backup_content = r#"{"entries":{"other.pdf":"C:\\docs\\other.pdf"}}"#;
        std::fs::write(&manifest_file, v1_content).unwrap();
        std::fs::write(&backup_file, backup_content).unwrap();

        assert!(QuarantineManifestV2::load_or_recover(&manifest_file).is_err());
        assert_eq!(std::fs::read_to_string(&manifest_file).unwrap(), v1_content);
        assert_eq!(std::fs::read_to_string(&backup_file).unwrap(), backup_content);
    }

    #[test]
    fn test_b2b_enumeration_errors_fail_closed() {
        let test_dir = TestQuarantineDir::new("enumeration_error");
        let not_a_directory = test_dir.path.join("file.bin");
        std::fs::write(&not_a_directory, b"payload").unwrap();

        assert!(QuarantineManifestV2::find_orphan_temps(&not_a_directory).is_err());
        assert!(QuarantineManifestV2::find_existing_state_files(&not_a_directory).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn test_b2b_worker_holds_cross_process_lock() {
        let Some(directory) = std::env::var_os("SYSPULSE_LOCK_TEST_DIR") else {
            return;
        };
        let ready = std::env::var_os("SYSPULSE_LOCK_TEST_READY")
            .map(PathBuf::from)
            .expect("missing ready path");
        let release = std::env::var_os("SYSPULSE_LOCK_TEST_RELEASE")
            .map(PathBuf::from)
            .expect("missing release path");
        let lock_path = PathBuf::from(directory).join(QUARANTINE_LOCK_FILE);
        let _lock = QuarantineProcessLock::acquire(&lock_path).expect("child must acquire lock");
        std::fs::write(&ready, b"ready").unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !release.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for lock release"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_b2b_cross_process_lock_is_exclusive() {
        use std::process::{Command, Stdio};

        let workspace = TestWorkspace::new("process_lock");
        let ready = workspace.root.join("ready");
        let release = workspace.root.join("release");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "modules::cleaner::tests::test_b2b_worker_holds_cross_process_lock",
                "--nocapture",
            ])
            .env("SYSPULSE_LOCK_TEST_DIR", &workspace.quarantine)
            .env("SYSPULSE_LOCK_TEST_READY", &ready)
            .env("SYSPULSE_LOCK_TEST_RELEASE", &release)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn lock worker");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !ready.exists() {
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                panic!("lock worker did not become ready");
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        let lock_path = workspace.quarantine.join(QUARANTINE_LOCK_FILE);
        let acquired = QuarantineProcessLock::acquire(&lock_path);
        let exclusive = acquired.is_err();
        drop(acquired);
        std::fs::write(&release, b"release").unwrap();
        let status = child.wait().unwrap();
        assert!(status.success(), "lock worker failed");
        assert!(exclusive, "second process must not acquire the quarantine lock");
    }
}
