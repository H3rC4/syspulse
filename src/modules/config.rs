use crate::models::Language;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const APP_NAME: &str = "SysPulse";
const CONFIG_FILE: &str = "settings.toml";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub language: Language,
    pub dark_mode: bool,
    pub light_mode: bool,
    pub start_with_os: bool,
    pub process_history_days: u32,
    pub quarantine_days: u32,
    pub permanent_delete: bool,  // NUEVO: eliminar permanentemente sin usar papelera
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            language: Language::English,
            dark_mode: true,
            light_mode: false,
            start_with_os: false,
            process_history_days: 30,
            quarantine_days: 7,
            permanent_delete: false,  // Default seguro: usar papelera
        }
    }
}

impl Settings {
    /// Loads settings from the OS config directory.
    pub fn load() -> Result<Self> {
        let path = Self::settings_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read settings from {:?}", path))?;

        let settings: Settings = toml::from_str(&content)
            .with_context(|| format!("Failed to parse settings from {:?}", path))?;

        Ok(settings)
    }

    /// Saves settings to the OS config directory.
    pub fn save(&self) -> Result<()> {
        let path = Self::settings_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config dir {:?}", parent))?;
        }

        let content = toml::to_string_pretty(self)
            .context("Failed to serialize settings")?;

        std::fs::write(&path, content)
            .with_context(|| format!("Failed to write settings to {:?}", path))?;

        Ok(())
    }

    /// Returns the full path to the settings file.
    pub fn settings_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .context("Failed to determine config directory")?;
        Ok(config_dir.join(APP_NAME).join(CONFIG_FILE))
    }

    /// Returns the application data directory (logs, DB, quarantine).
    pub fn app_data_dir() -> Result<PathBuf> {
        let data_dir = dirs::data_local_dir()
            .context("Failed to determine local data directory")?;
        Ok(data_dir.join(APP_NAME))
    }

    /// Returns the quarantine directory.
    pub fn quarantine_dir() -> Result<PathBuf> {
        Ok(Self::app_data_dir()?.join("quarantine"))
    }

    /// Returns the database file path.
    pub fn db_path() -> Result<PathBuf> {
        Ok(Self::app_data_dir()?.join("syspulse.db"))
    }

    /// Returns the logs directory.
    pub fn logs_dir() -> Result<PathBuf> {
        Ok(Self::app_data_dir()?.join("logs"))
    }

    /// Applies the start-with-OS setting using platform-specific mechanisms.
    pub fn apply_autostart(&self, executable_path: Option<&std::path::Path>) -> Result<()> {
        let exe = executable_path
            .map(PathBuf::from)
            .or_else(|| std::env::current_exe().ok())
            .context("Failed to determine executable path")?;

        if self.start_with_os {
            enable_autostart(&exe)?;
        } else {
            disable_autostart()?;
        }

        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn enable_autostart(executable: &std::path::Path) -> Result<()> {
    use windows::Win32::System::Registry::{
        RegCreateKeyExW, RegSetValueExW, HKEY_CURRENT_USER, KEY_WRITE,
        REG_SZ, REG_OPTION_NON_VOLATILE,
    };
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::core::w;

    let key_path = w!("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    let value_name = w!("SysPulse");
    let command = format!("\"{}\" --background", executable.display());
    let command_wide: Vec<u16> = command.encode_utf16().chain(Some(0)).collect();

    unsafe {
        let mut key = std::mem::zeroed();
        let result = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            key_path,
            0,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut key,
            None,
        );

        if result != ERROR_SUCCESS {
            anyhow::bail!("Failed to open registry run key");
        }

        let result = RegSetValueExW(
            key,
            value_name,
            0,
            REG_SZ,
            Some(std::slice::from_raw_parts(
                command_wide.as_ptr() as *const u8,
                command_wide.len() * 2,
            )),
        );

        if result != ERROR_SUCCESS {
            anyhow::bail!("Failed to set registry run value");
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn disable_autostart() -> Result<()> {
    use windows::Win32::System::Registry::{
        RegOpenKeyExW, RegDeleteValueW, HKEY_CURRENT_USER, KEY_WRITE,
    };
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::core::w;

    let key_path = w!("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    let value_name = w!("SysPulse");

    unsafe {
        let mut key = std::mem::zeroed();
        let result = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            key_path,
            0,
            KEY_WRITE,
            &mut key,
        );

        if result == ERROR_SUCCESS {
            let _ = RegDeleteValueW(key, value_name);
        }
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn enable_autostart(executable: &std::path::Path) -> Result<()> {
    let plist_path = dirs::home_dir()
        .context("Failed to get home directory")?
        .join("Library/LaunchAgents/com.syspulse.optimizer.plist");

    if let Some(parent) = plist_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create LaunchAgents dir {:?}", parent))?;
    }

    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.syspulse.optimizer</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>--background</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"#,
        executable.display()
    );

    std::fs::write(&plist_path, plist_content)
        .with_context(|| format!("Failed to write plist {:?}", plist_path))?;

    let _ = std::process::Command::new("launchctl")
        .args(["load", plist_path.to_str().unwrap_or("")])
        .output();

    Ok(())
}

#[cfg(target_os = "macos")]
fn disable_autostart() -> Result<()> {
    let plist_path = dirs::home_dir()
        .context("Failed to get home directory")?
        .join("Library/LaunchAgents/com.syspulse.optimizer.plist");

    if plist_path.exists() {
        let _ = std::process::Command::new("launchctl")
            .args(["unload", plist_path.to_str().unwrap_or("")])
            .output();
        let _ = std::fs::remove_file(&plist_path);
    }

    Ok(())
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn enable_autostart(_executable: &std::path::Path) -> Result<()> {
    tracing::warn!("Autostart is not supported on this platform");
    Ok(())
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn disable_autostart() -> Result<()> {
    Ok(())
}
