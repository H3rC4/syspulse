use crate::models::Language;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const APP_NAME: &str = "SysPulse";
const CONFIG_FILE: &str = "settings.toml";

fn default_net_metrics_retention_days() -> u32 {
    7
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Settings {
    pub language: Language,
    pub dark_mode: bool,
    pub light_mode: bool,
    pub start_with_os: bool,
    pub process_history_days: u32,
    pub quarantine_days: u32,
    pub permanent_delete: bool,  // Default seguro: usar papelera
    #[serde(default = "default_net_metrics_retention_days")]
    pub net_metrics_retention_days: u32,
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
            net_metrics_retention_days: 7,
        }
    }
}

impl Settings {
    /// Ensures theme settings are mutually exclusive and retention values are within bounds.
    pub fn sanitize(&mut self) {
        if self.light_mode {
            self.dark_mode = false;
        } else {
            self.dark_mode = true;
            self.light_mode = false;
        }

        if self.process_history_days == 0 {
            self.process_history_days = 30;
        }
        if self.quarantine_days == 0 {
            self.quarantine_days = 7;
        }
    }

    /// Loads settings from the OS config directory.
    pub fn load() -> Result<Self> {
        let path = Self::settings_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read settings from {:?}", path))?;

        let mut settings: Settings = toml::from_str(&content)
            .with_context(|| format!("Failed to parse settings from {:?}", path))?;

        settings.sanitize();
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
    #[allow(dead_code)]
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

    /// Checks whether SysPulse is currently registered in the OS auto-start registry or launch agents.
    pub fn is_autostart_registered() -> Result<bool> {
        check_autostart_registered()
    }
}

#[cfg(target_os = "windows")]
fn enable_autostart(executable: &std::path::Path) -> Result<()> {
    use windows::Win32::System::Registry::{
        RegCreateKeyExW, RegSetValueExW, RegCloseKey, HKEY_CURRENT_USER, KEY_WRITE,
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

        let _ = RegCloseKey(key);

        if result != ERROR_SUCCESS {
            anyhow::bail!("Failed to set registry run value");
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn disable_autostart() -> Result<()> {
    use windows::Win32::System::Registry::{
        RegOpenKeyExW, RegDeleteValueW, RegCloseKey, HKEY_CURRENT_USER, KEY_WRITE,
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
            let _ = RegCloseKey(key);
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn check_autostart_registered() -> Result<bool> {
    use windows::Win32::System::Registry::{
        RegOpenKeyExW, RegQueryValueExW, RegCloseKey, HKEY_CURRENT_USER, KEY_READ,
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
            KEY_READ,
            &mut key,
        );

        if result != ERROR_SUCCESS {
            return Ok(false);
        }

        let mut data_len = 0u32;
        let query_res = RegQueryValueExW(
            key,
            value_name,
            None,
            None,
            None,
            Some(&mut data_len),
        );

        let _ = RegCloseKey(key);
        Ok(query_res == ERROR_SUCCESS)
    }
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

#[cfg(target_os = "macos")]
fn check_autostart_registered() -> Result<bool> {
    let plist_path = dirs::home_dir()
        .context("Failed to get home directory")?
        .join("Library/LaunchAgents/com.syspulse.optimizer.plist");
    Ok(plist_path.exists())
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

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn check_autostart_registered() -> Result<bool> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settings_default_values() {
        let settings = Settings::default();
        assert_eq!(settings.language, Language::English);
        assert!(settings.dark_mode);
        assert!(!settings.light_mode);
        assert!(!settings.start_with_os);
        assert_eq!(settings.process_history_days, 30);
        assert_eq!(settings.quarantine_days, 7);
        assert!(!settings.permanent_delete);
        assert_eq!(settings.net_metrics_retention_days, 7);
    }

    #[test]
    fn test_theme_mutual_exclusivity_sanitization() {
        // Both true -> light_mode wins or dark_mode false
        let mut s1 = Settings {
            light_mode: true,
            dark_mode: true,
            ..Default::default()
        };
        s1.sanitize();
        assert!(s1.light_mode);
        assert!(!s1.dark_mode);

        // Both false -> dark_mode defaults to true
        let mut s2 = Settings {
            light_mode: false,
            dark_mode: false,
            ..Default::default()
        };
        s2.sanitize();
        assert!(!s2.light_mode);
        assert!(s2.dark_mode);

        // Zero retention days sanitized to sane defaults
        let mut s3 = Settings {
            process_history_days: 0,
            quarantine_days: 0,
            ..Default::default()
        };
        s3.sanitize();
        assert_eq!(s3.process_history_days, 30);
        assert_eq!(s3.quarantine_days, 7);
    }

    #[test]
    fn test_settings_toml_roundtrip() {
        let settings = Settings {
            language: Language::SpanishArgentina,
            dark_mode: false,
            light_mode: true,
            start_with_os: false,
            process_history_days: 45,
            quarantine_days: 14,
            permanent_delete: false,
            net_metrics_retention_days: 10,
        };

        let serialized = toml::to_string_pretty(&settings).unwrap();
        let deserialized: Settings = toml::from_str(&serialized).unwrap();
        assert_eq!(settings, deserialized);
        assert_eq!(deserialized.language, Language::SpanishArgentina);
        assert!(deserialized.light_mode);
        assert!(!deserialized.dark_mode);
    }

    #[test]
    fn test_disposable_settings_persistence() {
        let temp_dir = std::env::temp_dir().join(format!("syspulse_test_{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let temp_file = temp_dir.join("test_settings.toml");

        let settings = Settings {
            language: Language::SpanishArgentina,
            dark_mode: false,
            light_mode: true,
            start_with_os: false,
            process_history_days: 60,
            quarantine_days: 15,
            permanent_delete: false,
            net_metrics_retention_days: 14,
        };

        let content = toml::to_string_pretty(&settings).unwrap();
        std::fs::write(&temp_file, &content).unwrap();

        let read_content = std::fs::read_to_string(&temp_file).unwrap();
        let loaded: Settings = toml::from_str(&read_content).unwrap();
        assert_eq!(settings, loaded);

        let _ = std::fs::remove_file(&temp_file);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_autostart_query_is_non_destructive() {
        // Querying autostart registration should return Ok without altering anything
        let res = Settings::is_autostart_registered();
        assert!(res.is_ok(), "is_autostart_registered query should succeed safely: {:?}", res.err());
    }
}
