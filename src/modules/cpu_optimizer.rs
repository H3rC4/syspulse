use crate::models::ProcessEntry;
use anyhow::{Context, Result};
use std::collections::HashMap;
use sysinfo::{ProcessRefreshKind, System};

/// Lista de nombres canónicos de procesos críticos de Windows cuya prioridad nunca debe modificarse.
pub const CRITICAL_SYSTEM_PROCESSES: &[&str] = &[
    "system",
    "system idle process",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "lsm.exe",
    "winlogon.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "svchost.exe",
    "sihost.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "explorer.exe",
    "audiodg.exe",
    "spoolsv.exe",
    "securityhealthservice.exe",
    "mpcmdrun.exe",
    "msmpeng.exe",
];

/// Evalúa si un PID o nombre de proceso corresponde a un proceso crítico del sistema operativo o al propio proceso.
pub fn is_critical_process(pid: u32, name: Option<&str>) -> bool {
    if pid <= 4 || pid == std::process::id() {
        return true;
    }

    if let Some(n) = name {
        let n_lower = n.to_lowercase();
        let base_name = n_lower.trim_end_matches(".exe");
        for &crit in CRITICAL_SYSTEM_PROCESSES {
            let crit_base = crit.trim_end_matches(".exe");
            if n_lower == crit || base_name == crit_base {
                return true;
            }
        }
    }

    false
}

#[derive(Debug, Default)]
pub struct CpuOptimizer {
    focused_processes: HashMap<u32, FocusState>,
}

#[derive(Debug, Clone)]
struct FocusState {
    original_priority: u32,
    start_time_utc: u64,
}

impl CpuOptimizer {
    pub fn new() -> Self {
        Self {
            focused_processes: HashMap::new(),
        }
    }

    pub fn list_user_processes(&self) -> Vec<ProcessEntry> {
        let mut system = System::new_all();
        system.refresh_processes_specifics(ProcessRefreshKind::everything());

        system
            .processes()
            .iter()
            .filter_map(|(pid, process)| {
                let pid_u32 = pid.as_u32();
                if is_critical_process(pid_u32, Some(process.name())) {
                    return None;
                }

                Some(ProcessEntry {
                    pid: pid_u32,
                    name: process.name().to_string(),
                    executable_path: process
                        .exe()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    cpu_percent: process.cpu_usage(),
                    memory_mb: process.memory() / 1024 / 1024,
                    focused: self.focused_processes.contains_key(&pid_u32),
                })
            })
            .collect()
    }

    pub fn toggle_focus(&mut self, pid: u32) -> Result<()> {
        if self.focused_processes.contains_key(&pid) {
            self.unfocus(pid)?;
        } else {
            self.focus(pid)?;
        }
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn focus(&mut self, pid: u32) -> Result<()> {
        use windows::Win32::System::Threading::{
            GetPriorityClass, OpenProcess, SetPriorityClass, ABOVE_NORMAL_PRIORITY_CLASS,
            HIGH_PRIORITY_CLASS, REALTIME_PRIORITY_CLASS,
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION,
            QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
        };
        use windows::Win32::Foundation::CloseHandle;
        use windows::core::PWSTR;

        if is_critical_process(pid, None) {
            anyhow::bail!("Cannot alter priority of protected system or current process (PID {pid})");
        }

        unsafe {
            let handle = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION,
                false,
                pid,
            )
            .with_context(|| format!("Failed to open process (PID {pid}): insufficient permissions or process terminated"))?;

            // Query image name for critical process check
            let mut name_buf = [0u16; 1024];
            let mut size = name_buf.len() as u32;
            if QueryFullProcessImageNameW(handle, PROCESS_NAME_FORMAT(0), PWSTR(name_buf.as_mut_ptr()), &mut size).is_ok() {
                let full_path = String::from_utf16_lossy(&name_buf[..size as usize]);
                let exe_name = std::path::Path::new(&full_path)
                    .file_name()
                    .map(|f| f.to_string_lossy())
                    .unwrap_or_default();
                if is_critical_process(pid, Some(&exe_name)) {
                    let _ = CloseHandle(handle);
                    anyhow::bail!("Cannot elevate priority of critical system process '{exe_name}' (PID {pid})");
                }
            }

            let original = GetPriorityClass(handle);
            if original == 0 {
                let _ = CloseHandle(handle);
                anyhow::bail!("Failed to get process priority class for PID {pid}");
            }

            // Check unsafe priority classes
            if original == REALTIME_PRIORITY_CLASS.0 || original == HIGH_PRIORITY_CLASS.0 {
                let _ = CloseHandle(handle);
                anyhow::bail!("Refusing to alter priority of high/realtime process (PID {pid}, class 0x{original:X})");
            }
            if original == ABOVE_NORMAL_PRIORITY_CLASS.0 {
                let _ = CloseHandle(handle);
                anyhow::bail!("Process PID {pid} is already running with above-normal priority");
            }

            let res = SetPriorityClass(handle, ABOVE_NORMAL_PRIORITY_CLASS);
            let _ = CloseHandle(handle);
            res.with_context(|| format!("Failed to set priority class for PID {pid}"))?;

            let start_time_utc = crate::modules::pie::get_process_identity(pid)
                .map(|id| id.start_time_utc)
                .unwrap_or(0);

            self.focused_processes.insert(
                pid,
                FocusState {
                    original_priority: original,
                    start_time_utc,
                },
            );
        }

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn unfocus(&mut self, pid: u32) -> Result<()> {
        use windows::Win32::System::Threading::{
            OpenProcess, SetPriorityClass, PROCESS_SET_INFORMATION, PROCESS_CREATION_FLAGS,
        };
        use windows::Win32::Foundation::CloseHandle;

        let state = self
            .focused_processes
            .remove(&pid)
            .context("Process was not focused")?;

        // Protect against PID reuse: check start_time_utc
        if state.start_time_utc > 0 {
            if let Some(current_identity) = crate::modules::pie::get_process_identity(pid) {
                if current_identity.start_time_utc != state.start_time_utc {
                    anyhow::bail!(
                        "PID {pid} has been recycled (start time mismatch: expected {}, found {}); refusing to restore priority on recycled PID",
                        state.start_time_utc,
                        current_identity.start_time_utc
                    );
                }
            } else {
                tracing::info!("Process PID {pid} has already exited; cleaned up focus state without modifying system");
                return Ok(());
            }
        }

        unsafe {
            let handle = OpenProcess(PROCESS_SET_INFORMATION, false, pid)
                .with_context(|| format!("Failed to open process (PID {pid}) for restoring priority"))?;

            let res = SetPriorityClass(handle, PROCESS_CREATION_FLAGS(state.original_priority));
            let _ = CloseHandle(handle);
            res.with_context(|| format!("Failed to restore priority class for PID {pid}"))?;
        }

        Ok(())
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn focus(&mut self, pid: u32) -> Result<()> {
        if is_critical_process(pid, None) {
            anyhow::bail!("Cannot alter priority of protected system or current process (PID {pid})");
        }

        let original = unsafe { libc::getpriority(libc::PRIO_PROCESS, pid as libc::id_t) };
        if original < 0 && std::io::Error::last_os_error().raw_os_error() != Some(0) {
            anyhow::bail!("Failed to get process nice value");
        }

        let result = unsafe { libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, -5) };
        if result != 0 {
            anyhow::bail!("Failed to set process nice value");
        }

        let start_time_utc = crate::modules::pie::get_process_identity(pid)
            .map(|id| id.start_time_utc)
            .unwrap_or(0);

        self.focused_processes.insert(
            pid,
            FocusState {
                original_priority: original as u32,
                start_time_utc,
            },
        );

        Ok(())
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn unfocus(&mut self, pid: u32) -> Result<()> {
        let state = self
            .focused_processes
            .remove(&pid)
            .context("Process was not focused")?;

        let result = unsafe { libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, state.original_priority as i32) };
        if result != 0 {
            anyhow::bail!("Failed to restore process nice value");
        }

        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    fn focus(&mut self, pid: u32) -> Result<()> {
        tracing::warn!("CPU Focus is not implemented on this platform (pid={})", pid);
        self.focused_processes.insert(
            pid,
            FocusState {
                original_priority: 0,
                start_time_utc: 0,
            },
        );
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    fn unfocus(&mut self, pid: u32) -> Result<()> {
        self.focused_processes.remove(&pid);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_critical_process_pid_boundaries() {
        assert!(is_critical_process(0, None), "PID 0 (Idle) must be critical");
        assert!(is_critical_process(4, None), "PID 4 (System) must be critical");
        assert!(is_critical_process(std::process::id(), None), "Current process PID must be critical");
        assert!(!is_critical_process(99999, None), "Non-reserved PID without name is not critical");
    }

    #[test]
    fn test_is_critical_process_names() {
        assert!(is_critical_process(100, Some("csrss.exe")));
        assert!(is_critical_process(101, Some("CSRSS.EXE")));
        assert!(is_critical_process(102, Some("csrss")));
        assert!(is_critical_process(103, Some("services.exe")));
        assert!(is_critical_process(104, Some("lsass.exe")));
        assert!(is_critical_process(105, Some("dwm.exe")));
        assert!(is_critical_process(106, Some("svchost.exe")));
        assert!(is_critical_process(107, Some("explorer.exe")));
        assert!(is_critical_process(108, Some("system")));
        assert!(is_critical_process(109, Some("registry")));

        assert!(!is_critical_process(110, Some("notepad.exe")));
        assert!(!is_critical_process(111, Some("game.exe")));
        assert!(!is_critical_process(112, Some("calculator.exe")));
    }

    #[test]
    fn test_focus_rejects_critical_pids() {
        let mut opt = CpuOptimizer::new();
        assert!(opt.focus(0).is_err());
        assert!(opt.focus(4).is_err());
        assert!(opt.focus(std::process::id()).is_err());
    }

    #[test]
    fn test_focus_rejects_nonexistent_process() {
        let mut opt = CpuOptimizer::new();
        let res = opt.focus(4194300); // unlikely PID
        assert!(res.is_err());
    }

    #[test]
    fn test_pid_reuse_protection_on_unfocus() {
        let mut opt = CpuOptimizer::new();
        let current_pid = std::process::id();

        // Inject simulated focus state with stale start_time_utc for current process
        opt.focused_processes.insert(
            current_pid,
            FocusState {
                original_priority: 32, // NORMAL_PRIORITY_CLASS
                start_time_utc: 1,      // non-matching historical timestamp
            },
        );

        let res = opt.unfocus(current_pid);
        assert!(res.is_err(), "Unfocus must fail when PID start time has recycled");
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("recycled") || err_msg.contains("start time mismatch"));
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_disposable_process_focus_lifecycle() {
        // Spawn disposable dummy process (cmd.exe waiting)
        let child = std::process::Command::new("cmd.exe")
            .args(["/C", "pause"])
            .spawn();

        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Skipping disposable test: unable to spawn cmd.exe: {e}");
                return;
            }
        };

        let child_pid = child.id();
        let mut opt = CpuOptimizer::new();

        // Focus disposable process
        let focus_res = opt.focus(child_pid);
        assert!(focus_res.is_ok(), "Focus on disposable child process should succeed: {:?}", focus_res.err());
        assert!(opt.focused_processes.contains_key(&child_pid));

        // Attempting to focus already focused process should fail
        let double_focus = opt.focus(child_pid);
        assert!(double_focus.is_err(), "Double focus should be rejected");

        // Unfocus disposable process
        let unfocus_res = opt.unfocus(child_pid);
        assert!(unfocus_res.is_ok(), "Unfocus on disposable child process should succeed: {:?}", unfocus_res.err());
        assert!(!opt.focused_processes.contains_key(&child_pid));

        // Kill disposable process
        let _ = child.kill();
        let _ = child.wait();
    }
}
