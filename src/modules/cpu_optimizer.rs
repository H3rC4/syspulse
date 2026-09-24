use crate::models::ProcessEntry;
use anyhow::{Context, Result};
use std::collections::HashMap;
use sysinfo::{ProcessRefreshKind, System};

#[derive(Debug, Default)]
pub struct CpuOptimizer {
    focused_processes: HashMap<u32, FocusState>,
}

#[derive(Debug, Clone)]
struct FocusState {
    original_priority: u32,
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

        let current_pid = std::process::id();

        system
            .processes()
            .iter()
            .filter_map(|(pid, process)| {
                let pid_u32 = pid.as_u32();
                if pid_u32 == current_pid {
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
                    memory_mb: process.memory() / 1024,
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
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION,
        };
        use windows::Win32::Foundation::CloseHandle;

        unsafe {
            let handle = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION,
                false,
                pid,
            )
            .context("Failed to open process for setting priority")?;

            let original = GetPriorityClass(handle);
            if original == 0 {
                let _ = CloseHandle(handle);
                anyhow::bail!("Failed to get process priority class");
            }

            SetPriorityClass(handle, ABOVE_NORMAL_PRIORITY_CLASS)
                .context("Failed to set priority class")?;

            let _ = CloseHandle(handle);

            self.focused_processes.insert(
                pid,
                FocusState {
                    original_priority: original,
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

        unsafe {
            let handle = OpenProcess(PROCESS_SET_INFORMATION, false, pid)
                .context("Failed to open process for restoring priority")?;

            let _ = SetPriorityClass(handle, PROCESS_CREATION_FLAGS(state.original_priority));
            let _ = CloseHandle(handle);
        }

        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn focus(&mut self, pid: u32) -> Result<()> {
        let original = unsafe { libc::getpriority(libc::PRIO_PROCESS, pid as libc::id_t) };
        if original < 0 && std::io::Error::last_os_error().raw_os_error() != Some(0) {
            anyhow::bail!("Failed to get process nice value");
        }

        let result = unsafe { libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, -5) };
        if result != 0 {
            anyhow::bail!("Failed to set process nice value");
        }

        self.focused_processes.insert(
            pid,
            FocusState {
                original_priority: original as u32,
            },
        );

        Ok(())
    }

    #[cfg(target_os = "macos")]
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

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    fn focus(&mut self, pid: u32) -> Result<()> {
        tracing::warn!("CPU Focus is not implemented on this platform (pid={})", pid);
        self.focused_processes.insert(
            pid,
            FocusState {
                original_priority: 0,
            },
        );
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    fn unfocus(&mut self, pid: u32) -> Result<()> {
        self.focused_processes.remove(&pid);
        Ok(())
    }
}
