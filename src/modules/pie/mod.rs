#![allow(unused_imports)]
#![allow(dead_code)]

pub mod bus;
pub mod engine;
pub mod models;
pub mod rules;
#[cfg(test)]
mod tests;

pub use bus::PulseEventBus;
pub use engine::PulseIntelligenceEngine;
pub use models::{
    Incident, IncidentCategory, IncidentEvidence, IncidentSeverity, IncidentStatus,
    PersistedNetDevice, PersistedNetMetric, ProcessIdentity, PulseCriticalEvent, PulseEnvelope,
    TelemetryEvent,
};

/// Obtiene la identidad unívoca de un proceso en ejecución mediante su PID y tiempo de creación UTC.
#[cfg(target_os = "windows")]
pub fn get_process_identity(pid: u32) -> Option<ProcessIdentity> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, GetProcessTimes, PROCESS_QUERY_LIMITED_INFORMATION};
    use windows::Win32::Foundation::FILETIME;

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut creation_time = FILETIME::default();
        let mut exit_time = FILETIME::default();
        let mut kernel_time = FILETIME::default();
        let mut user_time = FILETIME::default();

        let success = GetProcessTimes(
            handle,
            &mut creation_time,
            &mut exit_time,
            &mut kernel_time,
            &mut user_time,
        ).is_ok();

        let _ = CloseHandle(handle);

        if success {
            // FILETIME representa intervalos de 100ns desde el 1 de enero de 1601 UTC.
            // Conversión a epoch Unix (1 de enero de 1970 UTC):
            let intervals = ((creation_time.dwHighDateTime as u64) << 32) | (creation_time.dwLowDateTime as u64);
            const FILETIME_TO_UNIX_OFFSET: u64 = 116444736000000000;
            if intervals >= FILETIME_TO_UNIX_OFFSET {
                let unix_secs = (intervals - FILETIME_TO_UNIX_OFFSET) / 10_000_000;
                return Some(ProcessIdentity::new(pid, unix_secs));
            }
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
pub fn get_process_identity(pid: u32) -> Option<ProcessIdentity> {
    // En sistemas POSIX / fallback
    Some(ProcessIdentity::new(pid, 0))
}
