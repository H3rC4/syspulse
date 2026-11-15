use crate::models::{CoreUsage, DiskInfo, SystemStats, TempInfo, TopProcess};
use sysinfo::{Components, Disks, Networks, System};
use std::time::Instant;

pub struct SysMonitor {
    system: System,
    networks: Networks,
    last_network_check: Option<Instant>,
    last_bytes_sent: u64,
    last_bytes_received: u64,
    event_bus: Option<crate::modules::pie::PulseEventBus>,
}

impl SysMonitor {
    pub fn new() -> Self {
        Self::new_with_bus(None)
    }

    pub fn new_with_bus(event_bus: Option<crate::modules::pie::PulseEventBus>) -> Self {
        let mut system = System::new();
        system.refresh_all();

        let networks = Networks::new_with_refreshed_list();
        let (last_bytes_sent, last_bytes_received) = Self::get_network_totals(&networks);

        Self {
            system,
            networks,
            last_network_check: Some(Instant::now()),
            last_bytes_sent,
            last_bytes_received,
            event_bus,
        }
    }

    #[allow(dead_code)]
    pub fn set_event_bus(&mut self, bus: crate::modules::pie::PulseEventBus) {
        self.event_bus = Some(bus);
    }

    pub fn refresh(&mut self) -> SystemStats {
        // Refresh system info
        self.system.refresh_all();

        // CPU
        let cpu_usage = self.system.global_cpu_info().cpu_usage();
        let cores: Vec<CoreUsage> = self
            .system
            .cpus()
            .iter()
            .map(|cpu| CoreUsage {
                name: cpu.name().to_string(),
                usage: cpu.cpu_usage(),
            })
            .collect();

        // Memory
        let total_memory = self.system.total_memory();
        let used_memory = self.system.used_memory();
        let total_swap = self.system.total_swap();
        let used_swap = self.system.used_swap();

        // Load average
        let load_avg = System::load_average();

        // Disks
        let disks = Disks::new_with_refreshed_list();
        let disk_infos: Vec<DiskInfo> = disks
            .iter()
            .map(|disk| DiskInfo {
                name: disk.name().to_string_lossy().to_string(),
                mount_point: disk.mount_point().to_string_lossy().to_string(),
                total_bytes: disk.total_space(),
                available_bytes: disk.available_space(),
            })
            .collect();

        // Network
        self.networks.refresh();
        let (current_sent, current_received) = Self::get_network_totals(&self.networks);
        let now = Instant::now();

        let (up_bps, down_bps) = if let Some(last_check) = self.last_network_check {
            let elapsed = now.duration_since(last_check).as_secs_f64();
            if elapsed > 0.0 {
                let up =
                    (current_sent.saturating_sub(self.last_bytes_sent) as f64 * 8.0) / elapsed;
                let down = (current_received.saturating_sub(self.last_bytes_received) as f64 * 8.0)
                    / elapsed;
                (up, down)
            } else {
                (0.0, 0.0)
            }
        } else {
            (0.0, 0.0)
        };

        self.last_network_check = Some(now);
        self.last_bytes_sent = current_sent;
        self.last_bytes_received = current_received;

        // Temperatures
        let components = Components::new_with_refreshed_list();
        let temps: Vec<TempInfo> = components
            .iter()
            .filter_map(|comp| {
                let temp = comp.temperature();
                if temp > 0.0 {
                    Some(TempInfo {
                        label: comp.label().to_string(),
                        temperature: temp,
                    })
                } else {
                    None
                }
            })
            .collect();

        // Uptime
        let uptime_seconds = System::uptime();

        // Top processes
        let mut processes: Vec<_> = self.system.processes().values().collect();

        // Top 5 by CPU
        processes.sort_by(|a, b| b.cpu_usage().partial_cmp(&a.cpu_usage()).unwrap_or(std::cmp::Ordering::Equal));
        let top_cpu: Vec<TopProcess> = processes
            .iter()
            .take(5)
            .map(|p| TopProcess {
                name: p.name().to_string(),
                pid: p.pid().as_u32(),
                value: p.cpu_usage(),
                memory_mb: p.memory() / 1024 / 1024,
            })
            .collect();

        // Top 5 by RAM
        processes.sort_by_key(|b| std::cmp::Reverse(b.memory()));
        let top_ram: Vec<TopProcess> = processes
            .iter()
            .take(5)
            .map(|p| TopProcess {
                name: p.name().to_string(),
                pid: p.pid().as_u32(),
                value: p.memory() as f32,
                memory_mb: p.memory() / 1024 / 1024,
            })
            .collect();

        // Emitir telemetría al Event Bus de PIE si está conectado
        if let Some(bus) = &self.event_bus {
            let logical_cpus = self.system.cpus().len().max(1) as f32;
            let top = top_cpu.first().map(|p| (p.pid, p.name.clone(), p.value / logical_cpus, p.value));
            bus.emit_telemetry(crate::modules::pie::TelemetryEvent::CpuLoad {
                global_usage: cpu_usage,
                top_process: top,
            });

            let mem_percent = if total_memory > 0 {
                (used_memory as f32 / total_memory as f32) * 100.0
            } else {
                0.0
            };

            let top_proc_mem: Vec<_> = top_ram
                .iter()
                .take(5)
                .map(|p| {
                    let start_time_utc = crate::modules::pie::get_process_identity(p.pid)
                        .map(|id| id.start_time_utc)
                        .unwrap_or(0);
                    (
                        crate::modules::pie::ProcessIdentity::new(p.pid, start_time_utc),
                        p.name.clone(),
                        p.value as u64,
                    )
                })
                .collect();

            bus.emit_telemetry(crate::modules::pie::TelemetryEvent::MemoryPressure {
                used_bytes: used_memory,
                total_bytes: total_memory,
                usage_percent: mem_percent,
                top_processes: top_proc_mem,
            });

            bus.emit_telemetry(crate::modules::pie::TelemetryEvent::NetworkThroughput {
                rx_bytes_sec: (down_bps / 8.0) as u64,
                tx_bytes_sec: (up_bps / 8.0) as u64,
            });

            for t in &temps {
                let lbl = t.label.to_lowercase();
                let thresh = if lbl.contains("nvme") || lbl.contains("disk") || lbl.contains("drive") {
                    70.0
                } else if lbl.contains("gpu") {
                    88.0
                } else if lbl.contains("cpu") || lbl.contains("core") || lbl.contains("package") {
                    90.0
                } else {
                    85.0
                };

                if t.temperature > thresh {
                    bus.emit_telemetry(crate::modules::pie::TelemetryEvent::ThermalAlert {
                        sensor_label: t.label.clone(),
                        temp_celsius: t.temperature,
                    });
                }
            }
        }

        SystemStats {
            cpu_usage,
            cores,
            total_memory,
            used_memory,
            total_swap,
            used_swap,
            load_avg_1: load_avg.one,
            load_avg_5: load_avg.five,
            load_avg_15: load_avg.fifteen,
            disks: disk_infos,
            network_up_bps: up_bps,
            network_down_bps: down_bps,
            temperatures: temps,
            uptime_seconds,
            top_cpu,
            top_ram,
        }
    }

    fn get_network_totals(networks: &Networks) -> (u64, u64) {
        let mut total_sent = 0u64;
        let mut total_received = 0u64;

        for (_, data) in networks.iter() {
            total_sent += data.total_transmitted();
            total_received += data.total_received();
        }

        (total_sent, total_received)
    }
}

impl Default for SysMonitor {
    fn default() -> Self {
        Self::new()
    }
}
