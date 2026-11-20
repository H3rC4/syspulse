mod models;
mod modules;

use anyhow::{Context, Result};
use clap::Parser;
use models::Language;
use modules::cleaner::Cleaner;
use modules::config::Settings;
use modules::cpu_optimizer::CpuOptimizer;
use modules::i18n;
use modules::process_hunter::{ExportFormat, ProcessHunter, ProcessHunterCommand};
use modules::sys_monitor::SysMonitor;
use modules::tray::{self, TrayEvent};
use slint::Model;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing_subscriber::{fmt, EnvFilter};

slint::include_modules!();

// Theme switching is handled via dark-mode property in Slint.
// Light mode support requires runtime theme globals which Slint doesn't fully support yet.
// For now, dark mode is the default and only fully supported theme.

#[derive(Parser, Debug)]
#[command(name = "syspulse", version, about = "Cross-platform system optimizer")]
struct Args {
    /// Start minimized to system tray
    #[arg(long)]
    background: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Setup logging
    fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    tracing::info!("SysPulse starting");

    // Load settings
    let settings = Settings::load().unwrap_or_default();
    i18n::set_global_language(settings.language);

    // Initialize modules
    // Initialize Pulse Intelligence Engine (PIE) Event Bus
    let (event_bus, pie_receiver) = crate::modules::pie::bus::PulseEventBus::new(
        crate::modules::pie::bus::DEFAULT_CRITICAL_CAPACITY,
        crate::modules::pie::bus::DEFAULT_TELEMETRY_CAPACITY,
    );

    // Launch PIE Engine background loop
    match crate::modules::pie::PulseIntelligenceEngine::new() {
        Ok(pie_engine) => {
            tokio::spawn(async move {
                pie_engine.run_loop(pie_receiver).await;
            });
            tracing::info!("Pulse Intelligence Engine (PIE) initialized and running");
        }
        Err(e) => {
            tracing::warn!("Failed to initialize PIE engine: {}", e);
        }
    }

    let cleaner = Arc::new(Cleaner::new().context("Failed to initialize Cleaner")?);
    let cpu_optimizer = Arc::new(Mutex::new(CpuOptimizer::new()));
    let sys_monitor = Arc::new(Mutex::new(SysMonitor::new_with_bus(Some(event_bus.clone()))));
    let duplicate_scan_cache = Arc::new(Mutex::new(HashMap::<String, u64>::new()));
    
    // Shared pause flag for cleaner operations
    let pause_flag = Arc::new(AtomicBool::new(false));
    
    // Shared cancellation token for cleaner operations
    let cancel_flag = Arc::new(AtomicBool::new(false));

    let (process_hunter, hunter_cmd_rx) =
        ProcessHunter::new_with_bus(Some(event_bus.clone())).context("Failed to initialize Process Hunter")?;
    let hunter_cmd_tx = process_hunter.command_sender();
    let process_hunter = Arc::new(process_hunter);

    // Start process hunter background task
    let history_days = settings.process_history_days;
    let hunter_task_clone = process_hunter.clone();
    tokio::spawn(async move {
        hunter_task_clone.start(hunter_cmd_rx, history_days).await;
    });

    // Start Network Guardian background task (Fase 1: Latency & Gateway monitor)
    let ng_bus = event_bus.clone();
    tokio::spawn(async move {
        let mut network_guardian = crate::modules::network_guardian::NetworkGuardian::new(Some(ng_bus));
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
        loop {
            interval.tick().await;
            if let Err(e) = network_guardian.run_health_check().await {
                tracing::debug!("Network Guardian background check: {}", e);
            }
        }
    });

    // Spawn tray
    tracing::info!("Spawning system tray...");
    let (tray_event_tx, mut tray_event_rx) = mpsc::unbounded_channel::<TrayEvent>();
    let tray_handle = Arc::new(tray::spawn_tray(tray_event_tx).map_err(|e| anyhow::anyhow!(e))?);
    let hunter_paused = Arc::new(AtomicBool::new(false));
    tracing::info!("System tray spawned");

    // Create Slint UI
    tracing::info!("Creating Slint UI...");
    let ui = AppWindow::new().context("Failed to create Slint window")?;
    tracing::info!("Slint UI created");

    // Set initial properties
    ui.set_app_version(env!("CARGO_PKG_VERSION").into());
    ui.set_language_index(match settings.language {
        Language::English => 0,
        Language::SpanishArgentina => 1,
    });
    ui.set_dark_mode(settings.dark_mode);
    ui.set_start_with_os(settings.start_with_os);
    ui.set_history_days(settings.process_history_days as f32);
    ui.set_quarantine_days(settings.quarantine_days as f32);
    ui.set_permanent_delete(settings.permanent_delete);  // NUEVO

    // Hide window if --background
    if args.background {
        ui.hide().ok();
    }

    // Cleanup old quarantine entries (temporarily suspended by security audit A11.09)
    tracing::info!("Quarantine auto-purge check (temporarily suspended by security audit A11.09)...");
    if let Err(e) = cleaner.purge_old_quarantine(settings.quarantine_days) {
        tracing::warn!("Failed to check quarantine purge: {}", e);
    }
    tracing::info!("Quarantine check complete (containment active: 0 files deleted)");
    tracing::info!("Setting up callbacks...");

    // ── Callback: Reset Scan ──
    let ui_weak = ui.as_weak();
    let cancel_flag_clone = cancel_flag.clone();
    let pause_flag_clone = pause_flag.clone();
    ui.on_reset_scan(move || {
        // Cancel any running operation
        cancel_flag_clone.store(true, Ordering::SeqCst);
        pause_flag_clone.store(false, Ordering::SeqCst);
        
        let ui_weak = ui_weak.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_cleaner_scanning(false);
                ui.set_cleaner_paused(false);
                ui.set_cleaner_status("Ready".into());
                ui.set_cleaner_progress(0.0);
                ui.set_cleaner_files_found(0);
                ui.set_cleaner_total_files(0);
                ui.set_cleaner_bytes_text("0 B".into());
                ui.set_duplicate_groups(slint::ModelRc::new(slint::VecModel::from(Vec::<DuplicateGroupData>::new())));
            }
        });
    });

    // ─ Callback: Scan System Temp ──
    let ui_weak = ui.as_weak();
    let cleaner_clone = cleaner.clone();
    let pause_flag_clone = pause_flag.clone();
    let cancel_flag_clone = cancel_flag.clone();
    ui.on_scan_system_temp(move || {
        let ui_weak = ui_weak.clone();
        let cleaner = cleaner_clone.clone();
        let pause_flag = pause_flag_clone.clone();
        let cancel_flag = cancel_flag_clone.clone();
        
        // Reset cancel flag and start new operation
        cancel_flag.store(false, Ordering::SeqCst);
        pause_flag.store(false, Ordering::SeqCst);
        
        tokio::spawn(async move {
            let token = tokio_util::sync::CancellationToken::new();
            let ui_weak_clone = ui_weak.clone();

            slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak_clone.upgrade() {
                    ui.set_cleaner_scanning(true);
                    ui.set_cleaner_paused(false);
                    ui.set_cleaner_status("Scanning...".into());
                    ui.set_cleaner_progress(0.0);
                }
            })
            .ok();

            let start_time = std::time::Instant::now();
            let result = cleaner
                .scan_system_temp(token, pause_flag, cancel_flag, {
                    let ui_weak = ui_weak.clone();
                    move |files, bytes| {
                        let ui_weak = ui_weak.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = ui_weak.upgrade() {
                                ui.set_cleaner_files_found(files as i32);
                                ui.set_cleaner_bytes_text(modules::cleaner::format_bytes(bytes).into());
                                // Update progress based on elapsed time (max 95% until complete)
                                let elapsed = start_time.elapsed().as_secs_f32();
                                let progress = (elapsed / 60.0).min(0.95);
                                ui.set_cleaner_progress(progress);
                            }
                        });
                    }
                })
                .await;

            slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_cleaner_scanning(false);
                    ui.set_cleaner_paused(false);
                    ui.set_cleaner_progress(1.0);
                    match result {
                        Ok(r) => {
                            ui.set_cleaner_total_files(r.files_found as i32);
                            ui.set_cleaner_status(
                                format!("Found {} files", r.files_found).into(),
                            );
                        }
                        Err(e) => {
                            ui.set_cleaner_status(format!("Error: {}", e).into());
                        }
                    }
                }
            })
            .ok();
        });
    });

    // ─ Callback: Clean System Temp ──
    let ui_weak = ui.as_weak();
    let cleaner_clone = cleaner.clone();
    let pause_flag_clone = pause_flag.clone();
    let cancel_flag_clone = cancel_flag.clone();
    ui.on_clean_system_temp(move || {
        let ui_weak = ui_weak.clone();
        let cleaner = cleaner_clone.clone();
        let pause_flag = pause_flag_clone.clone();
        let cancel_flag = cancel_flag_clone.clone();
        
        let total_files = ui_weak
            .upgrade()
            .map(|ui| ui.get_cleaner_files_found())
            .unwrap_or(0);
        if total_files == 0 {
            return;
        }
        let total_bytes_text = ui_weak
            .upgrade()
            .map(|ui| ui.get_cleaner_bytes_text().to_string())
            .unwrap_or_default();

        // Confirmation before irreversible operation (Block 4 / A11.13)
        let confirmed = rfd::MessageDialog::new()
            .set_title("Confirm System Cleaning")
            .set_description(format!(
                "Are you sure you want to clean {} files ({})?\nAll cleaned files will be safely sent to the Recycle Bin.",
                total_files, total_bytes_text
            ))
            .set_buttons(rfd::MessageButtons::YesNo)
            .show();

        if !matches!(confirmed, rfd::MessageDialogResult::Yes) {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_cleaner_status("Cleaning cancelled by user".into());
            }
            return;
        }

        // Reset cancel flag and start new operation
        cancel_flag.store(false, Ordering::SeqCst);
        pause_flag.store(false, Ordering::SeqCst);
        
        tokio::spawn(async move {
            // Leer configuración permanent_delete
            let permanent_delete = Settings::load()
                .map(|s| s.permanent_delete)
                .unwrap_or(false);
            
            let token = tokio_util::sync::CancellationToken::new();
            let ui_weak_clone = ui_weak.clone();

            slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak_clone.upgrade() {
                    ui.set_cleaner_scanning(true);
                    ui.set_cleaner_paused(false);
                    ui.set_cleaner_status("Cleaning...".into());
                    ui.set_cleaner_progress(0.0);
                    ui.set_cleaner_total_files(total_files);
                }
            })
            .ok();

            let start_time = std::time::Instant::now();
            let result = cleaner
                .clean_system_temp(token, pause_flag, cancel_flag, {  // progress_callback
                    let ui_weak = ui_weak.clone();
                    move |files, bytes| {
                        let ui_weak = ui_weak.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = ui_weak.upgrade() {
                                ui.set_cleaner_files_found(files as i32);
                                ui.set_cleaner_bytes_text(modules::cleaner::format_bytes(bytes).into());
                                // Update progress based on total files
                                if total_files > 0 {
                                    let progress = (files as f32 / total_files as f32).min(0.95);
                                    ui.set_cleaner_progress(progress);
                                } else {
                                    let elapsed = start_time.elapsed().as_secs_f32();
                                    let progress = (elapsed / 120.0).min(0.95);
                                    ui.set_cleaner_progress(progress);
                                }
                            }
                        });
                    }
                }, permanent_delete)
                .await;

            slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_cleaner_scanning(false);
                    ui.set_cleaner_paused(false);
                    ui.set_cleaner_progress(1.0);
                    match result {
                        Ok(r) => {
                            let status = if r.errors.is_empty() {
                                format!("Sent {} files to Recycle Bin", r.files_found)
                            } else {
                                format!("Sent {} files to Recycle Bin ({} errors: {})", r.files_found, r.errors.len(), r.errors[0])
                            };
                            ui.set_cleaner_status(status.into());
                            if !r.errors.is_empty() {
                                tracing::warn!("Clean errors: {:?}", r.errors);
                            }
                        }
                        Err(e) => {
                            ui.set_cleaner_status(format!("Clean error: {:#}", e).into());
                        }
                    }
                }
            })
            .ok();
        });
    });

    // ── Callback: Select Folder for Duplicates ──
    let ui_weak = ui.as_weak();
    ui.on_select_folder(move || {
        if let Some(path) = rfd::FileDialog::new()
            .set_title("Select folder to scan for duplicates")
            .pick_folder()
        {
            let path_str = path.to_string_lossy().to_string();
            let ui_weak = ui_weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_duplicate_folder_path(path_str.into());
                }
            });
        }
    });

    // ── Callback: Keep Oldest (select all except oldest) ──
    let ui_weak = ui.as_weak();
    ui.on_keep_oldest(move |group_index| {
        let ui_weak = ui_weak.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let groups = ui.get_duplicate_groups();
                let mut updated_groups = Vec::new();
                
                for i in 0..groups.row_count() {
                    if let Some(group) = groups.row_data(i) {
                        if i == group_index as usize {
                            // Only modify the selected group
                            let mut files = Vec::new();
                            for j in 0..group.files.row_count() {
                                if let Some(file) = group.files.row_data(j) {
                                    files.push(file);
                                }
                            }
                            
                            // Sort by created date (oldest first), then by filename as tiebreaker
                            files.sort_by(|a, b| {
                                let a_date = chrono::NaiveDateTime::parse_from_str(a.created.as_ref(), "%Y-%m-%d %H:%M")
                                    .unwrap_or_default();
                                let b_date = chrono::NaiveDateTime::parse_from_str(b.created.as_ref(), "%Y-%m-%d %H:%M")
                                    .unwrap_or_default();
                                let date_cmp = a_date.cmp(&b_date);
                                if date_cmp == std::cmp::Ordering::Equal {
                                    // If dates are equal, sort by filename
                                    let a_name = std::path::Path::new(&a.path.to_string())
                                        .file_name()
                                        .unwrap_or_default()
                                        .to_string_lossy()
                                        .to_string();
                                    let b_name = std::path::Path::new(&b.path.to_string())
                                        .file_name()
                                        .unwrap_or_default()
                                        .to_string_lossy()
                                        .to_string();
                                    a_name.cmp(&b_name)
                                } else {
                                    date_cmp
                                }
                            });
                            
                            // Select all except the first (oldest)
                            let updated_files: Vec<DuplicateFileData> = files
                                .into_iter()
                                .enumerate()
                                .map(|(idx, mut f)| {
                                    f.selected = idx > 0;
                                    f
                                })
                                .collect();
                            
                            updated_groups.push(DuplicateGroupData {
                                hash: group.hash,
                                size: group.size,
                                raw_size: group.raw_size,
                                files: slint::ModelRc::new(slint::VecModel::from(updated_files)),
                            });
                        } else {
                            // Keep other groups unchanged
                            updated_groups.push(group);
                        }
                    }
                }
                
                ui.set_duplicate_groups(slint::ModelRc::new(slint::VecModel::from(updated_groups)));
            }
        });
    });

    // ── Callback: Keep Newest (select all except newest) ──
    let ui_weak = ui.as_weak();
    ui.on_keep_newest(move |group_index| {
        let ui_weak = ui_weak.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let groups = ui.get_duplicate_groups();
                let mut updated_groups = Vec::new();
                
                for i in 0..groups.row_count() {
                    if let Some(group) = groups.row_data(i) {
                        if i == group_index as usize {
                            // Only modify the selected group
                            let mut files = Vec::new();
                            for j in 0..group.files.row_count() {
                                if let Some(file) = group.files.row_data(j) {
                                    files.push(file);
                                }
                            }
                            
                            // Sort by created date (newest first), then by filename as tiebreaker
                            files.sort_by(|a, b| {
                                let a_date = chrono::NaiveDateTime::parse_from_str(a.created.as_ref(), "%Y-%m-%d %H:%M")
                                    .unwrap_or_default();
                                let b_date = chrono::NaiveDateTime::parse_from_str(b.created.as_ref(), "%Y-%m-%d %H:%M")
                                    .unwrap_or_default();
                                let date_cmp = b_date.cmp(&a_date);
                                if date_cmp == std::cmp::Ordering::Equal {
                                    // If dates are equal, sort by filename
                                    let a_name = std::path::Path::new(&a.path.to_string())
                                        .file_name()
                                        .unwrap_or_default()
                                        .to_string_lossy()
                                        .to_string();
                                    let b_name = std::path::Path::new(&b.path.to_string())
                                        .file_name()
                                        .unwrap_or_default()
                                        .to_string_lossy()
                                        .to_string();
                                    a_name.cmp(&b_name)
                                } else {
                                    date_cmp
                                }
                            });
                            
                            // Select all except the first (newest)
                            let updated_files: Vec<DuplicateFileData> = files
                                .into_iter()
                                .enumerate()
                                .map(|(idx, mut f)| {
                                    f.selected = idx > 0;
                                    f
                                })
                                .collect();
                            
                            updated_groups.push(DuplicateGroupData {
                                hash: group.hash,
                                size: group.size,
                                raw_size: group.raw_size,
                                files: slint::ModelRc::new(slint::VecModel::from(updated_files)),
                            });
                        } else {
                            // Keep other groups unchanged
                            updated_groups.push(group);
                        }
                    }
                }
                
                ui.set_duplicate_groups(slint::ModelRc::new(slint::VecModel::from(updated_groups)));
            }
        });
    });

    // ── Callback: Toggle File Selection ─
    let ui_weak = ui.as_weak();
    ui.on_toggle_file_selection(move |group_index, file_index| {
        let ui_weak = ui_weak.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let groups = ui.get_duplicate_groups();
                let mut updated_groups = Vec::new();
                
                for i in 0..groups.row_count() {
                    if let Some(group) = groups.row_data(i) {
                        if i == group_index as usize {
                            // Toggle the selected file
                            let mut files = Vec::new();
                            for j in 0..group.files.row_count() {
                                if let Some(mut file) = group.files.row_data(j) {
                                    if j == file_index as usize {
                                        file.selected = !file.selected;
                                    }
                                    files.push(file);
                                }
                            }
                            
                            updated_groups.push(DuplicateGroupData {
                                hash: group.hash,
                                size: group.size,
                                raw_size: group.raw_size,
                                files: slint::ModelRc::new(slint::VecModel::from(files)),
                            });
                        } else {
                            updated_groups.push(group);
                        }
                    }
                }
                
                ui.set_duplicate_groups(slint::ModelRc::new(slint::VecModel::from(updated_groups)));
            }
        });
    });

    // ── Callback: Open File (Safe file opening: reveal in Explorer for quarantine / protected files) ─
    ui.on_open_file(move |path: slint::SharedString| {
        let path_str = path.to_string();
        let p = std::path::PathBuf::from(&path_str);
        if let Ok(qdir) = modules::config::Settings::quarantine_dir() {
            if p.starts_with(&qdir) || modules::cleaner::is_protected_path(&p, Some(&qdir)) {
                tracing::info!("File {:?} is quarantined or protected; safely revealing in file manager", p);
                reveal_in_file_manager(&p);
                return;
            }
        }
        if let Err(e) = open::that(&path_str) {
            tracing::error!("Failed to open file {}: {}", path_str, e);
            reveal_in_file_manager(&p);
        }
    });

    ui.on_reveal_file(move |path: slint::SharedString| {
        let p = std::path::PathBuf::from(path.as_str());
        reveal_in_file_manager(&p);
    });

    // ── Callback: Toggle Pause ──
    let pause_flag_clone = pause_flag.clone();
    let ui_weak = ui.as_weak();
    ui.on_toggle_pause(move || {
        let pause_flag = pause_flag_clone.clone();
        let new_state = !pause_flag.load(Ordering::Relaxed);
        pause_flag.store(new_state, Ordering::Relaxed);
        
        let ui_weak = ui_weak.clone();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_cleaner_paused(new_state);
                if new_state {
                    ui.set_cleaner_status("Paused".into());
                } else {
                    ui.set_cleaner_status("Resumed".into());
                }
            }
        });
    });

    // ── Callback: Scan Duplicates ──
    let ui_weak = ui.as_weak();
    let cleaner_clone = cleaner.clone();
    let pause_flag_clone = pause_flag.clone();
    let duplicate_scan_cache_clone = duplicate_scan_cache.clone();
    ui.on_scan_duplicates(move |path: slint::SharedString| {
        let ui_weak = ui_weak.clone();
        let cleaner = cleaner_clone.clone();
        let pause_flag = pause_flag_clone.clone();
        let duplicate_scan_cache = duplicate_scan_cache_clone.clone();
        let path = std::path::PathBuf::from(path.to_string());
        tokio::spawn(async move {
            let token = tokio_util::sync::CancellationToken::new();
            let ui_weak_clone = ui_weak.clone();

            slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak_clone.upgrade() {
                    ui.set_cleaner_scanning(true);
                    ui.set_cleaner_paused(false);
                    ui.set_cleaner_status("Scanning duplicates...".into());
                    ui.set_cleaner_progress(0.0);
                }
            })
            .ok();

            let start_time = std::time::Instant::now();
            let result = cleaner
                .find_duplicates(path, token, pause_flag, {
                    let ui_weak = ui_weak.clone();
                    move |files, bytes| {
                        let ui_weak = ui_weak.clone();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = ui_weak.upgrade() {
                                ui.set_cleaner_files_found(files as i32);
                                ui.set_cleaner_bytes_text(modules::cleaner::format_bytes(bytes).into());
                                // Update progress based on elapsed time (max 95% until complete)
                                let elapsed = start_time.elapsed().as_secs_f32();
                                let progress = (elapsed / 120.0).min(0.95);
                                ui.set_cleaner_progress(progress);
                            }
                        });
                    }
                })
                .await;

            slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_cleaner_scanning(false);
                    ui.set_cleaner_paused(false);
                    ui.set_cleaner_progress(1.0);
                    match result {
                        Ok(groups) => {
                            // R08: Guardar en cache original scan data
                            {
                                let mut cache = duplicate_scan_cache.lock().unwrap();
                                cache.clear();
                                for g in &groups {
                                    cache.insert(g.hash.clone(), g.size);
                                }
                            }

                            // Calcular total de MB de duplicados
                            let total_bytes: u64 = groups.iter().map(|g| g.size).sum();
                            let total_mb = modules::cleaner::format_bytes(total_bytes);
                            
                            let slint_groups: slint::ModelRc<DuplicateGroupData> =
                                slint::ModelRc::new(slint::VecModel::from(
                                    groups
                                        .into_iter()
                                        .map(|g| DuplicateGroupData {
                                            hash: g.hash.into(),
                                            size: modules::cleaner::format_bytes(g.size).into(),
                                            raw_size: g.size as f32,
                                            files: slint::ModelRc::new(slint::VecModel::from(
                                                g.files
                                                    .into_iter()
                                                    .map(|f| DuplicateFileData {
                                                        path: f.path.to_string_lossy().to_string().into(),
                                                        created: f
                                                            .created
                                                            .map(|c| c.format("%Y-%m-%d %H:%M").to_string())
                                                            .unwrap_or_default()
                                                            .into(),
                                                        selected: f.selected,
                                                    })
                                                    .collect::<Vec<_>>(),
                                            )),
                                        })
                                        .collect::<Vec<_>>(),
                                ));
                            ui.set_duplicate_groups(slint_groups);
                            ui.set_duplicates_total_mb(total_mb.into());
                            ui.set_cleaner_status("Scan complete".into());
                        }
                        Err(e) => {
                            ui.set_cleaner_status(format!("Error: {}", e).into());
                        }
                    }
                }
            })
            .ok();
        });
    });

    // ── Callback: Quarantine Selected Duplicates ──
    let ui_weak = ui.as_weak();
    let cleaner_clone = cleaner.clone();
    let duplicate_scan_cache_clone = duplicate_scan_cache.clone();
    ui.on_quarantine_selected_duplicates(move || {
        let ui_weak = ui_weak.clone();
        let cleaner = cleaner_clone.clone();
        let scan_cache_clone = duplicate_scan_cache_clone.clone();
        tokio::spawn(async move {
            let token = tokio_util::sync::CancellationToken::new();
            let (tx, rx) = tokio::sync::oneshot::channel();
            
            // Clone ui_weak for the first closure
            let ui_weak_clone = ui_weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                let groups = ui_weak_clone
                    .upgrade()
                    .map(|ui| ui.get_duplicate_groups())
                    .unwrap_or_default();

                // Extract data on the UI thread (ModelRc is not Send)
                let scan_cache = scan_cache_clone.lock().unwrap();
                let mut duplicate_groups = Vec::new();
                for i in 0..groups.row_count() {
                    if let Some(group) = groups.row_data(i) {
                        let mut files = Vec::new();
                        for j in 0..group.files.row_count() {
                            if let Some(file) = group.files.row_data(j) {
                                files.push(models::DuplicateFile {
                                    path: std::path::PathBuf::from(file.path.to_string()),
                                    created: None,
                                    selected: file.selected,
                                });
                            }
                        }
                        let hash_str = group.hash.to_string();
                        let size = scan_cache.get(&hash_str).copied().unwrap_or(group.raw_size as u64);
                        duplicate_groups.push(models::DuplicateGroup {
                            hash: hash_str,
                            size,
                            files,
                        });
                    }
                }
                let _ = tx.send(duplicate_groups);
            });

            let duplicate_groups = rx.await.unwrap_or_default();

            if !duplicate_groups.is_empty() {
                let selected_count: usize = duplicate_groups
                    .iter()
                    .map(|g| g.files.iter().filter(|f| f.selected).count())
                    .sum();
                if selected_count == 0 {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_cleaner_status("No duplicate files selected for quarantine".into());
                        }
                    });
                    return;
                }

                // Confirmation before irreversible operation (Block 4 / A11.13)
                let confirmed = rfd::MessageDialog::new()
                    .set_title("Confirm Quarantine")
                    .set_description(format!(
                        "Are you sure you want to move {} selected duplicate file(s) to Quarantine?",
                        selected_count
                    ))
                    .set_buttons(rfd::MessageButtons::YesNo)
                    .show();

                if !matches!(confirmed, rfd::MessageDialogResult::Yes) {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_cleaner_status("Quarantine cancelled by user".into());
                        }
                    });
                    return;
                }

                match cleaner
                    .quarantine_selected_duplicates(&duplicate_groups, token)
                    .await
                {
                    Ok(entries) => {
                        tracing::info!("Quarantined {} files", entries.len());
                        
                        // Recargar cuarentena y actualizar UI
                        let quarantine_entries = cleaner.list_quarantine().unwrap_or_default();
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = ui_weak.upgrade() {
                                let total_bytes: u64 = quarantine_entries.iter().map(|e| e.size).sum();
                                let total_size = modules::cleaner::format_bytes(total_bytes);
                                
                                let slint_entries: slint::ModelRc<QuarantineEntryData> =
                                    slint::ModelRc::new(slint::VecModel::from(
                                        quarantine_entries
                                            .iter()
                                            .map(map_quarantine_entry)
                                            .collect::<Vec<_>>(),
                                    ));
                                ui.set_quarantine_entries(slint_entries);
                                ui.set_quarantine_total_size(total_size.into());
                                ui.set_cleaner_status(format!("Quarantined {} files", entries.len()).into());
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("Failed to quarantine duplicates: {:#}", e);
                        let _ = slint::invoke_from_event_loop(move || {
                            if let Some(ui) = ui_weak.upgrade() {
                                ui.set_cleaner_status(format!("Quarantine error: {:#}", e).into());
                            }
                        });
                    }
                }
            }
        });
    });

    // ── Callback: Tab Changed ──
    // Auto-load quarantine when switching to Cleaner tab, auto-load events for Process Hunter
    let ui_weak = ui.as_weak();
    let cleaner_clone = cleaner.clone();
    let hunter_tab_clone = process_hunter.clone();
    ui.on_tab_changed(move |tab_index| {
        if tab_index == 1 {
            // Process Hunter tab - auto-load events
            let ui_weak = ui_weak.clone();
            let hunter = hunter_tab_clone.clone();
            tokio::spawn(async move {
                let events = hunter.list_events(100).await.unwrap_or_default();
                slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        let slint_events: slint::ModelRc<ProcessEventData> =
                            slint::ModelRc::new(slint::VecModel::from(
                                events
                                    .into_iter()
                                    .map(|e| ProcessEventData {
                                        id: e.id.unwrap_or(0) as i32,
                                        timestamp: e.timestamp.format("%Y-%m-%d %H:%M:%S").to_string().into(),
                                        name: e.name.into(),
                                        pid: e.pid as i32,
                                        parent_pid: e.parent_pid.unwrap_or(0) as i32,
                                        command_line: e.command_line.into(),
                                        lifetime: e.lifetime_seconds.map(|s| format!("{}s", s)).unwrap_or_else(|| "-".to_string()).into(),
                                    })
                                    .collect::<Vec<_>>(),
                            ));
                        ui.set_process_events(slint_events);
                    }
                })
                .ok();
            });
        } else if tab_index == 2 {
            // Cleaner tab - auto-load quarantine
            let ui_weak = ui_weak.clone();
            let cleaner = cleaner_clone.clone();
            tokio::spawn(async move {
                let entries = cleaner.list_quarantine().unwrap_or_default();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        // Calcular tamaño total de cuarentena
                        let total_bytes: u64 = entries.iter().map(|e| e.size).sum();
                        let total_size = modules::cleaner::format_bytes(total_bytes);
                        
                        let slint_entries: slint::ModelRc<QuarantineEntryData> =
                            slint::ModelRc::new(slint::VecModel::from(
                                entries
                                    .iter()
                                    .map(map_quarantine_entry)
                                    .collect::<Vec<_>>(),
                            ));
                        ui.set_quarantine_entries(slint_entries);
                        ui.set_quarantine_total_size(total_size.into());
                    }
                });
            });
        }
    });

    // ── Callback: Scan / Refresh Process Hunter Events ──
    let ui_weak = ui.as_weak();
    let hunter_for_scan = process_hunter.clone();
    ui.on_scan_processes(move || {
        let ui_weak = ui_weak.clone();
        let hunter = hunter_for_scan.clone();
        tokio::spawn(async move {
            let events = hunter.list_events(100).await.unwrap_or_default();
            slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    let slint_events: slint::ModelRc<ProcessEventData> =
                        slint::ModelRc::new(slint::VecModel::from(
                            events
                                .into_iter()
                                .map(|e| ProcessEventData {
                                    id: e.id.unwrap_or(0) as i32,
                                    timestamp: e.timestamp.format("%Y-%m-%d %H:%M:%S").to_string().into(),
                                    name: e.name.into(),
                                    pid: e.pid as i32,
                                    parent_pid: e.parent_pid.unwrap_or(0) as i32,
                                    command_line: e.command_line.into(),
                                    lifetime: e.lifetime_seconds.map(|s| format!("{}s", s)).unwrap_or_else(|| "-".to_string()).into(),
                                })
                                .collect::<Vec<_>>(),
                        ));
                    ui.set_process_events(slint_events);
                }
            })
            .ok();
        });
    });

    // ── Callback: Load Quarantine ──
    let ui_weak = ui.as_weak();
    let cleaner_clone = cleaner.clone();
    ui.on_load_quarantine(move || {
        let ui_weak = ui_weak.clone();
        let cleaner = cleaner_clone.clone();
        tokio::spawn(async move {
            let entries = cleaner.list_quarantine().unwrap_or_default();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    let total_bytes: u64 = entries.iter().map(|e| e.size).sum();
                    let total_size = modules::cleaner::format_bytes(total_bytes);
                    
                    let slint_entries: slint::ModelRc<QuarantineEntryData> =
                        slint::ModelRc::new(slint::VecModel::from(
                            entries
                                .iter()
                                .map(map_quarantine_entry)
                                .collect::<Vec<_>>(),
                        ));
                    ui.set_quarantine_entries(slint_entries);
                    ui.set_quarantine_total_size(total_size.into());
                }
            });
        });
    });

    // ── Callback: Restore Quarantine (Stable file identifier R06 & UI error reporting A11.14) ──
    let cleaner_clone = cleaner.clone();
    let ui_weak = ui.as_weak();
    ui.on_restore_quarantine(move |key: slint::SharedString| {
        let key_str = key.to_string();
        let cleaner = cleaner_clone.clone();
        let ui_weak = ui_weak.clone();
        tokio::spawn(async move {
            let entries = cleaner.list_quarantine().unwrap_or_default();
            let target = entries.iter().find(|e| {
                e.quarantine_path.file_name().map(|n| n.to_string_lossy().to_string()) == Some(key_str.clone())
                || e.quarantine_path.to_string_lossy() == key_str
            });

            let restore_res = match target {
                Some(entry) => cleaner.restore_from_quarantine(entry),
                None => Err(anyhow::anyhow!("Quarantine entry {:?} not found", key_str)),
            };

            let updated_entries = cleaner.list_quarantine().unwrap_or_default();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    let total_bytes: u64 = updated_entries.iter().map(|e| e.size).sum();
                    let total_size = modules::cleaner::format_bytes(total_bytes);
                    let slint_entries: slint::ModelRc<QuarantineEntryData> =
                        slint::ModelRc::new(slint::VecModel::from(
                            updated_entries
                                .iter()
                                .map(map_quarantine_entry)
                                .collect::<Vec<_>>(),
                        ));
                    ui.set_quarantine_entries(slint_entries);
                    ui.set_quarantine_total_size(total_size.into());
                    match restore_res {
                        Ok(()) => ui.set_cleaner_status("File restored successfully".into()),
                        Err(e) => {
                            tracing::error!("Failed to restore from quarantine: {:#}", e);
                            ui.set_cleaner_status(format!("Restore failed: {:#}", e).into());
                        }
                    }
                }
            });
        });
    });

    // ── Callback: Delete Quarantine (Confirmation A11.13, Stable key R06, UI error reporting A11.14) ──
    let cleaner_clone = cleaner.clone();
    let ui_weak = ui.as_weak();
    ui.on_delete_quarantine(move |key: slint::SharedString| {
        let key_str = key.to_string();
        let cleaner = cleaner_clone.clone();
        let ui_weak = ui_weak.clone();

        // Confirmation before irreversible operation (Block 4 / A11.13)
        let confirmed = rfd::MessageDialog::new()
            .set_title("Confirm Delete")
            .set_description("Are you sure you want to remove this file from Quarantine?\nIt will be sent to the Recycle Bin.")
            .set_buttons(rfd::MessageButtons::YesNo)
            .show();

        if !matches!(confirmed, rfd::MessageDialogResult::Yes) {
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_cleaner_status("Deletion cancelled by user".into());
                }
            });
            return;
        }

        tokio::spawn(async move {
            let entries = cleaner.list_quarantine().unwrap_or_default();
            let target = entries.iter().find(|e| {
                e.quarantine_path.file_name().map(|n| n.to_string_lossy().to_string()) == Some(key_str.clone())
                || e.quarantine_path.to_string_lossy() == key_str
            });

            let delete_res = match target {
                Some(entry) => cleaner.delete_quarantine_permanently(entry),
                None => Err(anyhow::anyhow!("Quarantine entry {:?} not found", key_str)),
            };

            let updated_entries = cleaner.list_quarantine().unwrap_or_default();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    let total_bytes: u64 = updated_entries.iter().map(|e| e.size).sum();
                    let total_size = modules::cleaner::format_bytes(total_bytes);
                    let slint_entries: slint::ModelRc<QuarantineEntryData> =
                        slint::ModelRc::new(slint::VecModel::from(
                            updated_entries
                                .iter()
                                .map(map_quarantine_entry)
                                .collect::<Vec<_>>(),
                        ));
                    ui.set_quarantine_entries(slint_entries);
                    ui.set_quarantine_total_size(total_size.into());
                    match delete_res {
                        Ok(()) => ui.set_cleaner_status("File sent to Recycle Bin".into()),
                        Err(e) => {
                            tracing::error!("Failed to delete from quarantine: {:#}", e);
                            ui.set_cleaner_status(format!("Delete failed: {:#}", e).into());
                        }
                    }
                }
            });
        });
    });

    // ── Callback: Refresh Processes ──
    let ui_weak = ui.as_weak();
    let cpu_optimizer_clone = cpu_optimizer.clone();
    ui.on_refresh_processes(move || {
        let ui_weak = ui_weak.clone();
        let cpu_optimizer = cpu_optimizer_clone.clone();
        tokio::spawn(async move {
            let entries = cpu_optimizer.lock().unwrap().list_user_processes();
            slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    let slint_entries: slint::ModelRc<ProcessEntryData> =
                        slint::ModelRc::new(slint::VecModel::from(
                            entries
                                .into_iter()
                                .map(|e| ProcessEntryData {
                                    pid: e.pid as i32,
                                    name: e.name.into(),
                                    cpu: format!("{:.1}%", e.cpu_percent).into(),
                                    memory: format!("{} MB", e.memory_mb).into(),
                                    focused: e.focused,
                                })
                                .collect::<Vec<_>>(),
                        ));
                    ui.set_process_entries(slint_entries);
                }
            })
            .ok();
        });
    });

    // ── Callback: Toggle Focus ──
    let ui_weak = ui.as_weak();
    let cpu_optimizer_clone = cpu_optimizer.clone();
    ui.on_toggle_focus(move |pid| {
        let cpu_optimizer = cpu_optimizer_clone.clone();
        let ui_weak = ui_weak.clone();
        tokio::spawn(async move {
            if let Err(e) = cpu_optimizer.lock().unwrap().toggle_focus(pid as u32) {
                tracing::error!("Failed to toggle focus for PID {}: {}", pid, e);
            };
            let entries = cpu_optimizer.lock().unwrap().list_user_processes();
            slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    let slint_entries: slint::ModelRc<ProcessEntryData> =
                        slint::ModelRc::new(slint::VecModel::from(
                            entries
                                .into_iter()
                                .map(|e| ProcessEntryData {
                                    pid: e.pid as i32,
                                    name: e.name.into(),
                                    cpu: format!("{:.1}%", e.cpu_percent).into(),
                                    memory: format!("{} MB", e.memory_mb).into(),
                                    focused: e.focused,
                                })
                                .collect::<Vec<_>>(),
                        ));
                    ui.set_process_entries(slint_entries);
                }
            })
            .ok();
        });
    });

    // ── Callback: Refresh System Stats ──
    let ui_weak = ui.as_weak();
    let sys_monitor_clone = sys_monitor.clone();
    ui.on_refresh_sys_stats(move || {
        let ui_weak = ui_weak.clone();
        let sys_monitor = sys_monitor_clone.clone();

        tokio::spawn(async move {
            let stats = sys_monitor.lock().unwrap().refresh();

            slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    // CPU
                    ui.set_sys_cpu_usage(stats.cpu_usage);

                    // Cores
                    let cores_model: Vec<CoreUsageData> = stats
                        .cores
                        .iter()
                        .enumerate()
                        .map(|(i, core)| CoreUsageData {
                            name: format!("Core {}", i).into(),
                            usage: core.usage,
                        })
                        .collect();
                    ui.set_sys_cores(slint::ModelRc::new(slint::VecModel::from(cores_model)));

                    // Memory
                    ui.set_sys_total_memory(stats.total_memory as f32);
                    ui.set_sys_used_memory(stats.used_memory as f32);
                    ui.set_sys_total_swap(stats.total_swap as f32);
                    ui.set_sys_used_swap(stats.used_swap as f32);

                    // Load average
                    ui.set_sys_load_avg_1(stats.load_avg_1 as f32);
                    ui.set_sys_load_avg_5(stats.load_avg_5 as f32);
                    ui.set_sys_load_avg_15(stats.load_avg_15 as f32);
                    ui.set_sys_load_avg_text(format!("{:.2} / {:.2} / {:.2}", stats.load_avg_1, stats.load_avg_5, stats.load_avg_15).into());

                    // Disks
                    let disks_model: Vec<DiskInfoData> = stats
                        .disks
                        .iter()
                        .map(|disk| DiskInfoData {
                            name: disk.name.clone().into(),
                            mount_point: disk.mount_point.clone().into(),
                            total_bytes: disk.total_bytes as f32,
                            available_bytes: disk.available_bytes as f32,
                        })
                        .collect();
                    ui.set_sys_disks(slint::ModelRc::new(slint::VecModel::from(disks_model)));

                    // Network
                    ui.set_sys_network_up(stats.network_up_bps as f32);
                    ui.set_sys_network_down(stats.network_down_bps as f32);

                    // Temperatures
                    let temps_model: Vec<TempInfoData> = stats
                        .temperatures
                        .iter()
                        .map(|temp| TempInfoData {
                            label: temp.label.clone().into(),
                            temperature: temp.temperature,
                        })
                        .collect();
                    ui.set_sys_temperatures(slint::ModelRc::new(slint::VecModel::from(temps_model)));

                    // Uptime
                    ui.set_sys_uptime(stats.uptime_seconds as f32);

                    // Top processes by CPU
                    let top_cpu_model: Vec<TopProcessData> = stats
                        .top_cpu
                        .iter()
                        .map(|p| TopProcessData {
                            name: p.name.clone().into(),
                            pid: p.pid as i32,
                            value: p.value,
                            value_text: format!("{:.1}", p.value).into(),
                            memory_mb: p.memory_mb as i32,
                        })
                        .collect();
                    ui.set_sys_top_cpu(slint::ModelRc::new(slint::VecModel::from(top_cpu_model)));

                    // Top processes by RAM
                    let top_ram_model: Vec<TopProcessData> = stats
                        .top_ram
                        .iter()
                        .map(|p| TopProcessData {
                            name: p.name.clone().into(),
                            pid: p.pid as i32,
                            value: p.value,
                            value_text: format!("{:.1}", p.value).into(),
                            memory_mb: p.memory_mb as i32,
                        })
                        .collect();
                    ui.set_sys_top_ram(slint::ModelRc::new(slint::VecModel::from(top_ram_model)));
                }
            })
            .ok();
        });
    });

    // ── Callback: Save Settings ─
    let ui_weak = ui.as_weak();
    ui.on_save_settings(move || {
        let ui_weak = ui_weak.clone();
        if let Some(ui) = ui_weak.upgrade() {
            tracing::debug!("=== Save Settings callback triggered ===");
            
            // Load current settings from disk BEFORE any changes
            let current_settings = Settings::load().unwrap_or_default();
            tracing::debug!("Loaded current settings from disk: language={:?}, dark_mode={}, start_with_os={}, history_days={}, quarantine_days={}, permanent_delete={}", 
                current_settings.language, current_settings.dark_mode, current_settings.start_with_os, 
                current_settings.process_history_days, current_settings.quarantine_days, current_settings.permanent_delete);
            
            // Determine new language from UI
            let new_language = match ui.get_language_index() {
                0 => Language::English,
                1 => Language::SpanishArgentina,
                _ => Language::English,
            };
            
            tracing::info!("Language comparison: current={:?}, new={:?}", current_settings.language, new_language);
            tracing::debug!("UI values: language_index={}, dark_mode={}, start_with_os={}, history_days={}, quarantine_days={}, permanent_delete={}", 
                ui.get_language_index(), ui.get_dark_mode(), ui.get_start_with_os(), 
                ui.get_history_days(), ui.get_quarantine_days(), ui.get_permanent_delete());
            
            // Build new settings from UI values
            let mut settings = current_settings.clone();
            settings.language = new_language;
            settings.dark_mode = ui.get_dark_mode();
            settings.start_with_os = ui.get_start_with_os();
            settings.process_history_days = ui.get_history_days() as u32;
            settings.quarantine_days = ui.get_quarantine_days() as u32;
            settings.permanent_delete = ui.get_permanent_delete();  // NUEVO

            // Save settings to disk
            if let Err(e) = settings.save() {
                tracing::error!("Failed to save settings: {}", e);
            } else {
                tracing::info!("Settings saved successfully to disk");
            }

            // Apply autostart setting
            if let Err(e) = settings.apply_autostart(None) {
                tracing::error!("Failed to apply autostart: {}", e);
            } else {
                tracing::debug!("Autostart applied successfully");
            }

            // Update global language (for current process)
            i18n::set_global_language(settings.language);
            tracing::debug!("Global language updated to {:?}", settings.language);
            
            // Restart app if language changed (requires new process to reload UI strings)
            let language_changed = new_language != current_settings.language;
            tracing::info!("Language changed: {}", language_changed);
            
            if language_changed {
                tracing::info!("Language changed from {:?} to {:?}, restarting app...", current_settings.language, new_language);
                let args: Vec<String> = std::env::args().collect();
                let exe = std::env::current_exe().unwrap();
                tracing::info!("Executable path: {:?}", exe);
                tracing::info!("Original args: {:?}", args);
                
                match std::process::Command::new(&exe)
                    .args(&args[1..])
                    .spawn()
                {
                    Ok(child) => {
                        tracing::info!("Successfully spawned new process with PID: {}", child.id());
                    }
                    Err(e) => {
                        tracing::error!("CRITICAL: Failed to spawn new process: {}", e);
                        tracing::error!("Settings were saved but app could not restart. Please restart manually.");
                    }
                }
                
                tracing::info!("Quitting current event loop...");
                slint::quit_event_loop().ok();
            } else {
                tracing::info!("Language unchanged ({:?}), no restart needed. Settings applied in-place.", new_language);
            }
            
            tracing::debug!("=== Save Settings callback complete ===");
        } else {
            tracing::warn!("Save Settings callback: UI window was dropped, cannot save");
        }
    });

    // ── Callback: Check Updates ──
    ui.on_check_updates(move || {
        if let Err(e) = open::that("https://github.com/H3rC4/syspulse/releases") {
            tracing::error!("Failed to open browser: {}", e);
        }
    });

    // ── Callback: Export Process ─
    let hunter_cmd_tx_clone = hunter_cmd_tx.clone();
    ui.on_export_process(move |id, format| {
        let format = match format.as_str() {
            "json" => ExportFormat::Json,
            "csv" => ExportFormat::Csv,
            _ => return,
        };

        let extension = format.as_str();
        let path = match rfd::FileDialog::new()
            .set_file_name(format!("process_{}.{}", id, extension))
            .save_file()
        {
            Some(p) => p,
            None => return,
        };

        if let Err(e) = hunter_cmd_tx_clone.send(ProcessHunterCommand::ExportSelected(
            id as i64,
            format,
            path,
        )) {
            tracing::error!("Failed to send export command: {}", e);
        }
    });

    // ── Auto-refresh System Monitor every 2 seconds ──
    let ui_weak_for_timer = ui.as_weak();
    let sys_monitor_for_timer = sys_monitor.clone();
    let _sys_monitor_timer = slint::Timer::default();
    _sys_monitor_timer.start(slint::TimerMode::Repeated, std::time::Duration::from_secs(2), move || {
        let ui_weak = ui_weak_for_timer.clone();
        let sys_monitor = sys_monitor_for_timer.clone();

        if let Some(ui) = ui_weak.upgrade() {
            if ui.get_current_tab() == 0 {
                // Only refresh when Monitor tab is active, in background task
                tokio::spawn(async move {
                    let stats = sys_monitor.lock().unwrap().refresh();

                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            // CPU
                            ui.set_sys_cpu_usage(stats.cpu_usage);

                            // Cores
                            let cores_model: Vec<CoreUsageData> = stats
                                .cores
                                .iter()
                                .enumerate()
                                .map(|(i, core)| CoreUsageData {
                                    name: format!("Core {}", i).into(),
                                    usage: core.usage,
                                })
                                .collect();
                            ui.set_sys_cores(slint::ModelRc::new(slint::VecModel::from(cores_model)));

                            // Memory
                            ui.set_sys_total_memory(stats.total_memory as f32);
                            ui.set_sys_used_memory(stats.used_memory as f32);
                            ui.set_sys_total_swap(stats.total_swap as f32);
                            ui.set_sys_used_swap(stats.used_swap as f32);

                            // Load average
                            ui.set_sys_load_avg_1(stats.load_avg_1 as f32);
                            ui.set_sys_load_avg_5(stats.load_avg_5 as f32);
                            ui.set_sys_load_avg_15(stats.load_avg_15 as f32);
                            ui.set_sys_load_avg_text(format!("{:.2} / {:.2} / {:.2}", stats.load_avg_1, stats.load_avg_5, stats.load_avg_15).into());

                            // Disks
                            let disks_model: Vec<DiskInfoData> = stats
                                .disks
                                .iter()
                                .map(|disk| DiskInfoData {
                                    name: disk.name.clone().into(),
                                    mount_point: disk.mount_point.clone().into(),
                                    total_bytes: disk.total_bytes as f32,
                                    available_bytes: disk.available_bytes as f32,
                                })
                                .collect();
                            ui.set_sys_disks(slint::ModelRc::new(slint::VecModel::from(disks_model)));

                            // Network
                            ui.set_sys_network_up(stats.network_up_bps as f32);
                            ui.set_sys_network_down(stats.network_down_bps as f32);

                            // Temperatures
                            let temps_model: Vec<TempInfoData> = stats
                                .temperatures
                                .iter()
                                .map(|temp| TempInfoData {
                                    label: temp.label.clone().into(),
                                    temperature: temp.temperature,
                                })
                                .collect();
                            ui.set_sys_temperatures(slint::ModelRc::new(slint::VecModel::from(temps_model)));

                            // Uptime
                            ui.set_sys_uptime(stats.uptime_seconds as f32);

                            // Top processes by CPU
                            let top_cpu_model: Vec<TopProcessData> = stats
                                .top_cpu
                                .iter()
                                .map(|p| TopProcessData {
                                    name: p.name.clone().into(),
                                    pid: p.pid as i32,
                                    value: p.value,
                                    value_text: format!("{:.1}", p.value).into(),
                                    memory_mb: p.memory_mb as i32,
                                })
                                .collect();
                            ui.set_sys_top_cpu(slint::ModelRc::new(slint::VecModel::from(top_cpu_model)));

                            // Top processes by RAM
                            let top_ram_model: Vec<TopProcessData> = stats
                                .top_ram
                                .iter()
                                .map(|p| TopProcessData {
                                    name: p.name.clone().into(),
                                    pid: p.pid as i32,
                                    value: p.value,
                                    value_text: format!("{:.1}", p.value).into(),
                                    memory_mb: p.memory_mb as i32,
                                })
                                .collect();
                            ui.set_sys_top_ram(slint::ModelRc::new(slint::VecModel::from(top_ram_model)));
                        }
                    });
                });
            }
        }
    });

    // ── Handle tray events ──
    let ui_weak = ui.as_weak();
    let hunter_cmd_tx_clone = hunter_cmd_tx.clone();
    let tray_handle_clone = tray_handle.clone();
    let hunter_paused_clone = hunter_paused.clone();
    tokio::spawn(async move {
        while let Some(event) = tray_event_rx.recv().await {
            match event {
                TrayEvent::Open => {
                    let ui_weak = ui_weak.clone();
                    slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.show().ok();
                        }
                    })
                    .ok();
                }
                TrayEvent::TogglePause => {
                    let new_paused = !hunter_paused_clone.load(Ordering::Relaxed);
                    hunter_paused_clone.store(new_paused, Ordering::Relaxed);
                    let cmd = if new_paused {
                        ProcessHunterCommand::Pause
                    } else {
                        ProcessHunterCommand::Resume
                    };
                    let _ = hunter_cmd_tx_clone.send(cmd);
                    tray_handle_clone.set_pause_label(new_paused);
                }
                TrayEvent::Exit => {
                    slint::quit_event_loop().ok();
                    break;
                }
            }
        }
    });

    // Run Slint event loop
    tracing::info!("Starting Slint event loop...");
    ui.run().context("Failed to run Slint event loop")?;

    tracing::info!("SysPulse shutting down");
    Ok(())
}

fn map_quarantine_entry(e: &models::QuarantineEntry) -> QuarantineEntryData {
    QuarantineEntryData {
        key: e
            .quarantine_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
            .into(),
        original_path: e.original_path.to_string_lossy().to_string().into(),
        quarantine_path: e.quarantine_path.to_string_lossy().to_string().into(),
        size: modules::cleaner::format_bytes(e.size).into(),
        quarantined_at: modules::cleaner::format_quarantined_date(e.quarantined_at).into(),
    }
}

fn reveal_in_file_manager(path: &std::path::Path) {
    #[cfg(windows)]
    {
        use std::process::Command;
        let _ = Command::new("explorer")
            .arg(format!("/select,\"{}\"", path.display()))
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let _ = Command::new("open")
            .arg("-R")
            .arg(path)
            .spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        use std::process::Command;
        if let Some(parent) = path.parent() {
            let _ = Command::new("xdg-open")
                .arg(parent)
                .spawn();
        }
    }
}
