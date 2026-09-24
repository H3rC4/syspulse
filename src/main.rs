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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing_subscriber::{fmt, EnvFilter};

slint::include_modules!();

fn apply_theme(ui: &AppWindow, is_light: bool) {
    if is_light {
        // Light theme
        ui.invoke_set_theme_colors(
            slint::Color::from_rgb_u8(255, 255, 255).into(), // bg-main
            slint::Color::from_rgb_u8(245, 245, 247).into(), // bg-panel
            slint::Color::from_rgb_u8(255, 255, 255).into(), // bg-card
            slint::Color::from_rgb_u8(240, 240, 242).into(), // bg-card-hover
            slint::Color::from_rgb_u8(232, 232, 236).into(), // bg-surface
            slint::Color::from_rgb_u8(26, 26, 46).into(),    // text-main
            slint::Color::from_rgb_u8(90, 90, 110).into(),   // text-sub
            slint::Color::from_rgb_u8(138, 138, 154).into(), // text-dim
            slint::Color::from_rgb_u8(208, 208, 216).into(), // border-main
            slint::Color::from_rgb_u8(224, 224, 232).into(), // border-dim
        );
    } else {
        // Dark theme
        ui.invoke_set_theme_colors(
            slint::Color::from_rgb_u8(5, 5, 8).into(),       // bg-main
            slint::Color::from_rgb_u8(10, 10, 15).into(),    // bg-panel
            slint::Color::from_rgb_u8(18, 18, 26).into(),    // bg-card
            slint::Color::from_rgb_u8(26, 26, 37).into(),    // bg-card-hover
            slint::Color::from_rgb_u8(30, 30, 42).into(),    // bg-surface
            slint::Color::from_rgb_u8(240, 240, 245).into(), // text-main
            slint::Color::from_rgb_u8(107, 107, 128).into(), // text-sub
            slint::Color::from_rgb_u8(74, 74, 90).into(),    // text-dim
            slint::Color::from_rgb_u8(30, 30, 42).into(),    // border-main
            slint::Color::from_rgb_u8(21, 21, 31).into(),    // border-dim
        );
    }
}

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
    let cleaner = Arc::new(Cleaner::new().context("Failed to initialize Cleaner")?);
    let cpu_optimizer = Arc::new(Mutex::new(CpuOptimizer::new()));
    let sys_monitor = Arc::new(Mutex::new(SysMonitor::new()));
    
    // Shared pause flag for cleaner operations
    let pause_flag = Arc::new(AtomicBool::new(false));
    
    // Shared cancellation token for cleaner operations
    let cancel_flag = Arc::new(AtomicBool::new(false));

    let (process_hunter, hunter_cmd_rx) =
        ProcessHunter::new().context("Failed to initialize Process Hunter")?;
    let hunter_cmd_tx = process_hunter.command_sender();

    // Start process hunter background task
    let history_days = settings.process_history_days;
    tokio::spawn(async move {
        process_hunter.start(hunter_cmd_rx, history_days).await;
    });

    // Spawn tray
    tracing::info!("Spawning system tray...");
    let (tray_event_tx, mut tray_event_rx) = mpsc::unbounded_channel::<TrayEvent>();
    let _tray_handle = tray::spawn_tray(tray_event_tx).map_err(|e| anyhow::anyhow!(e))?;
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
    ui.set_light_mode(settings.light_mode);
    ui.set_start_with_os(settings.start_with_os);
    ui.set_history_days(settings.process_history_days as f32);
    ui.set_quarantine_days(settings.quarantine_days as f32);
    ui.set_permanent_delete(settings.permanent_delete);  // NUEVO
    
    // Apply theme based on settings
    apply_theme(&ui, settings.light_mode);

    // Hide window if --background
    if args.background {
        ui.hide().ok();
    }

    // Cleanup old quarantine entries
    tracing::info!("Purging old quarantine...");
    if let Err(e) = cleaner.purge_old_quarantine(settings.quarantine_days) {
        tracing::error!("Failed to purge old quarantine: {}", e);
    }
    tracing::info!("Purge complete");
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
    let ui_weak_clean = ui_weak.clone();  // Para leer permanent_delete
    ui.on_clean_system_temp(move || {
        let ui_weak = ui_weak.clone();
        let cleaner = cleaner_clone.clone();
        let pause_flag = pause_flag_clone.clone();
        let cancel_flag = cancel_flag_clone.clone();
        
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

            // Get total files from scan before cleaning
            let total_files = ui_weak_clone
                .upgrade()
                .map(|ui| ui.get_cleaner_files_found())
                .unwrap_or(0);

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
                .clean_system_temp(token, pause_flag, cancel_flag, permanent_delete, {  // NUEVO: pasar permanent_delete
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
                })
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
                                format!("Sent {} files to Recycle Bin, {} errors", r.files_found, r.errors.len())
                            };
                            ui.set_cleaner_status(status.into());
                            if !r.errors.is_empty() {
                                tracing::warn!("Clean errors: {:?}", r.errors);
                            }
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
                                let a_date = chrono::NaiveDateTime::parse_from_str(&a.created.to_string(), "%Y-%m-%d %H:%M")
                                    .unwrap_or_else(|_| chrono::NaiveDateTime::from_timestamp_opt(0, 0).unwrap());
                                let b_date = chrono::NaiveDateTime::parse_from_str(&b.created.to_string(), "%Y-%m-%d %H:%M")
                                    .unwrap_or_else(|_| chrono::NaiveDateTime::from_timestamp_opt(0, 0).unwrap());
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
                                let a_date = chrono::NaiveDateTime::parse_from_str(&a.created.to_string(), "%Y-%m-%d %H:%M")
                                    .unwrap_or_else(|_| chrono::NaiveDateTime::from_timestamp_opt(0, 0).unwrap());
                                let b_date = chrono::NaiveDateTime::parse_from_str(&b.created.to_string(), "%Y-%m-%d %H:%M")
                                    .unwrap_or_else(|_| chrono::NaiveDateTime::from_timestamp_opt(0, 0).unwrap());
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

    // ── Callback: Open File ─
    ui.on_open_file(move |path: slint::SharedString| {
        let path = path.to_string();
        if let Err(e) = open::that(&path) {
            tracing::error!("Failed to open file {}: {}", path, e);
        }
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
    ui.on_scan_duplicates(move |path: slint::SharedString| {
        let ui_weak = ui_weak.clone();
        let cleaner = cleaner_clone.clone();
        let pause_flag = pause_flag_clone.clone();
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
    ui.on_quarantine_selected_duplicates(move || {
        let ui_weak = ui_weak.clone();
        let cleaner = cleaner_clone.clone();
        tokio::spawn(async move {
            let token = tokio_util::sync::CancellationToken::new();
            let (tx, rx) = tokio::sync::oneshot::channel();
            let _ = slint::invoke_from_event_loop(move || {
                let groups = ui_weak
                    .upgrade()
                    .map(|ui| ui.get_duplicate_groups())
                    .unwrap_or_default();

                // Extract data on the UI thread (ModelRc is not Send)
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
                        duplicate_groups.push(models::DuplicateGroup {
                            hash: group.hash.to_string(),
                            size: 0,
                            files,
                        });
                    }
                }
                let _ = tx.send(duplicate_groups);
            });

            let duplicate_groups = rx.await.unwrap_or_default();

            if !duplicate_groups.is_empty() {
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
                                // Calcular tamaño total de cuarentena
                                let total_bytes: u64 = quarantine_entries.iter().map(|e| e.size).sum();
                                let total_size = modules::cleaner::format_bytes(total_bytes);
                                
                                let slint_entries: slint::ModelRc<QuarantineEntryData> =
                                    slint::ModelRc::new(slint::VecModel::from(
                                        quarantine_entries
                                            .into_iter()
                                            .map(|e| QuarantineEntryData {
                                                original_path: e.original_path.to_string_lossy().to_string().into(),
                                                quarantine_path: e.quarantine_path.to_string_lossy().to_string().into(),
                                                size: modules::cleaner::format_bytes(e.size).into(),
                                                quarantined_at: e.quarantined_at.format("%Y-%m-%d %H:%M").to_string().into(),
                                            })
                                            .collect::<Vec<_>>(),
                                    ));
                                ui.set_quarantine_entries(slint_entries);
                                ui.set_quarantine_total_size(total_size.into());
                                ui.set_cleaner_status(format!("Quarantined {} files", entries.len()).into());
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("Failed to quarantine duplicates: {}", e);
                    }
                }
            }
        });
    });

    // ── Callback: Tab Changed ──
    // Auto-load quarantine when switching to Cleaner tab
    let ui_weak = ui.as_weak();
    let cleaner_clone = cleaner.clone();
    ui.on_tab_changed(move |tab_index| {
        if tab_index == 2 {
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
                                    .into_iter()
                                    .map(|e| QuarantineEntryData {
                                        original_path: e.original_path.to_string_lossy().to_string().into(),
                                        quarantine_path: e.quarantine_path.to_string_lossy().to_string().into(),
                                        size: modules::cleaner::format_bytes(e.size).into(),
                                        quarantined_at: e.quarantined_at.format("%Y-%m-%d %H:%M").to_string().into(),
                                    })
                                    .collect::<Vec<_>>(),
                            ));
                        ui.set_quarantine_entries(slint_entries);
                        ui.set_quarantine_total_size(total_size.into());
                    }
                });
            });
        }
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
                    // Calcular tamaño total de cuarentena
                    let total_bytes: u64 = entries.iter().map(|e| e.size).sum();
                    let total_size = modules::cleaner::format_bytes(total_bytes);
                    
                    let slint_entries: slint::ModelRc<QuarantineEntryData> =
                        slint::ModelRc::new(slint::VecModel::from(
                            entries
                                .into_iter()
                                .map(|e| QuarantineEntryData {
                                    original_path: e.original_path.to_string_lossy().to_string().into(),
                                    quarantine_path: e.quarantine_path.to_string_lossy().to_string().into(),
                                    size: modules::cleaner::format_bytes(e.size).into(),
                                    quarantined_at: e.quarantined_at.format("%Y-%m-%d %H:%M").to_string().into(),
                                })
                                .collect::<Vec<_>>(),
                        ));
                    ui.set_quarantine_entries(slint_entries);
                    ui.set_quarantine_total_size(total_size.into());
                }
            });
        });
    });

    // ─ Callback: Restore Quarantine ──
    let cleaner_clone = cleaner.clone();
    ui.on_restore_quarantine(move |index| {
        let cleaner = cleaner_clone.clone();
        let entries = cleaner.list_quarantine().unwrap_or_default();
        if let Some(entry) = entries.get(index as usize) {
            if let Err(e) = cleaner.restore_from_quarantine(entry) {
                tracing::error!("Failed to restore from quarantine: {}", e);
            }
        }
    });

    // ── Callback: Delete Quarantine ──
    let cleaner_clone = cleaner.clone();
    ui.on_delete_quarantine(move |index| {
        let cleaner = cleaner_clone.clone();
        let entries = cleaner.list_quarantine().unwrap_or_default();
        if let Some(entry) = entries.get(index as usize) {
            if let Err(e) = cleaner.delete_quarantine_permanently(entry) {
                tracing::error!("Failed to delete from quarantine: {}", e);
            }
        }
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
    let cpu_optimizer_clone = cpu_optimizer.clone();
    ui.on_toggle_focus(move |pid| {
        let cpu_optimizer = cpu_optimizer_clone.clone();
        if let Err(e) = cpu_optimizer.lock().unwrap().toggle_focus(pid as u32) {
            tracing::error!("Failed to toggle focus for PID {}: {}", pid, e);
        };
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
        if let Err(e) = open::that("https://github.com/yourusername/syspulse/releases") {
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
                // Only refresh when Monitor tab is active
                let stats = sys_monitor.lock().unwrap().refresh();

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
        }
    });

    // ── Handle tray events ──
    let ui_weak = ui.as_weak();
    let hunter_cmd_tx_clone = hunter_cmd_tx.clone();
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
                    let _ = hunter_cmd_tx_clone.send(ProcessHunterCommand::Pause);
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
