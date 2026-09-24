use std::sync::Arc;
use tao::event_loop::{ControlFlow, EventLoopBuilder};
#[cfg(target_os = "windows")]
use tao::platform::windows::EventLoopBuilderExtWindows;
use tokio::sync::Mutex;
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    TrayIconBuilder, TrayIconEvent,
};

#[derive(Debug, Clone)]
pub enum TrayCommand {
    SetPauseLabel(bool),
}

#[derive(Debug, Clone)]
pub enum TrayEvent {
    Open,
    TogglePause,
    Exit,
}

pub struct TrayHandle {
    command_tx: std::sync::mpsc::Sender<TrayCommand>,
}

impl TrayHandle {
    pub fn set_pause_label(&self, paused: bool) {
        let _ = self.command_tx.send(TrayCommand::SetPauseLabel(paused));
    }
}

pub fn spawn_tray(event_tx: tokio::sync::mpsc::UnboundedSender<TrayEvent>) -> Result<TrayHandle, String> {
    let (command_tx, command_rx) = std::sync::mpsc::channel::<TrayCommand>();

    std::thread::spawn(move || {
        let mut event_loop_builder = EventLoopBuilder::new();
        #[cfg(target_os = "windows")]
        event_loop_builder.with_any_thread(true);
        let event_loop = event_loop_builder.build();
        let menu = Menu::new();

        let open_item = MenuItem::new("Open SysPulse", true, None);
        let pause_item = MenuItem::new("Pause monitoring", true, None);
        let separator = PredefinedMenuItem::separator();
        let exit_item = MenuItem::new("Exit", true, None);

        menu.append(&open_item).ok();
        menu.append(&pause_item).ok();
        menu.append(&separator).ok();
        menu.append(&exit_item).ok();

        let icon = match load_icon() {
            Ok(i) => i,
            Err(e) => {
                tracing::error!("Failed to load icon: {}, falling back to default", e);
                match create_default_icon() {
                    Ok(i) => i,
                    Err(e) => {
                        tracing::error!("Failed to create default icon: {}", e);
                        return;
                    }
                }
            }
        };

        let _tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("SysPulse")
            .with_icon(icon)
            .build();

        let pause_item = Arc::new(Mutex::new(pause_item));

        event_loop.run(move |_event, _, control_flow| {
            *control_flow = ControlFlow::WaitUntil(
                std::time::Instant::now() + std::time::Duration::from_millis(100),
            );

            while let Ok(cmd) = command_rx.try_recv() {
                match cmd {
                    TrayCommand::SetPauseLabel(paused) => {
                        let label = if paused {
                            "Resume monitoring"
                        } else {
                            "Pause monitoring"
                        };
                        let _ = pause_item.blocking_lock().set_text(label);
                    }
                }
            }

            if let Ok(event) = TrayIconEvent::receiver().try_recv() {
                if let TrayIconEvent::DoubleClick { .. } = event {
                    let _ = event_tx.send(TrayEvent::Open);
                }
            }

            if let Ok(event) = MenuEvent::receiver().try_recv() {
                let id = event.id();
                if id == open_item.id() {
                    let _ = event_tx.send(TrayEvent::Open);
                } else if id == pause_item.blocking_lock().id() {
                    let _ = event_tx.send(TrayEvent::TogglePause);
                } else if id == exit_item.id() {
                    let _ = event_tx.send(TrayEvent::Exit);
                }
            }
        });
    });

    Ok(TrayHandle { command_tx })
}

fn load_icon() -> Result<tray_icon::Icon, String> {
    // Try to load icon.ico from assets directory
    let icon_path = std::path::Path::new("assets/icon.ico");
    if icon_path.exists() {
        let icon_data = std::fs::read(icon_path)
            .map_err(|e| format!("Failed to read icon.ico: {}", e))?;
        
        // Parse ICO file - extract first image (usually 256x256 or 32x32)
        if let Ok(icon) = parse_ico_to_tray_icon(&icon_data) {
            return Ok(icon);
        }
    }
    
    Err("Icon file not found or invalid".to_string())
}

fn parse_ico_to_tray_icon(ico_data: &[u8]) -> Result<tray_icon::Icon, String> {
    // Simple ICO parser - extract the largest PNG or BMP image
    if ico_data.len() < 6 {
        return Err("Invalid ICO file".to_string());
    }
    
    let _reserved = u16::from_le_bytes([ico_data[0], ico_data[1]]);
    let _type = u16::from_le_bytes([ico_data[2], ico_data[3]]);
    let count = u16::from_le_bytes([ico_data[4], ico_data[5]]) as usize;
    
    if count == 0 {
        return Err("ICO file has no images".to_string());
    }
    
    // Find the largest image (prefer 32x32 for tray)
    let mut best_idx = 0;
    let mut best_size = 0u32;
    
    for i in 0..count {
        let offset = 6 + i * 16;
        if offset + 16 > ico_data.len() {
            break;
        }
        
        let width = if ico_data[offset] == 0 { 256 } else { ico_data[offset] as u32 };
        let height = if ico_data[offset + 1] == 0 { 256 } else { ico_data[offset + 1] as u32 };
        let size = width * height;
        
        // Prefer 32x32 for tray icon
        if width == 32 && height == 32 {
            best_idx = i;
            break;
        }
        
        if size > best_size {
            best_size = size;
            best_idx = i;
        }
    }
    
    let entry_offset = 6 + best_idx * 16;
    let data_size = u32::from_le_bytes([
        ico_data[entry_offset + 8],
        ico_data[entry_offset + 9],
        ico_data[entry_offset + 10],
        ico_data[entry_offset + 11],
    ]) as usize;
    
    let data_offset = u32::from_le_bytes([
        ico_data[entry_offset + 12],
        ico_data[entry_offset + 13],
        ico_data[entry_offset + 14],
        ico_data[entry_offset + 15],
    ]) as usize;
    
    if data_offset + data_size > ico_data.len() {
        return Err("ICO data out of bounds".to_string());
    }
    
    let image_data = &ico_data[data_offset..data_offset + data_size];
    
    // Check if it's PNG (starts with PNG signature)
    if image_data.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        // PNG format - decode it
        decode_png_to_rgba(image_data)
    } else {
        // BMP format - parse ICO BMP header
        decode_ico_bmp_to_rgba(image_data)
    }
}

fn decode_png_to_rgba(png_data: &[u8]) -> Result<tray_icon::Icon, String> {
    // Use a simple PNG decoder - for now, fall back to default
    // In production, you'd use the `png` crate
    Err("PNG decoding not implemented".to_string())
}

fn decode_ico_bmp_to_rgba(bmp_data: &[u8]) -> Result<tray_icon::Icon, String> {
    if bmp_data.len() < 40 {
        return Err("BMP data too short".to_string());
    }
    
    let width = u32::from_le_bytes([bmp_data[4], bmp_data[5], bmp_data[6], bmp_data[7]]);
    let height = u32::from_le_bytes([bmp_data[8], bmp_data[9], bmp_data[10], bmp_data[11]]) / 2; // Height includes mask
    let bpp = u16::from_le_bytes([bmp_data[14], bmp_data[15]]);
    
    if bpp != 32 {
        return Err(format!("Unsupported BMP bit depth: {}", bpp));
    }
    
    let pixel_data_offset = 40; // ICO BMP has no file header
    let pixel_data = &bmp_data[pixel_data_offset..];
    
    let mut rgba = Vec::with_capacity((width * height * 4) as usize);
    
    // BMP stores pixels bottom-to-top, BGRA format
    for y in (0..height).rev() {
        for x in 0..width {
            let idx = ((y * width + x) * 4) as usize;
            if idx + 3 >= pixel_data.len() {
                break;
            }
            let b = pixel_data[idx];
            let g = pixel_data[idx + 1];
            let r = pixel_data[idx + 2];
            let a = pixel_data[idx + 3];
            rgba.push(r);
            rgba.push(g);
            rgba.push(b);
            rgba.push(a);
        }
    }
    
    tray_icon::Icon::from_rgba(rgba, width, height)
        .map_err(|e| format!("Failed to create icon from BMP: {:?}", e))
}

fn create_default_icon() -> Result<tray_icon::Icon, String> {
    let width = 64;
    let height = 64;
    let mut rgba = Vec::with_capacity(width * height * 4);

    for y in 0..height {
        for x in 0..width {
            let dx = x as f32 - width as f32 / 2.0;
            let dy = y as f32 - height as f32 / 2.0;
            let dist = (dx * dx + dy * dy).sqrt();
            let max_dist = width as f32 / 2.0;
            let t = 1.0 - (dist / max_dist).min(1.0);

            let r = (20.0 * t) as u8;
            let g = (220.0 * t) as u8;
            let b = (220.0 * t) as u8;
            let a = if dist < max_dist { 255 } else { 0 };

            rgba.push(r);
            rgba.push(g);
            rgba.push(b);
            rgba.push(a);
        }
    }

    tray_icon::Icon::from_rgba(rgba, width as u32, height as u32)
        .map_err(|e| format!("Failed to create icon: {:?}", e))
}
