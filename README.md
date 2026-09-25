# SysPulse

Cross-platform system optimizer with real-time monitoring, built with **Rust** and **Slint**.

![Version](https://img.shields.io/badge/version-0.3.0-blue)
![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)
![License](https://img.shields.io/badge/license-MIT-green)

## ✨ Features

| Module | Description |
|--------|-------------|
| **System Monitor** | Real-time CPU, RAM, Disk, Network, Temperatures, Uptime, Top Processes (auto-refresh 2s) |
| **Smart Cleaner** | Temp files cleanup + Duplicate finder (SHA-256) + Quarantine with manifest |
| **Process Hunter** | Transient process detection + SQLite history + JSON/CSV export for AI analysis |
| **CPU Focus** | Boost process priority (Above Normal on Windows) |
| **Premium UI** | Neon theme, smooth animations (200-300ms), i18n (EN / ES-AR) |
| **System Tray** | Background mode, context menu, double-click to restore |
| **✨ Permanent Delete** | Toggle to bypass Recycle Bin for large cleanups (instant, no RAM spike) |

## 📸 Screenshots

> *Add screenshots here after building*

## 🚀 Quick Start

### Windows (Pre-built)
1. Go to [Releases](../../releases)
2. Download `SysPulse-Setup-0.3.0.exe` (or `syspulse.exe` portable)
3. Run and enjoy

### Build from Source

**Prerequisites:**
- Windows 10/11
- [Rust 1.75+](https://rustup.rs/)
- Visual Studio 2022+ with **Desktop development with C++** workload

```powershell
# Clone
git clone https://github.com/H3rC4/syspulse.git
cd syspulse

# Build release
cargo build --release

# Run
.\target\release\syspulse.exe
```

### Run in Background (System Tray only)
```powershell
.\target\release\syspulse.exe --background
```

## ⚙️ Configuration

Settings are stored in:
- **Windows:** `%APPDATA%\SysPulse\settings.toml`
- **Data (DB, quarantine, logs):** `%LOCALAPPDATA%\SysPulse\`

### Key Settings (Settings tab)
- **Language:** English / Español (Argentina) — requires restart
- **Dark mode:** Always on (light theme WIP)
- **Start with OS:** Auto-start on login
- **Process history retention:** Days to keep process events (default 30)
- **Quarantine retention:** Days before auto-purge (default 7)
- **🗑️ Eliminar permanentemente:** **NEW** — Delete files directly without Recycle Bin (use for large cleanups >1GB to avoid system freeze)

## 🗂️ Project Structure

```
SysPulse/
├── Cargo.toml              # Dependencies
├── build.rs                # Slint compiler + icon embedding
├── assets/
│   ├── icon.svg            # Vector icon (heart + EKG neon)
│   └── icon.ico            # Windows icon (multi-res, TODO)
├── ui/
│   └── app.slint           # Complete UI (1700+ lines)
├── locales/
│   ├── en/main.ftl         # English (98 keys)
│   └── es-AR/main.ftl      # Spanish Argentina (98 keys)
├── src/
│   ├── main.rs             # Entry + callbacks + timers
│   ├── models.rs           # Data structures
│   └── modules/
│       ├── cleaner.rs      # Temp clean + duplicates + quarantine
│       ├── config.rs       # Settings + autostart
│       ├── sys_monitor.rs  # System metrics (sysinfo 0.30)
│       ├── process_hunter.rs
│       ├── cpu_optimizer.rs
│       ├── i18n.rs         # Fluent localization
│       └── tray.rs         # System tray (tao)
├── planes/                 # Project docs & plans
└── target/release/         # Build output
```

## 🛠️ Development

### Commands
```powershell
# Debug build (fast)
cargo build

# Release build (optimized)
cargo build --release

# Run with debug logs
$env:RUST_LOG="debug"; .\target\release\syspulse.exe

# Run with trace logs (very verbose)
$env:RUST_LOG="trace"; .\target\release\syspulse.exe

# Lint
cargo clippy

# Check without building
cargo check

# Clean build artifacts
cargo clean
```

### Tech Stack
| Layer | Technology |
|-------|------------|
| Language | Rust 2021 |
| GUI | Slint 1.2+ (native, GPU-accelerated) |
| System Info | sysinfo 0.30 |
| Async | tokio |
| Serialization | serde + toml |
| Hashing | sha2 (SHA-256) |
| i18n | fluent-rs |
| Tray | tao (cross-platform) |
| Trash | trash crate (Recycle Bin) |

### Slint Gotchas (for contributors)
- No `linear-gradient` → use solid colors
- No `.toFixed()` → format in Rust with `format!()`
- No `%` on floats → use `Math.mod()`
- `ModelRc` not `Send` → create inside `invoke_from_event_loop`
- No native tooltips → use descriptive Text
- `Timer::default()` + `.start()` not `Timer::new()`

## 📦 Distribution

### Create Windows Installer (Inno Setup)
1. Install [Inno Setup 6](https://jrsoftware.org/isdl.php)
2. Create `installer.iss` (see `planes/instrucciones-seguir.md`)
3. Compile → `output/SysPulse-Setup-0.3.0.exe`

### CI/CD (GitHub Actions)
Workflow at `.github/workflows/build.yml`:
- Builds on every push to `main`
- Uploads `syspulse.exe` as artifact
- Creates Release on tag `v*` with binary attached

## 🔮 Roadmap

### v0.3.1 (Next)
- [ ] Windows `.ico` icon (multi-resolution)
- [ ] Inno Setup installer
- [ ] GitHub Release with binaries
- [ ] CI/CD pipeline

### v0.4.0
- [ ] Light theme (full toggle)
- [ ] Real-time charts (CPU/RAM history)
- [ ] Windows toast notifications
- [ ] Portable mode (config in exe folder)

### v1.0.0
- [ ] Plugin system
- [ ] Cross-platform (Linux/macOS full support)
- [ ] Auto-updater

## 🤝 Contributing

1. Fork the repo
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push: `git push origin feature/amazing-feature`
5. Open Pull Request

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

## 👨‍💻 Author

**H3rC4** — [GitHub](https://github.com/H3rC4)

---

## 📋 Resume Instructions (for maintainers)

### If you're picking up this project:

1. **Clone & Setup**
   ```powershell
   git clone https://github.com/H3rC4/syspulse.git
   cd syspulse
   # Install Rust if needed: https://rustup.rs/
   ```

2. **Build & Test**
   ```powershell
   cargo build --release
   .\target\release\syspulse.exe
   ```

3. **Key Files to Know**
   - `src/main.rs` — App entry, callbacks, timers
   - `ui/app.slint` — All UI components
   - `src/modules/cleaner.rs` — Clean logic (permanent_delete toggle)
   - `src/modules/config.rs` — Settings persistence
   - `planes/plan-continuacion.md` — Detailed continuation plan

4. **Current Blockers**
   - Push to GitHub needs Personal Access Token
   - Icon `.ico` not created yet
   - Installer not built
   - Light theme blocked by Slint limitations

5. **Testing Checklist** (see `planes/plan-continuacion.md`)

---

**Last Updated:** 24 September 2026  
**Status:** v0.3.0 — Functional, ready for release pipeline# syspulse
