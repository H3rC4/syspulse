# SysPulse

Optimizador de sistema multiplataforma con monitoreo en tiempo real, construido con **Rust** y **Slint**.

![Version](https://img.shields.io/badge/version-0.3.0-blue)
![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)
![License](https://img.shields.io/badge/license-MIT-green)

## ✨ Características

| Módulo | Descripción |
|--------|-------------|
| **System Monitor** | CPU, RAM, Disco, Red, Temperaturas, Uptime, Top Procesos en tiempo real (auto-refresh 2s) |
| **Smart Cleaner** | Limpieza de temporales + Buscador de duplicados (SHA-256) + Cuarentena con manifiesto |
| **Process Hunter** | Detección de procesos transitorios + Historial SQLite + Export JSON/CSV para análisis IA |
| **CPU Focus** | Aumentar prioridad de proceso (Above Normal en Windows) |
| **Premium UI** | Tema neon, animaciones suaves (200-300ms), i18n (EN / ES-AR) |
| **System Tray** | Modo background, menú contextual, doble clic para restaurar |
| **✨ Eliminar permanentemente** | Toggle para omitir Papelera en limpiezas grandes (instantáneo, sin pico de RAM) |

## 📸 Capturas de pantalla

> *Agregar capturas tras compilar*

## 🚀 Inicio rápido

### Windows (Pre-compilado)
1. Ve a [Releases](../../releases)
2. Descarga `SysPulse-Setup-0.3.0.exe` (o `syspulse.exe` portable)
3. Ejecuta y disfruta

### Compilar desde código

**Requisitos:**
- Windows 10/11
- [Rust 1.75+](https://rustup.rs/)
- Visual Studio 2022+ con carga de trabajo **Desarrollo de escritorio con C++**

```powershell
# Clonar
git clone https://github.com/H3rC4/syspulse.git
cd syspulse

# Compilar release
cargo build --release

# Ejecutar
.\target\release\syspulse.exe
```

### Ejecutar en background (Solo System Tray)
```powershell
.\target\release\syspulse.exe --background
```

## ⚙️ Configuración

Los ajustes se guardan en:
- **Windows:** `%APPDATA%\SysPulse\settings.toml`
- **Datos (BD, cuarentena, logs):** `%LOCALAPPDATA%\SysPulse\`

### Ajustes clave (Pestaña Settings)
- **Idioma:** English / Español (Argentina) — requiere reinicio
- **Modo oscuro:** Siempre activo (tema claro en desarrollo)
- **Iniciar con Windows:** Auto-inicio al loguearse
- **Retención historial procesos:** Días a conservar eventos (default 30)
- **Retención cuarentena:** Días antes de auto-purga (default 7)
- **🗑️ Eliminar permanentemente:** **NUEVO** — Elimina archivos directo sin Papelera (usar en limpiezas >1GB para evitar freeze del sistema)

## 🗂️ Estructura del proyecto

```
SysPulse/
├── Cargo.toml              # Dependencias
├── build.rs                # Compilador Slint + embedding icono
├── assets/
│   ├── icon.svg            # Icono vectorial (corazón + EKG neon)
│   └── icon.ico            # Icono Windows (multi-res, PENDIENTE)
├── ui/
│   └── app.slint           # UI completa (1700+ líneas)
├── locales/
│   ├── en/main.ftl         # Inglés (98 claves)
│   └── es-AR/main.ftl      # Español Argentina (98 claves)
├── src/
│   ├── main.rs             # Entry + callbacks + timers
│   ├── models.rs           # Estructuras de datos
│   └── modules/
│       ├── cleaner.rs      # Limpieza temp + duplicados + cuarentena
│       ├── config.rs       # Settings + autostart
│       ├── sys_monitor.rs  # Métricas sistema (sysinfo 0.30)
│       ├── process_hunter.rs
│       ├── cpu_optimizer.rs
│       ├── i18n.rs         # Localización Fluent
│       └── tray.rs         # System tray (tao)
├── planes/                 # Documentación y planes
└── target/release/         # Build output
```

## 🛠️ Desarrollo

### Comandos
```powershell
# Build debug (rápido)
cargo build

# Build release (optimizado)
cargo build --release

# Ejecutar con logs debug
$env:RUST_LOG="debug"; .\target\release\syspulse.exe

# Ejecutar con logs trace (muy verboso)
$env:RUST_LOG="trace"; .\target\release\syspulse.exe

# Linter
cargo clippy

# Verificar sin compilar
cargo check

# Limpiar artifacts
cargo clean
```

### Stack tecnológico
| Capa | Tecnología |
|------|------------|
| Lenguaje | Rust 2021 |
| GUI | Slint 1.2+ (nativo, GPU-accelerated) |
| Info sistema | sysinfo 0.30 |
| Async | tokio |
| Serialización | serde + toml |
| Hashing | sha2 (SHA-256) |
| i18n | fluent-rs |
| Tray | tao (multiplataforma) |
| Papelera | trash crate (Recycle Bin) |

### Particularidades de Slint (para contribuidores)
- No `linear-gradient` → usar colores sólidos
- No `.toFixed()` → formatear en Rust con `format!()`
- No `%` sobre floats → usar `Math.mod()`
- `ModelRc` no es `Send` → crear dentro de `invoke_from_event_loop`
- No tooltips nativos → usar Text descriptivo
- `Timer::default()` + `.start()` no `Timer::new()`

## 📦 Distribución

### Crear instalador Windows (Inno Setup)
1. Instala [Inno Setup 6](https://jrsoftware.org/isdl.php)
2. Crea `installer.iss` (ver `planes/instrucciones-seguir.md`)
3. Compila → `output/SysPulse-Setup-0.3.0.exe`

### CI/CD (GitHub Actions)
Workflow en `.github/workflows/build.yml`:
- Compila en cada push a `main`
- Sube `syspulse.exe` como artifact
- Crea Release en tag `v*` con binario adjunto

## 🔮 Roadmap

### v0.3.1 (Próxima)
- [ ] Icono Windows `.ico` (multi-resolución)
- [ ] Instalador Inno Setup
- [ ] GitHub Release con binarios
- [ ] Pipeline CI/CD

### v0.4.0
- [ ] Tema claro (toggle completo)
- [ ] Gráficos tiempo real (historial CPU/RAM)
- [ ] Notificaciones toast Windows
- [ ] Modo portable (config en carpeta exe)

### v1.0.0
- [ ] Sistema de plugins
- [ ] Soporte completo Linux/macOS
- [ ] Auto-actualizador

## 🤝 Contribuir

1. Fork del repo
2. Rama feature: `git checkout -b feature/feature-increible`
3. Commit: `git commit -m 'Agregar feature increible'`
4. Push: `git push origin feature/feature-increible`
5. Abre Pull Request

## 📄 Licencia

MIT License — ver [LICENSE](LICENSE) para detalles.

## 👨‍💻 Autor

**H3rC4** — [GitHub](https://github.com/H3rC4)

---

## 📋 Instrucciones de continuación (para maintainers)

### Si retomas el proyecto:

1. **Clonar y configurar**
   ```powershell
   git clone https://github.com/H3rC4/syspulse.git
   cd syspulse
   # Instalar Rust si falta: https://rustup.rs/
   ```

2. **Compilar y testear**
   ```powershell
   cargo build --release
   .\target\release\syspulse.exe
   ```

3. **Archivos clave**
   - `src/main.rs` — Entry point, callbacks, timers
   - `ui/app.slint` — Todos los componentes UI
   - `src/modules/cleaner.rs` — Lógica limpieza (toggle permanent_delete)
   - `src/modules/config.rs` — Persistencia settings
   - `planes/plan-continuacion.md` — Plan detallado de continuación

4. **Bloqueadores actuales**
   - Push a GitHub requiere Personal Access Token
   - Icono `.ico` no creado aún
   - Instalador no compilado
   - Tema claro bloqueado por limitaciones de Slint

5. **Checklist de testing** (ver `planes/plan-continuacion.md`)

---

**Última actualización:** 25 de septiembre de 2026  
**Estado:** v0.3.0 — Funcional, listo para pipeline de release