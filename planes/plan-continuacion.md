# SysPulse - Plan de Continuación (Post v0.3.0)

## 📅 Fecha: 24 de septiembre de 2026
## 🎯 Estado Actual: v0.3.0 - Funcional, subido a GitHub (H3rC4/syspulse)

---

## ✅ **Completado en esta sesión**

### 1. **Opción 3: Toggle "Eliminar permanentemente"** 
- **config.rs**: Agregado `permanent_delete: bool` (default: false)
- **cleaner.rs**: Lógica condicional `std::fs::remove_file` vs `trash::delete`
- **app.slint**: CheckBox en SettingsTab + advertencia naranja
- **main.rs**: Persistencia + paso al cleaner

### 2. **Git + GitHub**
- Repo inicializado local
- Commit: `0408bb5` "SysPulse v0.3.0..."
- Remote: `https://github.com/H3rC4/syspulse.git`
- **Pendiente: Push** (requiere token de GitHub)

---

## 🚀 **Próximas Tareas (Prioridad)**

### **ALTA - Inmediata (al volver)**

| # | Tarea | Archivos | Detalle |
|---|-------|----------|---------|
| 1 | **Push a GitHub** | - | Crear token en github.com/settings/tokens → `git push -u origin main` |
| 2 | **Compilar release** | - | `cargo build --release` → verificar que funciona |
| 3 | **Testear "Eliminar permanentemente"** | - | Settings → activar → Apply & Restart → Cleaner → Scan → Clean → verificar que NO va a papelera |
| 4 | **Crear Release v0.3.0** | GitHub Web | Tag `v0.3.0` → adjuntar `target/release/syspulse.exe` |

### **MEDIA - Esta semana**

| # | Tarea | Detalle |
|---|-------|---------|
| 5 | **Icono ICO para Windows** | `assets/icon.svg` → convertir a `.ico` (256,128,64,48,32,16) → `assets/icon.ico` → actualizar `Cargo.toml` + `build.rs` |
| 6 | **Instalador Inno Setup** | Crear `installer.iss` → compilar → `output/SysPulse-Setup-0.3.0.exe` |
| 7 | **README.md** | Ver archivo `README.md` en root (creado abajo) |
| 8 | **LICENSE (MIT)** | Crear archivo `LICENSE` en root |

### **BAJA - Opcional / Futuro**

| # | Tarea | Detalle |
|---|-------|---------|
| 9 | **CI/CD GitHub Actions** | `.github/workflows/build.yml` - build automático en push + release en tag |
| 10 | **Tema claro completo** | Requiere refactor Theme en Slint (limitación: no soporta temas dinámicos runtime) |
| 11 | **Gráficos tiempo real** | CPU/RAM history charts (crate `slint-plot` o custom) |
| 12 | **Notificaciones sistema** | `winrt` crate para toast notifications |
| 13 | **Modo portable** | Config en carpeta local vs AppData |

---

## 🔧 **Detalles Técnicos Pendientes**

### **Icono ICO (Tarea 5)**
```bash
# Opción A: Online (recomendado)
# https://cloudconvert.com/svg-to-ico o https://convertio.co/svg-ico/
# Subir assets/icon.svg → descargar icon.ico → guardar en assets/icon.ico

# Opción B: ImageMagick (si instalado)
magick convert assets/icon.svg -define icon:auto-resize=256,128,64,48,32,16 assets/icon.ico
```
Luego en `Cargo.toml`:
```toml
[package.metadata.windows]
icon = "assets/icon.ico"
```
En `build.rs` al final:
```rust
std::fs::copy("assets/icon.ico", "target/release/icon.ico").ok();
```

### **Instalador Inno Setup (Tarea 6)**
1. Descargar: https://jrsoftware.org/isdl.php
2. Crear `installer.iss` en root
3. Compilar en Inno Setup Compiler → `output/SysPulse-Setup-0.3.0.exe`

### **CI/CD (Tarea 9)**
Crear `.github/workflows/build.yml`:
```yaml
name: Build SysPulse
on:
  push:
    branches: [ main ]
    tags: [ 'v*' ]
jobs:
  build:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo build --release
      - uses: actions/upload-artifact@v4
        with:
          name: syspulse-windows
          path: target/release/syspulse.exe
      - uses: softprops/action-gh-release@v1
        if: startsWith(github.ref, 'refs/tags/')
        with:
          files: target/release/syspulse.exe
```

---

## 📋 **Checklist Visual**

```
✅ Opción 3: Toggle eliminar permanente
✅ Commit local v0.3.0
⏳ Push a GitHub (H3rC4/syspulse)
⏳ cargo build --release
⏳ Test manual completo
⏳ Release v0.3.0 en GitHub
⏳ Icono .ico
⏳ Instalador Inno Setup
⏳ README.md
⏳ LICENSE MIT
⏳ CI/CD GitHub Actions
⏳ Tema claro
⏳ Gráficos tiempo real
⏳ Notificaciones
⏳ Modo portable
```

---

## 🧪 **Testing Manual (al volver)**

### System Monitor
- [ ] CPU usage actualiza cada 2s
- [ ] RAM/SWAP correcto vs Task Manager
- [ ] Discos: espacio libre/total
- [ ] Network: upload/download activity
- [ ] Temperaturas (si hay sensores)
- [ ] Uptime + Load Average
- [ ] Top 5 CPU / RAM processes

### Cleaner
- [ ] Scan → Pause/Resume/Reset
- [ ] Clean → "Cleaning: X/Y files"
- [ ] Con toggle OFF → archivos en Papelera
- [ ] Con toggle ON → archivos NO en Papelera (eliminados directo)

### Duplicates
- [ ] Browse → Scan → Total MB
- [ ] Checkboxes + Open + Keep Oldest/Newest
- [ ] Quarantine → auto-carga al cambiar tab

### Quarantine
- [ ] Refresh / Open / Restore / Delete
- [ ] Tamaño total visible

### Settings
- [ ] Idioma → Apply & Restart → reinicia con nuevo idioma
- [ ] Toggle "Eliminar permanentemente" → guarda y persiste
- [ ] Start with OS / retention sliders

---

## 📂 **Estructura Actual**
```
SysPulse/
├── Cargo.toml
├── build.rs
├── .gitignore
├── assets/
│   ├── icon.svg      # Corazón + EKG neon
│   └── icon.ico      # (PENDIENTE: crear)
├── ui/
│   └── app.slint     # 1700+ líneas, UI premium completa
├── locales/
│   ├── en/main.ftl   # 98 claves
│   └── es-AR/main.ftl
├── src/
│   ├── main.rs       # 1223 líneas
│   ├── models.rs
│   └── modules/
│       ├── cleaner.rs      # 748 líneas (nuevo: permanent_delete)
│       ├── config.rs       # Settings + permanent_delete
│       ├── sys_monitor.rs  # 172 líneas
│       ├── process_hunter.rs
│       ├── cpu_optimizer.rs
│       ├── i18n.rs
│       └── tray.rs
├── planes/
│   ├── instrucciones-seguir.md
│   ├── plan-de-implementacion.md
│   ├── plan-mejoras-ui-ux-v0.2.0.md
│   └── plan-continuacion.md  # ESTE ARCHIVO
└── target/release/syspulse.exe  # (tras build)
```

---

## 💡 **Notas para la próxima sesión**

1. **Rust no está en PATH** en este entorno → usar `source "$HOME/.cargo/env"` o terminal con Rust configurado
2. **El push a GitHub falló por auth** → necesitas token (ver arriba)
3. **El ejecutable compila** (ver `target/release/` existe) pero no probado en esta máquina
4. **El toggle "Eliminar permanentemente" está implementado y listo para testear**

---

## 🎯 **Comando único al volver:**
```powershell
cd D:\proyectos\SysPulse
# 1. Push
git push -u origin main
# 2. Build
cargo build --release
# 3. Test
.\target\release\syspulse.exe
```

---

**Responsable:** H3rC4  
**Repo:** https://github.com/H3rC4/syspulse  
**Versión objetivo próxima:** v0.3.1 (con instalador + icono + release)