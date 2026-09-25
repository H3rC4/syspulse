# SysPulse - Plan de Continuación (Post v0.3.0)

## 📅 Fecha: 25 de septiembre de 2026
## 🎯 Estado Actual: v0.3.0 - Funcional, compilando OK, subido a GitHub (H3rC4/syspulse)

---

## ✅ **Completado en esta sesión (25 sep 2026)**

### 1. **Fix errores de compilación**
- **cleaner.rs**: Unificados tipos de error (`std::io::Error` + `trash::Error` → `String`) en 2 lugares
- **app.slint**: Agregadas propiedades `light-mode`, `permanent-delete`; callback `set_theme_colors`; checkbox "Light mode" en SettingsTab; binding actualizado en AppWindow
- **main.rs**: Eliminada función `apply_theme` (cambio tema runtime complejo en Slint); eliminadas llamadas a `set_light_mode` y `apply_theme`; fix orden argumentos en `clean_system_temp` (closure primero, `permanent_delete` último); fix move `ui_weak` en callback quarantine

### 2. **Instalador Inno Setup**
- Creado `installer.iss` con check de actualizaciones automático (GitHub API)
- Verifica versión al iniciar wizard → avisa si hay versión nueva → botón "Cancelar" abre releases

### 3. **README.md en español**
- Traducido completo al español
- Incluye: características, instalación, configuración, estructura, desarrollo, distribución, roadmap, contribución, licencia

### 4. **Cargo.toml actualizado**
- Versión `0.3.0`
- Repository URL correcta: `https://github.com/H3rC4/syspulse`

### 5. **Git + GitHub**
- Push completado (commits: `81603b6` README español, `9f1fba2` installer + version, `0f0db82` installer con updates, `a7f91a8` fix Color, `422f110` fix ui_weak move)

---

## 🚀 **Próximas Tareas (Prioridad)**

### **ALTA - Inmediata (al volver)**

| # | Tarea | Archivos | Detalle |
|---|-------|----------|---------|
| 1 | **Compilar release en Windows** | - | `cargo build --release` → verificar que funciona |
| 2 | **Compilar instalador** | Inno Setup 7 | `& "C:\Program Files\Inno Setup 7\ISCC.exe" installer.iss` |
| 3 | **Testear "Eliminar permanentemente"** | - | Settings → activar → Apply & Restart → Cleaner → Scan → Clean → verificar NO va a papelera |
| 4 | **Crear Release v0.3.0** | GitHub Web | Tag `v0.3.0` → adjuntar `output/SysPulse-Setup-0.3.0.exe` |

### **MEDIA - Esta semana**

| # | Tarea | Detalle |
|---|-------|---------|
| 5 | **Icono ICO para Windows** | `assets/icon.svg` → convertir a `.ico` (256,128,64,48,32,16) → `assets/icon.ico` → actualizar `Cargo.toml` + `build.rs` |
| 6 | **LICENSE (MIT)** | Crear archivo `LICENSE` en root |
| 7 | **Test completo** | Ver checklist testing abajo |

### **BAJA - Opcional / Futuro**

| # | Tarea | Detalle |
|---|-------|---------|
| 8 | **CI/CD GitHub Actions** | `.github/workflows/build.yml` - build automático en push + release en tag |
| 9 | **Tema claro completo** | Requiere refactor Theme en Slint (limitación: no soporta temas dinámicos runtime) |
| 10 | **Gráficos tiempo real** | CPU/RAM history charts (crate `slint-plot` o custom) |
| 11 | **Notificaciones sistema** | `winrt` crate para toast notifications |
| 12 | **Modo portable** | Config en carpeta local vs AppData |

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

### **Instalador Inno Setup (Tarea 6)** - **YÁ CREADO**
```powershell
# Compilar:
& "C:\Program Files\Inno Setup 7\ISCC.exe" installer.iss
# Resultado: output\SysPulse-Setup-0.3.0.exe
```

### **CI/CD (Tarea 8)**
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
✅ Fix errores compilación (cleaner.rs, app.slint, main.rs)
✅ Instalador Inno Setup con check updates (installer.iss)
✅ README.md en español
✅ Cargo.toml version 0.3.0 + repo URL
✅ Push a GitHub (H3rC4/syspulse)
⏳ cargo build --release (en Windows)
⏳ Compilar instalador (Inno Setup 7)
⏳ Test manual completo
⏳ Release v0.3.0 en GitHub con instalador
⏳ Icono .ico
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
- [ ] Toggle "Light mode" → (solo UI, tema real requiere reinicio)
- [ ] Start with OS / retention sliders

---

## 📂 **Estructura Actual**

```
SysPulse/
├── Cargo.toml              # v0.3.0, repo URL correcta
├── build.rs
├── .gitignore
├── installer.iss           # NUEVO: Inno Setup con check updates
├── assets/
│   ├── icon.svg            # Corazón + EKG neon
│   └── icon.ico            # (PENDIENTE: crear)
├── ui/
│   └── app.slint           # ~1710 líneas, UI premium + light-mode prop
├── locales/
│   ├── en/main.ftl         # 98 claves
│   └── es-AR/main.ftl      # 98 claves
├── src/
│   ├── main.rs             # ~1190 líneas, fixes compilación
│   ├── models.rs
│   └── modules/
│       ├── cleaner.rs      # ~738 líneas, error types unificados
│       ├── config.rs       # Settings + permanent_delete + light_mode
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
└── target/release/         # (tras build)
    ├── syspulse.exe
    └── syspulse.pdb
```

---

## 💡 **Notas para la próxima sesión**

1. **En Windows**: Rust + VS Build Tools + Inno Setup 7 ya instalados
2. **Compilar**: `cargo build --release` → `ISCC.exe installer.iss`
3. **El toggle "Eliminar permanentemente" está implementado y listo para testear**
4. **Light mode**: Property agregada en UI + Settings, pero cambio real de tema requiere reinicio (limitación Slint)

---

## 🎯 **Comando único al volver:**

```powershell
cd D:\proyectos\SysPulse
# 1. Traer cambios
git pull origin main
# 2. Build release
cargo build --release
# 3. Compilar instalador
& "C:\Program Files\Inno Setup 7\ISCC.exe" installer.iss
# 4. Verificar
ls output\SysPulse-Setup-0.3.0.exe
# 5. Tag + push
git tag v0.3.0
git push origin v0.3.0
# 6. GitHub Web: New Release v0.3.0 + adjuntar instalador
```

---

**Responsable:** H3rC4  
**Repo:** https://github.com/H3rC4/syspulse  
**Versión objetivo próxima:** v0.3.1 (con instalador + icono + release)