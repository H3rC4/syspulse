# SysPulse - Instrucciones para Continuar

## 🎯 Tareas Pendientes (25 de septiembre de 2026)

### 🔴 ALTA PRIORIDAD - Inmediato

#### 1. **Compilar Release + Instalador en Windows**
**Estado actual:** Código compila OK. Falta build nativo en Windows + Inno Setup.

**Pasos en Developer PowerShell for VS 2022:**
```powershell
cd D:\proyectos\SysPulse
git pull origin main
cargo build --release
& "C:\Program Files\Inno Setup 7\ISCC.exe" installer.iss
ls output\SysPulse-Setup-0.3.0.exe
```

#### 2. **Crear Release v0.3.0 en GitHub**
```powershell
git tag v0.3.0
git push origin v0.3.0
```
**Luego en navegador:** https://github.com/H3rC4/syspulse/releases/new
- Tag: `v0.3.0`
- Title: `SysPulse v0.3.0 - System Monitor + Premium UI`
- Adjuntar: `output\SysPulse-Setup-0.3.0.exe`
- Publish release

#### 3. **Testear "Eliminar permanentemente"**
- Settings → Toggle "Eliminar permanentemente" ON → Apply & Restart
- Cleaner → Scan → Clean → Verificar que archivos NO van a Papelera

---

### 🟡 MEDIA PRIORIDAD - Esta semana

#### 4. **Convertir Icono SVG a ICO**
**Estado actual:** Tenemos `assets/icon.svg` (corazón + EKG neon). Falta `.ico` multi-resolución.

**Opción A: Online (recomendado)**
1. https://cloudconvert.com/svg-to-ico o https://convertio.co/svg-ico/
2. Subir `assets/icon.svg` → Configurar: 256,128,64,48,32,16 → Descargar `icon.ico`
3. Guardar en `assets/icon.ico`

**Opción B: ImageMagick**
```powershell
magick convert assets/icon.svg -define icon:auto-resize=256,128,64,48,32,16 assets/icon.ico
```

**Implementación en proyecto:**
```toml
# Cargo.toml
[package.metadata.windows]
icon = "assets/icon.ico"
```
```rust
# build.rs al final
std::fs::copy("assets/icon.ico", "target/release/icon.ico").ok();
```

#### 5. **Crear LICENSE (MIT)**
```text
MIT License

Copyright (c) 2026 H3rC4

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

### 🟢 BAJA PRIORIDAD - Futuro

#### 6. **CI/CD GitHub Actions**
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

#### 7. **Tema Claro Completo**
- Property `light_mode` ya existe en Settings + UI
- Limitación: Slint no soporta cambio runtime de Theme globals
- Requiere: duplicar componentes o esperar mejora en Slint

#### 8. **Otras mejoras**
- Gráficos tiempo real (CPU/RAM history)
- Notificaciones sistema (winrt crate)
- Modo portable (config en carpeta exe)

---

## 📋 Checklist Visual

```
✅ Toggle "Eliminar permanentemente" (config.rs, cleaner.rs, app.slint, main.rs)
✅ Fix errores compilación (error types, Color→color, ui_weak move, arg order)
✅ Instalador Inno Setup (installer.iss con check updates GitHub API)
✅ README.md en español completo
✅ Cargo.toml v0.3.0 + repo URL
✅ Push a GitHub (H3rC4/syspulse)
⏳ cargo build --release (en Windows)
⏳ Compilar instalador (Inno Setup 7)
⏳ Test manual completo
⏳ Release v0.3.0 en GitHub con instalador
⏳ Icono .ico multi-resolución
⏳ LICENSE MIT
⏳ CI/CD GitHub Actions
⏳ Tema claro real (runtime)
⏳ Gráficos tiempo real
⏳ Notificaciones toast
⏳ Modo portable
```

---

## 🧪 Testing Manual (al volver)

### System Monitor
- [ ] CPU usage actualiza cada 2s
- [ ] RAM/SWAP correcto vs Task Manager
- [ ] Discos: espacio libre/total + progress bars
- [ ] Network: upload/download activity
- [ ] Temperaturas (si hay sensores)
- [ ] Uptime + Load Average
- [ ] Top 5 CPU / RAM processes

### Cleaner
- [ ] Scan → Pause/Resume/Reset
- [ ] Clean → "Cleaning: X/Y files"
- [ ] Toggle OFF → archivos en Papelera
- [ ] Toggle ON → archivos NO en Papelera (eliminados directo)

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
- [ ] Toggle "Light mode" → (solo UI, tema real WIP)
- [ ] Start with OS / retention sliders

---

## 🚀 Comandos Útiles

### Compilar y ejecutar
```powershell
# Release build
cargo build --release

# Ejecutar
.\target\release\syspulse.exe

# Con logs debug
$env:RUST_LOG="debug"; .\target\release\syspulse.exe

# Con logs trace
$env:RUST_LOG="trace"; .\target\release\syspulse.exe
```

### Instalador
```powershell
# Compilar instalador (requiere Inno Setup 7)
& "C:\Program Files\Inno Setup 7\ISCC.exe" installer.iss

# Resultado: output\SysPulse-Setup-0.3.0.exe
```

### Git
```powershell
# Ver estado
git status

# Ver diff
git diff

# Commit
git add .
git commit -m "mensaje descriptivo"

# Push
git push origin main

# Tag + push
git tag v0.3.1
git push origin v0.3.1
```

### Limpieza
```powershell
# Limpiar build
cargo clean

# Limpiar target específico
Remove-Item -Recurse -Force target\release\build
```

---

## 📝 Notas Técnicas Actualizadas

### Slint
- No soporta `linear-gradient` → usar color sólido
- No soporta `.toFixed()` → formatear en Rust con `format!()`
- No soporta `%` sobre floats → usar `Math.mod()`
- `ModelRc` no es `Send` → crear dentro de `invoke_from_event_loop`
- No hay tooltips nativos → usar Text descriptivo
- `Timer::new()` no existe → `Timer::default()` + `.start()`
- `padding` solo funciona en layouts, no en Rectangle directamente
- **Type names en callbacks**: `color` (minúscula), no `Color`
- **Cambio tema runtime**: No soportado bien en globals → usar properties por componente

### Rust
- `trash::delete()` lento para muchos archivos → usar chunks (ya implementado)
- `CancellationToken` de tokio no soporta pausa → `AtomicBool` (ya implementado)
- `ModelRc` debe crearse en UI thread
- Closures deben clonar variables antes de `move` (fix aplicado en main.rs)
- `System::load_average()` es función asociada, no método
- `comp.temperature()` devuelve `f32` directo en sysinfo 0.30
- **Unificar error types**: `std::io::Error` + `trash::Error` → `String` (fix aplicado en cleaner.rs)

### Windows
- Límite 260 chars en rutas → nombres cortos con hash (ya implementado)
- `std::fs::rename` falla entre discos → fallback copy+delete
- System tray requiere `tao` con `with_any_thread(true)`
- Icono debe ser `.ico` multi-resolución (256,128,64,48,32,16)
- Inno Setup 7 compatible con scripts v6

### Inno Setup (installer.iss)
- Check updates: `TWinHttpRequest` a GitHub API `/repos/H3rC4/syspulse/releases/latest`
- Muestra aviso si hay versión nueva en página Welcome
- Botón Cancelar abre releases page
- Multi-idioma: English + Spanish
- Compresión LZMA2/max

---

## 🎯 Comando Único al Volver

```powershell
cd D:\proyectos\SysPulse
git pull origin main
cargo build --release
& "C:\Program Files\Inno Setup 7\ISCC.exe" installer.iss
ls output\SysPulse-Setup-0.3.0.exe
git tag v0.3.0
git push origin v0.3.0
# Luego: GitHub Web → Releases → New → v0.3.0 → adjuntar instalador
```

---

**Creado:** 10 de julio de 2026  
**Última actualización:** 25 de septiembre de 2026  
**Versión:** 0.3.0  
**Estado:** Código compila OK, listo para build Windows + release  
**Responsable:** H3rC4  
**Repo:** https://github.com/H3rC4/syspulse