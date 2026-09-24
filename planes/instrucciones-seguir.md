# SysPulse - Instrucciones para Continuar

## 🎯 Tareas Pendientes (11 de julio de 2026)

### 🔴 ALTA PRIORIDAD

#### 1. Convertir Icono SVG a ICO para Windows
**Estado actual:** Tenemos `assets/icon.svg` con diseño de corazón + EKG en estilo neon.

**Opciones para convertir:**

**Opción A: Herramienta online (recomendado)**
1. Ir a https://cloudconvert.com/svg-to-ico o https://convertio.co/svg-ico/
2. Subir `assets/icon.svg`
3. Configurar salida: 256x256, 128x128, 64x64, 48x48, 32x32, 16x16
4. Descargar `icon.ico`
5. Guardar en `assets/icon.ico`

**Opción B: Usar ImageMagick (si está instalado)**
```powershell
# Instalar ImageMagick desde https://imagemagick.org/script/download.php
magick convert assets/icon.svg -define icon:auto-resize=256,128,64,48,32,16 assets/icon.ico
```

**Opción C: Usar PowerShell con .NET**
```powershell
# Requiere tener el SVG como PNG primero
# Luego convertir PNG a ICO con herramienta dedicada
```

**Implementación en el proyecto:**
```rust
// En Cargo.toml, agregar sección:
[package.metadata.windows]
icon = "assets/icon.ico"

// En build.rs, agregar al final:
fn main() {
    // Compilación Slint existente...
    
    // Copiar icono al directorio de salida
    std::fs::copy("assets/icon.ico", "target/release/icon.ico").ok();
}
```

**Criterio de éxito:**
- Icono visible en taskbar de Windows
- Icono visible en system tray
- Icono embebido en el ejecutable

---

#### 2. Tema Claro Completo con Toggle
**Estado actual:** Solo tema oscuro hardcoded.

**Implementación:**

**Paso 1: Agregar property en Settings (src/modules/config.rs)**
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub language: Language,
    pub dark_mode: bool,
    pub light_mode: bool,  // NUEVO
    pub start_with_os: bool,
    pub process_history_days: u32,
    pub quarantine_days: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            language: Language::English,
            dark_mode: true,
            light_mode: false,  // NUEVO
            start_with_os: false,
            process_history_days: 30,
            quarantine_days: 7,
        }
    }
}
```

**Paso 2: Agregar toggle en UI (ui/app.slint)**
```slint
component SettingsTab inherits Rectangle {
    // ... propiedades existentes
    in-out property <bool> light-mode: false;  // NUEVO
    
    // ... en el VerticalLayout, después de dark-mode:
    SettingRow {
        label: "Light mode";
        CheckBox { checked <=> light-mode; }
    }
}
```

**Paso 3: Agregar colores de tema claro en Theme global**
```slint
export global Theme {
    // Tema oscuro (actual)
    in-out property <brush> pure-black: #050508;
    in-out property <brush> panel-bg: #0a0a0f;
    // ... colores existentes
    
    // Tema claro (nuevo)
    in-out property <bool> is-light-mode: false;
    
    // Colores dinámicos (requiere lógica condicional)
    in-out property <brush> bg-main: #050508;
    in-out property <brush> bg-panel: #0a0a0f;
    in-out property <brush> bg-card: #12121a;
}
```

**Paso 4: Manejar toggle en main.rs**
```rust
// En callback on_save_settings:
settings.light_mode = ui.get_light_mode();

// Al iniciar, aplicar tema:
if settings.light_mode {
    // Establecer colores claros en Theme global
}
```

**Limitación de Slint:**
Slint no soporta cambiar propiedades de globales en runtime fácilmente. Alternativa:
- Crear dos sets de componentes (uno para cada tema)
- Usar `if` condicional para mostrar el tema correcto
- O esperar a que Slint mejore el soporte de temas dinámicos

**Criterio de éxito:**
- Checkbox en Settings para cambiar entre tema oscuro/claro
- Todos los componentes se adaptan al tema seleccionado
- Preferencia se guarda y persiste entre reinicios

---

### 🟡 MEDIA PRIORIDAD

#### 3. Instalador con Inno Setup
**Objetivo:** Crear instalador `.exe` profesional para distribución.

**Pasos:**

1. **Descargar Inno Setup:**
   - Ir a https://jrsoftware.org/isdl.php
   - Descargar e instalar Inno Setup 6.x

2. **Crear script `installer.iss`:**
```inno
[Setup]
AppName=SysPulse
AppVersion=0.3.0
AppPublisher=SysPulse Team
DefaultDirName={autopf}\SysPulse
DefaultGroupName=SysPulse
OutputDir=output
OutputBaseFilename=SysPulse-Setup-0.3.0
Compression=lzma2/max
SolidCompression=yes
SetupIconFile=assets\icon.ico
UninstallDisplayIcon={app}\icon.ico
WizardStyle=modern
PrivilegesRequired=lowest

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "target\release\syspulse.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "assets\icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\SysPulse"; Filename: "{app}\syspulse.exe"
Name: "{group}\Uninstall SysPulse"; Filename: "{uninstallexe}"
Name: "{autodesktop}\SysPulse"; Filename: "{app}\syspulse.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\syspulse.exe"; Description: "{cm:LaunchProgram,SysPulse}"; Flags: nowait postinstall skipifsilent
```

3. **Compilar instalador:**
```powershell
# Abrir Inno Setup Compiler
# File > Open > seleccionar installer.iss
# Build > Compile (o Ctrl+F9)
```

4. **Resultado:**
   - Archivo: `output/SysPulse-Setup-0.3.0.exe`
   - Tamaño estimado: ~5-8 MB
   - Instala en `C:\Users\<usuario>\AppData\Local\Programs\SysPulse`

**Criterio de éxito:**
- Instalador genera `SysPulse-Setup-0.3.0.exe`
- Instala correctamente en Windows 10/11
- Crea accesos directos en menú inicio y escritorio (opcional)
- Desinstalador funcional

---

#### 4. Publicar en GitHub
**Pasos:**

1. **Crear `.gitignore` (si no existe):**
```gitignore
# Rust
/target/
**/*.rs.bk
*.pdb

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Build
/dist/
/output/
*.exe
!target/release/syspulse.exe
```

2. **Inicializar repositorio:**
```powershell
cd D:\proyectos\SysPulse
git init
git add .
git commit -m "Initial commit: SysPulse v0.3.0 with System Monitor and Premium UI"
```

3. **Crear repositorio en GitHub:**
   - Ir a https://github.com/new
   - Nombre: `syspulse`
   - Descripción: "Cross-platform system optimizer with real-time monitoring"
   - Público
   - NO inicializar con README

4. **Push a GitHub:**
```powershell
git remote add origin https://github.com/TU-USUARIO/syspulse.git
git branch -M main
git push -u origin main
```

5. **Crear README.md:**
```markdown
# SysPulse

Cross-platform system optimizer with real-time monitoring, built with Rust and Slint.

## Features

- **System Monitor**: Real-time CPU, RAM, disk, network, and temperature monitoring
- **Smart Cleaner**: Clean temporary files and find duplicates
- **Process Hunter**: Monitor and detect transient processes
- **CPU Focus**: Boost process priority for better performance
- **Premium UI**: Modern neon-themed interface with smooth animations

## Installation

### Windows
Download the latest installer from [Releases](../../releases).

### Build from Source
```powershell
# Prerequisites
# - Rust 1.75+
# - Visual Studio 2026 with C++ tools

cargo build --release
.\target\release\syspulse.exe
```

## Screenshots

[Add screenshots here]

## License

MIT
```

6. **Crear LICENSE:**
```
MIT License

Copyright (c) 2026 SysPulse

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

**Criterio de éxito:**
- Código fuente en GitHub
- README.md con instrucciones
- Licencia MIT
- `.gitignore` configurado correctamente

---

#### 5. CI/CD con GitHub Actions
**Objetivo:** Compilación automática en cada push.

**Crear `.github/workflows/build.yml`:**
```yaml
name: Build SysPulse

on:
  push:
    branches: [ main ]
    tags: [ 'v*' ]
  pull_request:
    branches: [ main ]

env:
  CARGO_TERM_COLOR: always

jobs:
  build:
    name: Build on ${{ matrix.os }}
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [windows-latest]

    steps:
    - uses: actions/checkout@v4

    - name: Install Rust
      uses: dtolnay/rust-toolchain@stable
      with:
        toolchain: stable

    - name: Rust Cache
      uses: Swatinem/rust-cache@v2
      with:
        workspaces: "."

    - name: Build
      run: cargo build --release --verbose

    - name: Run tests
      run: cargo test --verbose

    - name: Upload artifact (Windows)
      if: matrix.os == 'windows-latest'
      uses: actions/upload-artifact@v4
      with:
        name: syspulse-windows
        path: target/release/syspulse.exe

    - name: Create Release
      if: startsWith(github.ref, 'refs/tags/')
      uses: softprops/action-gh-release@v1
      with:
        files: target/release/syspulse.exe
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Criterio de éxito:**
- Cada push a `main` compila automáticamente
- Artifact descargable con `syspulse.exe`
- Tags crean release automático

---

### 🟢 BAJA PRIORIDAD

#### 6. Mejoras Adicionales (Opcionales)

**a) Gráficos en tiempo real para System Monitor**
- Implementar gráficos de líneas para CPU/RAM history
- Requiere componente custom en Slint o integrar crate de gráficos

**b) Notificaciones del sistema**
- Notificar cuando limpieza se completa
- Notificar cuando se encuentran muchos duplicados
- Usar `winrt` crate para notificaciones nativas de Windows

**c) Modo portable**
- Opción para guardar configuración en carpeta local en vez de AppData
- Útil para USB drives

**d) Plugins/Extensiones**
- Sistema de plugins para agregar funcionalidades
- Requiere arquitectura más compleja

---

## 📋 Checklist de Tareas

### Completado ✅
- [x] Fix botón "Apply & Restart"
- [x] Crear icono SVG personalizado
- [x] Animaciones de transición
- [x] Tooltips y ayuda contextual
- [x] System Monitor Dashboard
- [x] Mejoras en Duplicados (total MB)
- [x] Mejoras en Cuarentena (tamaño total + auto-carga)
- [x] Fix freeze post-cuarentena
- [x] UI Premium completa

### Pendiente ⏳
- [ ] Convertir icono SVG a ICO
- [ ] Tema claro completo
- [ ] Instalador con Inno Setup
- [ ] Publicar en GitHub
- [ ] CI/CD con GitHub Actions

---

## 🧪 Testing Manual

### System Monitor
- [ ] Abrir app → pestaña Monitor se muestra por defecto
- [ ] CPU usage se actualiza cada 2 segundos
- [ ] RAM muestra uso correcto (comparar con Task Manager)
- [ ] Discos muestran espacio correcto
- [ ] Network muestra actividad (descargar algo para probar)
- [ ] Temperaturas muestran valores (si hay sensores)
- [ ] Uptime muestra tiempo correcto
- [ ] Top procesos muestran los 5 más activos

### Cleaner
- [ ] Click "Scan" → escanea archivos temporales
- [ ] Durante escaneo → botón cambia a "Pause"
- [ ] Click "Pause" → escaneo se detiene
- [ ] Click "Resume" → escaneo continúa
- [ ] Click "Reset" → cancela y reinicia
- [ ] Después de escanear → botón "Clean" se habilita
- [ ] Click "Clean" → muestra "Cleaning: X / Y files"
- [ ] Al terminar → archivos van a papelera de Windows

### Duplicates
- [ ] Click "Browse" → abre selector de carpetas
- [ ] Seleccionar carpeta → ruta aparece en campo
- [ ] Click "Scan" → busca duplicados
- [ ] Se muestra total en MB de duplicados
- [ ] Click checkbox → selecciona/deselecciona archivo
- [ ] Click "Open" → abre archivo para verificar
- [ ] Click "Keep Oldest" → selecciona todos excepto el más antiguo
- [ ] Click "Keep Newest" → selecciona todos excepto el más nuevo
- [ ] Click "Send Selected to Quarantine" → mueve seleccionados
- [ ] UI no se congela después de cuarentenar

### Quarantine
- [ ] Click pestaña Cleaner → cambia a sub-tab Quarantine
- [ ] Se carga lista automáticamente
- [ ] Se muestra tamaño total de cuarentena
- [ ] Click "Refresh" → recarga lista
- [ ] Click "Open" → abre archivo en cuarentena
- [ ] Click "Restore" → devuelve a ubicación original
- [ ] Click "Delete" → envía a papelera de Windows

### Settings
- [ ] Cambiar idioma → apretar "Apply & Restart"
- [ ] App se reinicia con nuevo idioma
- [ ] Cambiar días de retención → guardar
- [ ] Toggle "Start with OS" → guardar

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
```

### Limpieza
```powershell
# Limpiar build
cargo clean

# Limpiar target específico
Remove-Item -Recurse -Force target\release\build
```

---

## 📝 Notas Técnicas

### Slint
- No soporta `linear-gradient` → usar color sólido
- No soporta `.toFixed()` → formatear en Rust
- No soporta `%` sobre floats → usar `Math.mod()`
- `ModelRc` no es `Send` → crear dentro de `invoke_from_event_loop`
- No hay tooltips nativos → usar Text descriptivo
- `Timer::new()` no existe → usar `Timer::default()` + `.start()`
- `padding` solo funciona en layouts, no en Rectangle directamente

### Rust
- `trash::delete()` es lento para muchos archivos → usar chunks
- `CancellationToken` de tokio no soporta pausa → usar `AtomicBool`
- `ModelRc` debe crearse en UI thread
- Closures deben clonar variables antes de `move`
- `System::load_average()` es función asociada, no método
- `comp.temperature()` devuelve `f32` directo en sysinfo 0.30

### Windows
- Límite de 260 caracteres en rutas → usar nombres cortos con hash
- `std::fs::rename` falla entre discos → fallback a copy+delete
- System tray requiere `tao` con `with_any_thread(true)`
- Icono debe ser formato `.ico` con múltiples resoluciones

---

**Creado:** 10 de julio de 2026  
**Última actualización:** 11 de julio de 2026  
**Versión:** 0.3.0  
**Estado:** Funcional con UI premium y System Monitor  
**Responsable:** Equipo de Desarrollo SysPulse
