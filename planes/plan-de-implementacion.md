# SysPulse - Plan de Implementación

## Estado Actual (25 de septiembre de 2026)

### ✅ Completado

#### Funcionalidades Core
- Visual Studio Community 2022 instalado (con C++ desktop workload)
- Rust instalado y configurado
- **Proyecto compila exitosamente** (`cargo build --release`)
- Aplicación se ejecuta sin crashes
- System tray operativo
- Escaneo de archivos temporales funcional
- Detección de duplicados funcional
- **Botón Clean funcional** (envía archivos a papelera de Windows)
- **Botón Pause/Resume** durante escaneo y limpieza
- **File picker nativo** para Duplicates (botón Browse)
- **Checkboxes clickeables** en Duplicates para selección manual
- **Botones Keep Oldest/Newest** con ordenamiento por fecha y nombre
- **Botón Open** en cada archivo de Duplicates para verificar
- **Botón Open** en Quarantine para ver archivos eliminados
- **Barra de progreso visual** con gradiente cyan
- **Contador de progreso** "Cleaning: X / Y files"
- **Botón Reset** para cancelar y reiniciar escaneo
- **Procesamiento por lotes** (chunks de 1000 archivos) para no saturar RAM
- **Cancel flag** para detener operaciones en curso
- **Auto-restart** al cambiar idioma en Settings
- **Manifest JSON** para cuarentena de duplicados (nombres cortos con hash)
- **Scroll en Quarantine** para listas largas
- **Botón Refresh** en Quarantine para recargar lista

#### Nuevas Funcionalidades (11 de julio)
- ✅ **System Monitor Dashboard** - Nueva pestaña con métricas en tiempo real:
  - CPU usage global + por core
  - RAM y SWAP con barras de progreso
  - Uso de discos con espacio libre/total
  - Network throughput (upload/download)
  - Temperaturas de sensores (si disponibles)
  - Uptime del sistema + Load Average
  - Top 5 procesos por CPU y RAM
  - Auto-refresh cada 2 segundos
- ✅ **Mejoras en Duplicados** - Muestra total en MB de archivos duplicados
- ✅ **Mejoras en Cuarentena** - Muestra tamaño total + auto-carga al cambiar a pestaña Cleaner
- ✅ **Fix freeze post-cuarentena** - La UI ahora se actualiza correctamente después de cuarentenar
- ✅ **Icono SVG personalizado** - Corazón con línea EKG en estilo neon (assets/icon.svg)

#### UI/UX Premium (11 de julio)
- ✅ **Rediseño completo del Theme**:
  - Paleta de colores más sofisticada con tonos dim
  - Nuevos tokens: `surface`, `card-bg-hover`, `text-tertiary`, `border-subtle`, `neon-orange`
  - Colores más oscuros y profundos para mayor contraste
- ✅ **Sidebar rediseñado**:
  - Logo con icono de corazón en card con fondo sutil
  - Secciones separadas: "NAVIGATION" y "SYSTEM"
  - Separadores visuales sutiles
  - Indicador activo: barra cyan de 3px en el lateral del botón activo
  - Status bar premium en la parte inferior con dot verde
  - Tipografía refinada con letter-spacing
- ✅ **Componentes premium**:
  - SidebarButton con indicador lateral y iconos más grandes
  - NeonButton con bordes más suaves y mejor feedback hover/pressed
  - TabPill con bordes sutiles y tipografía refinada
  - ProgressBar más compacta con animación en width
  - SectionTitle/Description con letter-spacing y pesos refinados
- ✅ **System Monitor Dashboard premium**:
  - Cards con iconos en badges de color
  - Labels en mayúsculas con letter-spacing
  - Top processes con rows en surface background
  - Discos con progress bars individuales
- ✅ **Settings premium**:
  - Card envolvente con separadores entre rows
  - Warning en naranja (neon-orange)
- ✅ **Todas las tabs actualizadas**:
  - Padding consistente: 36px horizontal, 28px vertical
  - Headers agrupados con spacing 6px
  - Border-radius 14px en cards
- ✅ **Animaciones implementadas**:
  - Hover y click en SidebarButton, NeonButton, TabPill
  - Transiciones suaves de 200-250ms
- ✅ **Descripciones en todas las pestañas**
- ✅ **Traducciones i18n completadas** (98 claves EN + ES-AR)

#### Nuevas Funcionalidades (25 de septiembre)
- ✅ **Toggle "Eliminar permanentemente"** - Opción para omitir Papelera (envía directo a `std::fs::remove_file`)
  - `config.rs`: Agregado `permanent_delete: bool` + `light_mode: bool` (default: false)
  - `cleaner.rs`: Lógica condicional unificando tipos de error (`String`)
  - `app.slint`: CheckBox en SettingsTab + advertencia naranja + checkbox "Light mode"
  - `main.rs`: Persistencia + paso al cleaner + fix move `ui_weak`
- ✅ **Instalador Inno Setup** - Script `installer.iss` con:
  - Check de actualizaciones automático (GitHub API al iniciar wizard)
  - Multi-idioma (English/Spanish)
  - Tareas opcionales: icono escritorio, iniciar con Windows
  - Desinstalador funcional
- ✅ **README.md en español** - Documentación completa traducida
- ✅ **Git + GitHub** - Repo público: https://github.com/H3rC4/syspulse
  - Push completado con historial limpio
  - Tags preparados para releases

### ⚠️ Pendiente
- Icono ICO para Windows (convertir SVG)
- LICENSE (MIT)
- Release v0.3.0 en GitHub con instalador
- CI/CD con GitHub Actions
- Tema claro completo (requiere refactor Theme - limitación Slint runtime)

---

## Historial de Problemas Resueltos

### Errores de Sintaxis Slint (11 de julio)
- `.toFixed()` no existe → formatear en Rust con `format!()`
- Operador `%` sobre `float` → usar `Math.mod()`
- Variables con guiones (`uptime-int`) → usar guiones bajos (`uptime_int`)
- `if condition : for ...` no válido → usar `for` directo
- `slint::Timer::new()` no existe → `Timer::default()` + `.start()`

### Errores de Compilación Rust (11 de julio)
- `self.system.load_average()` → `System::load_average()` (función asociada)
- `comp.temperature()` devuelve `f32` directo, no `Option<f32>`
- `_manifest` sin usar → renombrar a `manifest`
- UI se congelaba post-cuarentena → agregar actualización de UI
- `format_bytes` sin prefijo → `modules::cleaner::format_bytes`

### Errores de Compilación Rust (25 de septiembre)
- `if/else` tipos incompatibles: `std::io::Error` vs `trash::Error` → unificar a `Result<(), String>`
- `Color` vs `color` en Slint callbacks → usar minúscula
- `ui_weak` move error en closures múltiples → clonar antes de primer uso
- Orden argumentos `clean_system_temp`: closure primero, `permanent_delete` último
- `apply_theme` runtime no soportado bien en Slint → removido, solo dark-mode property

---

## Comandos de Desarrollo

### Compilar y Ejecutar
```powershell
# Compilar release
cargo build --release

# Ejecutar
.\target\release\syspulse.exe

# Con logs debug
$env:RUST_LOG="debug"; .\target\release\syspulse.exe

# Con logs trace (muy detallado)
$env:RUST_LOG="trace"; .\target\release\syspulse.exe
```

### Instalador
```powershell
# Compilar instalador (requiere Inno Setup 7)
& "C:\Program Files\Inno Setup 7\ISCC.exe" installer.iss

# Resultado: output\SysPulse-Setup-0.3.0.exe
```

### Otros
```powershell
# Debug build (rápido)
cargo build

# Limpiar
cargo clean

# Linter
cargo clippy

# Verificar sin compilar
cargo check
```

---

## Estructura del Proyecto

```
D:\proyectos\SysPulse\
├── Cargo.toml              # v0.3.0, repo URL correcta
├── build.rs                # Compilador Slint + winres
├── .gitignore
├── installer.iss           # NUEVO: Inno Setup script
├── assets/
│   ├── icon.svg           # Icono vectorial (corazón + EKG)
│   └── icon.ico           # (PENDIENTE: crear multi-res)
├── ui/
│   └── app.slint          # Interfaz premium (~1710 líneas)
├── locales/
│   ├── en/main.ftl        # Inglés (98 claves)
│   └── es-AR/main.ftl     # Español Argentina (98 claves)
├── src/
│   ├── main.rs            # Entry point + callbacks + timers (~1190 líneas)
│   ├── models.rs          # Modelos + SystemStats
│   └── modules/
│       ├── mod.rs
│       ├── i18n.rs        # Internacionalización (fluent-rs)
│       ├── config.rs      # Configuración + autostart + permanent_delete + light_mode
│       ├── process_hunter.rs  # Monitor procesos + SQLite
│       ├── cleaner.rs     # Limpieza + duplicados + cuarentena (~738 líneas)
│       ├── cpu_optimizer.rs   # Optimizador CPU
│       ├── sys_monitor.rs # Monitor sistema (sysinfo 0.30)
│       └── tray.rs        # System tray (tao + tray-icon)
├── planes/
│   ├── plan-de-implementacion.md       # Este archivo
│   ├── plan-continuacion.md            # Plan siguiente sesión
│   ├── instrucciones-seguir.md         # Instrucciones detalladas
│   └── plan-mejoras-ui-ux-v0.2.0.md   # Plan mejoras UI/UX v0.3.0
└── target/release/         # (tras build)
    ├── syspulse.exe
    └── syspulse.pdb
```

---

## Funcionalidades Implementadas

### 1. System Monitor ✅
- Dashboard en tiempo real con auto-refresh cada 2 segundos
- CPU usage global con barra de progreso + por core
- RAM y SWAP con indicadores visuales
- Discos con espacio libre/total y progress bars
- Network throughput (upload/download en KB/s)
- Temperaturas de sensores (si disponibles)
- Uptime del sistema formateado (Xd Xh Xm)
- Load Average (1, 5, 15 minutos)
- Top 5 procesos por CPU
- Top 5 procesos por RAM

### 2. Process Hunter ✅
- Monitoreo de procesos en tiempo real
- Detección de procesos transitorios (< 5 segundos)
- Historial en SQLite (configurable, default 30 días)
- Exportación a JSON/CSV para análisis con IA

### 3. Cleaner ✅
- Limpieza de archivos temporales (envía a papelera)
- Buscador de duplicados (SHA-256)
- Cuarentena propia para duplicados (con manifest JSON)
- Restauración desde cuarentena
- Eliminación permanente a papelera / directa (toggle)
- Botón Clean, Pause/Resume, Reset funcionales
- Procesamiento por lotes (no satura RAM)
- Barra de progreso visual
- **Total en MB de duplicados**

### 4. Duplicates ✅
- File picker nativo (botón Browse)
- Checkboxes clickeables para selección manual
- Botón Open para verificar archivos
- Botones Keep Oldest/Newest
- Botón "Send Selected to Quarantine"
- **Muestra total en MB de duplicados**

### 5. CPU Focus ✅
- Lista de procesos activos
- Cambio de prioridad (Above Normal en Windows)
- Restauración de prioridad original

### 6. Settings ✅
- Cambio de idioma (Inglés / Español Argentina) - requiere restart
- Modo oscuro (property `dark-mode`)
- Light mode property (`light-mode`) - UI only, real theme switch WIP
- Inicio con el sistema operativo
- Retención de historial y cuarentena configurable
- **Toggle "Eliminar permanentemente"** - NUEVO
- Botón "Apply & Restart" funcional
- Botón "Check for updates" - abre GitHub Releases

### 7. System Tray ✅
- Icono en bandeja del sistema
- Doble clic para restaurar ventana
- Menú contextual: Open, Pause/Resume, Exit
- Modo `--background` para iniciar minimizado

### 8. Quarantine ✅
- Lista de archivos en cuarentena
- Botones Open, Restore, Delete
- Scroll para listas largas
- **Muestra tamaño total de cuarentena**
- **Auto-carga al cambiar a pestaña Cleaner**

### 9. Installer ✅ (NUEVO - 25 sep)
- Inno Setup script `installer.iss`
- Check de actualizaciones al iniciar (GitHub API)
- Multi-idioma (English/Spanish)
- Compresión LZMA2/max
- Desinstalador completo

---

## Próximos Pasos

Ver `plan-continuacion.md` para detalles.

1. **Inmediato**: `cargo build --release` + compilar instalador + Release v0.3.0
2. **Esta semana**: Icono .ico + LICENSE + Test completo
3. **Futuro**: CI/CD + Tema claro + Gráficos + Notificaciones + Portable mode

---

**Última actualización:** 25 de septiembre de 2026  
**Versión del proyecto:** 0.3.0  
**Estado:** Funcional, compilando OK, listo para release pipeline  
**Responsable:** H3rC4  
**Repo:** https://github.com/H3rC4/syspulse