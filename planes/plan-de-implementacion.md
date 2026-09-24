# SysPulse - Plan de Implementación

## Estado Actual (11 de julio de 2026)

### ✅ Completado

#### Funcionalidades Core
- Visual Studio Community 2026 instalado
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
- ✅ **Traducciones i18n completadas** (19 claves nuevas EN + ES-AR)

### ⚠️ Pendiente
- Tema claro completo con toggle
- Convertir icono SVG a ICO para Windows
- Instalador con Inno Setup
- Publicar en GitHub
- CI/CD con GitHub Actions

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
├── Cargo.toml              # Dependencias
├── build.rs                # Compilador Slint
├── .gitignore
├── assets/
│   └── icon.svg           # Icono vectorial (corazón + EKG)
├── ui/
│   └── app.slint          # Interfaz premium (1657 líneas)
├── locales/
│   ├── en/main.ftl        # Inglés (98 claves)
│   └── es-AR/main.ftl     # Español Argentina (98 claves)
├── src/
│   ├── main.rs            # Entry point + callbacks + timer (1179 líneas)
│   ├── models.rs          # Modelos + SystemStats (140 líneas)
│   └── modules/
│       ├── mod.rs
│       ├── i18n.rs        # Internacionalización
│       ├── config.rs      # Configuración y autostart
│       ├── process_hunter.rs  # Monitor de procesos
│       ├── cleaner.rs     # Limpieza y duplicados
│       ├── cpu_optimizer.rs   # Optimizador CPU
│       ├── sys_monitor.rs # Monitor del sistema (172 líneas)
│       └── tray.rs        # System tray
└── planes/
    ├── plan-de-implementacion.md       # Este archivo
    ├── instrucciones-seguir.md         # Instrucciones para continuar
    └── plan-mejoras-ui-ux-v0.2.0.md   # Plan de mejoras UI/UX
```

---

## Funcionalidades Implementadas

### 1. System Monitor ✅ (NUEVO)
- Dashboard en tiempo real con auto-refresh cada 2 segundos
- CPU usage global con barra de progreso
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
- Eliminación permanente a papelera
- Botón Clean, Pause/Resume, Reset funcionales
- Procesamiento por lotes (no satura RAM)
- Barra de progreso visual
- **Total en MB de duplicados** (NUEVO)

### 4. Duplicates ✅
- File picker nativo (botón Browse)
- Checkboxes clickeables para selección manual
- Botón Open para verificar archivos
- Botones Keep Oldest/Newest
- Botón "Send Selected to Quarantine"
- **Muestra total en MB de duplicados** (NUEVO)

### 5. CPU Focus ✅
- Lista de procesos activos
- Cambio de prioridad (Above Normal en Windows)
- Restauración de prioridad original

### 6. Settings ✅
- Cambio de idioma (Inglés / Español Argentina)
- Modo oscuro (hardcoded)
- Inicio con el sistema operativo
- Retención de historial y cuarentena configurable
- Botón "Apply & Restart" funcional (con logs de debug)

### 7. System Tray ✅
- Icono en bandeja del sistema
- Doble clic para restaurar ventana
- Menú contextual: Open, Pause/Resume, Exit
- Modo `--background` para iniciar minimizado

### 8. Quarantine ✅
- Lista de archivos en cuarentena
- Botones Open, Restore, Delete
- Scroll para listas largas
- **Muestra tamaño total de cuarentena** (NUEVO)
- **Auto-carga al cambiar a pestaña Cleaner** (NUEVO)

---

## Próximos Pasos

Ver `instrucciones-seguir.md` para detalles de implementación.

1. Tema claro completo con toggle
2. Convertir icono SVG a ICO para Windows
3. Instalador con Inno Setup
4. Publicar en GitHub
5. Configurar CI/CD con GitHub Actions

---

**Última actualización:** 11 de julio de 2026  
**Versión del proyecto:** 0.3.0  
**Estado:** Funcional con UI premium y System Monitor  
**Responsable:** Equipo de Desarrollo SysPulse
