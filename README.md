# SysPulse

Optimizador de sistema multiplataforma y monitor de rendimiento en tiempo real, ligero, 100% offline y de código abierto. Desarrollado con un backend de bajo nivel en **Rust** y una interfaz gráfica nativa acelerada por GPU en **Slint** con estética neón oscura.

![Version](https://img.shields.io/badge/version-0.3.1-blue)
![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)
![Slint](https://img.shields.io/badge/slint-1.5%2B-purple)
![License](https://img.shields.io/badge/license-MIT-green)

---

## ✨ Características Principales

| Módulo | Descripción |
|--------|-------------|
| **System Monitor** | Monitoreo en tiempo real de CPU global y por núcleo, memoria RAM y SWAP, discos (espacio libre y total), tráfico de red de subida/bajada, temperaturas y uptime. Desacoplado asíncronamente en worker de Tokio para garantizar 60+ FPS fluidos sin micro-bloqueos. |
| **Smart Cleaner** | Limpieza de temporales del sistema y cachés de desarrollo (`npm`, `pip`, `cargo`). Buscador de duplicados ultrarrápido con **doble etapa de hashing** (pre-hashing de 16 KB + SHA-256 completo con búfer de 64 KB). Cuarentena reactiva con manifiesto JSON para restaurar o purgar. |
| **Process Hunter** | Auditoría continua de eventos de procesos en base de datos local SQLite (`syspulse.db`), detección y cálculo de tiempo de vida en procesos transitorios (< 5s), purga programada horaria y exportación forense a JSON/CSV. |
| **CPU Focus** | Elevación de prioridad inmediata a `ABOVE_NORMAL_PRIORITY_CLASS` en Windows (o `nice -5` en POSIX) para dar máxima fluidez a juegos o tareas críticas. Visualización en tiempo real de memoria en MB reales. |
| **System Tray & Ajustes** | Modo segundo plano (`--background`), icono con menú contextual y doble clic para restaurar. Configuración persistente en `settings.toml` e integración nativa de auto-inicio con Windows mediante el Registro. |
| **🗑️ Eliminación Permanente** | Opción seleccionable para omitir la Papelera de reciclaje en limpiezas masivas, evitando picos de RAM y bloqueos en el explorador de archivos. |
| **Instalador Oficial** | Generado con **Inno Setup 7** (~7.2 MB), con detección automática de arquitectura (`x64compatible`) y comprobación de nuevas versiones en segundo plano vía API de GitHub. |

---

## 📸 Capturas de Pantalla

> *Las capturas de pantalla de la interfaz v0.3.1 se encuentran disponibles en los assets de la release.*

---

## 🚀 Inicio Rápido

### Windows (Pre-compilado)
1. Dirígete a [Releases](https://github.com/H3rC4/syspulse/releases)
2. Descarga el instalador oficial **`SysPulse-Setup-0.3.1.exe`** (o `syspulse.exe`)
3. Ejecuta el instalador y sigue los pasos del asistente.

### Ejecución en Segundo Plano (Solo Bandeja del Sistema)
```powershell
.\syspulse.exe --background
```

### Compilar desde el Código Fuente

**Requisitos:**
- Windows 10/11 (o Linux / macOS)
- [Rust 1.75+](https://rustup.rs/)
- Visual Studio 2022+ con carga de trabajo **Desarrollo para el escritorio con C++**
- (Opcional) [Inno Setup 7](https://jrsoftware.org/isdl.php) para empaquetar el instalador.

```powershell
# 1. Clonar el repositorio
git clone https://github.com/H3rC4/syspulse.git
cd syspulse

# 2. Compilar en modo release optimizado
cargo build --release

# 3. Ejecutar el binario generado
.\target\release\syspulse.exe
```

---

## ⚙️ Configuración y Rutas del Sistema

Los archivos de configuración y datos se organizan siguiendo los estándares del sistema operativo:

- **Configuración (`settings.toml`):**  
  `%APPDATA%\SysPulse\settings.toml`
- **Base de datos local SQLite (`syspulse.db`):**  
  `%LOCALAPPDATA%\SysPulse\syspulse.db`
- **Carpeta de Cuarentena y Manifiestos:**  
  `%LOCALAPPDATA%\SysPulse\quarantine\`

### Ajustes Destacados
- **Iniciar con Windows:** Registra o desregistra la aplicación de forma segura en `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
- **Retención del Historial de Procesos:** Configuración de días de retención de auditoría con purga automática optimizada.
- **Retención de Cuarentena:** Días antes de la purga automática de archivos apartados.
- **Eliminación Permanente:** Activa/desactiva el bypass directo de la Papelera de reciclaje.

---

## 🗂️ Estructura del Proyecto

```
SysPulse/
├── Cargo.toml              # Dependencias y perfiles de compilación optimizados
├── installer.iss           # Script oficial de Inno Setup 7
├── build.rs                # Compilador Slint + integración de recursos Windows
├── assets/
│   ├── icon.svg            # Icono vectorial original
│   └── icon.ico            # Icono oficial Windows multi-resolución
├── ui/
│   └── app.slint           # Interfaz gráfica declarativa Slint (tema neón)
├── locales/
│   ├── en/main.ftl         # Traducciones en Inglés
│   └── es-AR/main.ftl      # Traducciones en Español (Argentina)
├── src/
│   ├── main.rs             # Punto de entrada, loops de eventos y callbacks
│   ├── models.rs           # Modelos de datos compartidos
│   └── modules/
│       ├── cleaner.rs      # Limpieza, doble etapa de hashing y cuarentena
│       ├── config.rs       # Gestión de settings y autoarranque Win32
│       ├── cpu_optimizer.rs# Prioridades de procesos y cálculo de RAM
│       ├── i18n.rs         # Soporte de internacionalización Fluent
│       ├── process_hunter.rs# Auditoría forense en SQLite
│       ├── sys_monitor.rs  # Monitoreo asíncrono con sysinfo
│       └── tray.rs         # Icono en bandeja de sistema (tao + tray-icon)
├── planes/
│   └── PLAN_DE_ACCION.md   # Documento único consolidado de ruta y estado
└── output/
    └── SysPulse-Setup-0.3.1.exe # Instalador empaquetado para distribución
```

---

## 🛠️ Comandos de Desarrollo

```powershell
# Comprobar código y tipos (rápido, sin generar binario)
cargo check

# Ejecutar suite de pruebas unitarias
cargo test

# Compilación de depuración para desarrollo
cargo build
.\target\debug\syspulse.exe

# Compilación final para distribución (LTO, strip, opt-level = "z")
cargo build --release
.\target\release\syspulse.exe

# Compilar el instalador oficial de Windows con Inno Setup 7
& "C:\Program Files\Inno Setup 7\ISCC.exe" installer.iss
```

---

## 🔮 Hoja de Ruta (Roadmap)

### ✅ Versión v0.3.1 (Actual)
- [x] Optimización y depuración de dependencias en `Cargo.toml` (compilación 100% limpia sin warnings).
- [x] Implementación de **pre-hashing de 16 KB** y ampliación de búfer a 64 KB en el buscador de duplicados.
- [x] Icono oficial multi-resolución integrado en el binario y bandeja de sistema.
- [x] Desacoplamiento asíncrono del System Monitor para una UI constante a 60+ FPS.
- [x] Corrección sintáctica y de arquitectura (`x64compatible`) del instalador con Inno Setup 7.
- [x] Generación del binario release final y Setup oficial (~7.2 MB).

### 🟡 Versión v0.4.0 (En progreso / Próxima)
- [ ] **Migración de Process Hunter a ETW (Event Tracing for Windows):** Reemplazar polling periódico por eventos del kernel en tiempo real con 0% de uso de CPU en reposo.
- [ ] **Gráficos en tiempo real:** Mini gráficos interactivos de los últimos 60 segundos para CPU, RAM y Red.
- [ ] **Notificaciones Toast nativas:** Alertas visuales de Windows al finalizar tareas de limpieza o ante umbrales térmicos elevados.
- [ ] **Modo Portable:** Detección de `portable.txt` junto al ejecutable para operar sin escribir en `AppData`.
- [ ] **Selector de Idioma Dinámico:** Alternancia fluida entre Español e Inglés en tiempo de ejecución.
- [ ] **Pipeline CI/CD:** Automatización de compilaciones y releases en GitHub Actions.

---

## 🤝 Contribuir

Las contribuciones son bienvenidas. Para cambios importantes, por favor abre un issue primero para discutir lo que te gustaría proponer:

1. Haz un Fork del repositorio
2. Crea tu rama de función (`git checkout -b feature/mejora-increible`)
3. Confirma tus cambios (`git commit -m 'feat: agrega mejora increíble'`)
4. Sube la rama (`git push origin feature/mejora-increible`)
5. Abre un Pull Request

---

## 📄 Licencia

Este proyecto está bajo la Licencia **MIT** — consulta el archivo [LICENSE](LICENSE) para más detalles.

---

## 👨‍💻 Autor

**H3rC4** — [GitHub Profile](https://github.com/H3rC4)
