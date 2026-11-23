# SysPulse — Documento Permanente de Estado y Continuidad de Contexto

**Ubicación:** `planes/ESTADO_ACTUAL.md`  
**Última actualización:** 22 de noviembre de 2026 (Pruebas de campo en GUI de Windows 10/11 verificadas; consolidación de hallazgos observados, bugs confirmados, mejoras propuestas y plan de trabajo v0.4.0; baseline `0dcc5b3`)
**Rama activa:** `review/a11-block-2b` (en desarrollo sobre base `develop/v0.4.0`)
**Versión de producción:** v0.3.1 (Setup oficial generado: `output/SysPulse-Setup-0.3.1.exe`)  
**Versión en desarrollo:** v0.4.0 (PIE Core & Network Guardian)  

---

## 1. Propósito de este Documento

Este archivo es la **fuente de verdad inmediata y permanente** para cualquier agente o desarrollador que retome el proyecto SysPulse.  
Permite recuperar el contexto de forma instantánea sin necesidad de re-auditar el repositorio, volver a leer todos los módulos ni repetir análisis previos.

---

## 2. Estado Global de la Solución

| Componente | Estado | Notas Técnicas |
|---|---|---|
| **Compilación Rust** | ✅ 0 errores | Verificado con `cargo check` y `cargo test` (124 tests unitarios pasando). |
| **System Monitor** | ✅ Completado | Desacoplado asíncronamente con Tokio (60+ FPS fluidos en Slint). Emisión de telemetría a PIE (`CpuLoad`, `MemoryPressure`, `NetworkThroughput`, `ThermalAlert`). |
| **Smart Cleaner** | ✅ Bloques 1 a 5 completados; purga suspendida (A11.09) y cross-volume destructivo deshabilitado (A11.10) | Manifiesto v2 atómico, bloqueo entre procesos (`QuarantineProcessLock`), transacciones con staging, SHA-256, no-replace, recuperación `Staged`/`Restoring`, preservación ADS/atributos NTFS, validación de rutas/reparse, backup v1 protegido, fail-closed en duplicados y control names (R01–R03, R05, R07). Bloque 3 ejecutado: validación estricta de rutas y componentes transversales (`validate_clean_path`, A11.01), directorios protegidos (`is_protected_path`, A11.02), rechazo de reparse points y enlaces duros (`ensure_not_hard_link`, A11.03), mitigación TOCTOU en duplicados mediante verificación atómica por handle de tamaño y SHA-256 (`quarantine_file_with_expected`, A11.04 OBLIGATORIO), verificación y retención de descriptor protegido de copia retenida inalterada (`open_protected_read` y anti-colisión de identidad, A11.05), y rechazo obligatorio en backend ante selección de todas las copias de un grupo (A11.06). Bloque 4 ejecutado: diálogos de confirmación previa con conteo y bytes (`rfd::MessageDialog`, A11.13), reporte visual de errores en UI y logs (`set_cleaner_status`, A11.14), apertura segura de archivos mediante acción "Reveal" en explorador en vez de ejecución directa (A11.15), identificación unívoca por clave estable en operaciones de restauración y borrado (`entry.key`, R06), caché de tamaños escaneados y `raw-size` (R08), blindaje de directorios reales de SysPulse (`app_data_dir`, `db_path`, `logs_dir`, `settings_path`, R09) y desactivación segura de borrado permanente directo ruteando a papelera (R10). Bloque 5 ejecutado: validación integral de ciclo de vida con archivos temporales descartables (`test_b5_final_validation_lifecycle`, A11.16). A11.10 y R04 permanecen contenidos temporalmente (cross-volume destructivo deshabilitado). Semántica de Papelera en `delete_quarantine_permanently` preservada. Purga automática suspendida (A11.09 CONTENIDO TEMPORALMENTE). 47 pruebas de cleaner/cuarentena (92 totales en workspace). |
| **CPU Focus** | ✅ Completado | Prioridad `ABOVE_NORMAL_PRIORITY_CLASS` (Win32) y memoria en MB reales. |
| **Process Hunter** | ✅ Completado | Registro forense continuo en SQLite (`syspulse.db`), cálculo de tiempo de vida en procesos transitorios (< 5s), purga horaria y exportación a JSON/CSV. Emisión de eventos a PIE (`ProcessSpawned`, `UntrustedExecutionLocation`, `TransientProcessDetected`). |
| **System Tray & Ajustes** | ✅ Completado | Minimizar a bandeja, autoarranque en Registro (`HKCU\...\Run`), detección robusta de `icon.ico`. Retención de métricas de red configurable (`net_metrics_retention_days`). |
| **Instalador Oficial** | ✅ Completado | Compilado con Inno Setup 7 (`SysPulse-Setup-0.3.1.exe`, ~7.2 MB). |
| **Pulse Intelligence Engine (PIE)** | ✅ Fase 0, Fase 4 y Fase 5 (UI Incidents & Export) Completadas | Event Bus centralizado con canal `broadcast(256)` y `mpsc(1024)`. Esquema SQLite versionado (`PRAGMA user_version = 3`) con clave compuesta `(network_id, mac)`, `correlation_key`, `last_updated` e índices compuestos. Motor de correlación heurística en tiempo real con 7 reglas prioritarias respaldadas 100% por productores reales, confirmación de condiciones sostenidas, histéresis, deduplicación entre reinicios, debouncing de evidencias (10s), resolución automática y explicabilidad Modo Simple/Avanzado bilingüe Fluent. Exportador forense unificado (Subtarea 4.4) a JSON estructurado y CSV RFC 4180 de incidentes y evidencias para análisis de IA local/offline con ordenamiento determinista. Centro de Incidentes en Slint (`PieIncidentsTab`) y controladores asíncronos reactivos en `main.rs` con filtrado y exportación de archivos bajo demanda. 33 tests de PIE ok (27 de reglas/persistencia + 6 de exportación forense; 98 en workspace). |
| **Network Guardian** | ✅ Fases 1, 2, 3 y 5 Completadas (Subtareas 5.1, 5.2 y 5.4) | Detección de interfaces físicas/virtuales (`GetAdaptersAddresses`), sondeo ICMP nativo sin UAC, RTT, Jitter RFC 3550 y Packet Loss. `WifiAnalyzer` nativo (`wlanapi.dll`): diagnóstico completo, detección de redes inseguras, matriz de congestión ponderada por RSSI y recomendación explicable. `DeviceScanner`: descubrimiento pasivo ARP kernel, escáner activo SendARP acotado (máx 25 req/s), resolución de hostnames con pool acotado (`Semaphore(4)` + `JoinSet`), base OUI oficial IEEE con detección estricta LAA. `SocketCorrelator`: vinculación nativa Win32 de sockets TCP/UDP con PIDs y procesos de Process Hunter (`GetExtendedTcpTable`/`GetExtendedUdpTable`). `NetworkGuardianTab` en Slint con 4 sub-pestañas operativas (Dispositivos, Wi-Fi Analyzer, Calidad de Enlace y Conexiones) y controladores asíncronos en `main.rs` sin bloqueos de renderizado. 29 tests de red ok (109 en workspace). |

---

## 3. Fases Completadas y Correcciones de la Última Jornada

### 3.1. Fases Completadas:
- **Fase 0 (PIE):** Event Bus, tipado de eventos críticos vs telemetría, `ProcessIdentity` anti-reciclaje y esquema de incidentes.
- **Fase 1 (Network Guardian):** Interfaces, Gateway, ICMP Ping nativo en modo usuario, Jitter RFC 3550 y Packet Loss.
- **Fase 2 (Network Guardian):** WlanAPI, diagnóstico de conexión Wi-Fi activa, congestión de canales circundantes y recomendaciones explicables.
- **Fase 3 (Network Guardian):** Descubrimiento ARP local, escáner activo bajo demanda, resolución de nombres, base OUI offline, categorización LAA e inventario silencioso inicial por red.
- **Fase 4: Subtarea 4.1 (Esquemas SQLite y Modelos Persistidos):**
  - Implementación de la **Alternativa D**: clave compuesta `(network_id, mac)` en `net_devices`, tabla `net_metrics_history` particionada por red e interfaz, índices optimizados.
  - Migración transaccional versionada (`PRAGMA user_version = 2`) no destructiva, conservando datos preexistentes bajo `legacy_unassigned` con `is_trusted = 0`.
  - Modelado con `Option<f32>` para distinguir valores ausentes (`NULL`) de mediciones reales cero (`0.0`).
- **Fase 4: Subtarea 4.2 (Conexión de Persistencia y Deduplicación en PIE Loop):**
  - Handlers asíncronos en `PulseIntelligenceEngine::process_critical_event` para persistir y deduplicar dispositivos descubiertos (`NewDeviceDiscovered`), actualizando `ip` y `last_seen` sin alterar alias ni confianza configurados por el usuario.
  - Handlers en `PulseIntelligenceEngine::process_telemetry_event` para registrar muestras periódicas de conectividad en `net_metrics_history`.
  - Mecanismo de purga horaria automática conforme al parámetro `net_metrics_retention_days` en `Settings` (7 días por defecto).
- **Fase 4: Subtarea 4.3 (Motor de Correlación Heurística en PIE - 100% de las 11 Decisiones Aprobadas Implementadas):**
  - Implementación exhaustiva de las 7 reglas heurísticas prioritarias con productores y telemetría reales:
    1. `PIE-R-WIFI-DEG`: Degradación severa del enlace Wi-Fi (< 25% sostenido) correlacionada centralmente en PIE con latencia local, jitter (> 20 ms) y pérdida (> 5%), con histéresis de recuperación (>= 45%).
    2. `PIE-R-NET-EXT-DOWN`: Falla de conectividad WAN con Gateway local operativo (< 40 ms RTT) propagando `InternetHealth` para diferenciar filtrado ICMP de desconexión real.
    3. `PIE-R005`: Detección de Gateway fraudulento o cambio anómalo de DNS con dispositivo no confiable, registrando contexto anterior y posterior (IP de gateway, red e interfaz).
    4. `PIE-R-NET-IP-CONFLICT`: Detección de colisión/suplantación de IP activa diferenciando reasignaciones normales de DHCP (> 10 min de inactividad de la MAC previa).
    5. `PIE-R-PROC-HIGH-CPU`: Consumo elevado y sostenido de CPU por proceso normalizado por núcleos lógicos, confirmación sostenida de 15–30 segundos configurables (`set_cpu_sustained_duration`), histéresis (< 50%) y diferenciación de carga legítima vs saturación.
    6. `PIE-R-MEM-PRESSURE`: Presión sostenida de memoria física (> 85% en 3 ticks) con seguimiento acotado del crecimiento de memoria de procesos mediante `ProcessIdentity` sin afirmar falsas fugas, y resolución por histéresis (< 75%).
    7. `PIE-R-SYS-SATURATION`: Saturación global de hardware y estrés térmico diferenciado por componente (NVMe > 70°C, GPU > 88°C, CPU > 90°C) sin asumir estrangulamiento térmico (throttling) sin evidencia de reloj.
    8. `Context Validation`: Validación estricta del contexto de red antes y después de cada escaneo (`run_device_scan`) o medición (`run_health_check`, `run_wifi_check`), descartando resultados ambiguos sin reasignaciones arbitrarias.
    9. `PIE Robustness`: Gestión de pérdida de eventos en el Event Bus, salto monotónico por suspensión/hibernación (> 60s) reseteando rachas transitorias, búfer circular acotado a 500 y expiración a 120s.
    10. `DNS Resolver Semaphore`: Permisos del semáforo retenidos dentro de la tarea bloqueante nativa hasta su culminación real, incluso tras timeout de 600 ms.
    11. `OUI & LAA Classification`: Detección estricta de MAC LAA y registro del requisito obligatorio previo a publicación final sobre la base OUI de la IEEE.
  - Deduplicación entre reinicios mediante columna `correlation_key` (migración SQLite v3) y precarga en caché de incidentes activos.
  - Debouncing de evidencias en SQLite (10 segundos) para evitar saturación de disco ante eventos continuos.
  - Resolución automática de incidentes por histéresis al normalizarse las condiciones medidas.
  - Preparación de datos para Modo Simple (resumen y recomendaciones amigables) y Modo Avanzado (impacto técnico, mitigación, limitaciones del diagnóstico sin afirmar certezas de malware) e integración de claves i18n en Fluent (`locales/es-AR/main.ftl` y `locales/en/main.ftl`).
  - Suite de pruebas de PIE ampliada a 27 pruebas unitarias (45 pruebas totales en el workspace).
- **Fase 4: Subtarea 4.4 (Exportador Forense Unificado para IA a JSON y CSV):**
  - Módulo `src/modules/pie/exporter.rs` con `ForensicExporter` y `ForensicExportFormat` (Json, Csv).
  - Exportación de incidentes y evidencias persistidas en SQLite (`pie_incidents`, `pie_incident_evidences`) sin mutaciones (solo lectura).
  - Formato JSON con estructura `ForensicReport` estructurada (`generated_at_utc`, `schema_version`, conteos e incidentes anidados con evidencias).
  - Formato CSV RFC 4180 con 21 columnas relacionales desnormalizadas preservando contexto relacional completo y escapado robusto.
  - Ordenamiento determinista (`id ASC`, evidencia `timestamp ASC, id ASC`) y manejo elegante de base de datos vacía e I/O errors.
  - Operación 100% local, offline y disparada bajo demanda; sin llamadas ni subidas a APIs externas.
  - 6 pruebas unitarias focalizadas (33 pruebas de PIE; 98 tests totales en el workspace).
- **Fase 5: Subtarea 5.1 (Correlador de Sockets Win32 - EJECUTADO y PUSHEADO [SHA `a848b15`]):**
  - Módulo `src/modules/network_guardian/socket_correlator.rs` con `SocketCorrelator`.
  - Consultas nativas Win32 no invasivas mediante `GetExtendedTcpTable` y `GetExtendedUdpTable` para IPv4 y IPv6.
  - Correlación asíncrona no bloqueante con procesos activos (`sysinfo`) e histórico SQLite de Process Hunter (`process_events`) para procesos recientemente finalizados.
  - Manejo seguro de procesos extintos, reutilización de PIDs y metadatos no disponibles sin inventar nombres ni estados (`Option::None` ante inaccesibilidad).
  - 5 pruebas unitarias específicas (decodificación de puertos/IPs, mapeos TCP, correlación en vivo/histórico y ejecución nativa en vivo sin UAC).
- **Fase 5: Subtarea 5.2 (Pestaña Slint `NetworkGuardianTab` - EJECUTADO [SHA `09134f6`]):**
  - Componente Slint `NetworkGuardianTab` con 4 sub-pestañas operativas (`TabPill`):
    1. **Dispositivos:** Inventario ARP con `display-name`, IP/MAC, fabricante, badges de confianza (`Confiable`, `Desconocido`, `Router`, `Este PC`) y último avistamiento.
    2. **Wi-Fi Analyzer:** Información de conexión activa (SSID, canal, señal dBm/%, protocolo PHY, seguridad) y mapa de congestión de canales circundantes con recomendaciones explicables.
    3. **Calidad de Enlace:** Banner de conectividad, cuadrícula de 4 métricas (latencia Gateway, latencia Internet, Jitter RFC 3550, Packet Loss) y diagnóstico explicable.
    4. **Conexiones:** Tabla interactiva de sockets activos con protocolo, endpoint local, endpoint remoto, estado TCP y proceso asociado (nombre, PID y estado vivo/cerrado).
  - Manejo integral de estados visuales: escaneo/carga (`is-scanning`, `is-loading`), listas vacías (`devices.length == 0`, `connections.length == 0`), adaptador no disponible o desconectado y reportes de error.
  - Contratos de UI adaptados en `ui_adapter.rs` (`UiSocketConnection`, `map_correlated_socket`) y 6 pruebas unitarias (109 tests totales).
- **Fase 5: Subtarea 5.3 (Centro de Incidentes Slint `PieIncidentsTab` - EJECUTADO [SHA `8a7b504`]):**
  - Componente Slint `PieIncidentsTab` con arquitectura master-detail neón:
    1. Barra superior con filtros de estado (Todos, Activos, Resueltos), selector de vista (Simple / Avanzada) y botones de acción (Actualizar, Exportar JSON, Exportar CSV).
    2. Lista master con tarjetas interactivas de incidentes, badges de severidad (`CRÍTICO`, `ALTO`, `MEDIO`, `INFO`), estado y contador de evidencias.
    3. Panel de detalle reactivo con explicabilidad en Modo Simple (resumen y recomendaciones claras) y Modo Avanzado (ID de regla técnica, impacto, mitigación técnica y limitaciones diagnósticas).
    4. Sub-lista de evidencias observables cronológicas con JSON formateado y origen.
    5. Manejo visual de estados: banners de carga, error y estado vacío cuando todos los subsistemas operan dentro de parámetros normales.
- **Fase 5: Subtarea 5.4 (Controladores Asíncronos en `src/main.rs` e i18n - EJECUTADO):**
  - Handlers de auto-carga en cambio de pestañas (`ui.on_tab_changed`): carga pasiva y sin tráfico de red del inventario ARP y calidad de enlace al entrar a Network Guardian (tab 5), y carga de incidentes al entrar a Incident Center (tab 6).
  - Callbacks operativos de Network Guardian: `refresh-net-devices` (escaneo pasivo), `scan-net-devices` (escaneo activo no invasivo con feedback visual de progreso), `refresh-wifi` (diagnóstico de canales y señal), `refresh-link-quality` (latencia, jitter y pérdida de paquetes) y `refresh-net-connections` (correlación nativa Win32 de sockets TCP/UDP con procesos).
  - Callbacks operativos de PIE Incidents: `refresh-pie-incidents` (recarga reactiva con filtro), `pie-filter-changed` (filtrado dinámico 0/1/2) y exportación forense asíncrona de incidentes y evidencias a JSON y CSV (`export-pie-forensic-json`, `export-pie-forensic-csv`) con diálogo nativo de guardado `rfd` y mensajes de estado en UI.
  - Tarea periódica Tokio en segundo plano para sondeo no invasivo de latencia de red (cada 15s) actualizando en vivo el panel de calidad de enlace sin micro-congelamientos.
  - Funciones de adaptación de modelos de dominio a estructuras generadas por Slint (`map_*_to_slint`).
  - Claves de internacionalización añadidas en Fluent (`locales/es-AR/main.ftl` y `locales/en/main.ftl`) para conexiones y exportación forense.

### 3.2. Observaciones de Pruebas de Campo en GUI Windows (22 de noviembre de 2026)

Se registraron y verificaron formalmente las siguientes observaciones durante las pruebas de campo sobre la interfaz gráfica en Windows 10/11:

#### A. Funcionalidades Verificadas y Superadas (PASSED):
- **Arranque del sistema:** La aplicación inicia correctamente tras la corrección del bloqueo por manifiesto v1 sobredimensionado (`MAX_MIGRATABLE_V1_ENTRIES = 1000`).
- **Network Guardian:** Las sub-pestañas Dispositivos, Wi-Fi Analyzer, Calidad de Enlace y Conexiones (correlación de sockets TCP/proceso) muestran datos reales del entorno.
- **Centro de Incidentes (PIE):** La pestaña abre adecuadamente; las funciones de exportación forense vacía a JSON y CSV operan sin errores ni bloqueos.
- **System Monitor:** Actualiza en tiempo real y con fluidez los valores de CPU global, memoria RAM y métricas de tráfico de red.
- **Process Hunter:** Registra procesos reales del sistema en tiempo de ejecución y exporta correctamente eventos a JSON (comprobado con `PING.EXE`).
- **CPU Focus:** Muestra la lista de procesos activos y el botón *Refresh* actualiza el listado.

#### B. Hallazgos Pendientes y Observaciones de Campo (PENDING / OBSERVED):
- **NG-01 (Mejora propuesta / Descubrimiento de red):** El descubrimiento inicial de dispositivos no detectó un iPhone alcanzable (`192.168.1.12`); apareció únicamente tras emitir un `ping` desde Windows que pobló la tabla ARP del kernel y refrescar la UI. Es necesario optimizar el descubrimiento activo sin depender únicamente de la caché ARP existente.
- **NG-02 (Mejora propuesta / Estado y clasificación):** Separar con claridad los dispositivos conocidos de los actualmente confirmados y los no confirmados / fuera de línea. Evitar marcar un dispositivo como "offline" basándose únicamente en una sonda fallida; mostrar marcas de tiempo del último avistamiento (`last_seen`).
- **NG-03 (Mejora propuesta / Identificación y persistencia):** Proveer soporte persistente para alias de dispositivo personalizados por el usuario e identificación unívoca, incluyendo direcciones MAC administradas localmente (LAA) o privadas/rotativas.
- **SM-01 (Defecto confirmado / UI & Backend):** El volumen `D:` se rotula únicamente como `"Volume"`; debe mostrarse la letra de unidad junto a la etiqueta (ej. `D: [Etiqueta]`). La unidad `C:` funciona correctamente.
- **SM-02 (Observación / Validación pendiente):** Verificar y medir rigurosamente el consumo sostenido de CPU y el overhead en reposo de SysPulse (< 0.5% en reposo con sondeo periódico).
- **CF-01 (Defecto confirmado / Muestreo de CPU):** CPU Focus muestra `0.0%` de CPU para todos los procesos visibles, incluso tras pulsar *Refresh*; se requiere investigar el muestreo y cálculo de uso de CPU por proceso.
- **CF-02 (Seguridad / Backend - IMPLEMENTADO, pendiente revisión independiente):** Implementadas restricciones en backend: rechazo estricto de PIDs críticos (<=4, self), lista canónica de procesos del sistema (`csrss`, `services`, `dwm`, etc.), verificación Win32 con `QueryFullProcessImageNameW`, protección contra reutilización de PID (`start_time_utc`) y rechazo de clases inseguras (`HIGH`/`REALTIME`). 6 pruebas unitarias específicas agregadas (119 tests totales en workspace).
- **UI (Defectos de presentación y usabilidad):**
  - Corregir espaciado excesivo entre componentes visuales.
  - Corregir etiquetas y botones recortados por límites rígidos de contenedor.
  - Subsanar mezcla de idiomas (inglés y español) en vistas y textos.
  - Eliminar formateo crudo de Rust como `Some(...)` en la interfaz.
  - Redondear decimales excesivos en métricas de Jitter.
  - Corregir badges engañosos `"Active"` en sockets que se encuentran en estado `LISTEN` (deben mostrarse como `Escuchando` / `Listening`).
  - Actualizar el indicador de versión en la UI que aún muestra `v0.3.1` (debe reflejar `v0.4.0`).
- **PIE (Observación / Validación pendiente):** La exportación forense de incidentes y evidencias con datos reales o descartables no vacíos permanece sin verificar; un estado de incidentes vacío no debe interpretarse como prueba de salud comprobada del sistema.
- **NG (Mejora propuesta / Wi-Fi):** Las recomendaciones de canales Wi-Fi deben diferenciar explícitamente entre las bandas de 2.4 GHz y 5 GHz.
- **Seguridad (Directiva permanente):** Preservar íntegramente los datos de usuario en cuarentena. Prohibido ejecutar pruebas destructivas de limpieza sobre archivos reales.

---

## 4. Resultados de Validación Técnica

- **`cargo check`:** ✅ 0 errores, 0 advertencias en todo el workspace.
- **`cargo test`:** ✅ 109 pruebas unitarias pasando (0 fallos, 0 ignoradas) en Windows `x86_64-pc-windows-msvc`.
- **`cargo clippy --all-targets`:** ✅ 0 errores; advertencias preexistentes intactas sin advertencias nuevas introducidas.
- **`git diff --check`:** ✅ 0 errores de whitespace.

---

## 5. Archivos Modificados en el Entorno de Trabajo

### Archivos de Planificación y Estado:
- `planes/ESTADO_ACTUAL.md` (actualizado con la culminación de Subtareas 4.1, 4.2, 4.3 y 4.4)
- `planes/PLAN_DE_ACCION.md` (desglose y marcado de Subtareas 4.1, 4.2, 4.3 y 4.4)
- `planes/PLAN_NETWORK_GUARDIAN.md` (esquema SQLite actualizado con Alternativa D)

### Módulo PIE Core (`src/modules/pie/`):
- `exporter.rs`: Exportador forense unificado de incidentes y evidencias a JSON (`ForensicReport`) y CSV tabular RFC 4180 con consultas de solo lectura, ordenamiento determinista y soporte offline.
- `engine.rs`: Integración de métodos asíncronos de exportación (`export_forensic_incidents`, `get_all_incidents`) y delegación en `ForensicExporter`.
- `mod.rs`: Re-exportación de `ForensicExportFormat`, `ForensicExporter` y `ForensicReport`.
- `models.rs`: Modelos `Incident` (con `correlation_key`, `last_updated_utc`, `technical_impact`, `technical_mitigation`, `diagnostic_limitations`) y `TelemetryEvent::NetworkLatencySample` con `gateway_rtt_ms` e `internet_rtt_ms`.
- `rules.rs`: 8 reglas de correlación completas con explicabilidad para Modo Simple y Avanzado (sin afirmaciones de malware, throttling ni fugas de memoria sin evidencia).
- `tests.rs`: 27 pruebas unitarias completas de PIE.

### Smart Cleaner / Auditoría A11:
- `src/modules/cleaner.rs`: manifiesto v2 atómico, bloqueo entre procesos (`QuarantineProcessLock`), validación de rutas/reparse, transacciones de cuarentena y restauración con staging, SHA-256, no-replace (`LockedFile`), recuperación `Staged`/`Restoring`, ADS y atributos NTFS preservados, y 25 pruebas de regresión de B2B (35 de cleaner en total; 80 totales en workspace). Reversión de borrado físico en `delete_quarantine_permanently` preservando papelera.
- `Cargo.toml`: features Win32 `Win32_Storage_FileSystem` y `Win32_System_IO`; sin dependencias nuevas.
- `planes/AUDITORIA_V0.4.0.md`, `planes/ESTADO_ACTUAL.md`, `planes/PLAN_DE_ACCION.md`: estado de Bloques 1, 2A/2B, seguimiento de R01–R07, cobertura y riesgos residuales.

### Módulo Network Guardian (`src/modules/network_guardian/`):
- `mod.rs`: Emisión de telemetría de latencia desagregando `gateway_rtt_ms` e `internet_rtt_ms`, y validación estricta de contexto antes y después de cada escaneo y medición (`run_device_scan`, `run_health_check`, `run_wifi_check`).
- `scanner.rs`: `dns_semaphore` acotado (`MAX_HOSTNAME_RESOLVER_WORKERS = 4`) garantizando que los permisos permanezcan retenidos dentro del hilo bloqueante nativo hasta su finalización real.
- `ping.rs`: Verificación TCP de respaldo con `matches!` optimizado para diferenciar filtrado ICMP de desconexión WAN.
- `oui.rs`: Identificación estricta de MAC LAA y base OUI offline.

### Modelos y Configuración:
- `src/models.rs`: Soporte de alias deserializados en enum `Language`.
- `locales/es-AR/main.ftl`: Claves de títulos amigables de PIE en español.
- `locales/en/main.ftl`: Claves equivalentes en inglés.

---

## 6. Decisiones Arquitectónicas Aprobadas (Alternativa D y Subtarea 4.3)

1. **Clave primaria compuesta `(network_id, mac)` en `net_devices`:** Cada red mantiene su propio inventario, historial, alias y confianza.
2. **Reutilización de `NetworkContext::network_id`:** Formato unívoco derivado de subred CIDR, IP de Gateway e identificador de interfaz.
3. **Aislamiento de dispositivos, alias y confianza por red:** Modificar alias o confianza en una red no altera los registros de otra red.
4. **Historial de métricas diferenciado por red e interfaz:** `net_metrics_history` incluye `network_id` e `interface_name`.
5. **Propagación del contexto de red:** Todos los eventos críticos y muestras de telemetría de red viajan con su `network_id` asociado.
6. **Captura del contexto en el momento de la observación:** En cada sondeo o escaneo se evalúa la interfaz primaria activa y se genera el contexto en ese instante.
7. **Migraciones SQLite versionadas y transaccionales:** Versionado hasta `PRAGMA user_version = 3` sin pérdida de datos.
8. **Conservación de datos históricos sin `network_id`:** Almacenados bajo la red `legacy_unassigned` con `is_trusted = 0`.
9. **Métricas indisponibles como `Option<f32>` / `NULL`:** Diferenciación estricta entre falta de datos y valores medidos en cero.
10. **Retención configurable:** `net_metrics_retention_days` en `Settings` con valor por defecto de 7 días.
11. **Compatibilidad retrospectiva:** Deserialización transparente de archivos `settings.toml` antiguos sin romper la aplicación.
12. **Persistencia y deduplicación entre reinicios:** Los eventos del loop de PIE actualizan automáticamente la base de datos sin duplicar dispositivos ni resetear configuraciones del usuario.
13. **Explicabilidad estructurada sin alarmismo:** Todo diagnóstico incluye hechos medidos objetivos, impacto real, pasos de mitigación y limitaciones técnicas sin afirmar certezas de malware, throttling ni fugas de memoria sin evidencia.
14. **Centralización de reglas Wi-Fi en PIE:** Correlación de señal débil (< 25%) con latencia local, jitter (> 20 ms) y pérdida de paquetes (> 5%).
15. **Diferenciación WAN con `InternetHealth`:** Detección de ausencia de respuesta ICMP diferenciada de pérdida real mediante comprobación TCP complementaria.
16. **Trazabilidad de cambios de Gateway y DNS:** Registro explícito de contexto previo y posterior y productor activo en adaptadores.
17. **Diferenciación de reasignaciones DHCP:** Exigencia de actividad reciente (<= 10 min) para clasificar conflicto IP/MAC, descartando rotaciones normales.
18. **Normalización de CPU y confirmación sostenida:** Consumo normalizado por núcleos lógicos con ventana configurable de 15–30 segundos e histéresis.
19. **Seguimiento acotado de memoria:** Presión global con seguimiento acotado de hasta 20 procesos mediante `ProcessIdentity` sin afirmar fugas sin evidencia.
20. **Diferenciación térmica por sensor:** Umbrales propios por componente (NVMe 70°C, GPU 88°C, CPU 90°C) sin asumir throttling sin telemetría de reloj.
21. **Validación bidireccional de red:** Validación antes y después de cada escaneo o medición, descartando resultados ambiguos.
22. **Robustez ante discontinuidades temporales:** Detección de suspensión (> 60s) reseteando rachas transitorias, búfer circular acotado a 500 y expiración a 120s.
23. **Retención de permisos DNS:** Retención de permits en `spawn_blocking` hasta culminación real para prevenir saturación de hilos.
24. **Base OUI y MAC LAA:** Clasificación precisa LAA y registro obligatorio de verificación de condiciones de redistribución IEEE como prerequisito previo a publicación.

---

## 7. Auditoría Externa v0.4.0 (ChatGPT) y Resolución Controlada de A11

- **Documento de Auditoría:** [planes/AUDITORIA_V0.4.0.md](file:///D:/proyectos/SysPulse/planes/AUDITORIA_V0.4.0.md) (Contiene los **20 hallazgos originales A01–A20** y el desglose de los **16 subhallazgos A11.01–A11.16** de Smart Cleaner).
- **Directivas Permanentes:** [AGENTS.md](file:///D:/proyectos/SysPulse/AGENTS.md) (Normas inmutables de desarrollo, optimización de tokens, no regresión y contraste previo).
- **Decisiones de Revisión Independiente:**
  - Prioridad inmediata: A11.09 (riesgo de pérdida automática de datos).
  - Rechazo de propuesta simplista en A11.11 (no invertir simplemente orden de movimiento y manifiesto para no generar archivos huérfanos).
  - Insuficiencia técnica de tamaño/mtime/pre-hash ante TOCTOU en A11.04.
  - Insuficiencia de `exists()` antes de `rename()` ante carreras en A11.08.
  - Diferenciación estricta entre fallo de restauración funcional y pérdida irreversible en A11.10.
  - Verificación de cobertura real en A11.16.
- **Estado de A11.09:** **CONTENIDO TEMPORALMENTE** (Bloque 1 completado exitosamente: purga automática desactivada, preservación íntegra de archivos y manifiestos, trazabilidad explícita en logging e i18n, sin fechas estimadas).
- **Resultado de Bloques 2A/2B:** `cargo check` limpio, 83 tests pasando y sin advertencias nuevas de clippy. Cuarentena/restauración transaccional con staging, SHA-256, no-replace (`LockedFile`), recuperación tras fallos, bloqueo entre procesos (`QuarantineProcessLock`), ADS y atributos NTFS preservados, fail-closed en enumeración y backup v1 protegido (R01–R03, R05 y R07 integradas). Semántica de Papelera en `delete_quarantine_permanently` preservada. A11.10 y R04 permanecen contenidos temporalmente (deshabilitadas transferencias destructivas cross-volume; staging y origen preservados). R06 pendiente para Bloque 4. Purga automática suspendida (A11.09 CONTENIDO TEMPORALMENTE). A11.04 asignado obligatoriamente a Bloque 3; Bloque 2C no autorizado.
- **Secuencia de Trabajo Planificada para A11:**
  - **Bloque 1:** Contención inmediata A11.09 — ✅ COMPLETADO (CONTENIDO TEMPORALMENTE).
  - **Bloque 2:** Integridad, persistencia y restauración de cuarentena — ✅ 2A/2B COMPLETADOS (R01–R05/R07 integradas).
  - **Bloque 3:** Seguridad de rutas y duplicados (A11.01–A11.06, incluye A11.04 obligatorio) — ✅ COMPLETADO (44 tests de cleaner, 89 totales).
  - **Bloque 4:** Seguridad de interfaz (A11.13–A11.15 y R06–R10) — ✅ COMPLETADO (46 tests de cleaner, 91 totales).
  - **Bloque 5:** Validación integral (A11.16) — ✅ COMPLETADO (47 tests de cleaner, 92 totales).

---

## 8. Instrucciones Exactas para Retomar en la Próxima Sesión

1. Leer directamente este archivo (`planes/ESTADO_ACTUAL.md`), [AGENTS.md](file:///D:/proyectos/SysPulse/AGENTS.md) y [planes/AUDITORIA_V0.4.0.md](file:///D:/proyectos/SysPulse/planes/AUDITORIA_V0.4.0.md).
2. **Rama activa:** Mantenerse en `review/a11-block-2b` (o la rama indicada por el usuario). Baseline: `0dcc5b3`.
3. **Estado del proyecto:** **124 tests unitarios pasando** (0 fallos, 0 errores en `cargo check`).
4. **Fix P0 Implementado (Smart Cleaner / Startup Blocker):**
   - Detección de manifiestos v1 sobredimensionados (`MAX_MIGRATABLE_V1_ENTRIES = 1000`, `MAX_MIGRATABLE_V1_BYTES = 1024 * 1024`).
   - Omisión de la migración automática y transición a modo degradado en < 1 ms para evitar el bloqueo del hilo principal de Slint.
   - Preservación íntegra de `manifest.json`, `manifest.v1.bak` y los archivos físicos en cuarentena.
   - Operaciones de cuarentena deshabilitadas fail-closed en modo degradado; resto de módulos 100% operativos.
   - Verificado con 2 pruebas de regresión automáticas y ratificado en pruebas de campo en Windows (2026-11-22).
5. **Plan Inmediato de Trabajo (PLANNED NEXT):**
   1. **Consolidar y priorizar problemas verificados en campo:** Abordar defectos funcionales (`SM-01`, `CF-01`, interfaz gráfica UI), observaciones y directivas de seguridad.
   2. **Simplificar Smart Cleaner:** Enfocarlo a una utilidad básica, manual y orientada a "no-destructivo primero". Mantener los datos de cuarentena y copias de seguridad existentes plenamente recuperables; no eliminarlos ni migrarlos automáticamente.
   3. **Resolver bloqueantes de release y validar v0.4.0 en Windows:** Subsanar los defectos confirmados y validar exhaustivamente la compilación en Windows 10/11.
   4. **Preparar release build, empaquetado e instalación limpia:** Compilar en modo release, empaquetar instalador con Inno Setup y verificar instalación limpia.
   5. **Trabajo diferido post-v0.4.0:** Tras culminar el trabajo planificado de v0.4.0, retomar la captura ETW / inicio temprano en Process Hunter y demás mejoras diferidas.
6. **Seguimiento de Hallazgos Residuales de Auditoría Externa:**
   - **A02:** Desacoplar la emisión de telemetría de `SysMonitor` respecto a la pestaña activa (actualmente dentro de `if ui.get_current_tab() == 0`, lo que silencia a PIE en reposo o minimizado en bandeja).
   - **A04:** Filtrar la tabla ARP del kernel en `read_arp_table_native` por la subred/interfaz activa para ignorar adaptadores virtuales ajenos.
   - **A12:** Transacción conjunta SQLite (`tx.transaction()`) al persistir incidente y sus evidencias observables en `persist_incident`.
7. No realizar commit ni push sin autorización explícita previa del usuario (Directiva Permanente 10).

---

## 9. Pruebas Manuales, Observaciones de Campo y Trabajo Diferido

### 9.1. Pruebas de Campo Verificadas en GUI Windows (2026-11-22) — PASSED:
1. **Inicio de la Aplicación:** La aplicación arranca sin demoras tras el fix del manifiesto v1 sobredimensionado, eliminando el cuelgue en la inicialización de Slint.
2. **Network Guardian:** Datos reales comprobados en las sub-pestañas Dispositivos, Wi-Fi Analyzer, Calidad de Enlace y Conexiones (correlación Win32 de sockets TCP con procesos).
3. **Centro de Incidentes (PIE):** Apertura correcta de la interfaz, visualización del estado y exportación de archivos JSON y CSV vacíos plenamente operativa.
4. **System Monitor:** Métricas de CPU global, memoria RAM y rendimiento de red actualizándose dinámicamente en vivo.
5. **Process Hunter:** Registro de procesos del sistema en tiempo de ejecución y exportación forense a JSON funcional (validado con `PING.EXE`).
6. **CPU Focus:** Lista de procesos visualizada y botón *Refresh* reactivo actualizando la lista.

### 9.2. Defectos Confirmados en Pruebas de Campo (BUGS VERIFICADOS):
1. **SM-01 (Volumen D: sin letra):** El volumen D: aparece rotulado únicamente como `"Volume"`; corregir para mostrar la letra de unidad junto a la etiqueta (ej. `D: [Etiqueta]`). La unidad C: funciona correctamente.
2. **CF-01 (Muestreo CPU Focus en 0.0%):** CPU Focus muestra `0.0%` en todos los procesos de la lista incluso tras pulsar *Refresh*; investigar el algoritmo de muestreo y cálculo de tiempo de CPU por proceso.
3. **UI (Ajustes de Interfaz y Usabilidad):**
   - Espaciado excesivo entre componentes visuales.
   - Etiquetas y botones recortados por límites rígidos de contenedor.
   - Textos inconsistentes con mezcla de inglés y español (i18n).
   - Formateo crudo de Rust visible en la interfaz (`Some(...)`).
   - Jitter con decimales excesivos sin redondear.
   - Badges engañosos `"Active"` en sockets con estado `LISTEN` (deben reflejar escucha/pasivo).
   - Indicador de versión desactualizado mostrando `v0.3.1` en lugar de `v0.4.0`.
4. **SET-01 a SET-05 (Ajustes y Preferencias - IMPLEMENTADOS, pendiente verificación GUI en campo):**
   - **SET-01 (Modo Oscuro/Claro):** Exclusión mutua estricta en UI, inicialización y persistencia garantizadas tras reinicio (`sanitize()`).
   - **SET-02 (Soporte Bilingüe es-AR/en):** Integración reactiva en Slint y Fluent de textos en español rioplatense e inglés conservados.
   - **SET-03 (Sliders de Retención):** Sliders visualizan valores numéricos en días; slider de cuarentena deshabilitado/bloqueado por A11.09.
   - **SET-04 (Etiquetas y Controles):** Ancho ampliado a 340px con elisión preventiva; versión actualizada a 0.4.0 en Ajustes y ventana principal.
   - **SET-05 (Inicio con Windows):** Consulta no destructiva del Registro Win32 (`is_autostart_registered()`) sincronizando estado real sin alteraciones automáticas.
   - 5 pruebas unitarias en `modules::config::tests` (124 tests totales en workspace).

### 9.3. Observaciones y Validaciones Pendientes:
1. **SM-02 (Uso de CPU en reposo):** Medir y verificar rigurosamente el uso sostenido de CPU y el overhead en reposo de SysPulse (< 0.5% en reposo con sondeo periódico).
2. **PIE (Exportación forense no vacía):** La exportación forense a JSON/CSV con datos reales o descartables no vacíos aún no ha sido verificada en campo; un estado de incidentes vacío no debe interpretarse como prueba de salud comprobada del sistema.

### 9.4. Mejoras Propuestas (Network Guardian):
1. **NG-01 (Descubrimiento activo independiente de caché ARP):** El descubrimiento inicial omitió un iPhone alcanzable (`192.168.1.12`), apareciendo solo tras ejecutar `ping` en Windows y refrescar. Optimizar el descubrimiento activo sin depender únicamente de la tabla ARP del kernel.
2. **NG-02 (Separación de estados y marcas temporales):** Separar en la UI los dispositivos conocidos de los actualmente confirmados y no confirmados/offline. No marcar offline a un dispositivo tras un único sondeo fallido; mostrar marcas de tiempo de último avistamiento (`last_seen`).
3. **NG-03 (Alias persistentes y direcciones MAC privadas/LAA):** Soportar alias definidos por el usuario de forma persistente e identificación unívoca, contemplando direcciones MAC administradas localmente (LAA) o privadas.
4. **NG (Recomendación Wi-Fi por banda):** Diferenciar explícitamente las recomendaciones de canales para las bandas de 2.4 GHz y 5 GHz.

### 9.5. Directivas de Seguridad Permanentes:
1. **Preservación de datos de usuario:** Preservar íntegramente los datos y archivos en cuarentena. Prohibido realizar pruebas destructivas de limpieza sobre archivos reales de usuario.
2. **CF-02 (Restricciones de backend en CPU Focus - IMPLEMENTADO, pendiente revisión independiente):** Restricciones implementadas en backend contra elevación de procesos críticos, PIDs reciclados y clases inseguras (6 pruebas pasando).

### 9.6. Trabajo Diferido (Post-v0.4.0):
1. **Process Hunter ETW:** Migración a Event Tracing for Windows (ETW) y captura en inicio temprano (early-start capture) para reemplazar el polling de `sysinfo`.
2. **Mejoras avanzadas adicionales:** Gráficos sparkline históricos en tiempo real, notificaciones toast nativas y cambio dinámico de idioma en UI.
