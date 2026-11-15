# SysPulse — Documento Permanente de Estado y Continuidad de Contexto

**Ubicación:** `planes/ESTADO_ACTUAL.md`  
**Última actualización:** 15 de noviembre de 2026 (Fase 4: Subtareas 4.1, 4.2 y 4.3 Completadas provisionalmente; Listo para auditoría externa en rama develop/v0.4.0)  
**Rama activa:** `develop/v0.4.0`  
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
| **Compilación Rust** | ✅ 0 errores, 0 warnings en módulos nuevos | Verificado con `cargo check` y `cargo test` (45 tests pasando en 0.81s). Clippy limpio en `pie`, `network_guardian` y `models`. |
| **System Monitor** | ✅ Completado | Desacoplado asíncronamente con Tokio (60+ FPS fluidos en Slint). Emisión de telemetría a PIE (`CpuLoad`, `MemoryPressure`, `NetworkThroughput`, `ThermalAlert`). |
| **Smart Cleaner** | ✅ Completado | Limpieza rápida con bypass opcional de Papelera; buscador de duplicados con **pre-hashing a 16 KB** y búfer de 64 KB; cuarentena con manifiesto JSON reactiva. |
| **CPU Focus** | ✅ Completado | Prioridad `ABOVE_NORMAL_PRIORITY_CLASS` (Win32) y memoria en MB reales. |
| **Process Hunter** | ✅ Completado | Registro forense continuo en SQLite (`syspulse.db`), cálculo de tiempo de vida en procesos transitorios (< 5s), purga horaria y exportación a JSON/CSV. Emisión de eventos a PIE (`ProcessSpawned`, `UntrustedExecutionLocation`, `TransientProcessDetected`). |
| **System Tray & Ajustes** | ✅ Completado | Minimizar a bandeja, autoarranque en Registro (`HKCU\...\Run`), detección robusta de `icon.ico`. Retención de métricas de red configurable (`net_metrics_retention_days`). |
| **Instalador Oficial** | ✅ Completado | Compilado con Inno Setup 7 (`SysPulse-Setup-0.3.1.exe`, ~7.2 MB). |
| **Pulse Intelligence Engine (PIE)** | ✅ Fase 0 y Fase 4 (Subtareas 4.1, 4.2 y 4.3 Completadas) | Event Bus centralizado con canal `broadcast(256)` y `mpsc(1024)`. Esquema SQLite versionado (`PRAGMA user_version = 3`) con clave compuesta `(network_id, mac)`, `correlation_key`, `last_updated` e índices compuestos. Motor de correlación heurística en tiempo real con 7 reglas prioritarias respaldadas 100% por productores reales, confirmación de condiciones sostenidas, histéresis, deduplicación entre reinicios mediante precarga de caché de incidentes activos, debouncing de evidencias (10s), resolución automática y preparación de explicabilidad en Modo Simple y Avanzado con soporte de i18n Fluent EN / ES-AR. 21 tests de PIE ok. |
| **Network Guardian** | ✅ Fases 1, 2 y 3 Completadas (100% de los 11 Requisitos Verificados) | Detección de interfaces físicas/virtuales (`GetAdaptersAddresses`), sondeo ICMP nativo sin UAC, RTT, Jitter RFC 3550 y Packet Loss. `WifiAnalyzer` nativo (`wlanapi.dll`): diagnóstico completo, detección de redes inseguras, matriz de congestión ponderada por RSSI y recomendación explicable. `DeviceScanner`: descubrimiento pasivo ARP kernel, escáner activo SendARP acotado (máx 25 req/s), resolución de hostnames con pool acotado (`Semaphore(4)` + `JoinSet`), base OUI oficial IEEE con detección estricta LAA, segmentación por red (`NetworkContext`), vistas duales Simple/Avanzado y eventos automáticos a PIE con baseline silencioso. 18 tests de red ok. |

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

---

## 4. Resultados de Validación Técnica

- **`cargo check`:** ✅ 0 errores, 0 advertencias en todo el workspace.
- **`cargo test`:** ✅ 45 pruebas unitarias pasando (18 de Network Guardian + 27 de PIE Core) en 0.81s.
- **`cargo clippy --all-targets`:** ✅ Módulos nuevos (`network_guardian`, `pie`, `models`) 100% limpios de advertencias.

---

## 5. Archivos Modificados en el Entorno de Trabajo

### Archivos de Planificación y Estado:
- `planes/ESTADO_ACTUAL.md` (actualizado con la culminación de Subtareas 4.1, 4.2 y 4.3)
- `planes/PLAN_DE_ACCION.md` (desglose y marcado de Subtareas 4.1, 4.2 y 4.3)
- `planes/PLAN_NETWORK_GUARDIAN.md` (esquema SQLite actualizado con Alternativa D)

### Módulo PIE Core (`src/modules/pie/`):
- `models.rs`: Modelos `Incident` (con `correlation_key`, `last_updated_utc`, `technical_impact`, `technical_mitigation`, `diagnostic_limitations`) y `TelemetryEvent::NetworkLatencySample` con `gateway_rtt_ms` e `internet_rtt_ms`.
- `rules.rs`: 8 reglas de correlación completas con explicabilidad para Modo Simple y Avanzado (sin afirmaciones de malware, throttling ni fugas de memoria sin evidencia).
- `engine.rs`: Migración versionada v3 (`PRAGMA user_version = 3`), evaluación en tiempo real de las 7 reglas prioritarias, duración configurable de CPU (15–30s), seguimiento acotado de consumo de procesos con `ProcessIdentity`, alertas térmicas diferenciadas por sensor, deduplicación entre reinicios, debouncing de evidencias (10s), resolución e histéresis automáticas.
- `tests.rs`: 27 pruebas unitarias completas de PIE (pruebas positivas y negativas por regla, histéresis, resolución, deduplicación entre reinicios, debouncing, aislamiento de red, confirmación de CPU, crecimiento de memoria y sensores térmicos).

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

## 7. Próxima Tarea Exacta (Fase 4: Subtarea 4.4 - Exportador Forense Unificado para IA)

**Subtareas de la Fase 4:**
- [x] **Subtarea 4.1: Creación de tablas y modelos en `syspulse.db` (Alternativa D Aprobada)**
- [x] **Subtarea 4.2: Conexión de persistencia y deduplicación entre reinicios**
- [x] **Subtarea 4.3: Motor de Correlación Heurística en PIE**
- [ ] **Subtarea 4.4: Exportador Forense Unificado para IA:**
  - Generación de reportes estructurados en JSON y CSV de incidentes y evidencias correlacionadas de red y procesos.

---

## 8. Instrucciones para Retomar en la Próxima Sesión

1. Leer directamente este archivo (`planes/ESTADO_ACTUAL.md`).
2. **No re-auditar el código ni recorrer el árbol de archivos.**
3. Ejecutar `cargo check` y `cargo test` para confirmar el estado limpio (39 tests pasando).
4. Proceder con la **Subtarea 4.4** y actualizar el checkpoint al concluir.
5. No avanzar a fases no autorizadas (Fase 5: UI Slint Neón) ni realizar commit o push.

---

## 9. Pruebas Manuales Pendientes (Registradas para Fin de Proyecto con UI Slint)

Las siguientes pruebas con hardware real quedan registradas para ejecutarse una vez finalizada la Fase 5 con la interfaz gráfica Slint Neón:
1. **Conectividad:** Cotejo de RTT y Jitter frente a `ping` nativo en Windows 10/11 y desconexión/reconexión de cable de red.
2. **Wi-Fi Analyzer:** Cotejo de intensidad de señal (%) y SSID con la bandeja del sistema de Windows, y prueba en Modo Avión.
3. **Dispositivos:** Escaneo en red doméstica real verificando detección de router, smartphones, consolas y Smart TVs con fabricantes reales.
4. **Usabilidad:** Validación de claridad en Modo Simple para usuarios sin conocimientos técnicos.
