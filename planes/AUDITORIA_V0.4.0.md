# SysPulse — Auditoría Estática Independiente v0.4.0 (ChatGPT)

**Fecha:** 15 de noviembre de 2026 (Actualizado: 18 de noviembre de 2026)
**Rama evaluada:** `develop/v0.4.0`
**Commit base:** `f97e1e55a71fbcfe93cff7c7ab71e8fa178dfa9a`
**Estado:** Bloques 1, 2A y 2B de A11 ejecutados; A11.04 pendiente; A11.09 contenido temporalmente; Bloque 2C no autorizado.

---

## 1. Registro de Hallazgos Preliminares Originales (A01 – A20)

| ID | Hallazgo Preliminar | Estado de Verificación |
|---|---|:---:|
| **A01** | Descubrimiento de dispositivos no conectado al flujo principal de ejecución. | Pendiente de contrastar |
| **A02** | Monitorización de CPU, RAM y temperatura dependiente de la pestaña activa. | Pendiente de contrastar |
| **A03** | Generación inconsistente de `network_id` entre Network Guardian y DeviceScanner. | Pendiente de contrastar |
| **A04** | Inventario ARP sin filtrado efectivo por interfaz. | Pendiente de contrastar |
| **A05** | Desconexión entre inventario en memoria, persistencia SQLite, alias y confianza. | Pendiente de contrastar |
| **A06** | Mezcla de métricas locales y externas en los diagnósticos Wi-Fi y ventanas de medición. | Pendiente de contrastar |
| **A07** | Correlaciones incorrectas de cambios de gateway y DNS. | Pendiente de contrastar |
| **A08** | Falsos positivos por reasignaciones DHCP interpretadas como conflictos IP/MAC. | Pendiente de contrastar |
| **A09** | Contadores de pérdida de eventos existentes, pero aparentemente no utilizados por PIE para gestionar la confianza. | Pendiente de contrastar |
| **A10** | Ciclo de vida incompleto de incidentes, resolución, histéresis e identidad de procesos. | Pendiente de contrastar |
| **A11** | Revisión de seguridad de Smart Cleaner, cuarentena, restauración y eliminación de archivos. Desglosado en subhallazgos A11.01–A11.16. | En proceso (Bloques 1, 2A y 2B ejecutados; A11.04 pendiente; A11.09 CONTENIDO TEMPORALMENTE) |
| **A12** | Persistencia de incidentes y evidencias sin transacción conjunta. | Pendiente de contrastar |
| **A13** | Timeout DNS que aparentemente no incluye la espera del semáforo. | Pendiente de contrastar |
| **A14** | Límite de procesos monitorizados en memoria posiblemente no efectivo. | Pendiente de contrastar |
| **A15** | Precisión insuficiente de ProcessIdentity y tratamiento de identidades desconocidas. | Pendiente de contrastar |
| **A16** | Respuestas de ping simuladas fuera de Windows. | Pendiente de contrastar |
| **A17** | Verificación pendiente de seguridad, permisos y elevación en llamadas al sistema. | Pendiente de contrastar |
| **A18** | Textos de diagnóstico escritos directamente en español sin integración completa con Fluent. | Pendiente de contrastar |
| **A19** | Posibles costes innecesarios de CPU y memoria por actualización y ordenación reiterada de recursos. | Pendiente de contrastar |
| **A20** | Versionado, dependencias, licencias y condiciones de redistribución OUI pendientes de revisión. | Pendiente de contrastar |

---

## 2. Metodología y Decisiones de la Revisión Independiente sobre A11

Se acepta provisionalmente la evidencia técnica presentada en la auditoría estática de Smart Cleaner, pero **NO se aprueban automáticamente las 16 propuestas de corrección sin análisis crítico**:

1. **A11.09 constituye la prioridad inmediata:** Existe un riesgo crítico real de pérdida automática e irreversible de datos del usuario al iniciar SysPulse si se calcula la antigüedad con marcas de tiempo del sistema de archivos (`mtime`).
2. **A11.11 — Rechazo de propuesta simplista:** Se rechaza la propuesta de invertir simplemente el orden entre el movimiento físico del archivo y la persistencia del manifiesto. Invertir ingenuamente el orden crearía archivos huérfanos en cuarentena sin registro alguno de su ubicación original ante fallos de disco o interrupciones. La solución requiere diseño atómico transaccional.
3. **A11.04 — Insuficiencia de validación superficial:** Se confirma que tamaño, `modified_time` y pre-hash no constituyen una validación suficiente de integridad ni eliminan las condiciones TOCTOU (Time-Of-Check to Time-Of-Use) frente a mutaciones concurrentes.
4. **A11.08 — Ineficacia de `exists()` ante carreras:** Se ratifica que comprobar `exists()` antes de `rename()` no garantiza la ausencia de sobrescritura ante condiciones de carrera en el sistema de archivos.
5. **A11.10 — Distinción de severidad en restauración:** Es imperativo distinguir entre un fallo de restauración funcional (el archivo permanece a salvo en cuarentena aunque no pueda moverse) y una pérdida irreversible de datos (destrucción o truncamiento).
6. **A11.16 — Verificación de cobertura real:** Se debe verificar la suite completa de pruebas unitarias y posibles pruebas de integración antes de afirmar cobertura nula en todo el repositorio.

---

## 3. Desglose de Subhallazgos de Smart Cleaner (A11.01 – A11.16)

| Subhallazgo | Descripción Técnica | Estado Actual | Bloque Asignado |
|---|---|:---:|:---:|
| **A11.01** | Rutas por defecto y escaneo de temporales sin validación estricta de cruce de junctions / symlinks hacia ubicaciones protegidas. | Pendiente de corrección | Bloque 3 |
| **A11.02** | Tratamiento no diferenciado de reparse points y enlaces simbólicos en la limpieza de temporales. | Pendiente de corrección | Bloque 3 |
| **A11.03** | Condición TOCTOU en `clean_paths` entre escaneo preliminar y la invocación de `remove_file` / `trash::delete`. | Pendiente de corrección | Bloque 3 |
| **A11.04** | Validación insuficiente de integridad y condición TOCTOU en detección de duplicados (tamaño, modified_time y pre-hash). | Pendiente de corrección | Bloque 3 (Obligatorio) |
| **A11.05** | Gestión de cancelaciones abruptas en `quarantine_selected_duplicates` dejando lotes a medio procesar. | Mitigado en B2B (transacción atómica por archivo) | Bloque 2 |
| **A11.06** | Generación de nombres en cuarentena basada en truncado de hash (16 chars) + PID, vulnerable a colisiones inter-sesión o reciclaje. | Pendiente de corrección | Bloque 3 |
| **A11.07** | Movimiento cross-device vía `copy` + `remove_file` sin verificación de suma de verificación ni atomicidad. | Corregido en B2B | Bloque 2 |
| **A11.08** | Restauración desde cuarentena mediante `rename` sin exclusión mutua atómica, susceptible de sobrescribir archivos destino existentes ante carreras. | Corregido en B2B | Bloque 2 |
| **A11.09** | **Purga automática de cuarentena basada en `metadata.modified()` que elimina datos antiguos al iniciar SysPulse sin considerar fecha real de ingreso.** | **CONTENIDO TEMPORALMENTE** | **Bloque 1** |
| **A11.10** | Manejo de errores en restauración sin distinguir bloqueo transitorio de pérdida definitiva. | Corregido en B2B | Bloque 2 |
| **A11.11** | Orden y atomicidad entre el desplazamiento físico del archivo y la persistencia en `manifest.json`. | Corregido en B2B | Bloque 2 |
| **A11.12** | Escritura directa no atómica de `manifest.json` susceptible de corrupción total ante apagones o caídas súbitas. | Corregido en B2A | Bloque 2 |
| **A11.13** | Manifiesto carente de metadatos indispensables (`quarantined_at`, hash original verificado, tamaño validado, atributos). | Corregido en B2A/B2B | Bloque 2 |
| **A11.14** | Heurística frágil de reconstrucción de rutas originales (`split("_0_")`) con riesgo de corrupción o escape de rutas. | Pendiente de corrección | Bloque 3 |
| **A11.15** | Promesa en UI / textos de retención automática de días que no se aplica o se aplica de forma destructiva insegura. | Pendiente de corrección | Bloque 4 |
| **A11.16** | Cobertura insuficiente de pruebas automatizadas sobre el ciclo de vida de cuarentena, manifiesto y duplicados. | En progreso (36 tests de cleaner; 81 totales) | Bloque 5 |

---

## 4. Secuencia de Trabajo para la Resolución Controlada de A11

1. **Bloque 1: Contención inmediata A11.09 (EJECUTADO)**
   - Desactivación total de la purga automática insegura basada en `mtime`.
   - Garantía de preservación total de archivos existentes y de `manifest.json`.
   - Compatibilidad conservada con `settings.toml`.
   - Sin fechas inventadas ni uso de `created()`, `modified()` o `accessed()` como sustitutos.
   - Registro explícito de suspensión en tracing y UI/i18n (EN y ES-AR).
   - Estado: **CONTENIDO TEMPORALMENTE**.
2. **Bloque 2: Integridad, persistencia y restauración de cuarentena**
   - **Bloque 2A (EJECUTADO):**
     - Manifiesto v2 retrocompatible con v1 (`version: 2`, `QuarantineRecordV2`).
     - Preservación estricta de históricos sin inventar fechas (`quarantined_at_utc: None`), hashes ni tamaños.
     - Persistencia atómica con archivo temporal exclusivo, `sync_all` a disco físico y reemplazo seguro.
     - Serialización de escrituras concurrentes (`Arc<Mutex<QuarantineManifestV2>>`).
     - Migración no destructiva con respaldo de seguridad `manifest.v1.bak`.
     - Recuperación conservadora ante corrupción o temporales huérfanos: bloqueo preventivo de operaciones destructivas; nunca se inicializa un manifiesto vacío ante ambigüedad.
     - Validación rigurosa de claves (anti-traversal, sin separadores de ruta ni colisiones de control) y rutas originales (sin auto-inclusión en directorio de cuarentena).
     - Purga automática permanece suspendida (A11.09 CONTENIDO TEMPORALMENTE).
     - 6 pruebas unitarias nuevas aisladas agregadas (10 pruebas unitarias de cleaner en total).
   - **Bloque 2B (EJECUTADO con revisiones R01–R05/R07 integradas):**
     - Transferencia física atómica en fases con copia exclusiva a staging, `sync_all`, verificación SHA-256 y revalidación de identidad antes de eliminar el origen (A11.07, A11.11).
     - Restauración atómica sin sobrescritura mediante destino exclusivo/no-replace, verificación SHA-256 y errores diferenciados para destino existente, origen alterado, fallo de verificación y ausencia transitoria (A11.08, A11.10).
     - Recuperación transaccional de estados `Staged`/`Restoring` al iniciar y antes de cada operación; ante incertidumbre se conservan ambas copias.
     - Bloqueo entre procesos (`QuarantineProcessLock`), validación de reparse points y rechazo de rutas de origen dentro de la cuarentena.
     - Corrección y blindaje de hallazgos de revisión R01–R05 y R07; preservación estricta de semántica de Papelera en `delete_quarantine_permanently`.
     - Blindaje contra nombres Windows/DOS equivalentes (`quarantine.lock`, short-names 8.3 `manife~*`/`quaran~*`) y rechazo fail-closed de claves duplicadas/colisionantes.
     - Transferencias cross-volume destructivas deshabilitadas temporalmente; archivos preserved en origen/cuarentena.
     - 26 pruebas de B2B (36 pruebas de cleaner en total; 81 totales en workspace). La purga automática sigue suspendida (A11.09).
   - **Pendiente del Bloque 2:** Ninguno. A11.04 asignado obligatoriamente a Bloque 3.
   - **Bloque 2C:** No autorizado ni iniciado.
3. **Bloque 3: Seguridad de rutas y duplicados (PENDIENTE - INCLUYE A11.04 OBLIGATORIO)**
   - Generación de identificadores unívocos no colisionables (A11.06).
   - Prevención de cruce de enlaces/junctions y canonicalización estricta (A11.01, A11.02).
   - Mitigación TOCTOU en eliminación preliminar (A11.03) e integridad/TOCTOU en duplicados (A11.04 obligatorio).
   - Blindaje de operaciones en lote ante cancelaciones (A11.05) y escape de rutas (A11.14).
4. **Bloque 4: Seguridad de interfaz (PENDIENTE)**
   - Ajuste definitivo de sliders, mensajes y reactividad en Slint Neón.
   - Internacionalización Fluent sincronizada en EN y ES-AR.
   - Tratamiento de R06 (promesa de retención y sliders en UI).
5. **Bloque 5: Validación integral (PENDIENTE)**
   - Suite completa de pruebas de estrés, escenarios de fallo de disco y cobertura unitaria/integración.

---

## 5. Registro Separado de Revisiones Técnicas de Bloque 2B (R01 – R07)

| ID | Área / Requisito Técnico | Estado en Bloque 2B | Resolución / Notas |
|---|---|:---:|---|
| **R01** | Bloqueo de nombres reservados DOS y extensiones con superíndices (`COM1-9¹²³`, `LPT1-9¹²³`). | ✅ Corregido | Incorporado en `validate_windows_component` con chequeo de caracteres Unicode. |
| **R02** | Bloqueo exclusivo entre procesos sobre directorio de cuarentena para prevenir colisiones concurrentes. | ✅ Corregido | Implementado `QuarantineProcessLock` mediante Win32 `LockFileEx` (`LOCKFILE_FAIL_IMMEDIATELY`). |
| **R03** | Identidad unívoca de archivo vía handle Win32 y movimiento atómico `FileRenameInfo` sin reemplazo. | ✅ Corregido | Implementado `LockedFile` (`BY_HANDLE_FILE_INFORMATION`, `FileRenameInfo` con `ReplaceIfExists = FALSE`). |
| **R04** | Preservación de Alternate Data Streams (ADS NTFS), atributos y descriptores de seguridad en transferencias cross-volume. | ✅ Corregido | Copia exhaustiva vía `FindFirstStreamW`/`FindNextStreamW`, `GetFileSecurityW`/`SetFileSecurityW` y `SetFileAttributesW`. |
| **R05** | Transaccionalidad de staging y recuperación fail-closed ante identidades de staging no verificables. | ✅ Corregido | `QuarantineTransaction` en `QuarantineRecordV2` con rechazo conservador ante staging sin identidad registrada. |
| **R06** | Sincronización de retención en Slint UI e i18n sin emitir falsas promesas de purga automática. | 🟡 Pendiente | Reservado para Bloque 4 (Seguridad de interfaz). Purga automática continúa suspendida. |
| **R07** | Protección incondicional del respaldo `manifest.v1.bak` y fail-closed en errores de enumeración de directorio. | ✅ Corregido | Verificación de preexistencia de backup v1 y propagación de errores de lectura de directorio sin asumir vacío. |

> **Nota de Seguridad sobre Eliminación:** En `delete_quarantine_permanently` se rechazó y revirtió la eliminación física irreversible introducida sin autorización, restableciendo la delegación segura a la Papelera de Reciclaje de Windows (`trash::delete`) con verificación previa de clave, registro en manifiesto y reparse points.
