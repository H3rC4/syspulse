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

| Subhallazgo | Definición Canónica | Estado Actual | Bloque Asignado |
|---|---|:---:|:---:|
| **A11.01** | Path validation | Implementado (pendiente revisión externa) | Bloque 3 |
| **A11.02** | Protected directories | Implementado (pendiente revisión externa) | Bloque 3 |
| **A11.03** | Symlinks/junctions/hard links | Implementado (pendiente revisión externa) | Bloque 3 |
| **A11.04** | Duplicate TOCTOU | Implementado (pendiente revisión externa) | Bloque 3 (Obligatorio) |
| **A11.05** | Retained copy validation | Implementado (pendiente revisión externa) | Bloque 3 |
| **A11.06** | Prevent selecting all copies | Implementado (pendiente revisión externa) | Bloque 3 |
| **A11.07** | Atomic manifest | Corregido en B2A | Bloque 2 |
| **A11.08** | Restore overwrite | Corregido en B2B | Bloque 2 |
| **A11.09** | Quarantine retention | **CONTENIDO TEMPORALMENTE** (Purga suspendida) | **Bloque 1** |
| **A11.10** | Cross-volume restoration | **CONTENIDO TEMPORALMENTE** (Transferencia cross-volume destructiva deshabilitada) | **Bloque 2** |
| **A11.11** | Manifest/file consistency | Corregido en B2B | Bloque 2 |
| **A11.12** | Recycle Bin semantics | Corregido en B2B | Bloque 2 |
| **A11.13** | User confirmations | Pendiente de corrección | Bloque 4 |
| **A11.14** | UI error reporting | Pendiente de corrección | Bloque 4 |
| **A11.15** | Unsafe file opening | Pendiente de corrección | Bloque 4 |
| **A11.16** | Regression tests | En progreso (44 tests de cleaner; 89 totales) | Bloque 5 |

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
     - Persistencia atómica con archivo temporal exclusivo, `sync_all` a disco físico y reemplazo seguro. Preservación del temporal ante fallo de rename.
     - Serialización de escrituras concurrentes (`Arc<Mutex<QuarantineManifestV2>>`).
     - Migración no destructiva con respaldo de seguridad `manifest.v1.bak`.
     - Recuperación conservadora ante corrupción o temporales huérfanos: bloqueo preventivo de operaciones destructivas; nunca se inicializa un manifiesto vacío ante ambigüedad.
     - Validación rigurosa de claves (anti-traversal, sin separadores de ruta ni colisiones de control) y rutas originales (sin auto-inclusión en directorio de cuarentena).
     - Purga automática permanece suspendida (A11.09 CONTENIDO TEMPORALMENTE).
     - 6 pruebas unitarias nuevas aisladas agregadas (10 pruebas unitarias de cleaner en total).
   - **Bloque 2B (EJECUTADO con revisiones R01–R05/R07 integradas):**
     - Transferencia física atómica en fases con copia exclusiva a staging, `sync_all`, verificación SHA-256 y revalidación de identidad antes de eliminar el origen (A11.07, A11.11).
     - Restauración atómica sin sobrescritura mediante destino exclusivo/no-replace, verificación SHA-256 y errores diferenciados para destino existente, origen alterado, fallo de verificación y ausencia transitoria (A11.08, A11.10).
     - Recuperación transaccional de estados `Staged`/`Restoring` al iniciar y antes de cada operación; ante incertidumbre se conservan ambas copias. Staging preservado ante ambigüedad y legacy staging retenido fail-closed sin promover copias incompletas (R01, R03).
     - Bloqueo entre procesos (`QuarantineProcessLock`), validación de reparse points y rechazo de rutas de origen dentro de la cuarentena. Si falla el lock, inicio inmediato en modo degradado sin leer ni escribir manifiesto (R05).
     - Corrección y blindaje de hallazgos de revisión R01–R03, R05 y R07; preservación estricta de semántica de Papelera en `delete_quarantine_permanently` (A11.12).
     - Blindaje contra nombres Windows/DOS equivalentes (`QUARANTINE_LOCK_FILE`, staging `.syspulse-staging`/`.syspulse-restore-*`, short-names 8.3 `manife~*`/`quaran~*`/`syspul~*`) y rechazo fail-closed de claves duplicadas/colisionantes (R07).
     - A11.10 y R04 permanecen CONTENIDOS TEMPORALMENTE: transferencias cross-volume destructivas deshabilitadas; archivos preservados íntegramente en origen/cuarentena.
     - 28 pruebas de B2B (38 pruebas de cleaner en total; 83 totales en workspace). La purga automática sigue suspendida (A11.09 CONTENIDO TEMPORALMENTE).
   - **Pendiente del Bloque 2:** Ninguno. A11.04 asignado obligatoriamente a Bloque 3.
   - **Bloque 2C:** No autorizado ni iniciado.
3. **Bloque 3: Seguridad de rutas y duplicados (EJECUTADO)**
   - **Path validation (A11.01):** Validación estricta con `validate_clean_path` y `validate_ancestors_safety`. Rechazo de rutas relativas, componentes transversales (`..`, `.`) y rutas fuera del directorio base permitido.
   - **Protected directories (A11.02):** Función canónica `is_protected_path` que previene operaciones sobre directorios de sistema (Windows, Program Files, ProgramData, `/bin`, `/etc`, etc.), directorio de la aplicación (`syspulse.db`, `settings.toml`), directorio de cuarentena y raíces de disco.
   - **Symlinks/junctions/hard links (A11.03):** Rechazo preventivo de reparse points (`ensure_not_reparse`) en objetivos, ancestros y destino; detección y rechazo de enlaces duros (`ensure_not_hard_link`, `FileIdentity.number_of_links > 1`) para evitar eliminación accidental de copias vinculadas.
   - **Duplicate TOCTOU (A11.04 - OBLIGATORIO):** Mitigación mediante apertura previa de handle exclusivo (`LockedFile::open_source`) y verificación atómica de longitud y hash SHA-256 (`quarantine_file_with_expected`) comparados con el escaneo previo, abortando ante cualquier mutación concurrente antes del traslado seguro.
   - **Retained copy validation (A11.05):** Verificación exhaustiva de al menos una copia retenida independiente, válida e inalterada con descriptor protegido (`open_protected_read`) activo durante toda la operación de grupo, con comprobación anti-colisión de identidad de objeto (`identity.same_object`).
   - **Prevent selecting all copies (A11.06):** Verificación obligatoria en backend de que `selected_count < total_count`, rechazando a nivel de motor cualquier solicitud que pretenda poner en cuarentena o eliminar todas las copias de un grupo.
   - **Suite de pruebas:** 6 pruebas unitarias nuevas agregadas (44 pruebas de cleaner; 89 en total en el workspace).
4. **Bloque 4: Seguridad de interfaz (PENDIENTE)**
   - User confirmations (A11.13).
   - UI error reporting (A11.14).
   - Unsafe file opening (A11.15).
   - Tratamiento de R06 (Unstable UI row indexes) y sincronización de sliders/retención en Slint UI sin falsas promesas.
5. **Bloque 5: Validación integral (PENDIENTE)**
   - Regression tests (A11.16). Suite completa de pruebas de estrés, escenarios de fallo de disco y cobertura unitaria/integración.

---

## 5. Registro Separado de Revisiones Técnicas de Bloque 2B (R01 – R07)

| ID | Definición Canónica | Estado en Bloque 2B | Resolución / Notas |
|---|---|:---:|---|
| **R01** | Destructive recovery | ✅ Corregido | Transaccionalidad Staged/Restoring, recuperación fail-closed, preservación de staging sin promover copias incompletas. |
| **R02** | File identity/races | ✅ Corregido | Identidad unívoca vía handle Win32 (`LockedFile`), `FileRenameInfo` sin reemplazo y bloqueo `QuarantineProcessLock`. |
| **R03** | Staging ownership | ✅ Corregido | Verificación exhaustiva de identidad y pertenencia de staging antes de cualquier operación; fail-closed ante ambigüedad. |
| **R04** | NTFS metadata | 🟡 **CONTENIDO TEMPORALMENTE** | Preservación de ADS, atributos y descriptores de seguridad implementada; transferencias destructivas cross-volume deshabilitadas preventivamente. |
| **R05** | Startup degradation | ✅ Corregido | Retorno inmediato en modo degradado si falla adquisición de lock; nunca se lee, migra ni escribe manifiesto sin lock. |
| **R06** | Unstable UI row indexes | 🟡 Pendiente | Reservado para Bloque 4 (Seguridad de interfaz en Slint UI). |
| **R07** | Manifest validation | ✅ Corregido | Validación estricta contra control/lock files (`QUARANTINE_LOCK_FILE`, staging, aliases 8.3) y rechazo fail-closed de claves duplicadas/colisionantes. |

> **Nota de Seguridad sobre Eliminación:** En `delete_quarantine_permanently` se rechazó y revirtió la eliminación física irreversible introducida sin autorización, restableciendo la delegación segura a la Papelera de Reciclaje de Windows (`trash::delete`) con verificación previa de clave, registro en manifiesto y reparse points (A11.12).
