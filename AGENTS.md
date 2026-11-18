# SysPulse — Guía y Directivas Permanentes para Agentes de Desarrollo

Este documento establece las reglas obligatorias e inmutables para cualquier agente o desarrollador que trabaje en el repositorio SysPulse.

---

## 1. Directivas Permanentes de Desarrollo

1. **No auditorías generales repetitivas:** No repetir auditorías generales ni inspeccionar árboles completos de archivos al retomar sesiones. Guiarse estrictamente por `planes/ESTADO_ACTUAL.md`.
2. **No reconstrucción de componentes existentes:** No revertir, reescribir ni reconstruir trabajo ya finalizado y probado.
3. **Evitar duplicación de código:** Favorecer abstracciones limpias, reutilización de modelos y tipos ya establecidos.
4. **Optimización de tokens:** Respuestas concisas, enfocadas en la tarea autorizada, evitando resúmenes extensos innecesarios.
5. **No omisión ni postergación de requisitos:** No aplazar ni suprimir directivas, requisitos funcionales ni de seguridad sin autorización explícita.
6. **Soporte Bilingüe (i18n):** Conservar y mantener la internacionalización Fluent en inglés (`en`) y español rioplatense (`es-AR`).
7. **Arquitectura Dual Simple / Avanzada:** Toda funcionalidad diagnóstica o de red debe proveer información comprensible para usuarios no técnicos (Modo Simple) y datos técnicos rigurosos para administradores o analistas (Modo Avanzado).
8. **Seguridad y Rendimiento:** Operación 100% offline, sin UAC, sin sniffing de tráfico ajeno, bajo consumo de CPU (< 0.5% en reposo) y memoria acotada (< 15 MB adicionales).
9. **Pruebas manuales:** Las pruebas de campo e interacción manual se postergan hasta contar con la interfaz Slint integrada al finalizar todas las fases.
10. **Aislamiento de versiones y ramas:**
    - No modificar la versión de producción estable `v0.3.1`.
    - No modificar `main` remoto.
    - No realizar `commit` ni `push` sin autorización explícita previa del usuario.
    - Trabajar exclusivamente en la rama de desarrollo asignada (`develop/v0.4.0`).
11. **Metodología de Auditoría:** Ante hallazgos de auditorías estáticas externas, contrastar siempre contra el código real antes de aplicar cambios, verificando si constituyen defectos confirmados o falsos positivos.
