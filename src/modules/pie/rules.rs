use crate::modules::pie::models::{IncidentCategory, IncidentSeverity};
use std::time::Duration;

/// Regla heurística de correlación con ventana temporal y explicabilidad para Modo Simple y Avanzado.
#[derive(Debug, Clone)]
pub struct CorrelationRule {
    pub id: &'static str,
    pub name: &'static str,
    pub category: IncidentCategory,
    pub severity: IncidentSeverity,
    pub base_risk_score: u8, // 0..100
    pub confidence: f32,      // 0.0..1.0 (nivel de certidumbre basado en hechos medidos)
    pub time_window: Duration,// Ventana temporal monotónica configurable por regla

    // ── Explicación para Modo Simple (Comprensible sin tecnicismos) ──
    pub simple_title: &'static str,
    pub simple_summary: &'static str,
    pub simple_recommendation: &'static str,

    // ── Explicación Técnica para Modo Avanzado (Profesional / Forense) ──
    pub technical_hypothesis: &'static str,
    pub technical_impact: &'static str,
    pub technical_mitigation: &'static str,
    pub diagnostic_limitations: &'static str,
}

impl CorrelationRule {
    /// 1. Degradación del enlace Wi-Fi (Prioridad 1)
    pub fn wifi_degradation() -> Self {
        Self {
            id: "PIE-R-WIFI-DEG",
            name: "Degradación severa del enlace Wi-Fi",
            category: IncidentCategory::Network,
            severity: IncidentSeverity::Medium,
            base_risk_score: 55,
            confidence: 0.85,
            time_window: Duration::from_secs(30),
            simple_title: "Señal Wi-Fi inestable o muy débil",
            simple_summary: "La conexión inalámbrica está experimentando una pérdida notable de calidad de señal, lo que puede causar desconexiones o lentitud al navegar.",
            simple_recommendation: "Acércate al router Wi-Fi o verifica si hay obstáculos físicos o fuentes de interferencia cercanas.",
            technical_hypothesis: "Señal Wi-Fi deprimida (< 25% o caída súbita) correlacionada con jitter elevado (> 20 ms) o pérdida de paquetes (> 5%).",
            technical_impact: "Aumento de retransmisiones 802.11, reducción de tasa de modulación (MCS) y potenciales caídas intermitentes de enlace.",
            technical_mitigation: "Cambiar de banda a 5 GHz si la distancia lo permite, reubicar el adaptador de antena o seleccionar canal con menor congestión en Wi-Fi Analyzer.",
            diagnostic_limitations: "Métricas obtenidas mediante WlanAPI e ICMP local. No distingue entre atenuación por distancia física vs interferencia electromagnética externa no-Wi-Fi.",
        }
    }

    /// 2. Falla de conectividad externa con enlace local estable (Prioridad 2)
    pub fn external_connectivity_down() -> Self {
        Self {
            id: "PIE-R-NET-EXT-DOWN",
            name: "Falla de conectividad WAN con Gateway local operativo",
            category: IncidentCategory::Network,
            severity: IncidentSeverity::High,
            base_risk_score: 75,
            confidence: 0.90,
            time_window: Duration::from_secs(20),
            simple_title: "Conexión local activa pero sin acceso a Internet",
            simple_summary: "Tu computadora se comunica correctamente con tu router o módem, pero el proveedor de internet no está respondiendo hacia el exterior.",
            simple_recommendation: "Reinicia el módem de tu proveedor o verifica si hay una avería general del servicio en tu zona.",
            technical_hypothesis: "Gateway local responde a ICMP Echo (< 15 ms, 0% pérdida), mientras que sondeos a resolutores públicos (1.1.1.1 / 8.8.8.8) fallan o sufren timeout sostenido.",
            technical_impact: "Imposibilidad total de navegación web y servicios en la nube a pesar de mantener direccionamiento IP local válido.",
            technical_mitigation: "Comprobar el estado de las luces WAN en el router, verificar asignación DHCP externa o reiniciar equipo CPE del proveedor.",
            diagnostic_limitations: "Basado en sondeo ICMP en modo usuario hacia hosts de referencia públicos. Puede reportar falso positivo si el proveedor bloquea selectivamente tráfico ICMP.",
        }
    }

    /// 3. Dispositivos desconocidos y cambios inesperados de Gateway o DNS (Prioridad 3)
    pub fn network_anomaly() -> Self {
        Self {
            id: "PIE-R005",
            name: "Anomalía de topología de red con dispositivo no confiable",
            category: IncidentCategory::Network,
            severity: IncidentSeverity::High,
            base_risk_score: 80,
            confidence: 0.85,
            time_window: Duration::from_secs(30),
            simple_title: "Cambio inesperado en la configuración de tu conexión",
            simple_summary: "Se detectó un nuevo dispositivo en la red justo al modificarse la puerta de enlace o los servidores de conexión.",
            simple_recommendation: "Comprueba si conectaste un nuevo router o extensor Wi-Fi. Si no fue así, revisa los dispositivos en Network Guardian.",
            technical_hypothesis: "Evento NewDeviceDiscovered no confiable temporalmente correlacionado con GatewayChanged en el mismo contexto de red.",
            technical_impact: "Potencial redirección de tráfico local (Rogue DHCP / ARP Gateway Hijacking) o desvío de resoluciones DNS.",
            technical_mitigation: "Verificar la MAC del Gateway legítimo en la etiqueta del router físico y marcar dispositivos conocidos como Confiables.",
            diagnostic_limitations: "Correlación heurística temporal en espacio de usuario. No confirma malware activo; puede originarse legítimamente al conectar extensores de rango (mesh).",
        }
    }

    /// 4. Cambios relevantes de identidad IP/MAC (Prioridad 4)
    pub fn ip_mac_conflict() -> Self {
        Self {
            id: "PIE-R-NET-IP-CONFLICT",
            name: "Conflicto o suplantación potencial de dirección IP",
            category: IncidentCategory::Network,
            severity: IncidentSeverity::High,
            base_risk_score: 78,
            confidence: 0.85,
            time_window: Duration::from_secs(30),
            simple_title: "Dos dispositivos están usando la misma dirección de red",
            simple_summary: "Se detectó que una dirección de red asignada previamente ahora responde con un identificador físico diferente en tu red local.",
            simple_recommendation: "Verifica si configuraste una IP fija duplicada en algún equipo o si reemplazaste recientemente el router.",
            technical_hypothesis: "Evento NewDeviceDiscovered en el mismo network_id donde la IP ya existía en net_devices asociada a una MAC previa distinta.",
            technical_impact: "Colisión de paquetes, inestabilidad en la tabla ARP de los clientes locales o potencial suplantación ARP (spoofing).",
            technical_mitigation: "Verificar si hay equipos con IP estática fuera del rango DHCP o inspeccionar la tabla ARP local en Network Guardian.",
            diagnostic_limitations: "Una reasignación rápida de DHCP por rotación de concesiones o cambio físico de placa de red en un host fijo produce este mismo patrón.",
        }
    }

    /// 5. Consumo elevado y sostenido de CPU asociado a procesos (Prioridad 5)
    pub fn sustained_process_cpu() -> Self {
        Self {
            id: "PIE-R-PROC-HIGH-CPU",
            name: "Consumo elevado y sostenido de procesador por proceso",
            category: IncidentCategory::Performance,
            severity: IncidentSeverity::Medium,
            base_risk_score: 60,
            confidence: 0.88,
            time_window: Duration::from_secs(15),
            simple_title: "Una aplicación está sobrecargando el procesador",
            simple_summary: "Un programa específico mantiene tu procesador trabajando a muy alta potencia de forma continua.",
            simple_recommendation: "Si no estás realizando tareas pesadas (como juegos o renders), considera cerrar la aplicación o priorizarla en CPU Focus.",
            technical_hypothesis: "Uso global de CPU > 75% sostenido durante múltiples muestras consecutivas con un único proceso consumiendo > 50%.",
            technical_impact: "Aumento de temperatura térmica, activación de ventiladores a máxima velocidad y pérdida de fluidez en otras ventanas.",
            technical_mitigation: "Ajustar afinidad o prioridad mediante CPU Focus, o finalizar el proceso si no responde desde Process Hunter.",
            diagnostic_limitations: "No distingue si el cómputo intensivo es deliberado (compilación, cálculo científico) o un bucle infinito no deseado.",
        }
    }

    /// 6. Crecimiento sostenido de memoria bajo presión global (Prioridad 6)
    pub fn sustained_memory_pressure() -> Self {
        Self {
            id: "PIE-R-MEM-PRESSURE",
            name: "Saturación sostenida de memoria RAM del sistema",
            category: IncidentCategory::Performance,
            severity: IncidentSeverity::Medium,
            base_risk_score: 55,
            confidence: 0.85,
            time_window: Duration::from_secs(30),
            simple_title: "La memoria del equipo está casi llena",
            simple_summary: "La memoria RAM está por encima del 85% de capacidad de forma continua, lo que puede provocar lentitud general.",
            simple_recommendation: "Cierra aplicaciones o pestañas del navegador que no estés utilizando para liberar memoria inmediatamente.",
            technical_hypothesis: "Métricas consecutivas de MemoryPressure superando el 85% de memoria física utilizada sin liberación espontánea.",
            technical_impact: "Incremento drástico de paginación a disco (thrashing), aumento de latencia de apertura de aplicaciones y stuttering en la interfaz.",
            technical_mitigation: "Ejecutar la herramienta Smart Cleaner para purgar cachés temporales y cerrar procesos con alto consumo de memoria.",
            diagnostic_limitations: "Mide la memoria asignada total del sistema operativo. No se afirman fugas de memoria sin evidencia; se realiza seguimiento acotado del conjunto de trabajo de los principales consumidores mediante ProcessIdentity.",
        }
    }

    /// 7. Saturación global de recursos de hardware (Prioridad 7)
    pub fn resource_saturation() -> Self {
        Self {
            id: "PIE-R-SYS-SATURATION",
            name: "Saturación global de recursos y estrés térmico",
            category: IncidentCategory::Performance,
            severity: IncidentSeverity::High,
            base_risk_score: 70,
            confidence: 0.90,
            time_window: Duration::from_secs(15),
            simple_title: "Tu equipo está operando al límite de su capacidad",
            simple_summary: "El procesador y la memoria están trabajando al máximo simultáneamente o el equipo ha alcanzado temperaturas elevadas.",
            simple_recommendation: "Reduce la carga de trabajo y asegúrate de que las rejillas de ventilación de tu equipo estén despejadas.",
            technical_hypothesis: "Condición sostenida simultánea de CPU > 90% y RAM > 85%, o alertas térmicas de componentes superando umbrales de seguridad específicos (NVMe > 70°C, GPU > 88°C, CPU > 90°C).",
            technical_impact: "Elevación de temperatura y estrés térmico del hardware. Riesgo potencial de estrangulamiento térmico (thermal throttling) si el componente alcanza su límite de diseño (TjMax).",
            technical_mitigation: "Suspender procesos no prioritarios, revisar base refrigerante en laptops y comprobar ventiladores.",
            diagnostic_limitations: "Los sensores térmicos dependen de las interfaces WMI/ACPI provistas por el fabricante. No se afirma estrangulamiento térmico (throttling) sin telemetría directa de caída en la frecuencia de reloj del procesador.",
        }
    }

    /// 8. Ejecución desde carpeta temporal (Seguridad complementaria)
    pub fn suspicious_temp_exec() -> Self {
        Self {
            id: "PIE-R001",
            name: "Ejecución sospechosa desde carpeta temporal con actividad de red",
            category: IncidentCategory::Security,
            severity: IncidentSeverity::High,
            base_risk_score: 85,
            confidence: 0.80,
            time_window: Duration::from_secs(30),
            simple_title: "Aplicación no habitual ejecutándose desde carpeta temporal",
            simple_summary: "Se detectó un programa ejecutándose desde una carpeta temporal del sistema que estableció comunicación con una dirección externa.",
            simple_recommendation: "Si no iniciaste una instalación reciente, te sugerimos examinar este programa en Process Hunter.",
            technical_hypothesis: "Posible payload temporal o instalador no verificado iniciando conexiones externas.",
            technical_impact: "Riesgo de persistencia oculta o ejecución no controlada de binarios transitorios en el perfil del usuario.",
            technical_mitigation: "Auditar la ruta de ejecución en Process Hunter y aislar el ejecutable si resulta desconocido.",
            diagnostic_limitations: "Muchos instaladores legítimos y actualizadores automáticos extraen binarios en %TEMP% durante su operación.",
        }
    }
}
