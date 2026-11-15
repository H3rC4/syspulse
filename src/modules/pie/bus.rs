use crate::modules::pie::models::{PulseCriticalEvent, PulseEnvelope, TelemetryEvent};
use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};

pub const DEFAULT_CRITICAL_CAPACITY: usize = 1024;
pub const DEFAULT_TELEMETRY_CAPACITY: usize = 256;

/// Estadísticas de salud del Event Bus para diagnóstico interno y auditoría.
#[derive(Debug, Clone, Copy, Default)]
pub struct EventBusMetrics {
    pub dropped_critical: u64,
    pub dropped_telemetry: u64,
}

/// Emisor del Event Bus centralizado para productores de eventos.
#[derive(Clone)]
pub struct PulseEventBus {
    critical_tx: mpsc::Sender<PulseEnvelope>,
    telemetry_tx: broadcast::Sender<TelemetryEvent>,
    dropped_critical: Arc<AtomicU64>,
    dropped_telemetry: Arc<AtomicU64>,
}

/// Receptor del Event Bus centralizado para el motor de correlación PIE.
pub struct PulseEventReceiver {
    pub critical_rx: mpsc::Receiver<PulseEnvelope>,
    pub telemetry_rx: broadcast::Receiver<TelemetryEvent>,
}

impl PulseEventBus {
    /// Inicializa el bus centralizado con capacidades diferenciadas para eventos críticos y telemetría.
    pub fn new(
        critical_capacity: usize,
        telemetry_capacity: usize,
    ) -> (Self, PulseEventReceiver) {
        let (critical_tx, critical_rx) = mpsc::channel(critical_capacity);
        let (telemetry_tx, telemetry_rx) = broadcast::channel(telemetry_capacity);

        let dropped_critical = Arc::new(AtomicU64::new(0));
        let dropped_telemetry = Arc::new(AtomicU64::new(0));

        let bus = Self {
            critical_tx,
            telemetry_tx,
            dropped_critical,
            dropped_telemetry,
        };

        let receiver = PulseEventReceiver {
            critical_rx,
            telemetry_rx,
        };

        (bus, receiver)
    }

    /// Emite un evento crítico con backpressure asíncrono.
    /// Si el búfer está completamente saturado, se contabiliza la pérdida y se emite un error.
    pub async fn emit_critical(&self, event: PulseCriticalEvent) -> Result<()> {
        let envelope = PulseEnvelope::new(event);

        match self.critical_tx.send_timeout(envelope, std::time::Duration::from_millis(500)).await {
            Ok(_) => Ok(()),
            Err(e) => {
                let drops = self.dropped_critical.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(
                    target: "pie::bus",
                    "CRITICAL EVENT DROPPED (Total drops: {}): {}",
                    drops,
                    e
                );
                Err(anyhow!("Failed to send critical event to PIE bus: {}", e))
            }
        }
    }

    /// Intenta emitir un evento crítico de manera inmediata (no bloqueante / síncrona).
    /// Útil en contextos donde no se puede pausar un worker o bucle de renderizado.
    pub fn try_emit_critical(&self, event: PulseCriticalEvent) -> Result<()> {
        let envelope = PulseEnvelope::new(event);

        match self.critical_tx.try_send(envelope) {
            Ok(_) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                let drops = self.dropped_critical.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(
                    target: "pie::bus",
                    "CRITICAL EVENT DROPPED DUE TO FULL BUFFER (Total drops: {})",
                    drops
                );
                Err(anyhow!("Critical event buffer full"))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(anyhow!("Critical event channel closed"))
            }
        }
    }

    /// Emite telemetría periódica descartable (lossy).
    /// Si ningún consumidor está suscrito o si los consumidores van retrasados,
    /// los eventos se descartan de forma natural sin bloquear el emisor.
    pub fn emit_telemetry(&self, event: TelemetryEvent) {
        if let Err(broadcast::error::SendError(_)) = self.telemetry_tx.send(event) {
            // No hay receptores activos en este instante (comportamiento esperado al iniciar)
            self.dropped_telemetry.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Permite a cualquier módulo o pestaña UI suscribirse a la telemetría en tiempo real.
    pub fn subscribe_telemetry(&self) -> broadcast::Receiver<TelemetryEvent> {
        self.telemetry_tx.subscribe()
    }

    /// Obtiene las métricas acumuladas de eventos descartados.
    pub fn metrics(&self) -> EventBusMetrics {
        EventBusMetrics {
            dropped_critical: self.dropped_critical.load(Ordering::Relaxed),
            dropped_telemetry: self.dropped_telemetry.load(Ordering::Relaxed),
        }
    }
}
