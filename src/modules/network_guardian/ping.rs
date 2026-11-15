use crate::modules::network_guardian::models::{
    GatewayHealth, InternetHealth, NetworkHealthDiagnostics, PingSample,
};
use anyhow::Result;
use std::collections::VecDeque;
use std::net::Ipv4Addr;

const PING_WINDOW_SIZE: usize = 20;
const DEFAULT_TIMEOUT_MS: u32 = 1000;
const PUBLIC_DNS_PRIMARY: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const PUBLIC_DNS_SECONDARY: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);

#[cfg(target_os = "windows")]
pub fn ping_ipv4_native(ip: Ipv4Addr, timeout_ms: u32) -> PingSample {
    use std::ffi::c_void;
    use std::mem::size_of;
    use windows::Win32::NetworkManagement::IpHelper::{
        IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY,
    };

    let target_str = ip.to_string();

    unsafe {
        let handle = match IcmpCreateFile() {
            Ok(h) => h,
            Err(_) => {
                return PingSample {
                    target: target_str.clone(),
                    ip: target_str,
                    rtt_ms: None,
                    is_success: false,
                    status_code: 999, // Fallo al crear handle ICMP
                };
            }
        };

        // Convertir IPv4 a u32 en orden de red esperado por Win32
        let dest_u32 = u32::from_ne_bytes(ip.octets());
        let request_data = b"SysPulseNetworkGuardianPingData!";
        let reply_size = size_of::<ICMP_ECHO_REPLY>() + request_data.len() + 16;
        let mut reply_buffer = vec![0u8; reply_size];

        let ret = IcmpSendEcho(
            handle,
            dest_u32,
            request_data.as_ptr() as *const c_void,
            request_data.len() as u16,
            None,
            reply_buffer.as_mut_ptr() as *mut c_void,
            reply_size as u32,
            timeout_ms,
        );

        let _ = IcmpCloseHandle(handle);

        if ret > 0 {
            let reply = &*(reply_buffer.as_ptr() as *const ICMP_ECHO_REPLY);
            if reply.Status == 0 {
                // IP_SUCCESS
                return PingSample {
                    target: target_str.clone(),
                    ip: target_str,
                    rtt_ms: Some(reply.RoundTripTime as f32),
                    is_success: true,
                    status_code: 0,
                };
            } else {
                return PingSample {
                    target: target_str.clone(),
                    ip: target_str,
                    rtt_ms: None,
                    is_success: false,
                    status_code: reply.Status,
                };
            }
        }

        PingSample {
            target: target_str.clone(),
            ip: target_str,
            rtt_ms: None,
            is_success: false,
            status_code: 11010, // IP_REQ_TIMED_OUT
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn ping_ipv4_native(ip: Ipv4Addr, _timeout_ms: u32) -> PingSample {
    PingSample {
        target: ip.to_string(),
        ip: ip.to_string(),
        rtt_ms: Some(12.0),
        is_success: true,
        status_code: 0,
    }
}

/// Monitor de latencia, jitter y pérdida de paquetes con cálculo bajo RFC 3550.
pub struct PingMonitor {
    samples: VecDeque<PingSample>,
    last_rtt: Option<f32>,
    current_jitter: f32,
}

impl Default for PingMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl PingMonitor {
    pub fn new() -> Self {
        Self {
            samples: VecDeque::with_capacity(PING_WINDOW_SIZE),
            last_rtt: None,
            current_jitter: 0.0,
        }
    }

    /// Registra una nueva muestra y actualiza métricas de jitter y packet loss.
    pub fn record_sample(&mut self, sample: PingSample) {
        if let Some(rtt) = sample.rtt_ms {
            if let Some(prev_rtt) = self.last_rtt {
                // Cálculo de Jitter según RFC 3550:
                // D(i-1, i) = |RTT_i - RTT_{i-1}|
                // J_i = J_{i-1} + (|D| - J_{i-1}) / 16.0
                let delta = (rtt - prev_rtt).abs();
                self.current_jitter += (delta - self.current_jitter) / 16.0;
            }
            self.last_rtt = Some(rtt);
        }

        if self.samples.len() >= PING_WINDOW_SIZE {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    /// Calcula el porcentaje de pérdida de paquetes en la ventana actual.
    pub fn packet_loss_percent(&self) -> f32 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let lost_count = self.samples.iter().filter(|s| !s.is_success).count();
        (lost_count as f32 / self.samples.len() as f32) * 100.0
    }

    /// Retorna el porcentaje de pérdida de paquetes como Option; None si no hay muestras.
    pub fn packet_loss_percent_opt(&self) -> Option<f32> {
        if self.samples.is_empty() {
            None
        } else {
            let lost_count = self.samples.iter().filter(|s| !s.is_success).count();
            Some((lost_count as f32 / self.samples.len() as f32) * 100.0)
        }
    }

    pub fn jitter_ms(&self) -> f32 {
        self.current_jitter
    }

    /// Retorna el jitter calculado bajo RFC 3550; None si no hay al menos 2 paquetes exitosos.
    pub fn jitter_ms_opt(&self) -> Option<f32> {
        let successful_count = self.samples.iter().filter(|s| s.is_success && s.rtt_ms.is_some()).count();
        if successful_count >= 2 {
            Some(self.current_jitter)
        } else {
            None
        }
    }

    /// Realiza un sondeo diagnóstico integral diferenciando:
    /// 1. Falla en el router local.
    /// 2. Falla en el proveedor de internet (ISP).
    /// 3. Ausencia de respuesta ICMP (bloqueo por firewall/proveedor sin pérdida real de internet).
    pub async fn run_diagnostic(
        &mut self,
        gateway_ip: Option<Ipv4Addr>,
        adapter_name: Option<String>,
        local_ip: Option<String>,
    ) -> Result<NetworkHealthDiagnostics> {
        let mut gw_health = GatewayHealth::NoGatewayConfigured;
        let mut gw_rtt = None;

        // 1. Probar conectividad con el Gateway local
        if let Some(gw) = gateway_ip {
            let gw_sample = tokio::task::spawn_blocking(move || {
                ping_ipv4_native(gw, DEFAULT_TIMEOUT_MS)
            })
            .await?;

            if gw_sample.is_success {
                let rtt = gw_sample.rtt_ms.unwrap_or(1.0);
                gw_rtt = Some(rtt);
                if rtt > 100.0 {
                    gw_health = GatewayHealth::HighLatency;
                } else {
                    gw_health = GatewayHealth::Reachable;
                }
            } else {
                gw_health = GatewayHealth::Unreachable;
            }
        }

        // 2. Probar conectividad con DNS primario (1.1.1.1)
        let primary_sample = tokio::task::spawn_blocking(move || {
            ping_ipv4_native(PUBLIC_DNS_PRIMARY, DEFAULT_TIMEOUT_MS)
        })
        .await?;

        // 3. Probar DNS secundario (8.8.8.8) solo si el primario no respondió
        let internet_sample = if primary_sample.is_success {
            primary_sample
        } else {
            tokio::task::spawn_blocking(move || {
                ping_ipv4_native(PUBLIC_DNS_SECONDARY, DEFAULT_TIMEOUT_MS)
            })
            .await?
        };

        let internet_rtt = internet_sample.rtt_ms;
        self.record_sample(internet_sample.clone());

        // 4. Determinar estado de Internet diferenciando causas
        let internet_health = match (gw_health, internet_sample.is_success) {
            (GatewayHealth::Unreachable, _) => {
                // Router no responde: problema local
                InternetHealth::Disconnected
            }
            (GatewayHealth::Reachable | GatewayHealth::HighLatency, true) => {
                if let Some(rtt) = internet_rtt {
                    if rtt > 180.0 || self.packet_loss_percent() > 15.0 {
                        InternetHealth::Degraded
                    } else {
                        InternetHealth::Connected
                    }
                } else {
                    InternetHealth::Connected
                }
            }
            (GatewayHealth::Reachable | GatewayHealth::HighLatency, false) => {
                // El router local responde perfectamente, pero el ping ICMP a 1.1.1.1 y 8.8.8.8 falló.
                // Verificación TCP ligera al puerto 53 para diferenciar filtrado ICMP de desconexión WAN real.
                let tcp_ok = match tokio::time::timeout(
                    std::time::Duration::from_millis(500),
                    tokio::net::TcpStream::connect("1.1.1.1:53"),
                ).await {
                    Ok(Ok(_stream)) => true,
                    _ => matches!(
                        tokio::time::timeout(
                            std::time::Duration::from_millis(500),
                            tokio::net::TcpStream::connect("8.8.8.8:53"),
                        ).await,
                        Ok(Ok(_stream))
                    ),
                };

                if tcp_ok {
                    InternetHealth::IcmpFiltered
                } else {
                    InternetHealth::Disconnected
                }
            }
            (GatewayHealth::NoGatewayConfigured, false) => InternetHealth::Disconnected,
            (GatewayHealth::NoGatewayConfigured, true) => InternetHealth::Connected,
        };

        // 5. Generar diagnóstico para Modo Simple (lenguaje cotidiano) y Modo Avanzado
        let (simple_title, simple_desc, simple_rec) = match internet_health {
            InternetHealth::Connected => (
                "Tu conexión a internet funciona correctamente".to_string(),
                format!(
                    "Estás conectado a través de '{}'. La señal y la respuesta son estables.",
                    adapter_name.as_deref().unwrap_or("tu adaptador de red")
                ),
                "No se requieren acciones. Tu red está optimizada.".to_string(),
            ),
            InternetHealth::Degraded => (
                "Tu conexión está experimentando lentitud o cortes".to_string(),
                format!(
                    "La latencia hacia internet es elevada ({:.0} ms) con {:.1}% de pérdida de datos.",
                    internet_rtt.unwrap_or(0.0),
                    self.packet_loss_percent()
                ),
                "Si estás usando Wi-Fi, acércate al router o evita descargas pesadas en segundo plano.".to_string(),
            ),
            InternetHealth::Disconnected => (
                "No tienes conexión con tu router o red local".to_string(),
                "Tu equipo no puede comunicarse con la puerta de enlace. Es posible que el Wi-Fi esté desactivado o el cable desconectado.".to_string(),
                "Comprueba que el router esté encendido y que el cable o la señal Wi-Fi estén conectados.".to_string(),
            ),
            InternetHealth::IcmpFiltered => (
                "Conexión con el router activa; salida externa no verificable por ICMP".to_string(),
                "Tu equipo se comunica con tu router sin problemas, pero los servidores de prueba no respondieron a la señal de ping.".to_string(),
                "Si puedes navegar normalmente, tu proveedor de internet podría tener bloqueado el tráfico de diagnóstico (ICMP).".to_string(),
            ),
            InternetHealth::Unknown => (
                "Verificando estado de red...".to_string(),
                "Analizando adaptadores y respuesta de la conexión.".to_string(),
                "Espera unos segundos mientras finaliza la comprobación.".to_string(),
            ),
        };

        let technical_summary = format!(
            "Adapter: {} | Local: {} | Gateway: {:?} ({:?}) | Internet: {:?} ({:.1} ms) | Jitter: {:.2} ms | Loss: {:.1}%",
            adapter_name.as_deref().unwrap_or("None"),
            local_ip.as_deref().unwrap_or("None"),
            gateway_ip,
            gw_health,
            internet_health,
            internet_rtt.unwrap_or(0.0),
            self.current_jitter,
            self.packet_loss_percent()
        );

        Ok(NetworkHealthDiagnostics {
            active_adapter_name: adapter_name,
            local_ip,
            gateway_ip: gateway_ip.map(|g| g.to_string()),
            gateway_health: gw_health,
            internet_health,
            gateway_rtt_ms: gw_rtt,
            internet_rtt_ms: internet_rtt,
            jitter_ms: self.current_jitter,
            packet_loss_percent: self.packet_loss_percent(),
            simple_status_title: simple_title,
            simple_description: simple_desc,
            simple_recommendation: simple_rec,
            technical_summary,
        })
    }
}
