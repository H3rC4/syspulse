use anyhow::{Context, Result};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(windows)]
use windows::Win32::Foundation::{BOOL, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
#[cfg(windows)]
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
    MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
    TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
#[cfg(windows)]
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

/// Protocolo de transporte de un socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SocketProtocol {
    Tcp,
    Udp,
}

impl SocketProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            SocketProtocol::Tcp => "TCP",
            SocketProtocol::Udp => "UDP",
        }
    }
}

/// Estado de una conexión TCP conforme a MIB-II / Win32.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    Unknown(u32),
}

impl TcpState {
    pub fn from_u32(state: u32) -> Self {
        match state {
            1 => TcpState::Closed,
            2 => TcpState::Listen,
            3 => TcpState::SynSent,
            4 => TcpState::SynReceived,
            5 => TcpState::Established,
            6 => TcpState::FinWait1,
            7 => TcpState::FinWait2,
            8 => TcpState::CloseWait,
            9 => TcpState::Closing,
            10 => TcpState::LastAck,
            11 => TcpState::TimeWait,
            12 => TcpState::DeleteTcb,
            other => TcpState::Unknown(other),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TcpState::Closed => "CLOSED",
            TcpState::Listen => "LISTEN",
            TcpState::SynSent => "SYN_SENT",
            TcpState::SynReceived => "SYN_RECEIVED",
            TcpState::Established => "ESTABLISHED",
            TcpState::FinWait1 => "FIN_WAIT_1",
            TcpState::FinWait2 => "FIN_WAIT_2",
            TcpState::CloseWait => "CLOSE_WAIT",
            TcpState::Closing => "CLOSING",
            TcpState::LastAck => "LAST_ACK",
            TcpState::TimeWait => "TIME_WAIT",
            TcpState::DeleteTcb => "DELETE_TCB",
            TcpState::Unknown(_) => "UNKNOWN",
        }
    }
}

/// Registro crudo de un socket leído desde la API nativa del kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSocketEntry {
    pub protocol: SocketProtocol,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub tcp_state: Option<TcpState>,
    pub pid: u32,
}

/// Metadatos conocidos de un proceso vivo en el sistema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveProcessMeta {
    pub name: String,
    pub executable_path: Option<String>,
    pub start_time_utc: Option<u64>,
}

/// Socket correlacionado con información de proceso de Process Hunter / Sistema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelatedSocket {
    pub protocol: SocketProtocol,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub tcp_state: Option<TcpState>,
    pub pid: u32,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub is_process_alive: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Decodificadores de bajo nivel (puros y testeables sin I/O ni privilegios)
// ─────────────────────────────────────────────────────────────────────────────

/// Decodifica el puerto Win32 (DWORD con los 2 primeros bytes en network byte order).
pub fn decode_port(dw_port: u32) -> u16 {
    let ne_bytes = dw_port.to_ne_bytes();
    u16::from_be_bytes([ne_bytes[0], ne_bytes[1]])
}

/// Decodifica la dirección IPv4 Win32 (in_addr en network byte order en memoria).
pub fn decode_ipv4_addr(dw_addr: u32) -> Ipv4Addr {
    let ne_bytes = dw_addr.to_ne_bytes();
    Ipv4Addr::new(ne_bytes[0], ne_bytes[1], ne_bytes[2], ne_bytes[3])
}

/// Decodifica la dirección IPv6 Win32 (16 bytes en network order).
pub fn decode_ipv6_addr(bytes: [u8; 16]) -> Ipv6Addr {
    Ipv6Addr::from(bytes)
}

#[cfg(windows)]
pub fn parse_tcp4_row(row: &MIB_TCPROW_OWNER_PID) -> RawSocketEntry {
    let local_addr = IpAddr::V4(decode_ipv4_addr(row.dwLocalAddr));
    let local_port = decode_port(row.dwLocalPort);
    let state = TcpState::from_u32(row.dwState);

    let (remote_addr, remote_port) = if state == TcpState::Listen || row.dwRemoteAddr == 0 {
        (None, None)
    } else {
        (
            Some(IpAddr::V4(decode_ipv4_addr(row.dwRemoteAddr))),
            Some(decode_port(row.dwRemotePort)),
        )
    };

    RawSocketEntry {
        protocol: SocketProtocol::Tcp,
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        tcp_state: Some(state),
        pid: row.dwOwningPid,
    }
}

#[cfg(windows)]
pub fn parse_tcp6_row(row: &MIB_TCP6ROW_OWNER_PID) -> RawSocketEntry {
    let local_addr = IpAddr::V6(decode_ipv6_addr(row.ucLocalAddr));
    let local_port = decode_port(row.dwLocalPort);
    let state = TcpState::from_u32(row.dwState);
    let is_remote_unspecified = row.ucRemoteAddr.iter().all(|&b| b == 0);

    let (remote_addr, remote_port) = if state == TcpState::Listen || is_remote_unspecified {
        (None, None)
    } else {
        (
            Some(IpAddr::V6(decode_ipv6_addr(row.ucRemoteAddr))),
            Some(decode_port(row.dwRemotePort)),
        )
    };

    RawSocketEntry {
        protocol: SocketProtocol::Tcp,
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        tcp_state: Some(state),
        pid: row.dwOwningPid,
    }
}

#[cfg(windows)]
pub fn parse_udp4_row(row: &MIB_UDPROW_OWNER_PID) -> RawSocketEntry {
    RawSocketEntry {
        protocol: SocketProtocol::Udp,
        local_addr: IpAddr::V4(decode_ipv4_addr(row.dwLocalAddr)),
        local_port: decode_port(row.dwLocalPort),
        remote_addr: None,
        remote_port: None,
        tcp_state: None,
        pid: row.dwOwningPid,
    }
}

#[cfg(windows)]
pub fn parse_udp6_row(row: &MIB_UDP6ROW_OWNER_PID) -> RawSocketEntry {
    RawSocketEntry {
        protocol: SocketProtocol::Udp,
        local_addr: IpAddr::V6(decode_ipv6_addr(row.ucLocalAddr)),
        local_port: decode_port(row.dwLocalPort),
        remote_addr: None,
        remote_port: None,
        tcp_state: None,
        pid: row.dwOwningPid,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Correlación lógica con procesos
// ─────────────────────────────────────────────────────────────────────────────

/// Correlaciona registros crudos con metadatos de procesos en memoria e historial SQLite.
pub fn correlate_sockets_with_processes(
    raw_sockets: Vec<RawSocketEntry>,
    live_processes: &HashMap<u32, LiveProcessMeta>,
    db_history: Option<&HashMap<u32, (String, Option<String>)>>,
) -> Vec<CorrelatedSocket> {
    raw_sockets
        .into_iter()
        .map(|raw| {
            let pid = raw.pid;

            let (process_name, process_path, is_alive) = if let Some(live) = live_processes.get(&pid) {
                (Some(live.name.clone()), live.executable_path.clone(), true)
            } else if let Some(history) = db_history.and_then(|h| h.get(&pid)) {
                // Proceso que cerró o finalizó recientemente registrado en Process Hunter
                (Some(history.0.clone()), history.1.clone(), false)
            } else {
                // No inventar nombres si no están disponibles o acceso denegado
                (None, None, false)
            };

            CorrelatedSocket {
                protocol: raw.protocol,
                local_addr: raw.local_addr,
                local_port: raw.local_port,
                remote_addr: raw.remote_addr,
                remote_port: raw.remote_port,
                tcp_state: raw.tcp_state,
                pid,
                process_name,
                process_path,
                is_process_alive: is_alive,
            }
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Colector Asíncrono de Sockets
// ─────────────────────────────────────────────────────────────────────────────

pub struct SocketCorrelator {
    db: Option<Arc<Mutex<Connection>>>,
}

impl Default for SocketCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

impl SocketCorrelator {
    pub fn new() -> Self {
        Self { db: None }
    }

    pub fn new_with_db(db: Arc<Mutex<Connection>>) -> Self {
        Self { db: Some(db) }
    }

    /// Recolecta todos los sockets TCP y UDP del sistema y los correlaciona
    /// asíncronamente con los procesos de Process Hunter y el sistema.
    pub async fn collect_correlated_sockets(&self) -> Result<Vec<CorrelatedSocket>> {
        let db_opt = self.db.clone();

        tokio::task::spawn_blocking(move || {
            // 1. Recolección nativa de sockets crudos
            let raw_sockets = Self::collect_native_sockets()?;

            // 2. Obtener mapa de procesos vivos del sistema
            let live_processes = Self::query_live_processes();

            // 3. Obtener PIDs que no están vivos para buscar en histórico SQLite
            let missing_pids: Vec<u32> = raw_sockets
                .iter()
                .map(|s| s.pid)
                .filter(|pid| *pid > 0 && !live_processes.contains_key(pid))
                .collect();

            let history_map = if !missing_pids.is_empty() {
                if let Some(db_lock) = db_opt {
                    let conn = db_lock.blocking_lock();
                    Self::query_db_process_history(&conn, &missing_pids)
                } else {
                    HashMap::new()
                }
            } else {
                HashMap::new()
            };

            // 4. Correlación determinista
            let correlated = correlate_sockets_with_processes(
                raw_sockets,
                &live_processes,
                Some(&history_map),
            );

            Ok(correlated)
        })
        .await
        .context("Socket correlator worker task panicked")?
    }

    /// Consulta procesos vivos del sistema con sysinfo de forma acotada y segura.
    fn query_live_processes() -> HashMap<u32, LiveProcessMeta> {
        use sysinfo::{ProcessRefreshKind, System};
        let mut sys = System::new();
        sys.refresh_processes_specifics(ProcessRefreshKind::new().with_exe(sysinfo::UpdateKind::OnlyIfNotSet));

        let mut map = HashMap::new();
        for (pid, proc_) in sys.processes() {
            let pid_u32 = pid.as_u32();
            let name = proc_.name().to_string();
            let exe = proc_.exe().map(|p| p.to_string_lossy().to_string());
            let start_time_utc = crate::modules::pie::get_process_identity(pid_u32)
                .map(|id| id.start_time_utc);

            map.insert(
                pid_u32,
                LiveProcessMeta {
                    name,
                    executable_path: exe,
                    start_time_utc,
                },
            );
        }
        map
    }

    /// Consulta el histórico SQLite de Process Hunter para PIDs no activos.
    fn query_db_process_history(
        conn: &Connection,
        pids: &[u32],
    ) -> HashMap<u32, (String, Option<String>)> {
        let mut map = HashMap::new();
        if pids.is_empty() {
            return map;
        }

        let mut stmt = match conn.prepare(
            "SELECT name, executable_path FROM process_events
             WHERE pid = ?1
             ORDER BY timestamp DESC
             LIMIT 1",
        ) {
            Ok(s) => s,
            Err(_) => return map,
        };

        for &pid in pids {
            if let Ok((name, exe)) = stmt.query_row([pid], |row| {
                let name: String = row.get(0)?;
                let exe: Option<String> = row.get(1).ok();
                Ok((name, exe))
            }) {
                map.insert(pid, (name, exe));
            }
        }

        map
    }

    /// Recolección nativa Win32 mediante GetExtendedTcpTable y GetExtendedUdpTable.
    #[cfg(windows)]
    fn collect_native_sockets() -> Result<Vec<RawSocketEntry>> {
        let mut results = Vec::new();

        // 1. TCP IPv4
        if let Ok(mut entries) = Self::collect_tcp_ipv4() {
            results.append(&mut entries);
        }

        // 2. TCP IPv6
        if let Ok(mut entries) = Self::collect_tcp_ipv6() {
            results.append(&mut entries);
        }

        // 3. UDP IPv4
        if let Ok(mut entries) = Self::collect_udp_ipv4() {
            results.append(&mut entries);
        }

        // 4. UDP IPv6
        if let Ok(mut entries) = Self::collect_udp_ipv6() {
            results.append(&mut entries);
        }

        Ok(results)
    }

    #[cfg(not(windows))]
    fn collect_native_sockets() -> Result<Vec<RawSocketEntry>> {
        Ok(Vec::new())
    }

    #[cfg(windows)]
    fn collect_tcp_ipv4() -> Result<Vec<RawSocketEntry>> {
        let mut dw_size: u32 = 0;
        let mut retries = 0;

        // Primer llamado para obtener tamaño requerido
        unsafe {
            let _ = GetExtendedTcpTable(
                None,
                &mut dw_size,
                BOOL::from(true),
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        }

        while retries < 3 && dw_size > 0 {
            let mut buffer = vec![0u8; dw_size as usize];
            let res = unsafe {
                GetExtendedTcpTable(
                    Some(buffer.as_mut_ptr() as *mut _),
                    &mut dw_size,
                    BOOL::from(true),
                    AF_INET.0 as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };

            if res == NO_ERROR.0 {
                let table_ptr = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
                let num_entries = unsafe { (*table_ptr).dwNumEntries as usize };
                let header_size = std::mem::size_of::<u32>();
                let row_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();

                if header_size + num_entries * row_size > buffer.len() {
                    return Ok(Vec::new());
                }

                let first_row = unsafe { std::ptr::addr_of!((*table_ptr).table) as *const MIB_TCPROW_OWNER_PID };
                let mut entries = Vec::with_capacity(num_entries);

                for i in 0..num_entries {
                    let row = unsafe { &*first_row.add(i) };
                    entries.push(parse_tcp4_row(row));
                }

                return Ok(entries);
            } else if res == ERROR_INSUFFICIENT_BUFFER.0 {
                retries += 1;
            } else {
                break;
            }
        }

        Ok(Vec::new())
    }

    #[cfg(windows)]
    fn collect_tcp_ipv6() -> Result<Vec<RawSocketEntry>> {
        let mut dw_size: u32 = 0;
        let mut retries = 0;

        unsafe {
            let _ = GetExtendedTcpTable(
                None,
                &mut dw_size,
                BOOL::from(true),
                AF_INET6.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        }

        while retries < 3 && dw_size > 0 {
            let mut buffer = vec![0u8; dw_size as usize];
            let res = unsafe {
                GetExtendedTcpTable(
                    Some(buffer.as_mut_ptr() as *mut _),
                    &mut dw_size,
                    BOOL::from(true),
                    AF_INET6.0 as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };

            if res == NO_ERROR.0 {
                let table_ptr = buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
                let num_entries = unsafe { (*table_ptr).dwNumEntries as usize };
                let header_size = std::mem::size_of::<u32>();
                let row_size = std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>();

                if header_size + num_entries * row_size > buffer.len() {
                    return Ok(Vec::new());
                }

                let first_row = unsafe { std::ptr::addr_of!((*table_ptr).table) as *const MIB_TCP6ROW_OWNER_PID };
                let mut entries = Vec::with_capacity(num_entries);

                for i in 0..num_entries {
                    let row = unsafe { &*first_row.add(i) };
                    entries.push(parse_tcp6_row(row));
                }

                return Ok(entries);
            } else if res == ERROR_INSUFFICIENT_BUFFER.0 {
                retries += 1;
            } else {
                break;
            }
        }

        Ok(Vec::new())
    }

    #[cfg(windows)]
    fn collect_udp_ipv4() -> Result<Vec<RawSocketEntry>> {
        let mut dw_size: u32 = 0;
        let mut retries = 0;

        unsafe {
            let _ = GetExtendedUdpTable(
                None,
                &mut dw_size,
                BOOL::from(true),
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
        }

        while retries < 3 && dw_size > 0 {
            let mut buffer = vec![0u8; dw_size as usize];
            let res = unsafe {
                GetExtendedUdpTable(
                    Some(buffer.as_mut_ptr() as *mut _),
                    &mut dw_size,
                    BOOL::from(true),
                    AF_INET.0 as u32,
                    UDP_TABLE_OWNER_PID,
                    0,
                )
            };

            if res == NO_ERROR.0 {
                let table_ptr = buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
                let num_entries = unsafe { (*table_ptr).dwNumEntries as usize };
                let header_size = std::mem::size_of::<u32>();
                let row_size = std::mem::size_of::<MIB_UDPROW_OWNER_PID>();

                if header_size + num_entries * row_size > buffer.len() {
                    return Ok(Vec::new());
                }

                let first_row = unsafe { std::ptr::addr_of!((*table_ptr).table) as *const MIB_UDPROW_OWNER_PID };
                let mut entries = Vec::with_capacity(num_entries);

                for i in 0..num_entries {
                    let row = unsafe { &*first_row.add(i) };
                    entries.push(parse_udp4_row(row));
                }

                return Ok(entries);
            } else if res == ERROR_INSUFFICIENT_BUFFER.0 {
                retries += 1;
            } else {
                break;
            }
        }

        Ok(Vec::new())
    }

    #[cfg(windows)]
    fn collect_udp_ipv6() -> Result<Vec<RawSocketEntry>> {
        let mut dw_size: u32 = 0;
        let mut retries = 0;

        unsafe {
            let _ = GetExtendedUdpTable(
                None,
                &mut dw_size,
                BOOL::from(true),
                AF_INET6.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );
        }

        while retries < 3 && dw_size > 0 {
            let mut buffer = vec![0u8; dw_size as usize];
            let res = unsafe {
                GetExtendedUdpTable(
                    Some(buffer.as_mut_ptr() as *mut _),
                    &mut dw_size,
                    BOOL::from(true),
                    AF_INET6.0 as u32,
                    UDP_TABLE_OWNER_PID,
                    0,
                )
            };

            if res == NO_ERROR.0 {
                let table_ptr = buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID;
                let num_entries = unsafe { (*table_ptr).dwNumEntries as usize };
                let header_size = std::mem::size_of::<u32>();
                let row_size = std::mem::size_of::<MIB_UDP6ROW_OWNER_PID>();

                if header_size + num_entries * row_size > buffer.len() {
                    return Ok(Vec::new());
                }

                let first_row = unsafe { std::ptr::addr_of!((*table_ptr).table) as *const MIB_UDP6ROW_OWNER_PID };
                let mut entries = Vec::with_capacity(num_entries);

                for i in 0..num_entries {
                    let row = unsafe { &*first_row.add(i) };
                    entries.push(parse_udp6_row(row));
                }

                return Ok(entries);
            } else if res == ERROR_INSUFFICIENT_BUFFER.0 {
                retries += 1;
            } else {
                break;
            }
        }

        Ok(Vec::new())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pruebas Unitarias Focalizadas y Offline
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_port_and_ipv4() {
        // En Windows x86, el puerto 80 (0x0050) en network byte order tiene bytes [0x00, 0x50, 0x00, 0x00]
        let dw_port: u32 = 0x5000;
        assert_eq!(decode_port(dw_port), 80);

        // Puerto 443 (0x01BB) en network order tiene bytes [0x01, 0xBB, 0x00, 0x00] -> dw_port = 0xBB01
        let dw_port_https: u32 = 0xBB01;
        assert_eq!(decode_port(dw_port_https), 443);

        // Puerto 8080 (0x1F90) -> bytes [0x1F, 0x90] -> dw_port = 0x901F
        let dw_port_alt: u32 = 0x901F;
        assert_eq!(decode_port(dw_port_alt), 8080);

        // IP 127.0.0.1 -> bytes [127, 0, 0, 1] -> u32 = 0x0100007F en LE
        let dw_addr: u32 = u32::from_ne_bytes([127, 0, 0, 1]);
        assert_eq!(decode_ipv4_addr(dw_addr), Ipv4Addr::new(127, 0, 0, 1));

        // IP 192.168.1.100 -> bytes [192, 168, 1, 100]
        let dw_addr_lan: u32 = u32::from_ne_bytes([192, 168, 1, 100]);
        assert_eq!(decode_ipv4_addr(dw_addr_lan), Ipv4Addr::new(192, 168, 1, 100));
    }

    #[test]
    fn test_tcp_state_mappings() {
        assert_eq!(TcpState::from_u32(1), TcpState::Closed);
        assert_eq!(TcpState::from_u32(2), TcpState::Listen);
        assert_eq!(TcpState::from_u32(5), TcpState::Established);
        assert_eq!(TcpState::from_u32(11), TcpState::TimeWait);
        assert_eq!(TcpState::from_u32(99), TcpState::Unknown(99));

        assert_eq!(TcpState::Established.as_str(), "ESTABLISHED");
        assert_eq!(TcpState::Listen.as_str(), "LISTEN");
        assert_eq!(TcpState::Unknown(99).as_str(), "UNKNOWN");
    }

    #[test]
    fn test_correlate_sockets_live_and_exited_processes() {
        let raw = vec![
            RawSocketEntry {
                protocol: SocketProtocol::Tcp,
                local_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                local_port: 8080,
                remote_addr: None,
                remote_port: None,
                tcp_state: Some(TcpState::Listen),
                pid: 1001,
            },
            RawSocketEntry {
                protocol: SocketProtocol::Tcp,
                local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
                local_port: 54321,
                remote_addr: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
                remote_port: Some(443),
                tcp_state: Some(TcpState::Established),
                pid: 2002,
            },
            RawSocketEntry {
                protocol: SocketProtocol::Udp,
                local_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                local_port: 5353,
                remote_addr: None,
                remote_port: None,
                tcp_state: None,
                pid: 9999, // PID no registrado ni vivo
            },
        ];

        let mut live = HashMap::new();
        live.insert(
            1001,
            LiveProcessMeta {
                name: "webserver.exe".to_string(),
                executable_path: Some("C:\\web\\webserver.exe".to_string()),
                start_time_utc: Some(1700000000),
            },
        );

        let mut db_history = HashMap::new();
        db_history.insert(
            2002,
            ("curl.exe".to_string(), Some("C:\\Windows\\System32\\curl.exe".to_string())),
        );

        let correlated = correlate_sockets_with_processes(raw, &live, Some(&db_history));
        assert_eq!(correlated.len(), 3);

        // 1. Proceso vivo
        assert_eq!(correlated[0].pid, 1001);
        assert_eq!(correlated[0].process_name.as_deref(), Some("webserver.exe"));
        assert_eq!(correlated[0].process_path.as_deref(), Some("C:\\web\\webserver.exe"));
        assert!(correlated[0].is_process_alive);
        assert_eq!(correlated[0].tcp_state, Some(TcpState::Listen));

        // 2. Proceso que cerró / finalizó (recuperado de histórico)
        assert_eq!(correlated[1].pid, 2002);
        assert_eq!(correlated[1].process_name.as_deref(), Some("curl.exe"));
        assert_eq!(correlated[1].process_path.as_deref(), Some("C:\\Windows\\System32\\curl.exe"));
        assert!(!correlated[1].is_process_alive);
        assert_eq!(correlated[1].tcp_state, Some(TcpState::Established));

        // 3. Proceso desconocido / sin metadatos (nunca inventar nombres)
        assert_eq!(correlated[2].pid, 9999);
        assert_eq!(correlated[2].process_name, None);
        assert_eq!(correlated[2].process_path, None);
        assert!(!correlated[2].is_process_alive);
        assert_eq!(correlated[2].protocol, SocketProtocol::Udp);
        assert_eq!(correlated[2].tcp_state, None);
    }

    #[test]
    fn test_correlate_with_sqlite_empty_and_populated() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "CREATE TABLE process_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                pid INTEGER NOT NULL,
                parent_pid INTEGER,
                name TEXT NOT NULL,
                executable_path TEXT NOT NULL,
                command_line TEXT NOT NULL,
                lifetime_seconds INTEGER
            )",
            [],
        ).unwrap();

        // 1. Vacío
        let history_empty = SocketCorrelator::query_db_process_history(&conn, &[555]);
        assert!(history_empty.is_empty());

        // 2. Con evento persistido
        conn.execute(
            "INSERT INTO process_events (timestamp, pid, parent_pid, name, executable_path, command_line, lifetime_seconds)
             VALUES ('2026-11-21T10:00:00Z', 555, 1, 'transient_worker.exe', 'C:\\bin\\worker.exe', 'worker.exe --arg', 2)",
            [],
        ).unwrap();

        let history_found = SocketCorrelator::query_db_process_history(&conn, &[555, 999]);
        assert_eq!(history_found.len(), 1);
        let (name, exe) = history_found.get(&555).unwrap();
        assert_eq!(name, "transient_worker.exe");
        assert_eq!(exe.as_deref(), Some("C:\\bin\\worker.exe"));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn test_native_socket_collection_runs_without_uac() {
        let correlator = SocketCorrelator::new();
        let sockets = correlator.collect_correlated_sockets().await.expect("Failed to collect sockets");

        // En cualquier sistema Windows en ejecución, existen sockets abiertos (ej. RPC, DNS, System, etc.)
        assert!(!sockets.is_empty(), "Should detect at least some active TCP or UDP sockets");

        for s in &sockets {
            // Verificar invariantes fundamentales
            if s.protocol == SocketProtocol::Udp {
                assert!(s.tcp_state.is_none());
            }
            if s.tcp_state == Some(TcpState::Listen) {
                assert!(s.remote_addr.is_none());
                assert!(s.remote_port.is_none());
            }
            // Si el nombre no está disponible, debe ser None (nunca inventado)
            if let Some(name) = &s.process_name {
                assert!(!name.is_empty());
            }
        }
    }
}
