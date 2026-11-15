use crate::modules::network_guardian::models::NetworkInterfaceInfo;
use anyhow::{Context, Result};
use std::net::Ipv4Addr;

#[cfg(target_os = "windows")]
pub fn get_network_interfaces() -> Result<Vec<NetworkInterfaceInfo>> {
    use windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN,
    };

    let flags = GAA_FLAG_INCLUDE_GATEWAYS;
    let mut buffer_size: u32 = 16384;
    let mut buffer = vec![0u8; buffer_size as usize];

    unsafe {
        let mut ret = GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
            flags,
            None,
            Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
            &mut buffer_size,
        );

        if ret == ERROR_BUFFER_OVERFLOW.0 {
            buffer = vec![0u8; buffer_size as usize];
            ret = GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                flags,
                None,
                Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut buffer_size,
            );
        }

        if ret != 0 {
            anyhow::bail!("GetAdaptersAddresses failed with Win32 error code: {}", ret);
        }

        let mut interfaces = Vec::new();
        let mut current_ptr = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;

        while !current_ptr.is_null() {
            let adapter = &*current_ptr;

            let name = adapter.AdapterName.to_string().unwrap_or_default();
            let friendly_name = adapter.FriendlyName.to_string().unwrap_or_default();

            // Dirección física (MAC)
            let mac_address = if adapter.PhysicalAddressLength == 6 {
                let mac = &adapter.PhysicalAddress[..6];
                Some(format!(
                    "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                ))
            } else {
                None
            };

            let is_up = adapter.OperStatus.0 == 1; // IfOperStatusUp
            let is_loopback = adapter.IfType == 24; // IF_TYPE_SOFTWARE_LOOPBACK

            let description = adapter.Description.to_string().unwrap_or_default().to_lowercase();
            let friendly_lower = friendly_name.to_lowercase();
            let is_vpn_or_virtual = adapter.IfType == 23 // IF_TYPE_PPP
                || adapter.IfType == 53 // IF_TYPE_PROP_VIRTUAL
                || description.contains("vpn")
                || description.contains("virtual")
                || description.contains("tap")
                || description.contains("tun")
                || description.contains("wintun")
                || description.contains("wireguard")
                || description.contains("zerotier")
                || description.contains("tailscale")
                || description.contains("hyper-v")
                || description.contains("virtualbox")
                || description.contains("vmware")
                || friendly_lower.contains("vpn")
                || friendly_lower.contains("wireguard")
                || friendly_lower.contains("tailscale")
                || friendly_lower.contains("zerotier");

            let mut ipv4_addresses = Vec::new();
            let mut ipv6_addresses = Vec::new();
            let mut prefix_length: Option<u8> = None;

            // Direcciones Unicast asociadas
            let mut unicast_ptr = adapter.FirstUnicastAddress;
            while !unicast_ptr.is_null() {
                let unicast = &*unicast_ptr;
                let sockaddr = unicast.Address.lpSockaddr;
                if !sockaddr.is_null() {
                    let family = (*sockaddr).sa_family;
                    if family == AF_INET {
                        let sin = &*(sockaddr as *const SOCKADDR_IN);
                        let ip_be = sin.sin_addr.S_un.S_addr;
                        let ipv4 = Ipv4Addr::from(u32::from_be(ip_be));
                        ipv4_addresses.push(ipv4.to_string());
                        if prefix_length.is_none() && unicast.OnLinkPrefixLength > 0 && unicast.OnLinkPrefixLength <= 32 {
                            prefix_length = Some(unicast.OnLinkPrefixLength);
                        }
                    } else if family == AF_INET6 {
                        // Extraer IPv6 simplificado si se requiere
                        ipv6_addresses.push("IPv6".to_string());
                    }
                }
                unicast_ptr = unicast.Next;
            }

            // Puerta de enlace (Gateway IPv4)
            let mut gateway_ipv4 = None;
            let mut gw_ptr = adapter.FirstGatewayAddress;
            while !gw_ptr.is_null() {
                let gw = &*gw_ptr;
                let sockaddr = gw.Address.lpSockaddr;
                if !sockaddr.is_null() {
                    let family = (*sockaddr).sa_family;
                    if family == AF_INET {
                        let sin = &*(sockaddr as *const SOCKADDR_IN);
                        let ip_be = sin.sin_addr.S_un.S_addr;
                        let ipv4 = Ipv4Addr::from(u32::from_be(ip_be));
                        gateway_ipv4 = Some(ipv4.to_string());
                        break;
                    }
                }
                gw_ptr = gw.Next;
            }

            // Servidores DNS
            let mut dns_servers = Vec::new();
            let mut dns_ptr = adapter.FirstDnsServerAddress;
            while !dns_ptr.is_null() {
                let dns = &*dns_ptr;
                let sockaddr = dns.Address.lpSockaddr;
                if !sockaddr.is_null() {
                    let family = (*sockaddr).sa_family;
                    if family == AF_INET {
                        let sin = &*(sockaddr as *const SOCKADDR_IN);
                        let ip_be = sin.sin_addr.S_un.S_addr;
                        let ipv4 = Ipv4Addr::from(u32::from_be(ip_be));
                        dns_servers.push(ipv4.to_string());
                    }
                }
                dns_ptr = dns.Next;
            }

            interfaces.push(NetworkInterfaceInfo {
                id: name.clone(),
                name,
                friendly_name,
                mac_address,
                ipv4_addresses,
                ipv6_addresses,
                gateway_ipv4,
                dns_servers,
                is_up,
                is_loopback,
                prefix_length,
                is_vpn_or_virtual,
            });

            current_ptr = adapter.Next;
        }

        Ok(interfaces)
    }
}

#[cfg(not(target_os = "windows"))]
pub fn get_network_interfaces() -> Result<Vec<NetworkInterfaceInfo>> {
    Ok(vec![NetworkInterfaceInfo {
        id: "lo0".to_string(),
        name: "lo0".to_string(),
        friendly_name: "Loopback".to_string(),
        mac_address: None,
        ipv4_addresses: vec!["127.0.0.1".to_string()],
        ipv6_addresses: vec!["::1".to_string()],
        gateway_ipv4: None,
        dns_servers: Vec::new(),
        is_up: true,
        is_loopback: true,
        prefix_length: Some(8),
        is_vpn_or_virtual: false,
    }])
}

/// Identifica la interfaz de red principal activa (con Gateway y conectada).
/// Prioriza adaptadores físicos sobre VPN o interfaces virtuales.
pub fn get_primary_active_interface() -> Result<Option<NetworkInterfaceInfo>> {
    let interfaces = get_network_interfaces().context("Failed to list network interfaces")?;
    
    // 1. Intentar seleccionar interfaz física no virtual con Gateway
    let physical = interfaces.iter().find(|i| {
        i.is_up && !i.is_loopback && !i.is_vpn_or_virtual && i.gateway_ipv4.is_some() && !i.ipv4_addresses.is_empty()
    });
    if let Some(iface) = physical {
        return Ok(Some(iface.clone()));
    }

    // 2. Fallback: cualquier interfaz activa con Gateway
    for iface in interfaces {
        if iface.is_up && !iface.is_loopback && iface.gateway_ipv4.is_some() && !iface.ipv4_addresses.is_empty() {
            return Ok(Some(iface));
        }
    }
    Ok(None)
}

/// Calcula el rango IPv4 de hosts utilizables para una IP y un prefijo CIDR.
/// Retorna `(primera_ip_host, ultima_ip_host, total_hosts_en_subred)`.
pub fn calculate_subnet_range(ip: Ipv4Addr, prefix_len: u8) -> (Ipv4Addr, Ipv4Addr, u32) {
    if prefix_len == 0 || prefix_len > 32 {
        return (ip, ip, 1);
    }
    if prefix_len >= 31 {
        // Enlace punto a punto (RFC 3021)
        return (ip, ip, 2);
    }

    let mask = !((1u32 << (32 - prefix_len)) - 1);
    let ip_u32 = u32::from(ip);
    let net_u32 = ip_u32 & mask;
    let bcast_u32 = net_u32 | !mask;

    let first_host = Ipv4Addr::from(net_u32 + 1);
    let last_host = Ipv4Addr::from(bcast_u32 - 1);
    let total_hosts = (1u32 << (32 - prefix_len)) - 2;

    (first_host, last_host, total_hosts)
}
