//! Base de datos OUI (Organizationally Unique Identifier) estática y offline
//! para identificar fabricantes de adaptadores de red a partir de la dirección MAC.
//!
//! **Fuente y Términos de Redistribución:**
//! Los datos provienen del registro público oficial de la IEEE (*IEEE Standards Association Public OUI Registry*,
//! disponible en https://standards-oui.ieee.org/). Los prefijos OUI son asignaciones técnicas de dominio público
//! para interoperabilidad de protocolos de enlace IEEE 802. No contienen código con copyright ni datos privados.

/// Determina si una dirección MAC es Administrada Localmente (LAA) conforme al estándar IEEE 802.
/// El bit 1 del octeto inicial (0x02) indica que no proviene de una asignación universal IEEE OUI,
/// sino que fue generada localmente (por ejemplo, direcciones privadas Wi-Fi de Android/iOS/Windows,
/// adaptadores virtuales de Hyper-V/Docker/VirtualBox o túneles VPN).
pub fn is_locally_administered(mac: &str) -> bool {
    let clean_mac = mac.trim().replace('-', ":");
    if let Some(first_part) = clean_mac.split(':').next() {
        if let Ok(byte0) = u8::from_str_radix(first_part, 16) {
            return (byte0 & 0x02) != 0;
        }
    }
    false
}

/// Busca el fabricante asociado a una dirección MAC (formato `XX:XX:XX:...`).
pub fn lookup_vendor(mac: &str) -> Option<&'static str> {
    let clean_mac = mac.trim().replace('-', ":").to_ascii_uppercase();
    let parts: Vec<&str> = clean_mac.split(':').collect();
    if parts.len() < 3 {
        return None;
    }

    // Detección de Dirección Administrada Localmente (LAA - Locally Administered Address)
    if is_locally_administered(&clean_mac) {
        return Some("Dirección Administrada Localmente (LAA: Virtual, VPN o Privada)");
    }

    let prefix = format!("{}:{}:{}", parts[0], parts[1], parts[2]);

    match prefix.as_str() {
        // ── Apple ──
        "00:17:F2" | "00:1E:C2" | "00:23:12" | "00:25:00" | "00:26:08" | "3C:07:54"
        | "3C:D9:2B" | "48:D7:05" | "50:BC:96" | "60:F8:1D" | "70:EC:E4" | "88:66:5A"
        | "A4:83:E7" | "AC:BC:32" | "BC:D1:D3" | "F0:18:98" | "F4:F1:5A" | "DC:A9:04"
        | "A8:60:B6" | "14:7D:DA" | "00:F4:8D" | "78:4F:43" | "8C:85:90" | "B0:34:95" => {
            Some("Apple")
        }

        // ── Samsung ──
        "00:07:AB" | "00:12:47" | "00:16:6C" | "00:23:D7" | "08:08:C2" | "14:49:E0"
        | "24:4B:03" | "30:07:4D" | "40:4E:36" | "50:85:69" | "84:25:19" | "94:35:0A"
        | "A0:0B:BA" | "BC:72:B9" | "CC:07:AB" | "F4:09:D8" | "5C:A3:9D" | "78:40:E4" => {
            Some("Samsung Electronics")
        }

        // ── Intel ──
        "00:02:B3" | "00:03:47" | "00:04:23" | "00:0E:0C" | "00:13:02" | "00:15:00"
        | "00:1B:21" | "00:1E:67" | "34:13:E8" | "48:51:B7" | "68:05:CA" | "80:86:F2"
        | "8C:EC:4B" | "A4:4C:C8" | "C8:5B:76" | "E8:D8:D1" | "F8:63:3F" => {
            Some("Intel")
        }

        // ── TP-Link ──
        "00:0A:EB" | "00:14:78" | "00:1D:0F" | "00:21:27" | "00:23:CD" | "00:25:86"
        | "14:CC:20" | "1C:3B:F3" | "30:DE:4B" | "50:C7:BF" | "60:32:B1" | "74:05:A5"
        | "84:16:F9" | "98:DA:C4" | "A4:2B:B0" | "C0:25:E9" | "E8:48:B8" | "F4:F2:6D" => {
            Some("TP-Link Technologies")
        }

        // ── Xiaomi ──
        "00:9E:C8" | "0C:98:38" | "18:59:36" | "28:6C:07" | "34:80:13" | "58:44:98"
        | "64:09:80" | "7C:49:EB" | "8C:DE:52" | "AC:C1:EE" | "C4:0B:CB" | "D4:97:0B"
        | "20:34:FB" | "50:64:2B" => Some("Xiaomi Communications"),

        // ── Espressif (Módulos IoT ESP8266 / ESP32) ──
        "18:FE:34" | "24:0A:C4" | "24:6F:28" | "2C:F4:32" | "30:AE:A4" | "3C:61:05"
        | "3C:71:BF" | "40:F5:20" | "48:3F:DA" | "48:55:19" | "5C:CF:7F" | "60:01:94"
        | "84:0D:8E" | "84:F3:EB" | "A4:CF:12" | "B4:E6:2D" | "C4:4F:33" | "DC:4F:22" => {
            Some("Espressif Inc (Dispositivo IoT)")
        }

        // ── Raspberry Pi ──
        "B8:27:EB" | "DC:A6:32" | "E4:5F:01" | "28:CD:C1" => Some("Raspberry Pi Foundation"),

        // ── Realtek ──
        "00:00:21" | "00:07:40" | "00:0E:2E" | "00:14:D1" | "00:18:E7" | "00:E0:4C"
        | "54:EE:75" | "8C:AE:4B" => Some("Realtek Semiconductor"),

        // ── Cisco / Linksys ──
        "00:00:0C" | "00:01:42" | "00:01:43" | "00:01:63" | "00:01:64" | "00:02:16"
        | "00:02:17" | "00:04:4D" | "00:06:52" | "00:11:20" | "00:18:BA" | "00:21:A0"
        | "00:22:55" | "00:24:14" | "00:25:45" | "C4:72:95" => Some("Cisco Systems / Linksys"),

        // ── Microsoft ──
        "00:03:FF" | "00:0D:3A" | "00:12:5A" | "00:15:5D" | "00:17:FA" | "00:1D:D8"
        | "00:22:48" | "00:25:AE" | "28:18:78" | "60:45:BD" | "7C:1E:52" | "98:5F:D3"
        | "DC:98:40" | "F8:8A:C5" => Some("Microsoft"),

        // ── Google ──
        "00:1A:11" | "3C:5A:B4" | "54:60:09" | "F4:F5:D8" | "F4:03:04" | "D8:A1:19"
        | "64:16:66" | "A4:77:33" => Some("Google"),

        // ── Amazon ──
        "00:FC:8B" | "18:74:2E" | "38:F7:3D" | "40:B4:CD" | "44:65:0D" | "68:37:E9"
        | "68:54:FD" | "74:75:48" | "84:D6:D0" | "AC:63:BE" | "B4:7C:9C" | "FC:A6:67" => {
            Some("Amazon Technologies (Echo / Fire)")
        }

        // ── Dell ──
        "00:06:5B" | "00:08:74" | "00:0B:DB" | "00:0D:56" | "00:0F:1F" | "00:11:43"
        | "00:12:17" | "00:14:22" | "00:18:8B" | "18:03:73" | "24:B6:FD" | "44:A8:42"
        | "70:5A:0F" | "84:2B:2B" | "D4:BE:D9" => Some("Dell Inc."),

        // ── HP ──
        "00:01:E6" | "00:02:A5" | "00:08:02" | "00:0B:CD" | "00:0E:7F" | "00:0F:20"
        | "00:11:85" | "00:14:C2" | "00:16:35" | "10:1F:74" | "94:57:A5" | "C4:34:6B" => {
            Some("HP Inc. (Hewlett-Packard)")
        }

        // ── Netgear ──
        "00:09:5B" | "00:0F:B5" | "00:14:6C" | "00:18:4D" | "00:1B:2F" | "00:1E:2A"
        | "00:24:B2" | "00:26:F2" | "20:4E:7F" | "28:C6:8E" | "44:94:FC" | "6C:B0:CE"
        | "84:1B:5E" | "9C:3D:CF" => Some("Netgear"),

        // ── Huawei ──
        "00:18:82" | "00:1E:10" | "00:25:68" | "00:25:9E" | "00:46:4B" | "04:25:C5"
        | "08:19:A6" | "0C:96:BF" | "10:47:80" | "20:08:89" | "48:46:FB" | "70:72:3C"
        | "88:53:D4" | "A4:DC:BE" | "D0:2D:B3" => Some("Huawei Technologies"),

        // ── ASUS ──
        "00:0C:6E" | "00:0E:A6" | "00:11:2F" | "00:13:D4" | "00:15:F2" | "00:17:31"
        | "00:18:F3" | "00:1A:92" | "00:1B:FC" | "04:D9:F5" | "10:7B:44" | "1C:87:2C"
        | "2C:4D:54" | "38:2C:4A" | "40:16:7E" | "50:46:5D" | "70:8B:CD" => {
            Some("ASUSTek Computer")
        }

        // ── Sony ──
        "00:01:4A" | "00:04:1F" | "00:0A:D9" | "00:13:15" | "00:15:C1" | "00:19:C7"
        | "00:1D:BA" | "00:24:8D" | "28:0D:FC" | "70:9E:29" | "AC:9B:0A" | "F8:D0:BD" => {
            Some("Sony Interactive / Electronics")
        }

        // ── LG Electronics ──
        "00:05:C9" | "00:19:A1" | "00:1C:62" | "00:1E:75" | "00:21:FB" | "00:22:A9"
        | "00:24:83" | "10:F9:6F" | "14:C9:13" | "20:21:A5" | "34:FC:EF" | "58:A2:B5"
        | "A8:23:FE" | "C4:36:6C" => Some("LG Electronics"),

        // ── Ubiquiti ──
        "00:15:6D" | "00:27:22" | "24:A4:3C" | "44:D9:E7" | "68:D7:9A" | "74:83:C2"
        | "80:2A:A8" | "B4:FB:E4" | "DC:9F:DB" | "F0:9F:C2" => Some("Ubiquiti Networks"),

        // ── Broadcom ──
        "00:10:18" | "00:05:B5" | "00:0A:F7" | "00:1B:E9" => Some("Broadcom"),

        _ => None,
    }
}
