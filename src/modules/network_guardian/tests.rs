use crate::modules::network_guardian::adapters::get_network_interfaces;
    use crate::modules::network_guardian::models::{
        GatewayHealth, InternetHealth, PingSample,
    };
    use crate::modules::network_guardian::ping::PingMonitor;
    use std::net::Ipv4Addr;

    #[test]
    fn test_network_interfaces_detection() {
        let result = get_network_interfaces();
        assert!(result.is_ok(), "Debe obtener interfaces de red sin error");
        let ifaces = result.unwrap();
        assert!(!ifaces.is_empty(), "Debe detectar al menos una interfaz de red");

        for iface in &ifaces {
            assert!(!iface.name.is_empty(), "Cada interfaz debe tener identificador o nombre");
        }
    }

    #[test]
    fn test_jitter_rfc3550_calculation() {
        let mut monitor = PingMonitor::new();

        // Muestra inicial: RTT = 20 ms -> Jitter = 0.0
        monitor.record_sample(PingSample {
            target: "1.1.1.1".to_string(),
            ip: "1.1.1.1".to_string(),
            rtt_ms: Some(20.0),
            is_success: true,
            status_code: 0,
        });
        assert_eq!(monitor.jitter_ms(), 0.0);

        // Muestra 2: RTT = 36 ms -> Delta = |36 - 20| = 16 ms
        // J = 0 + (16 - 0) / 16.0 = 1.0 ms
        monitor.record_sample(PingSample {
            target: "1.1.1.1".to_string(),
            ip: "1.1.1.1".to_string(),
            rtt_ms: Some(36.0),
            is_success: true,
            status_code: 0,
        });
        assert!((monitor.jitter_ms() - 1.0).abs() < 0.001);

        // Muestra 3: RTT = 52 ms -> Delta = |52 - 36| = 16 ms
        // J = 1.0 + (16 - 1.0) / 16.0 = 1.0 + 0.9375 = 1.9375 ms
        monitor.record_sample(PingSample {
            target: "1.1.1.1".to_string(),
            ip: "1.1.1.1".to_string(),
            rtt_ms: Some(52.0),
            is_success: true,
            status_code: 0,
        });
        assert!((monitor.jitter_ms() - 1.9375).abs() < 0.001);
    }

    #[test]
    fn test_packet_loss_calculation() {
        let mut monitor = PingMonitor::new();

        // 3 éxitos, 1 fallo = 25% de pérdida
        for _ in 0..3 {
            monitor.record_sample(PingSample {
                target: "1.1.1.1".to_string(),
                ip: "1.1.1.1".to_string(),
                rtt_ms: Some(15.0),
                is_success: true,
                status_code: 0,
            });
        }
        monitor.record_sample(PingSample {
            target: "1.1.1.1".to_string(),
            ip: "1.1.1.1".to_string(),
            rtt_ms: None,
            is_success: false,
            status_code: 11010,
        });

        assert_eq!(monitor.packet_loss_percent(), 25.0);
    }

    #[tokio::test]
    async fn test_network_health_diagnostics_classification() {
        let mut monitor = PingMonitor::new();

        // Diagnóstico con Gateway local inalcanzable (simulado con IP reservada)
        let diag = monitor
            .run_diagnostic(
                Some(Ipv4Addr::new(192, 0, 2, 1)), // TEST-NET-1 (no enruta)
                Some("Ethernet".to_string()),
                Some("192.168.1.50".to_string()),
            )
            .await;

        assert!(diag.is_ok());
        let diag = diag.unwrap();
        // Si el Gateway es inalcanzable, debe clasificarse GatewayHealth::Unreachable
        assert_eq!(diag.gateway_health, GatewayHealth::Unreachable);
        assert_eq!(diag.internet_health, InternetHealth::Disconnected);
        assert!(!diag.simple_status_title.is_empty());
        assert!(!diag.simple_recommendation.is_empty());
    }

    #[test]
    fn test_wifi_frequency_to_channel_and_band_conversion() {
        use crate::modules::network_guardian::wifi_models::{
            frequency_khz_to_channel, WifiBand,
        };

        // 2.4 GHz
        assert_eq!(frequency_khz_to_channel(2_412_000), Some(1));
        assert_eq!(frequency_khz_to_channel(2_437_000), Some(6));
        assert_eq!(frequency_khz_to_channel(2_462_000), Some(11));
        assert_eq!(frequency_khz_to_channel(2_472_000), Some(13));
        assert_eq!(frequency_khz_to_channel(2_484_000), Some(14));
        assert_eq!(WifiBand::from_frequency_khz(2_437_000), WifiBand::Band2_4GHz);

        // 5 GHz
        assert_eq!(frequency_khz_to_channel(5_180_000), Some(36));
        assert_eq!(frequency_khz_to_channel(5_240_000), Some(48));
        assert_eq!(frequency_khz_to_channel(5_745_000), Some(149));
        assert_eq!(WifiBand::from_frequency_khz(5_180_000), WifiBand::Band5GHz);

        // 6 GHz (Wi-Fi 6E)
        assert_eq!(frequency_khz_to_channel(5_955_000), Some(1));
        assert_eq!(WifiBand::from_frequency_khz(5_955_000), WifiBand::Band6GHz);

        // Frecuencia desconocida
        assert_eq!(frequency_khz_to_channel(1_200_000), None);
        assert_eq!(WifiBand::from_frequency_khz(1_200_000), WifiBand::Unknown);
    }

    #[test]
    fn test_wifi_security_level_classification() {
        use crate::modules::network_guardian::wifi_models::WifiSecurityLevel;

        assert!(WifiSecurityLevel::InsecureOpen.is_insecure());
        assert!(WifiSecurityLevel::InsecureWep.is_insecure());
        assert!(WifiSecurityLevel::WeakWpa.is_insecure());

        assert!(!WifiSecurityLevel::SecureWpa2.is_insecure());
        assert!(!WifiSecurityLevel::ModernWpa3.is_insecure());
        assert!(!WifiSecurityLevel::Enterprise.is_insecure());

        assert_eq!(WifiSecurityLevel::InsecureOpen.simple_label(), "Insegura (Abierta)");
        assert_eq!(WifiSecurityLevel::SecureWpa2.simple_label(), "Segura (WPA2)");
        assert_eq!(WifiSecurityLevel::ModernWpa3.simple_label(), "Excelente (WPA3)");
    }

    #[test]
    fn test_wifi_channel_congestion_and_recommendations() {
        use crate::modules::network_guardian::wifi::WifiAnalyzer;
        use crate::modules::network_guardian::wifi_models::{
            NearbyNetwork, WifiBand, WifiSecurityLevel,
        };

        // Redes simuladas: Canal 1 y Canal 6 congestionados, Canal 11 completamente libre
        let nearby = vec![
            NearbyNetwork {
                ssid: "Vecino1".to_string(),
                is_hidden: false,
                bssid: "AA:BB:CC:11:22:33".to_string(),
                signal_quality: 90,
                rssi_dbm: -45,
                channel: 1,
                frequency_khz: 2_412_000,
                band: WifiBand::Band2_4GHz,
                security_level: WifiSecurityLevel::SecureWpa2,
                auth_algorithm: "WPA2-Personal".to_string(),
                cipher_algorithm: "AES-CCMP".to_string(),
            },
            NearbyNetwork {
                ssid: "Vecino2".to_string(),
                is_hidden: false,
                bssid: "AA:BB:CC:11:22:44".to_string(),
                signal_quality: 75,
                rssi_dbm: -55,
                channel: 6,
                frequency_khz: 2_437_000,
                band: WifiBand::Band2_4GHz,
                security_level: WifiSecurityLevel::SecureWpa2,
                auth_algorithm: "WPA2-Personal".to_string(),
                cipher_algorithm: "AES-CCMP".to_string(),
            },
            NearbyNetwork {
                ssid: "Vecino3_Fuerte".to_string(),
                is_hidden: false,
                bssid: "AA:BB:CC:11:22:55".to_string(),
                signal_quality: 95,
                rssi_dbm: -38,
                channel: 6,
                frequency_khz: 2_437_000,
                band: WifiBand::Band2_4GHz,
                security_level: WifiSecurityLevel::SecureWpa2,
                auth_algorithm: "WPA2-Personal".to_string(),
                cipher_algorithm: "AES-CCMP".to_string(),
            },
        ];

        let (congestion, recommendations) =
            WifiAnalyzer::analyze_channels_and_congestion(&nearby, &None);

        assert!(!congestion.is_empty(), "Debe computar métricas para la matriz de canales");
        assert!(!recommendations.is_empty(), "Debe generar recomendaciones");

        // En 2.4 GHz, el canal 11 está libre y debe ser el recomendado
        let rec_2_4 = recommendations
            .iter()
            .find(|r| r.band == WifiBand::Band2_4GHz)
            .expect("Debe haber recomendación para 2.4 GHz");

        assert_eq!(rec_2_4.recommended_channel, 11);
        assert!(!rec_2_4.physical_rf_disclaimer.is_empty(), "Debe incluir el disclaimer físico");

        // Verificar que el canal 11 en la lista tenga is_recommended == true
        let ch11_entry = congestion
            .iter()
            .find(|c| c.band == WifiBand::Band2_4GHz && c.channel == 11)
            .expect("Debe existir entrada para canal 11");
        assert!(ch11_entry.is_recommended);
    }

    #[tokio::test]
    async fn test_wifi_graceful_diagnostics_live_or_fallback() {
        use crate::modules::network_guardian::wifi::WifiAnalyzer;

        let analyzer = WifiAnalyzer::new();
        let diag = analyzer.get_diagnostics(true).await;

        assert!(diag.is_ok(), "El diagnóstico Wi-Fi nunca debe arrojar error fatal");
        let report = diag.unwrap();

        assert!(!report.simple.status_title.is_empty());
        assert!(!report.advanced.last_scan_utc.is_empty());
        // El disclaimer debe estar presente en Modo Avanzado
        assert!(report.advanced.pie_correlation_note.is_some());
    }

    #[test]
    fn test_oui_vendor_lookup_and_randomized_mac() {
        use crate::modules::network_guardian::oui::{is_locally_administered, lookup_vendor};

        // Fabricantes conocidos
        assert_eq!(lookup_vendor("00:17:F2:11:22:33"), Some("Apple"));
        assert_eq!(lookup_vendor("00:07:AB:44:55:66"), Some("Samsung Electronics"));
        assert_eq!(lookup_vendor("B8:27:EB:AA:BB:CC"), Some("Raspberry Pi Foundation"));
        assert_eq!(lookup_vendor("00:0A:EB:12:34:56"), Some("TP-Link Technologies"));
        assert_eq!(lookup_vendor("18:FE:34:78:9A:BC"), Some("Espressif Inc (Dispositivo IoT)"));
        assert_eq!(lookup_vendor("D8:A1:19:11:22:33"), Some("Google"));

        // Función auxiliar de comprobación de bit LAA (bit 1 del octeto 0)
        assert!(is_locally_administered("02:11:22:33:44:55"));
        assert!(is_locally_administered("DA:A1:19:66:77:88"));
        assert!(is_locally_administered("06:00:00:00:00:00"));
        assert!(is_locally_administered("0A:00:00:00:00:00"));
        assert!(is_locally_administered("0E:00:00:00:00:00"));
        assert!(!is_locally_administered("00:17:F2:11:22:33"));
        assert!(!is_locally_administered("D8:A1:19:11:22:33"));

        // MAC con bit LAA activo clasificada correctamente como Administrada Localmente
        assert_eq!(
            lookup_vendor("02:11:22:33:44:55"),
            Some("Dirección Administrada Localmente (LAA: Virtual, VPN o Privada)")
        );
        assert_eq!(
            lookup_vendor("DA:A1:19:66:77:88"),
            Some("Dirección Administrada Localmente (LAA: Virtual, VPN o Privada)")
        );

        // Prefijo desconocido
        assert_eq!(lookup_vendor("00:00:01:23:45:67"), None);
    }

    #[test]
    fn test_calculate_subnet_range() {
        use crate::modules::network_guardian::adapters::calculate_subnet_range;
        use std::net::Ipv4Addr;

        // Subred /24 típica (254 hosts)
        let (first, last, total) = calculate_subnet_range(Ipv4Addr::new(192, 168, 1, 50), 24);
        assert_eq!(first, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(last, Ipv4Addr::new(192, 168, 1, 254));
        assert_eq!(total, 254);

        // Subred /23 amplia (510 hosts)
        let (first, last, total) = calculate_subnet_range(Ipv4Addr::new(192, 168, 0, 10), 23);
        assert_eq!(first, Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(last, Ipv4Addr::new(192, 168, 1, 254));
        assert_eq!(total, 510);

        // Subred /28 acotada (14 hosts)
        let (first, last, total) = calculate_subnet_range(Ipv4Addr::new(10, 0, 0, 35), 28);
        assert_eq!(first, Ipv4Addr::new(10, 0, 0, 33));
        assert_eq!(last, Ipv4Addr::new(10, 0, 0, 46));
        assert_eq!(total, 14);
    }

    #[test]
    fn test_discovered_device_display_name_and_models() {
        use crate::modules::network_guardian::device_models::{
            DeviceDetectionSource, DeviceDisplayCategory, DiscoveredDevice,
        };
        use chrono::Utc;

        let now = Utc::now();

        // 1. Prioridad: Alias personalizado
        let dev_with_alias = DiscoveredDevice {
            network_id: "test_net".to_string(),
            mac: "AA:BB:CC:DD:EE:01".to_string(),
            ip: "192.168.1.100".to_string(),
            hostname: Some("Desktop-PC".to_string()),
            vendor: Some("Intel".to_string()),
            is_trusted: true,
            is_gateway: false,
            is_local_machine: false,
            custom_alias: Some("Mi Estación de Trabajo".to_string()),
            display_category: DeviceDisplayCategory::KnownVendor("Intel".to_string()),
            first_seen_utc: now,
            last_seen_utc: now,
            detection_source: DeviceDetectionSource::ArpCache,
        };
        assert_eq!(dev_with_alias.display_name(), "Mi Estación de Trabajo");

        // 2. Prioridad: Este equipo
        let mut dev_local = dev_with_alias.clone();
        dev_local.custom_alias = None;
        dev_local.is_local_machine = true;
        dev_local.display_category = DeviceDisplayCategory::ThisDevice;
        assert_eq!(dev_local.display_name(), "Este equipo (SysPulse)");
        assert_eq!(dev_local.display_category.label_es(), "Tu equipo");
        assert_eq!(dev_local.display_category.label_en(), "This PC");
        assert_eq!(dev_local.display_category.i18n_key(), "net_device_this_pc");

        // 3. Prioridad: Router / Gateway
        let mut dev_gw = dev_with_alias.clone();
        dev_gw.custom_alias = None;
        dev_gw.is_gateway = true;
        dev_gw.display_category = DeviceDisplayCategory::GatewayRouter;
        assert_eq!(dev_gw.display_name(), "Router / Puerta de Enlace");
        assert_eq!(dev_gw.display_category.i18n_key(), "net_device_gateway");

        // 4. Prioridad: Hostname
        let mut dev_host = dev_with_alias.clone();
        dev_host.custom_alias = None;
        assert_eq!(dev_host.display_name(), "Desktop-PC");

        // 5. Prioridad: Vendor
        let mut dev_vendor = dev_with_alias.clone();
        dev_vendor.custom_alias = None;
        dev_vendor.hostname = None;
        assert_eq!(dev_vendor.display_name(), "Dispositivo Intel");

        // 5.1. Prioridad: LAA (Dirección Localmente Administrada)
        let mut dev_laa = dev_with_alias.clone();
        dev_laa.custom_alias = None;
        dev_laa.hostname = None;
        dev_laa.display_category = DeviceDisplayCategory::LocallyAdministered;
        assert_eq!(dev_laa.display_name(), "Dispositivo con MAC Privada / Virtual");

        // 6. Fallback: IP
        let mut dev_ip = dev_with_alias;
        dev_ip.custom_alias = None;
        dev_ip.hostname = None;
        dev_ip.vendor = None;
        dev_ip.display_category = DeviceDisplayCategory::Unknown;
        assert_eq!(dev_ip.display_name(), "Dispositivo (192.168.1.100)");
        assert_eq!(dev_ip.display_category.label_es(), "Dispositivo Desconocido");
    }

    #[tokio::test]
    async fn test_device_scanner_passive_and_full_scan() {
        use crate::modules::network_guardian::scanner::DeviceScanner;
        use std::net::Ipv4Addr;

        let scanner = DeviceScanner::new(0, 256); // 0 ms delay para tests rápidos

        // 1. Escaneo pasivo de la tabla ARP
        let passive = scanner.scan_passive_arp("test_network").await;
        assert!(passive.is_ok(), "El escaneo pasivo de ARP debe completar sin error");

        // 2. Escaneo completo pasivo con contexto de red
        let report = scanner
            .perform_full_scan(
                Some(Ipv4Addr::new(192, 168, 1, 50)),
                Some(24),
                Some(Ipv4Addr::new(192, 168, 1, 1)),
                Some("eth0".to_string()),
                false, // no vpn
                false, // pasivo
                None,  // sin cancel token
            )
            .await;

        assert!(report.is_ok(), "El escaneo completo debe finalizar con éxito");
        let rep = report.unwrap();

        // Verificar consistencia entre vistas Simple y Avanzada
        assert_eq!(rep.simple.total_devices_count, rep.advanced.devices.len());
        assert_eq!(
            rep.simple.trusted_count + rep.simple.unknown_count,
            rep.simple.total_devices_count
        );
        assert!(!rep.advanced.last_scan_utc.is_empty());
        assert_eq!(rep.advanced.network_context.prefix_length, 24);
    }

    #[tokio::test]
    async fn test_scan_cancellation_and_partial_scan() {
        use crate::modules::network_guardian::scanner::DeviceScanner;
        use std::net::Ipv4Addr;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let scanner = DeviceScanner::new(10, 256); // 10 ms por host
        let cancel_token = Arc::new(AtomicBool::new(false));

        // Activar cancelación anticipada
        let token_clone = cancel_token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            token_clone.store(true, Ordering::SeqCst);
        });

        let result = scanner
            .scan_active_subnet(
                Ipv4Addr::new(192, 168, 1, 50),
                24,
                Some(Ipv4Addr::new(192, 168, 1, 1)),
                "test_net",
                Some(cancel_token),
            )
            .await;

        assert!(result.is_ok(), "El escaneo cancelado debe retornar Ok con flag parcial");
        let (_, is_partial, total_hosts, scanned_count) = result.unwrap();
        assert!(is_partial, "Debe marcarse como escaneo parcial tras cancelación");
        assert_eq!(total_hosts, 254);
        assert!(scanned_count < 254, "No debe haber escaneado todos los hosts tras cancelarse");
    }

    #[tokio::test]
    async fn test_silent_baseline_inventory_and_alert_suppression() {
        use crate::modules::network_guardian::NetworkGuardian;
        use crate::modules::pie::PulseEventBus;

        let (bus, mut receiver) = PulseEventBus::new(32, 32);
        let mut guardian = NetworkGuardian::new(Some(bus));

        // 1. Primer escaneo: debe ser el inventario baseline silencioso (0 eventos críticos de nuevo dispositivo)
        let report1 = guardian.run_device_scan(false).await;
        assert!(report1.is_ok());

        // Verificar que el receptor no haya recibido ninguna alerta de NewDeviceDiscovered
        let mut critical_events_count = 0;
        while let Ok(envelope) = receiver.critical_rx.try_recv() {
            if let crate::modules::pie::PulseCriticalEvent::NewDeviceDiscovered { .. } = envelope.event {
                critical_events_count += 1;
            }
        }
        assert_eq!(
            critical_events_count, 0,
            "El escaneo inicial (baseline) debe ser silencioso y no disparar alertas masivas"
        );
    }

    #[test]
    fn test_configurable_max_active_hosts_and_rate() {
        use crate::modules::network_guardian::scanner::DeviceScanner;
        use crate::modules::network_guardian::NetworkGuardian;

        let mut scanner = DeviceScanner::default();
        assert_eq!(scanner.max_active_hosts(), 256);
        assert_eq!(scanner.active_rate_ms(), 40);

        scanner.set_max_active_hosts(64);
        scanner.set_active_rate_ms(20);
        assert_eq!(scanner.max_active_hosts(), 64);
        assert_eq!(scanner.active_rate_ms(), 20);

        let mut guardian = NetworkGuardian::default();
        assert_eq!(guardian.max_active_hosts(), 256);
        guardian.set_max_active_hosts(128);
        assert_eq!(guardian.max_active_hosts(), 128);
    }

    #[tokio::test]
    async fn test_hostname_resolution_with_cache_and_workers() {
        use crate::modules::network_guardian::scanner::DeviceScanner;
        use std::net::Ipv4Addr;

        let scanner = DeviceScanner::default();
        let loopback = Ipv4Addr::new(127, 0, 0, 1);

        // Primera resolución: puebla la caché
        let name1 = scanner.resolve_hostname_cached(loopback).await;

        // Segunda resolución: debe retornar inmediatamente desde la caché en memoria
        let name2 = scanner.resolve_hostname_cached(loopback).await;
        assert_eq!(name1, name2);
    }

    #[tokio::test]
    async fn test_device_identity_differentiated_by_network() {
        use crate::modules::network_guardian::device_models::*;
        use chrono::Utc;
        use std::collections::{HashMap, HashSet};

        // Simula dos contextos de red distintos (ej. Red Hogar vs. Red Oficina)
        let ctx_home = NetworkContext::new(
            "192.168.1.0/24".to_string(),
            24,
            Some("192.168.1.1".to_string()),
            "iface_home".to_string(),
            false,
        );

        let ctx_office = NetworkContext::new(
            "10.0.0.0/24".to_string(),
            24,
            Some("10.0.0.1".to_string()),
            "iface_office".to_string(),
            false,
        );

        assert_ne!(ctx_home.network_id, ctx_office.network_id, "Cada red debe tener un network_id único");

        // Dispositivo con la misma MAC pero en redes distintas
        let now = Utc::now();
        let dev_home = DiscoveredDevice {
            network_id: ctx_home.network_id.clone(),
            mac: "AA:BB:CC:DD:EE:01".to_string(),
            ip: "192.168.1.100".to_string(),
            hostname: Some("Laptop-Hogar".to_string()),
            vendor: Some("Intel".to_string()),
            is_trusted: true,
            is_gateway: false,
            is_local_machine: false,
            custom_alias: None,
            display_category: DeviceDisplayCategory::KnownVendor("Intel".to_string()),
            first_seen_utc: now,
            last_seen_utc: now,
            detection_source: DeviceDetectionSource::ArpCache,
        };

        let dev_office = DiscoveredDevice {
            network_id: ctx_office.network_id.clone(),
            mac: "AA:BB:CC:DD:EE:01".to_string(),
            ip: "10.0.0.50".to_string(),
            hostname: Some("Laptop-Oficina".to_string()),
            vendor: Some("Intel".to_string()),
            is_trusted: false,
            is_gateway: false,
            is_local_machine: false,
            custom_alias: None,
            display_category: DeviceDisplayCategory::KnownVendor("Intel".to_string()),
            first_seen_utc: now,
            last_seen_utc: now,
            detection_source: DeviceDetectionSource::ArpCache,
        };

        // Inventario indexado por network_id
        let mut inventory_by_network: HashMap<String, HashSet<String>> = HashMap::new();
        inventory_by_network
            .entry(dev_home.network_id.clone())
            .or_default()
            .insert(dev_home.mac.clone());

        assert!(inventory_by_network.get(&ctx_home.network_id).unwrap().contains(&dev_home.mac));
        assert!(
            !inventory_by_network.contains_key(&ctx_office.network_id),
            "La red de oficina no debe tener dispositivos registrados de la red de hogar"
        );

        // Registrar dispositivo en red de oficina y comprobar aislamiento
        inventory_by_network
            .entry(dev_office.network_id.clone())
            .or_default()
            .insert(dev_office.mac.clone());
        assert!(inventory_by_network.get(&ctx_office.network_id).unwrap().contains(&dev_office.mac));
        assert_eq!(inventory_by_network.len(), 2, "Deben coexistir 2 redes con identidades aisladas");
    }

    #[test]
    fn test_device_category_i18n_labels() {
        use crate::modules::network_guardian::device_models::DeviceDisplayCategory;

        let categories = vec![
            (DeviceDisplayCategory::ThisDevice, "Tu equipo", "This PC", "net_device_this_pc"),
            (DeviceDisplayCategory::GatewayRouter, "Router / Puerta de Enlace", "Router / Gateway", "net_device_gateway"),
            (DeviceDisplayCategory::KnownVendor("Apple".to_string()), "Dispositivo Apple", "Apple Device", "net_device_vendor"),
            (DeviceDisplayCategory::LocallyAdministered, "Dirección LAA (Virtual / Privada)", "LAA Address (Virtual / Private)", "net_device_laa"),
            (DeviceDisplayCategory::Unknown, "Dispositivo Desconocido", "Unknown Device", "net_device_unknown"),
        ];

        for (cat, es_expected, en_expected, key_expected) in categories {
            assert_eq!(cat.label_es(), es_expected);
            assert_eq!(cat.label_en(), en_expected);
            assert_eq!(cat.label("es-AR"), es_expected);
            assert_eq!(cat.label("en"), en_expected);
            assert_eq!(cat.i18n_key(), key_expected);
        }
    }
