//! Network configuration must fail closed before hotspot association.
use plaud_transport_wifi::network::NetworkConfig;
#[test]
fn rejects_unsafe_or_ambiguous_network_configuration() {
    for serial in ["", "bad serial", "881"] {
        let config = NetworkConfig {
            serial: serial.into(),
            restore_ssid: "home".into(),
            interface: "en0".into(),
            restore_password_file: None,
            ssid: None,
        };
        assert!(config.validate().is_err());
    }
    let config = NetworkConfig {
        serial: "881123456789012345678901234".into(),
        restore_ssid: "home".into(),
        interface: "en0".into(),
        restore_password_file: None,
        ssid: None,
    };
    assert_eq!(config.hotspot_ssid().unwrap(), "Plaud1234");
    assert_eq!(config.identity_digest().unwrap().len(), 32);
}

#[test]
fn isolated_hotspot_uses_dhcp_server_without_a_router_option() {
    use plaud_transport_wifi::network::hotspot_peer;
    assert_eq!(
        hotspot_peer("192.168.40.100", "172.16.0.2", Some("172.16.0.1"), None)
            .unwrap()
            .to_string(),
        "172.16.0.1"
    );
    assert!(hotspot_peer("192.168.40.100", "192.168.40.100", Some("192.168.40.1"), None).is_none());
    assert!(hotspot_peer("192.168.40.100", "169.254.1.2", None, None).is_none());
}

#[test]
fn ignores_stale_or_invalid_dhcp_options() {
    use plaud_transport_wifi::network::hotspot_peer;
    assert_eq!(
        hotspot_peer("192.168.40.100", "172.16.0.2", Some(""), Some("172.16.0.1"))
            .unwrap()
            .to_string(),
        "172.16.0.1"
    );
    assert_eq!(
        hotspot_peer("192.168.40.100", "172.16.0.2", Some("192.168.40.1"), Some("172.16.0.1"))
            .unwrap()
            .to_string(),
        "172.16.0.1"
    );
    assert!(hotspot_peer("192.168.40.100", "192.168.40.101", Some("192.168.40.1"), None).is_none());
    assert!(hotspot_peer("192.168.40.100", "172.16.0.2", Some("garbage"), None).is_none());
}
