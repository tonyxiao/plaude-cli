//! Independent Wi-Fi counters must not perturb the BLE session.
use plaud_transport_ble::crypto::ProCipher;
#[test]
fn wifi_cipher_restarts_sequence_and_keeps_ble_counters() {
    let mut ble = ProCipher::new(&[7; 32], [8; 12], [9; 12]);
    let first = ble.seal(b"first").unwrap();
    let mut wifi = ble.fork_for_wifi();
    assert_eq!(wifi.seal(b"first").unwrap(), first);
    assert_ne!(ble.seal(b"first").unwrap(), first);
    let mut receiver = ProCipher::new(&[7; 32], [8; 12], [9; 12]);
    assert_eq!(receiver.open(&first).unwrap().unwrap(), b"first");
    assert!(receiver.open(&first).unwrap().is_none());
}
