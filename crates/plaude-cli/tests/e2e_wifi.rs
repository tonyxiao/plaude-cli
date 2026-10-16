//! Wi-Fi CLI selection fails before hardware access when setup is missing.
use assert_cmd::Command;
use predicates::prelude::*;
#[test]
fn wifi_requires_configuration_before_touching_hardware() {
    let dir = tempfile::tempdir().unwrap();
    Command::cargo_bin("plaude")
        .unwrap()
        .args(["--backend", "wifi", "--config-dir", dir.path().to_str().unwrap(), "battery"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("wifi.json"));
}
