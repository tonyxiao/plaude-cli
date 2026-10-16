//! End-to-end tests for the `plaude auth` subcommand tree.
//!
//! Every test sandboxes the token file under a per-test `tempdir`
//! via the global `--config-dir` flag, so the user's real
//! `~/.config/plaude/token` is never touched.
//!
//! Journey: specs/plaude-v1/journeys/M04-auth-storage.md

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::TempDir;

const BIN_NAME: &str = "plaude";
const SAMPLE_TOKEN: &str = "b4b48c21074f89d287c01e9f4b1ffab7";
const FINGERPRINT_LINE: &str = "Fingerprint:";
const STORED_LINE: &str = "Token stored";
const REMOVED_LINE: &str = "Token removed";
const INVALID_TOKEN: &str = "not-hex";
const EXPECTED_USAGE_EXIT: i32 = 2;

fn cmd(tmp: &TempDir) -> Command {
    let mut c = Command::cargo_bin(BIN_NAME).expect("built");
    c.arg("--config-dir").arg(tmp.path());
    c
}

#[test]
fn auth_set_token_stores_and_show_returns_a_fingerprint() {
    let tmp = tempfile::tempdir().expect("tempdir");
    cmd(&tmp)
        .args(["auth", "set-token", SAMPLE_TOKEN])
        .assert()
        .success()
        .stdout(contains(STORED_LINE))
        .stdout(contains(FINGERPRINT_LINE));
    cmd(&tmp)
        .args(["auth", "show"])
        .assert()
        .success()
        .stdout(contains(FINGERPRINT_LINE));
}

#[test]
fn auth_set_token_does_not_print_the_raw_token() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let output = cmd(&tmp).args(["auth", "set-token", SAMPLE_TOKEN]).output().expect("run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains(SAMPLE_TOKEN),
        "stdout must not contain the raw token, got: {stdout}"
    );
}

#[test]
fn auth_show_before_any_token_exits_with_usage_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    cmd(&tmp)
        .args(["auth", "show"])
        .assert()
        .code(EXPECTED_USAGE_EXIT)
        .stderr(contains("no token stored"));
}

#[test]
fn auth_clear_is_idempotent_on_empty_sandbox() {
    let tmp = tempfile::tempdir().expect("tempdir");
    cmd(&tmp).args(["auth", "clear"]).assert().success().stdout(contains(REMOVED_LINE));
}

#[test]
fn auth_set_token_rejects_invalid_input_with_usage_exit() {
    let tmp = tempfile::tempdir().expect("tempdir");
    cmd(&tmp)
        .args(["auth", "set-token", INVALID_TOKEN])
        .assert()
        .code(EXPECTED_USAGE_EXIT)
        .stderr(contains("invalid token"));
}

#[test]
fn auth_set_then_clear_then_show_returns_usage() {
    let tmp = tempfile::tempdir().expect("tempdir");
    cmd(&tmp).args(["auth", "set-token", SAMPLE_TOKEN]).assert().success();
    cmd(&tmp).args(["auth", "clear"]).assert().success();
    cmd(&tmp).args(["auth", "show"]).assert().code(EXPECTED_USAGE_EXIT);
}

#[cfg(not(target_os = "linux"))]
#[test]
fn bootstrap_explains_supported_token_import_on_macos() {
    let tmp = tempfile::tempdir().expect("tempdir");
    cmd(&tmp)
        .args(["auth", "bootstrap", "--timeout", "1"])
        .assert()
        .code(69)
        .stderr(contains("auth set-token"))
        .stderr(contains("Linux/BlueZ"));
}

#[test]
fn pro_import_persists_paired_credentials_and_clear_removes_them() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let source = tmp.path().join("import.json");
    let private = include_str!("../../plaud-transport-ble/tests/fixtures/pro-test-private.pem");
    let public = include_str!("../../plaud-transport-ble/tests/fixtures/pro-test-public.pem");
    std::fs::write(
        &source,
        serde_json::to_vec(&serde_json::json!({
            "snSignature":"c2lnbmF0dXJl", "userRSAPrivateKey":private, "userRSAPublicKey":public, "token":SAMPLE_TOKEN
        }))
        .expect("JSON"),
    )
    .expect("fixture");
    let output = cmd(&tmp).args(["auth", "import-pro"]).arg(&source).assert().success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(stdout.contains("Note Pro credentials stored"));
    assert!(!stdout.contains(SAMPLE_TOKEN));
    assert!(!stdout.contains("BEGIN PRIVATE KEY"));
    cmd(&tmp).args(["auth", "show"]).assert().success();
    let stored = tmp.path().join("pro-credentials.json");
    assert!(stored.exists());
    cmd(&tmp).args(["auth", "clear"]).assert().success();
    assert!(!stored.exists());
    cmd(&tmp).args(["auth", "show"]).assert().code(EXPECTED_USAGE_EXIT);
}

#[test]
fn pro_import_rejects_invalid_credentials_without_storing_them() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let source = tmp.path().join("invalid.json");
    std::fs::write(&source, r#"{"private_key":"do-not-print-this-secret"}"#).expect("fixture");
    let output = cmd(&tmp)
        .args(["auth", "import-pro"])
        .arg(&source)
        .assert()
        .code(EXPECTED_USAGE_EXIT);
    assert!(!String::from_utf8_lossy(&output.get_output().stderr).contains("do-not-print-this-secret"));
    assert!(!tmp.path().join("pro-credentials.json").exists());
}
