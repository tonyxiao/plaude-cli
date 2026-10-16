//! Existing paired Note Pro credentials, stored separately from session keys.

use plaud_transport::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Credentials exported from the owner's existing paired Plaud app.
/// The private key and token are never included in diagnostic output.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ProCredentials {
    /// Cloud-signed serial, base64 encoded.
    #[serde(rename = "snSignature", alias = "sn_signature")]
    pub sn_signature: String,
    /// Existing account RSA public key, in PEM format.
    #[serde(rename = "userRSAPublicKey", alias = "public_key")]
    pub public_key: String,
    /// Matching account RSA private key, in PKCS#8 PEM format.
    #[serde(rename = "userRSAPrivateKey", alias = "private_key")]
    pub private_key: String,
    /// Existing 16- or 32-character device binding token.
    pub token: String,
}

/// Persist credentials in macOS Keychain, or a private sandbox/platform file.
///
/// # Errors
/// Returns storage errors without including credential values.
pub async fn save(credentials: &ProCredentials, config_dir: Option<&Path>) -> Result<()> {
    let json = zeroize::Zeroizing::new(
        serde_json::to_string(credentials).map_err(|_| Error::Protocol("cannot serialize Pro credentials".to_owned()))?,
    );
    let dir = config_dir.map(Path::to_path_buf);
    tokio::task::spawn_blocking(move || {
        #[cfg(target_os = "macos")]
        if dir.is_none() {
            return keyring::Entry::new(crate::constants::KEYRING_SERVICE, "pro-credentials")
                .and_then(|entry| entry.set_password(&json))
                .map_err(|_| Error::Transport("cannot save Pro credentials in Keychain".to_owned()));
        }
        use std::io::Write;
        let path = credential_path(dir.as_deref())?;
        let parent = path
            .parent()
            .ok_or_else(|| Error::Protocol("invalid Pro credential directory".to_owned()))?;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(parent).map_err(Error::Io)?;
        let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(Error::Io)?;
        temp.write_all(json.as_bytes()).map_err(Error::Io)?;
        temp.persist(path).map_err(|e| Error::Io(e.error))?;
        Ok(())
    })
    .await
    .map_err(|_| Error::Transport("Pro credential storage task failed".to_owned()))?
}

/// Load existing paired credentials without contacting the cloud.
///
/// # Errors
/// Returns malformed credential or storage errors, with values redacted.
pub async fn load(config_dir: Option<&Path>) -> Result<Option<ProCredentials>> {
    let dir = config_dir.map(Path::to_path_buf);
    tokio::task::spawn_blocking(move || {
        #[cfg(target_os = "macos")]
        if dir.is_none() {
            let entry = keyring::Entry::new(crate::constants::KEYRING_SERVICE, "pro-credentials")
                .map_err(|_| Error::Transport("cannot open Pro Keychain entry".to_owned()))?;
            return match entry.get_password() {
                Ok(json) => decode(&zeroize::Zeroizing::new(json)).map(Some),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(_) => Err(Error::Transport("cannot read Pro credentials from Keychain".to_owned())),
            };
        }
        match std::fs::read_to_string(credential_path(dir.as_deref())?) {
            Ok(json) => decode(&zeroize::Zeroizing::new(json)).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(Error::Io(error)),
        }
    })
    .await
    .map_err(|_| Error::Transport("Pro credential storage task failed".to_owned()))?
}

/// Remove paired Pro credentials from the configured storage backend.
///
/// # Errors
/// Returns storage errors if credentials could not be removed.
pub async fn clear(config_dir: Option<&Path>) -> Result<()> {
    let dir = config_dir.map(Path::to_path_buf);
    tokio::task::spawn_blocking(move || {
        #[cfg(target_os = "macos")]
        if dir.is_none() {
            let entry = keyring::Entry::new(crate::constants::KEYRING_SERVICE, "pro-credentials")
                .map_err(|_| Error::Transport("cannot open Pro Keychain entry".to_owned()))?;
            return match entry.delete_credential() {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(_) => Err(Error::Transport("cannot clear Pro credentials from Keychain".to_owned())),
            };
        }
        match std::fs::remove_file(credential_path(dir.as_deref())?) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Error::Io(error)),
        }
    })
    .await
    .map_err(|_| Error::Transport("Pro credential storage task failed".to_owned()))?
}

fn credential_path(config_dir: Option<&Path>) -> Result<std::path::PathBuf> {
    match config_dir {
        Some(dir) => Ok(dir.join("pro-credentials.json")),
        None => Ok(crate::FileStore::default_path()?.with_file_name("pro-credentials.json")),
    }
}

fn decode(json: &str) -> Result<ProCredentials> {
    serde_json::from_str(json).map_err(|_| Error::Protocol("invalid stored Pro credentials".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sandbox_credentials_round_trip_without_exposing_world_readable_keys() {
        let dir = tempfile::tempdir().expect("sandbox");
        let credentials = ProCredentials {
            sn_signature: "signature".to_owned(),
            public_key: "public".to_owned(),
            private_key: "private".to_owned(),
            token: "0123456789abcdef".to_owned(),
        };
        save(&credentials, Some(dir.path())).await.expect("save");
        let reloaded = load(Some(dir.path())).await.expect("load").expect("stored credentials");
        assert_eq!(reloaded.token, credentials.token);
        let raw = std::fs::read(dir.path().join("pro-credentials.json")).expect("private file");
        let loaded: ProCredentials = serde_json::from_slice(&raw).expect("credentials JSON");
        assert_eq!(loaded.private_key, credentials.private_key);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(dir.path().join("pro-credentials.json"))
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}
