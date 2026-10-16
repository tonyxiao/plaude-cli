//! macOS hotspot association with an explicit, verified network restore target.
use crate::protocol::invalid;
use md5::{Digest, Md5};
use plaud_transport::{Error, Result};
use serde::Deserialize;
use std::path::PathBuf;
use tokio::{
    process::Command,
    time::{Duration, Instant, timeout},
};
use zeroize::Zeroizing;

/// Private local configuration; no passwords are stored inline.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Full recorder serial used to verify encrypted SayHello.
    pub serial: String,
    /// Existing network to restore after transfer (required when macOS hides SSID).
    pub restore_ssid: String,
    /// macOS Wi-Fi interface, normally en0.
    #[serde(default = "default_interface")]
    pub interface: String,
    /// Optional mode-0600 file containing the existing network's password.
    pub restore_password_file: Option<PathBuf>,
    /// Firmware-specific hotspot SSID override.
    pub ssid: Option<String>,
}
fn default_interface() -> String {
    "en0".to_owned()
}
impl NetworkConfig {
    /// Validate identity and association targets before changing any network.
    pub fn validate(&self) -> Result<()> {
        if self.serial.len() < 8
            || self.serial.len() > 56
            || !self.serial.bytes().all(|b| b.is_ascii_alphanumeric())
            || self.restore_ssid.is_empty()
            || self.restore_ssid.len() > 32
            || self.restore_ssid.contains(['\n', '\0'])
            || self.interface.len() > 16
            || !self.interface.bytes().all(|b| b.is_ascii_alphanumeric())
            || self
                .ssid
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.len() > 32 || s.contains(['\n', '\0']))
        {
            return Err(invalid("invalid Wi-Fi configuration (serial, restore_ssid, interface or ssid)"));
        }
        if self.hotspot_ssid()? == self.restore_ssid {
            return Err(invalid("restore network cannot be recorder hotspot"));
        }
        Ok(())
    }
    /// Derive the SDK's Pro hotspot name, or use the explicit firmware override.
    pub fn hotspot_ssid(&self) -> Result<String> {
        if let Some(ssid) = &self.ssid {
            return Ok(ssid.clone());
        }
        if self.serial.len() < 4 || !self.serial.is_ascii() {
            return Err(invalid("invalid Wi-Fi serial"));
        }
        Ok(format!("Plaud{}", &self.serial[self.serial.len() - 4..]))
    }
    /// SDK SayHello contains the uppercase MD5 digest of the recorder serial.
    pub fn identity_digest(&self) -> Result<String> {
        if self.serial.is_empty() {
            return Err(invalid("missing Wi-Fi recorder serial"));
        }
        Ok(format!("{:X}", Md5::digest(self.serial.as_bytes())))
    }
}

/// A prepared network restore plan. Association is always explicit.
pub struct MacNetwork {
    config: NetworkConfig,
    original_router: String,
    original_address: String,
    password: Option<Zeroizing<String>>,
    helper: tempfile::TempDir,
}
impl MacNetwork {
    /// Resolve restore credentials and verify the current network before mutation.
    pub async fn prepare(config: NetworkConfig) -> Result<Self> {
        if !cfg!(target_os = "macos") {
            return Err(Error::Unsupported {
                capability: "automatic Wi-Fi association currently requires macOS",
            });
        }
        config.validate()?;
        run("/usr/bin/xcode-select", &["-p"], Duration::from_secs(5))
            .await
            .map_err(|_| invalid("Wi-Fi requires Apple Swift from Xcode Command Line Tools (xcode-select --install)"))?;
        let preferred = run(
            "/usr/sbin/networksetup",
            &["-listpreferredwirelessnetworks", &config.interface],
            Duration::from_secs(10),
        )
        .await?;
        if !preferred.lines().any(|s| s.trim() == config.restore_ssid) {
            return Err(invalid("restore SSID must already be a saved Mac Wi-Fi network"));
        }
        let current = run(
            "/usr/sbin/networksetup",
            &["-getairportnetwork", &config.interface],
            Duration::from_secs(10),
        )
        .await?;
        if let Some(ssid) = current.trim().strip_prefix("Current Wi-Fi Network: ") {
            if ssid != config.restore_ssid {
                return Err(invalid("configured restore SSID differs from current Wi-Fi network"));
            }
        }
        let original_router = run(
            "/usr/sbin/ipconfig",
            &["getoption", &config.interface, "router"],
            Duration::from_secs(5),
        )
        .await?
        .trim()
        .to_owned();
        if original_router.parse::<std::net::Ipv4Addr>().is_err() {
            return Err(invalid("cannot establish current Wi-Fi router for restoration"));
        }
        let original_address = run("/usr/sbin/ipconfig", &["getifaddr", &config.interface], Duration::from_secs(5))
            .await?
            .trim()
            .to_owned();
        let password = if let Some(path) = &config.restore_password_file {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if tokio::fs::metadata(path).await?.permissions().mode() & 0o077 != 0 {
                    return Err(invalid("Wi-Fi restore password file must be private (chmod 600)"));
                }
            }
            Some(Zeroizing::new(
                tokio::fs::read_to_string(path).await?.trim_end_matches(['\n', '\r']).to_owned(),
            ))
        } else {
            return Err(invalid(
                "automatic Wi-Fi restoration requires a private restore_password_file in wifi.json",
            ));
        };
        let helper = tempfile::tempdir()?;
        tokio::fs::write(helper.path().join("associate.swift"), include_bytes!("associate.swift")).await?;
        Ok(Self {
            helper,
            config,
            original_router,
            original_address,
            password,
        })
    }
    /// Original home IPv4 address used to reject queued LAN peers before hotspot setup.
    pub fn original_address(&self) -> Result<std::net::Ipv4Addr> {
        self.original_address.parse().map_err(|_| invalid("invalid original IPv4 address"))
    }
    /// Join the recorder hotspot using a fresh eight-byte password requested over BLE.
    pub async fn join(&self, password: &str) -> Result<std::net::Ipv4Addr> {
        let ssid = self.config.hotspot_ssid()?;
        // The recorder discovers its downloader from DHCP. Forget only our
        // temporary hotspot profile so macOS performs a fresh association.
        run(
            "/usr/sbin/networksetup",
            &["-removepreferredwirelessnetwork", &self.config.interface, &ssid],
            Duration::from_secs(10),
        )
        .await?;
        // Use Apple's association utility for prompt hotspot setup. The fresh
        // eight-character hotspot password expires when this transfer closes.
        let join_deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let result = run(
                "/usr/sbin/networksetup",
                &["-setairportnetwork", &self.config.interface, &ssid, password],
                Duration::from_secs(12),
            )
            .await;
            if result.is_ok_and(|output| output.trim().is_empty()) {
                break;
            }
            if Instant::now() >= join_deadline {
                return Err(invalid("macOS could not join recorder hotspot; check that the Pro is awake"));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut last_address = String::new();
        loop {
            let address = run("/usr/sbin/ipconfig", &["getifaddr", &self.config.interface], Duration::from_secs(3))
                .await
                .unwrap_or_default();
            let server = run(
                "/usr/sbin/ipconfig",
                &["getoption", &self.config.interface, "server_identifier"],
                Duration::from_secs(3),
            )
            .await
            .ok();
            let router = run(
                "/usr/sbin/ipconfig",
                &["getoption", &self.config.interface, "router"],
                Duration::from_secs(3),
            )
            .await
            .ok();
            tracing::debug!(address=%address.trim(), server=?server.as_deref().map(str::trim), router=?router.as_deref().map(str::trim), "hotspot DHCP state");
            if let Some(peer) = hotspot_peer(
                &self.original_address,
                address.trim(),
                server.as_deref().map(str::trim),
                router.as_deref().map(str::trim),
            ) {
                return Ok(peer);
            }
            last_address.clear();
            last_address.push_str(address.trim());
            if Instant::now() >= deadline {
                return Err(Error::Protocol(format!(
                    "hotspot did not obtain a distinct DHCP lease (current IPv4: {last_address})"
                )));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
    /// Rejoin the original network and verify its DHCP router is restored.
    pub async fn restore(&self) -> Result<()> {
        let password = self.password.as_deref().map(|s| s.as_str());
        if self.associate(&self.config.restore_ssid, password).await.is_err() {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if self.associate(&self.config.restore_ssid, password).await.is_err() {
                // CoreWLAN can temporarily miss a saved 6-GHz/MLO SSID after a 2.4-GHz hotspot.
                // Apple's system utility provides a recovery path; never log its arguments.
                let mut args = vec!["-setairportnetwork", &self.config.interface, &self.config.restore_ssid];
                if let Some(password) = password {
                    args.push(password);
                }
                let output = run("/usr/sbin/networksetup", &args, Duration::from_secs(30)).await?;
                if !output.trim().is_empty() {
                    return Err(invalid("system Wi-Fi restore failed; rejoin restore_ssid in macOS Wi-Fi settings"));
                }
            }
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok(router) = run(
                "/usr/sbin/ipconfig",
                &["getoption", &self.config.interface, "router"],
                Duration::from_secs(3),
            )
            .await
            {
                if router.trim() == self.original_router {
                    if let Ok(ssid) = self.config.hotspot_ssid() {
                        let _ = run(
                            "/usr/sbin/networksetup",
                            &["-removepreferredwirelessnetwork", &self.config.interface, &ssid],
                            Duration::from_secs(10),
                        )
                        .await;
                    }
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                return Err(invalid(
                    "original Wi-Fi router was not restored; rejoin the configured restore_ssid in macOS Wi-Fi settings",
                ));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
    async fn associate(&self, ssid: &str, password: Option<&str>) -> Result<()> {
        use std::process::Stdio;
        use tokio::io::AsyncWriteExt;
        let input = Zeroizing::new(
            serde_json::to_vec(&serde_json::json!({"interface":self.config.interface,"ssid":ssid,"password":password}))
                .map_err(|_| invalid("cannot encode network request"))?,
        );
        let mut child = Command::new("/usr/bin/swift")
            .arg(self.helper.path().join("associate.swift"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let operation = async {
            let mut stdin = child.stdin.take().ok_or_else(|| invalid("cannot open CoreWLAN helper input"))?;
            stdin.write_all(&input).await?;
            drop(stdin);
            let output = child.wait_with_output().await?;
            if !output.status.success() || output.stdout != b"associated\n" {
                let reason = match output.status.code() {
                    Some(2) => "Wi-Fi interface not found",
                    Some(3) => "requested Wi-Fi SSID not found",
                    Some(4) => "CoreWLAN association rejected; check password and Location Services",
                    _ => "Apple Swift/CoreWLAN helper failed; check Xcode Command Line Tools",
                };
                return Err(invalid(reason));
            }
            Ok(())
        };
        timeout(Duration::from_secs(30), operation)
            .await
            .map_err(|_| Error::Timeout { seconds: 30 })?
    }
}
async fn run(binary: &str, args: &[&str], budget: Duration) -> Result<String> {
    let output = timeout(budget, Command::new(binary).args(args).kill_on_drop(true).output())
        .await
        .map_err(|_| Error::Timeout { seconds: budget.as_secs() })??;
    if !output.status.success() {
        return Err(invalid("macOS network command failed"));
    }
    String::from_utf8(output.stdout).map_err(|_| invalid("invalid macOS network command output"))
}

/// Network boundary used to verify cleanup independently of physical Wi-Fi.
#[async_trait::async_trait]
pub trait NetworkAssociation: Send + Sync {
    /// Join the hotspot and return the expected recorder peer address.
    async fn join(&self, password: &str) -> Result<std::net::Ipv4Addr>;
    /// Restore the original network, reporting failures explicitly.
    async fn restore(&self) -> Result<()>;
}
#[async_trait::async_trait]
impl NetworkAssociation for MacNetwork {
    async fn join(&self, password: &str) -> Result<std::net::Ipv4Addr> {
        MacNetwork::join(self, password).await
    }
    async fn restore(&self) -> Result<()> {
        MacNetwork::restore(self).await
    }
}

/// Select a recorder peer for isolated hotspots that omit a default-router option.
#[must_use]
pub fn hotspot_peer(original_address: &str, address: &str, server: Option<&str>, router: Option<&str>) -> Option<std::net::Ipv4Addr> {
    let ip: std::net::Ipv4Addr = address.parse().ok()?;
    let original: std::net::Ipv4Addr = original_address.parse().ok()?;
    if !ip.is_private() || ip.octets()[..3] == original.octets()[..3] {
        return None;
    }
    [router, server]
        .into_iter()
        .flatten()
        .filter_map(|s| s.trim().parse::<std::net::Ipv4Addr>().ok())
        .find(|peer| peer.is_private() && *peer != ip && peer.octets()[..3] == ip.octets()[..3])
}
