//! Wi-Fi provider and explicit cleanup of hotspot, socket and Mac association.
use super::backend::TransportProvider;
use async_trait::async_trait;
use plaud_domain::AuthToken;
use plaud_transport::{Error, Result, Transport};
use plaud_transport_ble::{BleSession, BleTransport, backend::connect_pro_peripheral};
use plaud_transport_wifi::{
    network::{MacNetwork, NetworkAssociation, NetworkConfig},
    session::WifiSession,
    transport::WifiTransport,
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{net::TcpListener, sync::Mutex};

pub(crate) struct WifiProvider {
    config_dir: Option<PathBuf>,
    lease: Mutex<Option<Lease>>,
}
struct Lease {
    ble: Arc<Mutex<BleSession>>,
    network: Arc<dyn NetworkAssociation>,
    socket: Option<Arc<Mutex<WifiSession>>>,
    pending: Option<tokio::task::AbortHandle>,
    opened: bool,
    switched: bool,
}
impl WifiProvider {
    pub(crate) fn new(config_dir: Option<&Path>) -> Self {
        Self {
            config_dir: config_dir.map(Path::to_path_buf),
            lease: Mutex::new(None),
        }
    }
    async fn config(&self) -> Result<NetworkConfig> {
        let path = if let Some(dir) = &self.config_dir {
            dir.join("wifi.json")
        } else {
            plaud_auth::FileStore::default_path()?.with_file_name("wifi.json")
        };
        let bytes = tokio::fs::read(path).await.map_err(|_| {
            Error::Transport("Wi-Fi requires wifi.json in the plaude configuration directory; see docs/usage/macos.md".into())
        })?;
        let config: NetworkConfig =
            serde_json::from_slice(&bytes).map_err(|_| Error::Protocol("invalid wifi.json configuration".into()))?;
        config.validate()?;
        Ok(config)
    }
}
#[async_trait]
impl TransportProvider for WifiProvider {
    async fn connect_anonymous(&self) -> Result<Box<dyn Transport>> {
        self.config().await?;
        Err(Error::Unsupported {
            capability: "Wi-Fi is for authenticated files list/pull-one; use --backend ble for battery",
        })
    }
    async fn connect_authenticated(&self, token: AuthToken) -> Result<Box<dyn Transport>> {
        if self.lease.lock().await.is_some() {
            return Err(Error::Transport("Wi-Fi provider is already connected".into()));
        }
        let config = self.config().await?;
        let identity = config.identity_digest()?;
        let network = Arc::new(MacNetwork::prepare(config).await?);
        // Fail on a port collision before touching the recorder or network.
        let listener = TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, 8081)).await?;
        let credentials = plaud_auth::pro::load(self.config_dir.as_deref())
            .await?
            .ok_or(Error::AuthRequired)?;
        let (raw, battery) = tokio::time::timeout(Duration::from_secs(30), connect_pro_peripheral(Duration::from_secs(15)))
            .await
            .map_err(|_| Error::Timeout { seconds: 30 })??;
        let (channel, cipher) = plaud_transport_ble::crypto::secure_channel_with_wifi(
            raw,
            &credentials.sn_signature,
            &credentials.public_key,
            &credentials.private_key,
        )
        .await?;
        let mut session = BleSession::new(channel);
        session.authenticate(&token).await?;
        let ble = Arc::new(Mutex::new(session));
        let control: Arc<dyn Transport> = Arc::new(BleTransport::from_parts(ble.clone(), Arc::new(battery)));
        let home = network.original_address()?;
        let incoming = tokio::spawn(async move {
            WifiSession::accept_hello_excluding(&listener, cipher, &identity, Duration::from_secs(90), Some(home)).await
        });
        *self.lease.lock().await = Some(Lease {
            pending: Some(incoming.abort_handle()),
            ble: ble.clone(),
            network: network.clone(),
            socket: None,
            opened: false,
            switched: false,
        });
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).map_err(|_| Error::Transport("cannot generate hotspot password".into()))?;
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let password = zeroize::Zeroizing::new(random.iter().map(|b| char::from(alphabet[usize::from(b & 63)])).collect::<String>());
        let mut request = vec![1, 10, 0, 0];
        request.extend_from_slice(password.as_bytes());
        // Track mutation intent before awaiting so Ctrl-C also closes an in-flight open.
        if let Some(lease) = self.lease.lock().await.as_mut() {
            lease.opened = true;
        }
        let reply = ble.lock().await.send_control(request.into(), 10).await?;
        if reply.first() != Some(&0) {
            return Err(Error::Protocol("recorder rejected opening Wi-Fi hotspot".into()));
        }
        if reply.len() < 9 || &reply[1..9] != password.as_bytes() {
            return Err(Error::Protocol("recorder did not accept requested hotspot password".into()));
        }
        eprintln!("Connecting to recorder Wi-Fi…");
        if let Some(lease) = self.lease.lock().await.as_mut() {
            lease.switched = true;
        }
        let router = network.join(&password).await?;
        eprintln!("Recorder Wi-Fi connected. Authenticating fast transfer…");
        let mut session = incoming
            .await
            .map_err(|_| Error::Transport("Wi-Fi listener task failed".into()))??;
        let peer = session.peer_address()?;
        if !matches!(peer,std::net::IpAddr::V4(ip) if ip.octets()[..3]==router.octets()[..3]) {
            return Err(Error::Protocol(
                "WebSocket peer is outside the verified recorder hotspot subnet".into(),
            ));
        }
        session.authenticate(token.as_str()).await?;
        eprintln!("Wi-Fi fast transfer authenticated.");
        let socket = Arc::new(Mutex::new(session));
        if let Some(lease) = self.lease.lock().await.as_mut() {
            lease.socket = Some(socket.clone());
        }
        Ok(Box::new(WifiTransport::new(socket, control)))
    }
    async fn shutdown(&self) -> Result<()> {
        let Some(lease) = self.lease.lock().await.take() else {
            return Ok(());
        };
        if let Some(pending) = lease.pending {
            pending.abort();
        }
        let mut failures = Vec::new();
        if let Some(socket) = lease.socket {
            if let Err(error) = socket.lock().await.close().await {
                failures.push(format!("WebSocket cleanup: {error}"));
            }
        }
        if lease.opened {
            let result = lease.ble.lock().await.send_control(vec![1, 13, 0].into(), 13).await;
            match result {
                Ok(reply) if reply.first() == Some(&0) => {}
                _ => failures.push("could not confirm hotspot closure; recorder Wi-Fi may remain active".into()),
            }
        }
        // Always restore networking even if recorder cleanup failed.
        if lease.switched {
            if let Err(error) = lease.network.restore().await {
                failures.push(format!(
                    "network restoration: {error}; rejoin restore_ssid through macOS Wi-Fi settings"
                ));
            } else {
                eprintln!("Original Mac Wi-Fi restored.");
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(Error::Transport(failures.join("; ")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Network {
        restored: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl NetworkAssociation for Network {
        async fn join(&self, _: &str) -> Result<std::net::Ipv4Addr> {
            Ok(std::net::Ipv4Addr::LOCALHOST)
        }
        async fn restore(&self) -> Result<()> {
            self.restored.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    #[tokio::test]
    async fn network_is_restored_even_when_hotspot_close_is_rejected() {
        let (channel, mut peer) = plaud_transport_ble::BleChannel::loopback_pair();
        let recorder = tokio::spawn(async move {
            let auth = peer.receive().await.unwrap();
            assert_eq!(&auth[..3], &[1, 1, 0]);
            peer.send(vec![1, 1, 0, 0].into()).await.unwrap();
            assert_eq!(&peer.receive().await.unwrap()[..], &[1, 13, 0]);
            peer.send(vec![1, 13, 0, 1].into()).await.unwrap();
        });
        let mut ble = BleSession::new(channel);
        ble.authenticate(&AuthToken::new("0123456789abcdef0123456789abcdef").unwrap())
            .await
            .unwrap();
        let restored = Arc::new(AtomicUsize::new(0));
        let provider = WifiProvider::new(None);
        *provider.lease.lock().await = Some(Lease {
            ble: Arc::new(Mutex::new(ble)),
            network: Arc::new(Network {
                restored: restored.clone(),
            }),
            socket: None,
            pending: None,
            opened: true,
            switched: true,
        });
        assert!(provider.shutdown().await.is_err());
        assert_eq!(restored.load(Ordering::SeqCst), 1);
        assert!(provider.shutdown().await.is_ok());
        assert_eq!(restored.load(Ordering::SeqCst), 1);
        recorder.await.unwrap();
    }
}
