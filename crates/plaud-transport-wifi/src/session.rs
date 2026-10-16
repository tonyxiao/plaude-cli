//! Encrypted WebSocket session with fixed deadlines and strict file assembly.
use crate::protocol::{FileAssembler, MAX_PACKET, Packet, WifiFile, invalid, number};
use futures::{SinkExt, StreamExt};
use plaud_domain::Recording;
use plaud_transport::{Error, Result};
use plaud_transport_ble::crypto::ProCipher;
use serde_json::{Value, json};
use tokio::{
    net::{TcpListener, TcpStream},
    time::{Duration, Instant, timeout_at},
};
use tokio_tungstenite::{
    WebSocketStream, accept_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};

/// One authenticated recorder connection. Never logs token-bearing frames.
pub struct WifiSession {
    socket: WebSocketStream<TcpStream>,
    cipher: ProCipher,
    version: u8,
    budget: Duration,
    active: Option<(u64, u16)>,
    negotiated: bool,
    authenticated: bool,
}
impl WifiSession {
    /// Accept, verify the expected serial digest, and authenticate one recorder.
    pub async fn accept(listener: &TcpListener, cipher: ProCipher, expected_identity: &str, token: &str, budget: Duration) -> Result<Self> {
        Self::accept_from(listener, cipher, expected_identity, token, budget, None).await
    }
    /// Accept only the recorder's DHCP router address when supplied, skipping queued LAN peers.
    pub async fn accept_from(
        listener: &TcpListener,
        cipher: ProCipher,
        expected_identity: &str,
        token: &str,
        budget: Duration,
        expected_peer: Option<std::net::IpAddr>,
    ) -> Result<Self> {
        let mut session = Self::accept_hello_from(listener, cipher, expected_identity, budget, expected_peer, None).await?;
        session.authenticate(token).await?;
        Ok(session)
    }
    /// Upgrade promptly and verify SayHello, without sending any binding token.
    /// Start this concurrently with association so the recorder's upgrade cannot time out.
    pub async fn accept_hello(listener: &TcpListener, cipher: ProCipher, expected_identity: &str, budget: Duration) -> Result<Self> {
        Self::accept_hello_excluding(listener, cipher, expected_identity, budget, None).await
    }
    /// Discard clients from the original home subnet before the recorder hotspot is joined.
    pub async fn accept_hello_excluding(
        listener: &TcpListener,
        cipher: ProCipher,
        expected_identity: &str,
        budget: Duration,
        home: Option<std::net::Ipv4Addr>,
    ) -> Result<Self> {
        let deadline = Instant::now() + budget;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::Timeout { seconds: budget.as_secs() });
            }
            let attempt = (deadline - now).min(Duration::from_secs(1));
            let candidate = timeout_at(
                deadline,
                Self::accept_hello_from(listener, cipher.fork_for_wifi(), expected_identity, attempt, None, home),
            )
            .await
            .map_err(|_| Error::Timeout { seconds: budget.as_secs() })?;
            match candidate {
                Ok(mut session) => {
                    session.budget = budget;
                    return Ok(session);
                }
                Err(error) => {
                    tracing::debug!(%error,"dropping unverified Wi-Fi peer");
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    continue;
                }
            }
        }
    }
    async fn accept_hello_from(
        listener: &TcpListener,
        cipher: ProCipher,
        expected_identity: &str,
        budget: Duration,
        expected_peer: Option<std::net::IpAddr>,
        home: Option<std::net::Ipv4Addr>,
    ) -> Result<Self> {
        let deadline = Instant::now() + budget;
        let stream = loop {
            let (stream, peer) = timeout_at(deadline, listener.accept())
                .await
                .map_err(|_| Error::Timeout { seconds: budget.as_secs() })??;
            tracing::debug!(%peer, "incoming Wi-Fi TCP peer");
            if home.is_some_and(|home| matches!(peer.ip(),std::net::IpAddr::V4(ip) if ip.octets()[..3]==home.octets()[..3])) {
                continue;
            }
            if expected_peer.is_none_or(|ip| ip == peer.ip()) {
                break stream;
            }
        };
        // An arriving client gets a full handshake budget even if accept spent
        // most of its own budget waiting. The caller caps overall setup time.
        let deadline = Instant::now() + budget;
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_PACKET + 20))
            .max_frame_size(Some(MAX_PACKET + 20));
        let socket = timeout_at(deadline, accept_async_with_config(stream, Some(config)))
            .await
            .map_err(|_| Error::Timeout { seconds: budget.as_secs() })?
            .map_err(|_| invalid("Wi-Fi WebSocket upgrade failed"))?;
        tracing::debug!("Wi-Fi WebSocket upgraded");
        let mut session = Self {
            socket,
            cipher,
            version: 0,
            budget,
            active: None,
            negotiated: false,
            authenticated: false,
        };
        let hello = session.receive(deadline).await?;
        if hello.opcode != 2
            || !hello
                .json
                .get("token")
                .and_then(Value::as_str)
                .is_some_and(|s| s.eq_ignore_ascii_case(expected_identity))
        {
            return Err(invalid("Wi-Fi recorder identity mismatch"));
        }
        tracing::debug!(version = hello.version, "Wi-Fi SayHello identity verified");
        session.version = hello.version;
        session.negotiated = true;
        Ok(session)
    }
    /// Actual TCP peer, checked against the newly acquired hotspot subnet before auth.
    pub fn peer_address(&self) -> Result<std::net::IpAddr> {
        Ok(self.socket.get_ref().peer_addr()?.ip())
    }
    /// Send the binding token only after the caller verifies hotspot network identity.
    pub async fn authenticate(&mut self, token: &str) -> Result<()> {
        if self.authenticated {
            return Err(invalid("Wi-Fi session already authenticated"));
        }
        let deadline = Instant::now() + self.budget;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| invalid("system clock predates epoch"))?
            .as_secs();
        let token = format!("{token:0<32}");
        timeout_at(deadline, self.send(1, json!({"token":token,"stamp":stamp})))
            .await
            .map_err(|_| Error::Timeout {
                seconds: self.budget.as_secs(),
            })??;
        let reply = self.wait_for(1, deadline).await?;
        let status = u8::try_from(number(&reply.json, "status")?).map_err(|_| invalid("invalid Wi-Fi auth status"))?;
        if status != 0 {
            return Err(Error::AuthRejected { status });
        }
        self.authenticated = true;
        Ok(())
    }
    async fn send(&mut self, opcode: u16, json: Value) -> Result<()> {
        let packet = Packet {
            version: self.version,
            opcode,
            json,
            data: Vec::new(),
        }
        .encode()?;
        let encrypted = self.cipher.seal(&packet)?;
        self.socket
            .send(Message::Binary(encrypted.into()))
            .await
            .map_err(|_| invalid("Wi-Fi send failed"))
    }
    async fn receive(&mut self, deadline: Instant) -> Result<Packet> {
        loop {
            let message = timeout_at(deadline, self.socket.next())
                .await
                .map_err(|_| Error::Timeout {
                    seconds: self.budget.as_secs(),
                })?
                .ok_or_else(|| invalid("Wi-Fi recorder disconnected"))?
                .map_err(|_| invalid("Wi-Fi receive failed"))?;
            match message {
                Message::Binary(data) => {
                    if let Some(plain) = self.cipher.open(&data)? {
                        let packet = Packet::decode(&plain)?;
                        let fields: Vec<&str> = packet
                            .json
                            .as_object()
                            .into_iter()
                            .flat_map(|m| m.keys().map(String::as_str))
                            .collect();
                        tracing::debug!(opcode=packet.opcode,fields=?fields,status=?packet.json.get("status").and_then(|value|value.as_i64()),binary_bytes=packet.data.len(),"Wi-Fi response fields");
                        if self.negotiated && packet.version != self.version {
                            return Err(invalid("Wi-Fi PDU version changed"));
                        }
                        return Ok(packet);
                    }
                }
                Message::Ping(data) => {
                    timeout_at(deadline, self.socket.send(Message::Pong(data)))
                        .await
                        .map_err(|_| Error::Timeout {
                            seconds: self.budget.as_secs(),
                        })?
                        .map_err(|_| invalid("Wi-Fi pong failed"))?;
                }
                Message::Close(_) => return Err(invalid("Wi-Fi recorder disconnected")),
                _ => return Err(invalid("unexpected nonbinary Wi-Fi message")),
            }
        }
    }
    async fn wait_for(&mut self, opcode: u16, deadline: Instant) -> Result<Packet> {
        loop {
            let packet = self.receive(deadline).await?;
            match packet.opcode {
                op if op == opcode => return Ok(packet),
                3 => {
                    timeout_at(deadline, self.send(3, json!({}))).await.map_err(|_| Error::Timeout {
                        seconds: self.budget.as_secs(),
                    })??;
                }
                0 | 4 => return Err(invalid("recorder rejected Wi-Fi operation or closed hotspot")),
                _ => {}
            }
        }
    }
    /// List recording metadata; validates contiguous batches and stable count/uid.
    pub async fn list(&mut self) -> Result<Vec<Recording>> {
        Ok(self.list_files().await?.into_iter().map(|file| file.recording).collect())
    }
    /// List files with their opaque SDK file type retained.
    pub async fn list_files(&mut self) -> Result<Vec<WifiFile>> {
        self.request_files(0, false).await
    }
    /// Resolve one exact recording even when the general device listing is a delta.
    pub async fn find_file(&mut self, id: u64) -> Result<Option<WifiFile>> {
        let files = self.request_files(id, true).await?;
        let mut matches = files.into_iter().filter(|file| file.recording.id().as_unix_seconds() as u64 == id);
        let first = matches.next();
        if matches.next().is_some() {
            return Err(invalid("recording id occurs in multiple Wi-Fi file types"));
        }
        Ok(first)
    }
    async fn request_files(&mut self, start: u64, single: bool) -> Result<Vec<WifiFile>> {
        if !self.authenticated {
            return Err(Error::AuthRequired);
        }
        let deadline = Instant::now() + self.budget;
        let uid = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| invalid("invalid clock"))?
            .as_secs();
        timeout_at(deadline, self.send(11, json!({"uid":uid,"start":start,"single":u8::from(single)})))
            .await
            .map_err(|_| Error::Timeout {
                seconds: self.budget.as_secs(),
            })??;
        let mut out = Vec::new();
        let mut expected = None;
        loop {
            let packet = self.wait_for(11, deadline).await?;
            if number(&packet.json, "uid")? != uid {
                return Err(invalid("Wi-Fi list uid mismatch"));
            }
            if packet.json.get("offset").is_some() {
                if number(&packet.json, "offset")? != out.len() as u64 {
                    return Err(invalid("Wi-Fi list offset mismatch"));
                }
            } else if !packet.data.is_empty() {
                return Err(invalid("Wi-Fi list data has no offset"));
            }
            let count = number(&packet.json, "count")?;
            if expected.is_some_and(|n| n != count) {
                return Err(invalid("Wi-Fi list count changed"));
            }
            expected = Some(count);
            let entries = packet.files()?;
            if entries.is_empty() && out.len() as u64 != count {
                continue;
            }
            for entry in entries {
                if out
                    .iter()
                    .any(|r: &WifiFile| r.recording.id() == entry.recording.id() && r.file_type == entry.file_type)
                {
                    return Err(invalid("duplicate Wi-Fi recording id"));
                }
                out.push(entry);
            }
            if out.len() as u64 == count {
                return Ok(out);
            }
            if out.len() as u64 > count {
                return Err(invalid("Wi-Fi list exceeded count"));
            }
        }
    }
    /// Read one recording without deleting it or acknowledging cloud sync.
    pub async fn read(&mut self, id: u64, scene: u16, size: Option<usize>) -> Result<Vec<u8>> {
        let size = size.filter(|size| *size > 0);
        if !self.authenticated {
            return Err(Error::AuthRequired);
        }
        if size.is_some_and(|n| n > crate::protocol::MAX_RECORDING) {
            return Err(invalid("recording exceeds in-memory limit"));
        }
        if self.active.is_some() {
            return Err(invalid(
                "previous Wi-Fi download failed; reconnect before reading another recording",
            ));
        }
        let mut deadline = Instant::now() + self.budget;
        let overall_deadline = Instant::now() + Duration::from_secs(4 * 60 * 60);
        self.active = Some((id, scene));
        let started = Instant::now();
        tracing::debug!(recording_id=id,scene,expected_bytes=?size,"requesting Wi-Fi recording");
        timeout_at(
            deadline,
            self.send(
                12,
                json!({"session":id,"scene":scene,"start":0,"end":size.unwrap_or(crate::protocol::MAX_RECORDING)}),
            ),
        )
        .await
        .map_err(|_| Error::Timeout {
            seconds: self.budget.as_secs(),
        })??;
        let mut file = FileAssembler::new(id, size);
        loop {
            let packet = self.receive(deadline).await?;
            match packet.opcode {
                13 => {
                    if file.push(&packet)? {
                        self.active = None;
                        let bytes = file.finish()?;
                        tracing::info!(
                            recording_id = id,
                            bytes = bytes.len(),
                            elapsed_ms = started.elapsed().as_millis(),
                            "Wi-Fi recording downloaded"
                        );
                        return Ok(bytes);
                    }
                    // Only validated file progress resets the idle timeout.
                    deadline = (Instant::now() + self.budget).min(overall_deadline);
                }
                12 => {
                    let status = number(&packet.json, "status")?;
                    if status != 0 {
                        return Err(Error::Protocol(format!("Wi-Fi file sync rejected (device status {status})")));
                    }
                    if packet.json.get("session").is_some() && number(&packet.json, "session")? != id {
                        return Err(invalid("Wi-Fi file sync status session mismatch"));
                    }
                }
                3 => {
                    timeout_at(deadline, self.send(3, json!({}))).await.map_err(|_| Error::Timeout {
                        seconds: self.budget.as_secs(),
                    })??;
                }
                0 | 4 => return Err(invalid("Wi-Fi download rejected or interrupted")),
                _ => {}
            }
        }
    }
    /// Stop any transfer and close the WebSocket with a bounded cleanup budget.
    pub async fn close(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(3);
        let result = if let Some((id, scene)) = self.active.take() {
            timeout_at(deadline, self.send(15, json!({"session":id,"scene":scene})))
                .await
                .map_err(|_| Error::Timeout { seconds: 3 })?
        } else {
            Ok(())
        };
        let close = timeout_at(deadline, self.socket.close(None))
            .await
            .map_err(|_| Error::Timeout { seconds: 3 })?
            .map_err(|_| invalid("WebSocket close failed"));
        result.and(close)
    }
}
