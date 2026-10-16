//! Encrypted Note Pro session codec and pre-handshake.

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, Payload},
};
use plaud_transport::{Error, Result};

/// A negotiated Pro cipher, including per-direction replay counters.
pub struct ProCipher {
    cipher: ChaCha20Poly1305,
    aes: aes_gcm::Aes256Gcm,
    wifi: bool,
    features: std::sync::Arc<std::sync::atomic::AtomicU8>,
    nonce: [u8; 12],
    aad: [u8; 12],
    outbound: u32,
    inbound: Option<u32>,
}

impl ProCipher {
    /// Initialize from the RSA-unwrapped session material.
    #[must_use]
    pub fn new(key: &[u8; 32], nonce: [u8; 12], aad: [u8; 12]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(key.into()),
            aes: aes_gcm::Aes256Gcm::new(key.into()),
            wifi: false,
            features: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0)),
            nonce,
            aad,
            outbound: 1,
            inbound: None,
        }
    }

    /// Create the SDK-compatible independent Wi-Fi sequence space.
    #[must_use]
    pub fn fork_for_wifi(&self) -> Self {
        Self {
            cipher: self.cipher.clone(),
            aes: self.aes.clone(),
            wifi: true,
            features: self.features.clone(),
            nonce: self.nonce,
            aad: self.aad,
            outbound: 1,
            inbound: None,
        }
    }

    /// Whether this Wi-Fi fork selected the SDK's AES-GCM feature flag.
    #[must_use]
    pub fn wifi_uses_aes(&self) -> bool {
        self.wifi && self.features.load(std::sync::atomic::Ordering::Relaxed) & 8 != 0
    }

    /// Add a sequence number and authenticate a vendor frame.
    ///
    /// # Errors
    /// Returns an error when the sequence space is exhausted.
    pub fn seal(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        self.outbound = self
            .outbound
            .checked_add(1)
            .ok_or_else(|| Error::Protocol("Pro sequence exhausted".to_owned()))?;
        let mut plain = self.outbound.to_le_bytes().to_vec();
        plain.extend_from_slice(frame);
        let payload = Payload {
            msg: &plain,
            aad: &self.aad,
        };
        let result = if self.wifi_uses_aes() {
            self.aes.encrypt((&self.nonce).into(), payload)
        } else {
            self.cipher.encrypt((&self.nonce).into(), payload)
        };
        result.map_err(|_| Error::Protocol("Pro encryption failed".to_owned()))
    }
    /// Authenticate a notification and reject duplicate or older sequence numbers.
    ///
    /// # Errors
    /// Returns an error on invalid tags or short plaintext; duplicate/older
    /// authenticated frames return `None` without resetting replay protection.
    pub fn open(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>> {
        let payload = Payload {
            msg: packet,
            aad: &self.aad,
        };
        let plain = if self.wifi_uses_aes() {
            self.aes.decrypt((&self.nonce).into(), payload).or_else(|_| {
                self.cipher.decrypt(
                    (&self.nonce).into(),
                    Payload {
                        msg: packet,
                        aad: &self.aad,
                    },
                )
            })
        } else {
            self.cipher.decrypt((&self.nonce).into(), payload).or_else(|error| {
                if self.wifi {
                    self.aes.decrypt(
                        (&self.nonce).into(),
                        Payload {
                            msg: packet,
                            aad: &self.aad,
                        },
                    )
                } else {
                    Err(error)
                }
            })
        }
        .map_err(|_| Error::Protocol("Pro notification authentication failed".to_owned()))?;
        if plain.len() < 5 {
            return Err(Error::Protocol("Pro notification is too short".to_owned()));
        }
        let sequence = u32::from_le_bytes([plain[0], plain[1], plain[2], plain[3]]);
        if self.inbound.is_some_and(|previous| sequence <= previous) {
            return Ok(None);
        }
        self.inbound = Some(sequence);
        Ok(Some(plain[4..].to_vec()))
    }
}

/// Validate the paired key material before it is stored or sent to a device.
///
/// # Errors
/// Rejects invalid encodings and mismatched RSA public/private pairs.
pub fn validate_credentials(signature: &str, public_key: &str, private_key: &str) -> Result<()> {
    use base64::Engine;
    use rsa::{
        pkcs8::{DecodePrivateKey, DecodePublicKey},
        traits::PublicKeyParts,
    };
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature)
        .map_err(|_| Error::Protocol("invalid Pro signed-serial encoding".to_owned()))?;
    if signature.is_empty() {
        return Err(Error::Protocol("empty Pro signed serial".to_owned()));
    }
    let private = rsa::RsaPrivateKey::from_pkcs8_pem(private_key).map_err(|_| Error::Protocol("invalid Pro RSA private key".to_owned()))?;
    let public =
        rsa::RsaPublicKey::from_public_key_pem(public_key).map_err(|_| Error::Protocol("invalid Pro RSA public key".to_owned()))?;
    if private.n() != public.n() || private.e() != public.e() {
        return Err(Error::Protocol("Pro RSA public and private keys do not match".to_owned()));
    }
    Ok(())
}

/// Negotiate a Pro session using existing paired credentials and wrap a channel.
///
/// # Errors
/// Returns an error if the handshake cannot be authenticated or completed.
pub async fn secure_channel(channel: crate::BleChannel, signature: &str, public_key: &str, private_key: &str) -> Result<crate::BleChannel> {
    secure_channel_with_wifi(channel, signature, public_key, private_key)
        .await
        .map(|(channel, _)| channel)
}

/// Negotiate BLE and return the SDK-compatible independent Wi-Fi cipher.
///
/// # Errors
/// Rejects invalid credentials, handshake fragments, or session authentication.
pub async fn secure_channel_with_wifi(
    mut channel: crate::BleChannel,
    signature: &str,
    public_key: &str,
    private_key: &str,
) -> Result<(crate::BleChannel, ProCipher)> {
    use base64::Engine;
    use rsa::pkcs8::DecodePrivateKey;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(signature)
        .map_err(|_| Error::Protocol("invalid Pro signed-serial encoding".to_owned()))?;
    let private = rsa::RsaPrivateKey::from_pkcs8_pem(private_key).map_err(|_| Error::Protocol("invalid Pro RSA private key".to_owned()))?;
    let cipher = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        send_fragments(&channel, 0xfe10, &signature).await?;
        let mut parts: Vec<Option<Vec<u8>>> = Vec::new();
        let mut sent_public_key = false;
        loop {
            let frame = channel
                .rx
                .recv()
                .await
                .ok_or_else(|| Error::Transport("Pro handshake channel closed".to_owned()))?;
            if frame.len() < 2 {
                return Err(Error::Protocol("short Pro handshake frame".to_owned()));
            }
            let kind = u16::from_le_bytes([frame[0], frame[1]]);
            if kind == 0xfe11 {
                if !sent_public_key {
                    send_fragments(&channel, 0xfe12, public_key.as_bytes()).await?;
                    sent_public_key = true;
                }
                continue;
            }
            if kind != 0xfe12 || frame.len() < 5 {
                return Err(Error::Protocol("unexpected Pro handshake frame".to_owned()));
            }
            let total = usize::from(frame[2]);
            let index = usize::from(frame[3]);
            if total == 0 || total > 16 || index >= total {
                return Err(Error::Protocol("invalid Pro handshake fragment index".to_owned()));
            }
            if parts.is_empty() {
                parts.resize(total, None);
            }
            if parts.len() != total {
                return Err(Error::Protocol("Pro handshake fragment count changed".to_owned()));
            }
            let data = frame[4..].to_vec();
            if parts[index].as_ref().is_some_and(|previous| previous != &data) {
                return Err(Error::Protocol("conflicting Pro handshake fragment".to_owned()));
            }
            parts[index] = Some(data);
            if parts.iter().any(Option::is_none) {
                continue;
            }
            let encrypted: Vec<u8> = parts.into_iter().flatten().flatten().collect();
            let material = zeroize::Zeroizing::new(
                private
                    .decrypt(rsa::Pkcs1v15Encrypt, &encrypted)
                    .map_err(|_| Error::Protocol("Pro RSA handshake authentication failed".to_owned()))?,
            );
            return cipher_from_material(&material);
        }
    })
    .await
    .map_err(|_| Error::Timeout { seconds: 15 })??;
    let wifi = cipher.fork_for_wifi();
    Ok((wrap_channel(channel, cipher), wifi))
}

async fn send_fragments(channel: &crate::BleChannel, kind: u16, data: &[u8]) -> Result<()> {
    let total = u8::try_from(data.len().div_ceil(100)).map_err(|_| Error::Protocol("Pro handshake payload too large".to_owned()))?;
    if total == 0 {
        return Err(Error::Protocol("empty Pro handshake payload".to_owned()));
    }
    for (index, chunk) in data.chunks(100).enumerate() {
        let mut frame = kind.to_le_bytes().to_vec();
        frame.extend_from_slice(&[total, index as u8]);
        frame.extend_from_slice(chunk);
        channel
            .tx
            .send(bytes::Bytes::from(frame))
            .await
            .map_err(|_| Error::Transport("Pro handshake write channel closed".to_owned()))?;
    }
    Ok(())
}

fn cipher_from_material(material: &[u8]) -> Result<ProCipher> {
    if material.len() < 80 {
        return Err(Error::Protocol("short Pro session material".to_owned()));
    }
    let mut key = zeroize::Zeroizing::new([0; 32]);
    key.copy_from_slice(&material[..32]);
    let mut nonce = [0; 12];
    nonce.copy_from_slice(&material[32..44]);
    let mut aad = [0; 12];
    aad.copy_from_slice(&material[44..56]);
    let cipher = ProCipher::new(&key, nonce, aad);
    let marker = cipher
        .cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: &material[56..],
                aad: &aad,
            },
        )
        .map_err(|_| Error::Protocol("Pro session marker authentication failed".to_owned()))?;
    if marker != b"PLAUD.AI" {
        return Err(Error::Protocol("invalid Pro session marker".to_owned()));
    }
    Ok(cipher)
}

fn wrap_channel(mut raw: crate::BleChannel, mut cipher: ProCipher) -> crate::BleChannel {
    use bytes::Bytes;
    use tokio::sync::mpsc;
    let (tx, mut requests) = mpsc::channel::<Bytes>(crate::constants::DEFAULT_CHANNEL_CAPACITY);
    let (notifications, rx) = mpsc::channel::<Bytes>(crate::constants::DEFAULT_CHANNEL_CAPACITY);
    tokio::spawn(async move {
        let mut feature_acknowledged = false;
        loop {
            tokio::select! {
                frame = requests.recv() => {
                    let Some(frame) = frame else { break; };
                    match cipher.seal(&frame) {
                        Ok(packet) => if raw.tx.send(Bytes::from(packet)).await.is_err() { break; },
                        Err(error) => { tracing::warn!(%error, "Pro encryption stopped"); break; }
                    }
                }
                packet = raw.rx.recv() => {
                    let Some(packet) = packet else { break; };
                    match cipher.open(&packet) {
                        Ok(Some(frame)) => {
                            if frame.starts_with(&[1,138,0]) && frame.len()>=4 {
                                if !feature_acknowledged {
                                    feature_acknowledged=true;
                                    cipher.features.store(frame[3],std::sync::atomic::Ordering::Relaxed);
                                    tracing::debug!(features=frame[3],wifi_aes=frame[3]&8!=0,"Pro feature negotiation");
                                    let Ok(reply)=cipher.seal(&[1,138,0,255]) else {break;};
                                    if raw.tx.send(Bytes::from(reply)).await.is_err(){break;}
                                }
                                continue;
                            }
                            if notifications.send(Bytes::from(frame)).await.is_err(){break;}
                        },
                        Ok(None) => {},
                        Err(error) => { tracing::warn!(%error, "Pro notification rejected"); break; }
                    }
                }
            }
        }
    });
    crate::BleChannel { tx, rx }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_authenticated_frame_and_rejects_replay_and_tampering() {
        let packet = vec![
            218, 230, 198, 139, 197, 159, 156, 235, 218, 98, 175, 41, 129, 163, 86, 238, 227, 50, 141, 46, 246, 234, 84,
        ];
        let mut cipher = ProCipher::new(&[7; 32], [8; 12], [9; 12]);
        let mut bad = packet.clone();
        bad[0] ^= 1;
        assert!(cipher.open(&bad).is_err());
        assert_eq!(cipher.open(&packet).expect("authenticated frame"), Some(vec![1, 3, 0]));
        assert!(cipher.open(&packet).expect("authenticated duplicate").is_none());
    }

    #[test]
    fn seals_sequence_and_frame_with_cross_implementation_vector() {
        let mut cipher = ProCipher::new(&[7; 32], [8; 12], [9; 12]);
        let packet = cipher.seal(&[1, 3, 0]).expect("seal");
        assert_eq!(
            packet,
            vec![
                218, 230, 198, 139, 197, 159, 156, 235, 218, 98, 175, 41, 129, 163, 86, 238, 227, 50, 141, 46, 246, 234, 84
            ]
        );
    }
    #[tokio::test]
    async fn negotiates_cached_key_and_exchanges_encrypted_vendor_frames() {
        round_trip(false).await;
    }

    #[tokio::test]
    async fn supplies_existing_public_key_when_device_requests_it() {
        round_trip(true).await;
    }

    async fn round_trip(request_public: bool) {
        use bytes::Bytes;
        use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, pkcs8::DecodePrivateKey, rand_core::OsRng};
        let private_pem = include_str!("../tests/fixtures/pro-test-private.pem");
        let (channel, mut peer) = crate::BleChannel::loopback_pair();
        let device = tokio::spawn(async move {
            let signature = peer.receive().await.expect("signed serial");
            assert_eq!(&signature[..4], &[0x10, 0xfe, 1, 0]);
            assert_eq!(&signature[4..], b"signature");
            if request_public {
                peer.send(Bytes::from_static(&[0x11, 0xfe, 0, 0]))
                    .await
                    .expect("request public key");
                let expected = include_str!("../tests/fixtures/pro-test-public.pem").as_bytes();
                let total = expected.len().div_ceil(100);
                let mut received = Vec::new();
                for index in 0..total {
                    let frame = peer.receive().await.expect("public key fragment");
                    assert_eq!(&frame[..4], &[0x12, 0xfe, total as u8, index as u8]);
                    received.extend_from_slice(&frame[4..]);
                }
                assert_eq!(received, expected);
            }
            let cipher = ChaCha20Poly1305::new((&[7; 32]).into());
            let marker = cipher
                .encrypt(
                    (&[8; 12]).into(),
                    Payload {
                        msg: b"PLAUD.AI",
                        aad: &[9; 12],
                    },
                )
                .expect("marker");
            let mut material = [vec![7; 32], vec![8; 12], vec![9; 12]].concat();
            material.extend(marker);
            let key = RsaPrivateKey::from_pkcs8_pem(private_pem).expect("test key");
            let encrypted = key.to_public_key().encrypt(&mut OsRng, Pkcs1v15Encrypt, &material).expect("RSA");
            let total = encrypted.len().div_ceil(100);
            for (index, chunk) in encrypted.chunks(100).enumerate() {
                let mut frame = vec![0x12, 0xfe, total as u8, index as u8];
                frame.extend_from_slice(chunk);
                peer.send(Bytes::from(frame)).await.expect("handshake response");
            }
            let mut cipher = ProCipher::new(&[7; 32], [8; 12], [9; 12]);
            let frame = peer.receive().await.expect("encrypted request");
            assert_eq!(cipher.open(&frame).expect("decrypt request"), Some(vec![1, 3, 0]));
            let response = Bytes::from(cipher.seal(&[1, 3, 0, 99]).expect("encrypt response"));
            peer.send(response.clone()).await.expect("response");
            peer.send(response).await.expect("duplicate response");
            peer.send(Bytes::from(cipher.seal(&[1, 3, 0, 66]).expect("next response")))
                .await
                .expect("next response");
        });
        let mut secured = secure_channel(
            channel,
            "c2lnbmF0dXJl",
            include_str!("../tests/fixtures/pro-test-public.pem"),
            private_pem,
        )
        .await
        .expect("handshake");
        secured.tx.send(Bytes::from_static(&[1, 3, 0])).await.expect("request");
        assert_eq!(&secured.rx.recv().await.expect("decrypted response")[..], &[1, 3, 0, 99]);
        assert_eq!(
            &secured.rx.recv().await.expect("valid response after duplicate")[..],
            &[1, 3, 0, 66]
        );
        device.await.expect("fake device");
    }
}

#[cfg(test)]
mod wifi_features_tests {
    use super::*;
    #[tokio::test]
    async fn acknowledges_feature_push_once_without_exposing_it_as_a_command_reply() {
        let (raw, mut peer) = crate::BleChannel::loopback_pair();
        let cipher = ProCipher::new(&[7; 32], [8; 12], [9; 12]);
        let mut wifi = cipher.fork_for_wifi();
        let mut wrapped = super::wrap_channel(raw, cipher);
        let mut device = ProCipher::new(&[7; 32], [8; 12], [9; 12]);
        peer.send(device.seal(&[1, 138, 0, 8]).unwrap().into()).await.unwrap();
        let ack = tokio::time::timeout(std::time::Duration::from_millis(200), peer.receive())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(device.open(&ack).unwrap().unwrap(), [1, 138, 0, 255]);
        assert!(wifi.wifi_uses_aes());
        let vector = wifi.seal(b"frame").unwrap().iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(vector, "3e405e9e91498790bb3d4619937ace4451a1855c5cda780024");
        peer.send(device.seal(&[1, 138, 0, 0]).unwrap().into()).await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), peer.receive())
                .await
                .is_err()
        );
        peer.send(device.seal(&[1, 10, 0, 0]).unwrap().into()).await.unwrap();
        assert_eq!(&wrapped.rx.recv().await.unwrap()[..], &[1, 10, 0, 0]);
    }
}

#[cfg(test)]
mod wifi_fallback_tests {
    use super::*;
    #[test]
    fn wifi_accepts_authenticated_packets_during_algorithm_negotiation() {
        let mut aes_sender = ProCipher::new(&[7; 32], [8; 12], [9; 12]).fork_for_wifi();
        aes_sender.features.store(8, std::sync::atomic::Ordering::Relaxed);
        let packet = aes_sender.seal(b"frame").unwrap();
        let mut receiver = ProCipher::new(&[7; 32], [8; 12], [9; 12]).fork_for_wifi();
        assert_eq!(receiver.open(&packet).unwrap().unwrap(), b"frame");
        assert!(receiver.open(&packet).unwrap().is_none());
        let mut chacha_sender = ProCipher::new(&[7; 32], [8; 12], [9; 12]).fork_for_wifi();
        let packet = chacha_sender.seal(b"frame").unwrap();
        let mut receiver = ProCipher::new(&[7; 32], [8; 12], [9; 12]).fork_for_wifi();
        receiver.features.store(8, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(receiver.open(&packet).unwrap().unwrap(), b"frame");
        let mut ble = ProCipher::new(&[7; 32], [8; 12], [9; 12]);
        let mut aes_sender = ProCipher::new(&[7; 32], [8; 12], [9; 12]).fork_for_wifi();
        aes_sender.features.store(8, std::sync::atomic::Ordering::Relaxed);
        assert!(ble.open(&aes_sender.seal(b"frame").unwrap()).is_err());
    }
}
