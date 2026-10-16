//! Real loopback WebSocket recorder exercising encrypted handshake and downloads.
use futures::{SinkExt, StreamExt};
use plaud_transport_ble::crypto::ProCipher;
use plaud_transport_wifi::{protocol::Packet, session::WifiSession};
use serde_json::json;
use tokio::{net::TcpListener, time::Duration};
use tokio_tungstenite::{connect_async, tungstenite::Message};
fn cipher() -> ProCipher {
    ProCipher::new(&[7; 32], [8; 12], [9; 12])
}

#[tokio::test]
async fn downloads_without_delete_or_sync_acknowledgement() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let device = tokio::spawn(async move {
        let (mut ws, _) = connect_async(format!("ws://{addr}")).await.unwrap();
        let mut c = cipher();
        let hello = Packet {
            version: 1,
            opcode: 2,
            json: json!({"token":"device-hash","pVer":20}),
            data: vec![],
        };
        ws.send(Message::Binary(c.seal(&hello.encode().unwrap()).unwrap().into()))
            .await
            .unwrap();
        let mut operations = Vec::new();
        while let Some(Ok(Message::Binary(b))) = ws.next().await {
            let p = Packet::decode(&c.open(&b).unwrap().unwrap()).unwrap();
            operations.push(p.opcode);
            let response = match p.opcode {
                1 => Packet {
                    version: 1,
                    opcode: 1,
                    json: json!({"status":0}),
                    data: vec![],
                },
                11 => {
                    if p.json["single"] == 0 {
                        let empty = Packet {
                            version: 1,
                            opcode: 11,
                            json: json!({"status":0,"uid":p.json["uid"],"count":0,"offset":0}),
                            data: vec![],
                        };
                        ws.send(Message::Binary(c.seal(&empty.encode().unwrap()).unwrap().into()))
                            .await
                            .unwrap();
                        continue;
                    }
                    assert_eq!(p.json["start"], 1792099106);
                    let header = Packet {
                        version: 1,
                        opcode: 11,
                        json: json!({"status":0,"uid":p.json["uid"],"count":1}),
                        data: vec![],
                    };
                    ws.send(Message::Binary(c.seal(&header.encode().unwrap()).unwrap().into()))
                        .await
                        .unwrap();
                    let mut data = 1792099106u32.to_le_bytes().to_vec();
                    data.extend_from_slice(&0u32.to_le_bytes());
                    data.extend_from_slice(&4u16.to_le_bytes());
                    Packet {
                        version: 1,
                        opcode: 11,
                        json: json!({"status":0,"uid":p.json["uid"],"count":1,"offset":0}),
                        data,
                    }
                }
                12 => {
                    assert_eq!(p.json["scene"], 0);
                    assert_eq!(p.json["end"], plaud_transport_wifi::protocol::MAX_RECORDING);
                    let status = Packet {
                        version: 1,
                        opcode: 12,
                        json: json!({"status":0}),
                        data: vec![],
                    };
                    ws.send(Message::Binary(c.seal(&status.encode().unwrap()).unwrap().into()))
                        .await
                        .unwrap();
                    Packet {
                        version: 1,
                        opcode: 13,
                        json: json!({"session":1792099106,"offset":0,"length":3,"last":1}),
                        data: vec![1, 2, 3],
                    }
                }
                15 => break,
                _ => panic!("unexpected opcode {}", p.opcode),
            };
            ws.send(Message::Binary(c.seal(&response.encode().unwrap()).unwrap().into()))
                .await
                .unwrap();
        }
        operations
    });
    let session = WifiSession::accept(
        &listener,
        cipher(),
        "device-hash",
        "0123456789abcdef0123456789abcdef",
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    let session = std::sync::Arc::new(tokio::sync::Mutex::new(session));
    let ble = plaud_sim::SimDevice::builder().build().authenticated_transport();
    let transport = plaud_transport_wifi::transport::WifiTransport::new(session.clone(), std::sync::Arc::from(ble));
    use plaud_transport::Transport;
    let list = transport.list_recordings().await.unwrap();
    assert!(list.is_empty());
    let id = plaud_domain::RecordingId::new("1792099106").unwrap();
    assert_eq!(transport.read_recording(&id).await.unwrap(), [1, 2, 3]);
    session.lock().await.close().await.unwrap();
    assert_eq!(device.await.unwrap(), [1, 11, 11, 12]);
}

#[tokio::test]
async fn rejects_wrong_identity_before_sending_token() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let device = tokio::spawn(async move {
        let (mut ws, _) = connect_async(format!("ws://{addr}")).await.unwrap();
        let p = Packet {
            version: 1,
            opcode: 2,
            json: json!({"token":"wrong","pVer":20}),
            data: vec![],
        };
        ws.send(Message::Binary(cipher().seal(&p.encode().unwrap()).unwrap().into()))
            .await
            .unwrap();
    });
    assert!(
        WifiSession::accept(&listener, cipher(), "right", "secret", Duration::from_secs(1))
            .await
            .is_err()
    );
    device.await.unwrap();
}

#[tokio::test]
async fn ignores_unexpected_peer_until_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let _ = tokio::net::TcpStream::connect(addr).await;
    });
    let result = WifiSession::accept_from(
        &listener,
        cipher(),
        "id",
        "token",
        Duration::from_millis(50),
        Some("127.0.0.2".parse().unwrap()),
    )
    .await;
    assert!(matches!(result, Err(plaud_transport::Error::Timeout { .. })));
    peer.await.unwrap();
}

#[tokio::test]
async fn active_file_progress_resets_idle_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut ws, _) = connect_async(format!("ws://{addr}")).await.unwrap();
        let mut c = cipher();
        let p = Packet {
            version: 1,
            opcode: 2,
            json: json!({"token":"id","pVer":20}),
            data: vec![],
        };
        ws.send(Message::Binary(c.seal(&p.encode().unwrap()).unwrap().into()))
            .await
            .unwrap();
        let _ = ws.next().await;
        let p = Packet {
            version: 1,
            opcode: 1,
            json: json!({"status":0}),
            data: vec![],
        };
        ws.send(Message::Binary(c.seal(&p.encode().unwrap()).unwrap().into()))
            .await
            .unwrap();
        let _ = ws.next().await;
        for offset in 0..3 {
            tokio::time::sleep(Duration::from_millis(180)).await;
            let p = Packet {
                version: 1,
                opcode: 13,
                json: json!({"session":1792099106,"offset":offset,"length":1,"last":u8::from(offset==2)}),
                data: vec![offset as u8],
            };
            if ws
                .send(Message::Binary(c.seal(&p.encode().unwrap()).unwrap().into()))
                .await
                .is_err()
            {
                return;
            }
        }
        let _ = ws.next().await;
    });
    let mut session = WifiSession::accept(&listener, cipher(), "id", "token", Duration::from_millis(300))
        .await
        .unwrap();
    assert_eq!(session.read(1792099106, 0, Some(3)).await.unwrap(), [0, 1, 2]);
    session.close().await.unwrap();
    peer.await.unwrap();
}

#[tokio::test]
async fn early_upgrade_withholds_token_until_network_is_verified() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut ws, _) = connect_async(format!("ws://{addr}")).await.unwrap();
        let mut c = cipher();
        let hello = Packet {
            version: 1,
            opcode: 2,
            json: json!({"token":"id","pVer":20}),
            data: vec![],
        };
        ws.send(Message::Binary(c.seal(&hello.encode().unwrap()).unwrap().into()))
            .await
            .unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(50), ws.next()).await.is_err());
        ready_tx.send(()).unwrap();
        let Message::Binary(bytes) = ws.next().await.unwrap().unwrap() else {
            panic!("expected encrypted auth")
        };
        let auth = Packet::decode(&c.open(&bytes).unwrap().unwrap()).unwrap();
        assert_eq!(auth.opcode, 1);
        let reply = Packet {
            version: 1,
            opcode: 1,
            json: json!({"status":0}),
            data: vec![],
        };
        ws.send(Message::Binary(c.seal(&reply.encode().unwrap()).unwrap().into()))
            .await
            .unwrap();
        let _ = ws.next().await;
    });
    let mut session = WifiSession::accept_hello(&listener, cipher(), "id", Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(session.peer_address().unwrap(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());
    assert!(matches!(session.list().await, Err(plaud_transport::Error::AuthRequired)));
    ready_rx.await.unwrap();
    session.authenticate("token").await.unwrap();
    session.close().await.unwrap();
    peer.await.unwrap();
}

#[tokio::test]
async fn bogus_peer_does_not_consume_the_recorder_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio::spawn(async move { WifiSession::accept_hello(&listener, cipher(), "id", Duration::from_secs(4)).await });
    let (mut bogus, _) = connect_async(format!("ws://{addr}")).await.unwrap();
    bogus.send(Message::Binary(vec![0].into())).await.unwrap();
    let (_silent, _) = connect_async(format!("ws://{addr}")).await.unwrap();
    let (mut real, _) = connect_async(format!("ws://{addr}")).await.unwrap();
    let hello = Packet {
        version: 1,
        opcode: 2,
        json: json!({"token":"id","pVer":20}),
        data: vec![],
    };
    real.send(Message::Binary(cipher().seal(&hello.encode().unwrap()).unwrap().into()))
        .await
        .unwrap();
    let mut session = incoming.await.unwrap().unwrap();
    assert!(matches!(session.list().await, Err(plaud_transport::Error::AuthRequired)));
    session.close().await.unwrap();
}
