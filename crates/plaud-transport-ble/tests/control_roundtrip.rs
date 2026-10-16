//! Tests for `BleSession::send_control`.
//!
//! Journey: specs/plaude-cli-v1/journeys/M05-transport-ble.md

use bytes::Bytes;
use plaud_domain::AuthToken;
use plaud_transport::Error;
use plaud_transport_ble::{BleChannel, BleSession};

const SAMPLE_TOKEN: &str = "b4b48c21074f89d287c01e9f4b1ffab7";
const AUTH_ACCEPTED: &[u8] = &[
    0x01, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x01, 0x01, 0x00, 0x00, 0x56, 0x5f, 0x00, 0x00,
];
const GET_DEVICE_NAME_OPCODE: u16 = 0x006C;
const PLAUD_NAME_ASCII: &[u8] = b"PLAUD_NOTE";
const UNSOLICITED_RESPONSE: &[u8] = &[0x01, 0x09, 0x00, 0xaa];

fn token() -> AuthToken {
    AuthToken::new(SAMPLE_TOKEN).expect("hand-validated")
}

async fn authenticated_session() -> (BleSession, plaud_transport_ble::TestPeer) {
    let (channel, mut peer) = BleChannel::loopback_pair();
    let mut session = BleSession::new(channel);
    // Prime auth via a background task.
    let peer_handle = tokio::spawn(async move {
        let _ = peer.receive().await;
        peer.send(Bytes::from_static(AUTH_ACCEPTED)).await.expect("auth send");
        peer
    });
    session.authenticate(&token()).await.expect("auth");
    let peer = peer_handle.await.expect("peer task joined");
    (session, peer)
}

#[tokio::test]
async fn send_control_returns_payload_when_opcode_matches() {
    let (mut session, mut peer) = authenticated_session().await;
    // Build a GetDeviceName response: 01 6C 00 <PLAUD_NOTE bytes padded with zeros>
    let mut response = Vec::from([0x01, 0x6c, 0x00]);
    response.extend_from_slice(PLAUD_NAME_ASCII);
    response.extend_from_slice(&[0x00; 20]);
    let response_bytes = Bytes::from(response);
    tokio::spawn(async move {
        let _ = peer.receive().await;
        peer.send(response_bytes).await.expect("send");
    });
    let frame = plaud_proto::encode::device::get_device_name();
    let payload = session.send_control(frame, GET_DEVICE_NAME_OPCODE).await.expect("ok");
    assert!(payload.starts_with(PLAUD_NAME_ASCII));
}

#[tokio::test]
async fn send_control_without_auth_returns_auth_required() {
    let (channel, _peer) = BleChannel::loopback_pair();
    let mut session = BleSession::new(channel);
    let frame = plaud_proto::encode::device::get_device_name();
    let err = session.send_control(frame, GET_DEVICE_NAME_OPCODE).await.unwrap_err();
    assert!(matches!(err, Error::AuthRequired));
}

// Journey: specs/journeys/JOURNEY-20261016-macos-note-pro.md
#[tokio::test]
async fn send_control_ignores_unsolicited_notifications_before_matching_response() {
    let (mut session, mut peer) = authenticated_session().await;
    tokio::spawn(async move {
        let _ = peer.receive().await;
        peer.send(Bytes::from_static(UNSOLICITED_RESPONSE))
            .await
            .expect("unsolicited update");
        peer.send(Bytes::from_static(&[1, 0x6c, 0, 42])).await.expect("matching response");
    });
    let frame = plaud_proto::encode::device::get_device_name();
    let payload = session
        .send_control(frame, GET_DEVICE_NAME_OPCODE)
        .await
        .expect("matching response");
    assert_eq!(&payload[..], &[42]);
}

#[tokio::test(start_paused = true)]
async fn unsolicited_notifications_do_not_extend_the_command_deadline() {
    let (mut session, mut peer) = authenticated_session().await;
    tokio::spawn(async move {
        let _ = peer.receive().await;
        for _ in 0..10 {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if peer.send(Bytes::from_static(UNSOLICITED_RESPONSE)).await.is_err() {
                break;
            }
        }
    });
    let result = session
        .send_control(plaud_proto::encode::device::get_device_name(), GET_DEVICE_NAME_OPCODE)
        .await;
    assert!(matches!(result, Err(Error::Timeout { seconds: 5 })));
}

#[tokio::test(start_paused = true)]
async fn multi_response_listing_skips_unsolicited_updates() {
    let (mut session, mut peer) = authenticated_session().await;
    let device = tokio::spawn(async move {
        let _ = peer.receive().await;
        peer.send(Bytes::from_static(UNSOLICITED_RESPONSE)).await.expect("update");
        peer.send(Bytes::from_static(&[1, 0x1a, 0, 42])).await.expect("batch");
        peer.send(Bytes::from_static(UNSOLICITED_RESPONSE)).await.expect("update");
        peer.send(Bytes::from_static(&[1, 0x1a, 0, 43])).await.expect("batch");
        std::future::pending::<()>().await;
    });
    let result = session
        .send_control_multi(Bytes::from_static(&[1, 0x1a, 0]), 0x1a)
        .await
        .expect("listing");
    assert_eq!(result, vec![Bytes::from_static(&[42]), Bytes::from_static(&[43])]);
    device.abort();
}
