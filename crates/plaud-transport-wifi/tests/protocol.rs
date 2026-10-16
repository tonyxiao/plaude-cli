//! Vendor Wi-Fi framing and recording assembly regression tests.
use plaud_transport_wifi::protocol::{FileAssembler, Packet};
use serde_json::json;

#[test]
fn frame_roundtrip_and_checked_lengths() {
    let p = Packet {
        version: 1,
        opcode: 13,
        json: json!({"length":3}),
        data: vec![1, 2, 3],
    };
    let bytes = p.encode().unwrap();
    assert_eq!(bytes[0] as usize, bytes.len());
    let got = Packet::decode(&bytes).unwrap();
    assert_eq!(got.opcode, 13);
    assert_eq!(got.data, [1, 2, 3]);
    for n in 0..bytes.len() {
        assert!(Packet::decode(&bytes[..n]).is_err());
    }
    let mut bad = bytes.clone();
    bad[6] = 255;
    bad[7] = 255;
    assert!(Packet::decode(&bad).is_err());
}

#[test]
fn assembly_rejects_wrong_recording_offsets_and_truncation() {
    let mut file = FileAssembler::new(42, Some(6));
    let mut p = Packet {
        version: 1,
        opcode: 13,
        json: json!({"session":42,"offset":0,"length":3,"last":0}),
        data: vec![1, 2, 3],
    };
    assert!(!file.push(&p).unwrap());
    assert!(file.push(&p).is_err());
    p.json = json!({"session":43,"offset":3,"length":3,"last":1});
    assert!(file.push(&p).is_err());
    p.json = json!({"session":42,"offset":3,"length":3,"last":1});
    assert!(file.push(&p).unwrap());
    assert_eq!(file.finish().unwrap(), [1, 2, 3, 1, 2, 3]);
    assert!(FileAssembler::new(42, Some(6)).finish().is_err());
}

#[test]
fn list_entries_are_ten_bytes_and_count_is_bounded() {
    let mut data = 1792099106u32.to_le_bytes().to_vec();
    data.extend_from_slice(&123u32.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    let mut p = Packet {
        version: 1,
        opcode: 11,
        json: json!({"status":0,"count":1,"offset":0}),
        data,
    };
    let entries = p.recordings().unwrap();
    assert_eq!(entries[0].id().as_str(), "1792099106");
    assert_eq!(entries[0].asr_size(), 123);
    p.data.pop();
    assert!(p.recordings().is_err());
}

#[test]
fn retains_file_type_without_confusing_it_with_download_scene() {
    let mut data = 1792099106u32.to_le_bytes().to_vec();
    data.extend_from_slice(&42u32.to_le_bytes());
    data.extend_from_slice(&4u16.to_le_bytes());
    let packet = Packet {
        version: 1,
        opcode: 11,
        json: json!({"status":0,"count":1,"offset":0}),
        data,
    };
    let files = packet.files().unwrap();
    assert_eq!(files[0].file_type, 4);
    assert_eq!(files[0].recording.asr_size(), 42);
}
