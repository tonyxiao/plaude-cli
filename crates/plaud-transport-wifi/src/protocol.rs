//! Bounded Wi-Fi PDU framing and lossless recording assembly.
use plaud_domain::{Recording, RecordingId, RecordingKind};
use plaud_transport::{Error, Result};
use serde_json::Value;

/// Normal audio stream selected by the SDK's syncWifiFile call.
pub const NORMAL_AUDIO_SCENE: u16 = 0;

/// Maximum single plaintext message (8 MiB).
pub const MAX_PACKET: usize = 8 * 1024 * 1024;
/// Maximum in-memory recording (512 MiB), matching the current download API.
pub const MAX_RECORDING: usize = 512 * 1024 * 1024;

/// A decoded vendor PDU. Secrets in JSON must not be logged.
pub struct Packet {
    /// PDU version negotiated by SayHello.
    pub version: u8,
    /// WebSocket opcode, distinct from Bluetooth control opcodes.
    pub opcode: u16,
    /// Request/response fields.
    pub json: Value,
    /// Optional binary payload following JSON.
    pub data: Vec<u8>,
}

/// File metadata with the SDK's per-recording file type preserved.
#[derive(Clone)]
pub struct WifiFile {
    /// Common listing data exposed through the transport trait.
    pub recording: Recording,
    /// Opaque file type from the final two bytes; distinct from the sync stream scene.
    pub file_type: u16,
}

/// Construct a protocol error without including untrusted payloads.
pub(crate) fn invalid(message: &str) -> Error {
    Error::Protocol(message.to_owned())
}

/// Read a required non-negative integer field.
pub(crate) fn number(json: &Value, name: &str) -> Result<u64> {
    json.get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| Error::Protocol(format!("missing/invalid Wi-Fi integer field: {name}")))
}

impl Packet {
    /// Encode a complete PDU, checking all wire lengths.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let json = serde_json::to_vec(&self.json).map_err(|_| invalid("Wi-Fi JSON encoding failed"))?;
        let len = 8 + json.len() + self.data.len();
        if json.len() > usize::from(u16::MAX) || len > MAX_PACKET {
            return Err(invalid("Wi-Fi PDU exceeds size limit"));
        }
        let mut out = Vec::with_capacity(len);
        out.extend_from_slice(&(len as u32).to_le_bytes()[..3]);
        out.push(self.version);
        out.extend_from_slice(&self.opcode.to_le_bytes());
        out.extend_from_slice(&(json.len() as u16).to_le_bytes());
        out.extend_from_slice(&json);
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    /// Decode exactly one complete PDU; trailing or truncated data is rejected.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 || bytes.len() > MAX_PACKET {
            return Err(invalid("invalid Wi-Fi PDU size"));
        }
        let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]) as usize;
        let json_len = u16::from_le_bytes([bytes[6], bytes[7]]) as usize;
        if len != bytes.len() || json_len > bytes.len() - 8 {
            return Err(invalid("Wi-Fi PDU length mismatch"));
        }
        let json: Value = serde_json::from_slice(&bytes[8..8 + json_len]).map_err(|_| invalid("invalid Wi-Fi JSON"))?;
        if !json.is_object() {
            return Err(invalid("Wi-Fi JSON must be an object"));
        }
        Ok(Self {
            version: bytes[3],
            opcode: u16::from_le_bytes([bytes[4], bytes[5]]),
            json,
            data: bytes[8 + json_len..].to_vec(),
        })
    }

    /// Decode this file-list batch's fixed ten-byte entries.
    pub fn recordings(&self) -> Result<Vec<Recording>> {
        Ok(self.files()?.into_iter().map(|file| file.recording).collect())
    }
    /// Decode file entries while retaining the SDK file-type value.
    pub fn files(&self) -> Result<Vec<WifiFile>> {
        if self.opcode != 11 || number(&self.json, "status")? != 0 || self.data.len() % 10 != 0 {
            return Err(invalid("invalid Wi-Fi file list"));
        }
        let count = number(&self.json, "count")?;
        if count > 100_000 || self.data.len() / 10 > count as usize {
            return Err(invalid("invalid Wi-Fi file count"));
        }
        self.data
            .chunks_exact(10)
            .map(|entry| {
                let id = u32::from_le_bytes(entry[..4].try_into().map_err(|_| invalid("invalid file id"))?);
                let size = u32::from_le_bytes(entry[4..8].try_into().map_err(|_| invalid("invalid file size"))?);
                let id = RecordingId::new(id.to_string()).map_err(|_| invalid("invalid recording id"))?;
                Ok(WifiFile {
                    recording: Recording::new(id, RecordingKind::Note, 0, u64::from(size)),
                    file_type: u16::from_le_bytes([entry[8], entry[9]]),
                })
            })
            .collect()
    }
}

/// Strict contiguous file assembler: no wrong-session, overlapping or missing bytes.
pub struct FileAssembler {
    session: u64,
    expected: Option<usize>,
    bytes: Vec<u8>,
    complete: bool,
}
impl FileAssembler {
    /// Start a recording, with optional size from a verified device listing.
    #[must_use]
    pub fn new(session: u64, expected: Option<usize>) -> Self {
        Self {
            session,
            expected,
            bytes: Vec::new(),
            complete: false,
        }
    }
    /// Append a validated data PDU; returns true only at the terminal chunk.
    pub fn push(&mut self, packet: &Packet) -> Result<bool> {
        if self.complete
            || packet.opcode != 13
            || number(&packet.json, "session")? != self.session
            || number(&packet.json, "offset")? != self.bytes.len() as u64
            || number(&packet.json, "length")? != packet.data.len() as u64
        {
            return Err(invalid("Wi-Fi recording chunk session/offset/length mismatch"));
        }
        let last = number(&packet.json, "last")?;
        if last > 1
            || self.bytes.len() + packet.data.len() > MAX_RECORDING
            || self.expected.is_some_and(|n| self.bytes.len() + packet.data.len() > n)
        {
            return Err(invalid("Wi-Fi recording exceeds expected size"));
        }
        if packet.data.is_empty() && last == 0 {
            return Err(invalid("empty nonterminal Wi-Fi recording chunk"));
        }
        self.bytes.extend_from_slice(&packet.data);
        self.complete = last == 1;
        if self.complete && self.expected.is_some_and(|n| n != self.bytes.len()) {
            return Err(invalid("truncated Wi-Fi recording"));
        }
        Ok(self.complete)
    }
    /// Publish only a complete recording.
    pub fn finish(self) -> Result<Vec<u8>> {
        if !self.complete || self.bytes.is_empty() {
            return Err(invalid("incomplete Wi-Fi recording"));
        }
        Ok(self.bytes)
    }
}
