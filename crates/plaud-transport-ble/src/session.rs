//! `BleSession` — the protocol state machine for a connected vendor
//! characteristic pair.
//!
//! The session owns a [`BleChannel`] and drives the three flows M5
//! ships end-to-end:
//!
//! 1. **`authenticate`** — writes the V0095 auth frame, waits up to
//!    [`crate::constants::AUTH_RESPONSE_TIMEOUT`] for the response
//!    notification, verifies the status byte via
//!    [`plaud_proto::auth_response`], and flips the session's
//!    authenticated flag.
//! 2. **`send_control`** — writes an arbitrary control frame, waits
//!    for the next notification, parses it via
//!    [`plaud_proto::parse_notification`], returns the control-frame
//!    payload (skipping unsolicited control notifications).
//! 3. **`read_bulk`** — writes a bulk-trigger frame (typically the
//!    `ReadFileChunk` opcode), then feeds every incoming frame
//!    through a [`BulkReassembler`] until it sees a `BulkEnd`.
//!
//! The session is deliberately FIFO-ordered. Opcode-tagged
//! correlation skips unsolicited updates while callers wait for
//! the single response that belongs to the single request they just
//! issued, which matches how the Plaud app itself operates.

use std::time::Duration;

use bytes::Bytes;
use plaud_domain::AuthToken;
use plaud_proto::{AuthStatus, Frame};
use plaud_transport::{Error, Result};

use crate::{
    bulk::{BulkReassembler, FeedStatus},
    channel::BleChannel,
    constants::{AUTH_RESPONSE_TIMEOUT, AUTH_STATUS_REJECTED, BULK_FRAME_TIMEOUT, CAP_RSA_HANDSHAKE, CONTROL_RESPONSE_TIMEOUT},
};

/// Error message when the inbound channel closes mid-flow.
const ERR_CHANNEL_CLOSED: &str = "ble channel closed unexpectedly";

/// Error message when the reply to `send_control` is not a control
/// frame (e.g. a bulk frame leaked through).
const ERR_EXPECTED_CONTROL: &str = "expected control frame, got other variant";

/// Protocol session over a connected BLE vendor characteristic pair.
#[derive(Debug)]
pub struct BleSession {
    channel: BleChannel,
    authenticated: bool,
}

impl BleSession {
    /// Wrap an existing `BleChannel` into a fresh session. The
    /// session is unauthenticated on construction.
    #[must_use]
    pub fn new(channel: BleChannel) -> Self {
        Self {
            channel,
            authenticated: false,
        }
    }

    /// Whether the session has completed a successful auth handshake.
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// Perform the V0095 auth handshake.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] if no response arrives within
    /// [`AUTH_RESPONSE_TIMEOUT`], [`Error::AuthRejected`] on status
    /// byte `0x01`, [`Error::Protocol`] on a malformed response, or
    /// [`Error::Unsupported`] if the device replies with a Mode B
    /// handshake preamble (`0xFE11` / `0xFE12`).
    pub async fn authenticate(&mut self, token: &AuthToken) -> Result<()> {
        let frame = plaud_proto::encode::auth::authenticate(token);
        self.channel
            .tx
            .send(frame)
            .await
            .map_err(|_| Error::Transport(ERR_CHANNEL_CLOSED.to_owned()))?;
        let bytes = tokio::time::timeout(AUTH_RESPONSE_TIMEOUT, self.channel.rx.recv())
            .await
            .map_err(|_| Error::Timeout {
                seconds: AUTH_RESPONSE_TIMEOUT.as_secs(),
            })?
            .ok_or_else(|| Error::Transport(ERR_CHANNEL_CLOSED.to_owned()))?;
        let parsed = plaud_proto::parse_notification(bytes).map_err(|e| Error::Protocol(format!("auth response parse: {e}")))?;
        if let Frame::Handshake { .. } = &parsed {
            return Err(Error::Unsupported {
                capability: CAP_RSA_HANDSHAKE,
            });
        }
        let status = plaud_proto::auth_response(&parsed).map_err(|e| Error::Protocol(format!("auth status: {e}")))?;
        match status {
            AuthStatus::Accepted => {
                self.authenticated = true;
                Ok(())
            }
            AuthStatus::Rejected => Err(Error::AuthRejected {
                status: AUTH_STATUS_REJECTED,
            }),
            other => Err(Error::Protocol(format!("unknown auth status variant: {other:?}"))),
        }
    }

    /// Send a pre-encoded control frame and wait for the matching
    /// control-frame response. Verifies the response opcode matches
    /// `expected_opcode`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AuthRequired`] if the session has not been
    /// authenticated, [`Error::Timeout`] on a missing response,
    /// [`Error::Protocol`] on a malformed or wrong-opcode response.
    pub async fn send_control(&mut self, frame: Bytes, expected_opcode: u16) -> Result<Bytes> {
        if !self.authenticated {
            return Err(Error::AuthRequired);
        }
        self.channel
            .tx
            .send(frame)
            .await
            .map_err(|_| Error::Transport(ERR_CHANNEL_CLOSED.to_owned()))?;
        self.receive_control(expected_opcode, CONTROL_RESPONSE_TIMEOUT).await
    }

    async fn receive_control(&mut self, expected_opcode: u16, budget: Duration) -> Result<Bytes> {
        tokio::time::timeout(budget, async {
            loop {
                let bytes = self
                    .channel
                    .rx
                    .recv()
                    .await
                    .ok_or_else(|| Error::Transport(ERR_CHANNEL_CLOSED.to_owned()))?;
                let parsed = plaud_proto::parse_notification(bytes).map_err(|e| Error::Protocol(format!("control response parse: {e}")))?;
                match parsed {
                    Frame::Control { opcode, payload } if opcode == expected_opcode => return Ok(payload),
                    Frame::Control { opcode, .. } => tracing::debug!(opcode, expected_opcode, "ignoring unsolicited control notification"),
                    _ => return Err(Error::Protocol(ERR_EXPECTED_CONTROL.to_owned())),
                }
            }
        })
        .await
        .map_err(|_| Error::Timeout { seconds: budget.as_secs() })?
    }

    /// Send a control frame for a multi-response opcode and collect
    /// all response payloads until the channel goes quiet (3 s timeout
    /// between consecutive responses).
    ///
    /// Multi-response opcodes (like `0x001A` for file listing) produce
    /// multiple control-frame responses with the same opcode. The
    /// Tinnotech SDK accumulates them; we do the same.
    pub async fn send_control_multi(&mut self, frame: Bytes, expected_opcode: u16) -> Result<Vec<Bytes>> {
        if !self.authenticated {
            return Err(Error::AuthRequired);
        }
        self.channel
            .tx
            .send(frame)
            .await
            .map_err(|_| Error::Transport(ERR_CHANNEL_CLOSED.to_owned()))?;

        let mut responses = Vec::new();
        loop {
            let timeout = if responses.is_empty() {
                CONTROL_RESPONSE_TIMEOUT
            } else {
                Duration::from_secs(3)
            };
            match self.receive_control(expected_opcode, timeout).await {
                Ok(payload) => responses.push(payload),
                Err(Error::Timeout { .. }) if !responses.is_empty() => break,
                Err(error) => return Err(error),
            }
        }
        Ok(responses)
    }

    /// Send a bulk-trigger frame and reassemble the resulting bulk
    /// stream until a `BulkEnd` arrives.
    ///
    /// If `progress_tx` is `Some`, the accumulated byte count is sent
    /// after each chunk so a progress bar can update in real time.
    pub async fn read_bulk(&mut self, trigger: Bytes) -> Result<Vec<u8>> {
        if !self.authenticated {
            return Err(Error::AuthRequired);
        }
        self.channel
            .tx
            .send(trigger)
            .await
            .map_err(|_| Error::Transport(ERR_CHANNEL_CLOSED.to_owned()))?;
        let mut reassembler = BulkReassembler::new();
        loop {
            let raw = tokio::time::timeout(BULK_FRAME_TIMEOUT, self.channel.rx.recv())
                .await
                .map_err(|_| Error::Timeout {
                    seconds: BULK_FRAME_TIMEOUT.as_secs(),
                })?
                .ok_or_else(|| Error::Transport(ERR_CHANNEL_CLOSED.to_owned()))?;
            let frame = plaud_proto::parse_notification(raw).map_err(|e| Error::Protocol(format!("bulk frame parse: {e}")))?;
            if let Frame::Control { opcode, .. } = &frame {
                tracing::debug!(opcode, "skipping control frame in bulk stream");
                continue;
            }
            match reassembler.feed(frame)? {
                FeedStatus::InProgress => continue,
                FeedStatus::Done => break,
            }
        }
        reassembler.finish()
    }
}
