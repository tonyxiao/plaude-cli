# Note Pro Wi-Fi download journey

The user requests fast local downloads alongside the official phone/cloud path,
and preservation of hardware highlights. The approved design is
[here](../../docs/superpowers/specs/2026-10-16-note-pro-wifi-design.md).

## Implemented

Explicit Wi-Fi selection, owner-preserving encrypted BLE setup, negotiated
WebSocket authentication, checked recording assembly, original ASR plus lossless
Ogg/metadata and playable WAV, and original-network restoration. Normal termination,
errors, Ctrl-C, SIGTERM/SIGHUP and command panic invoke cleanup. No delete or
cloud-sync acknowledgement commands are sent. Claude reviewed successive changes.

## Automated validation

505 tests passed before final physical validation; two physical-adapter BLE tests
are explicitly ignored by default. Clippy/fmt passed and the signed release is
installed. Dependency audit unavailable because cargo-audit is not installed.
Final validation changed documentation only, so these checks were not rerun.

## Physical validation completed

A fresh recording transferred 31,744 bytes over AES-GCM Wi-Fi in 77 ms, excluding
connection setup. It decrypted to 31,232 bytes of multiplexed Ogg and decoded to
7.2 seconds of mono 16 kHz PCM. A subsequent Bluetooth download matched the ASR
byte for byte. The Mac's original Wi-Fi was restored.

Before reopening the official phone app, the fresh recording was absent from the
cloud list. After phone import it appeared with its transcript ready. The phone's
Ogg exactly matched the Mac's Ogg. This verifies that local Wi-Fi retrieval did
not prevent the official import path in this test.

## Remaining marker limitation

The supplied marked sample contained no PTAG bytes in either the complete Mac Ogg
or the official phone copy, and non-audio packets were zero-filled after their
PLAUD.AI header. Metadata is retained; decoded highlight timing remains unvalidated.
The separate SDK GetRecTags query appears to recover live recording marks after a
reconnect, not read marks from finished files. See the hardware-marks protocol doc.
