# Journey: Apple Silicon Mac and paired Note Pro access

## User outcome

Use the recorder locally from the Mac, preserving the existing Android pairing.
The installed CLI can discover the Pro, authenticate an encrypted session, list
recordings, download an encrypted ASR container, and create a playable WAV.

## Implementation

- Linux BlueZ bootstrap is platform-gated; macOS uses CoreBluetooth.
- Original Note discovery remains supported. Pro matching uses its observed
  name/manufacturer, or manufacturer+service when macOS omits the name.
- Discovery watches updates for up to15seconds and stops when a candidate is found.
- `auth import-pro` validates the owner's signed serial, matching RSA pair, and
  bind token. macOS stores the bundle in Keychain; explicit config sandboxes and
  Linux use atomic0600files. Credential buffers are zeroized.
- FE10/FE11/FE12 establish fresh RSA/ChaCha20-Poly1305 sessions using existing
  paired keys. No force-clear/rebinding flow is used.
- Control response correlation ignores unsolicited updates under a fixed budget;
  encrypted notification replay is discarded, invalid tags fail closed.
- Pro recordings use a separate512-byte header, RSA-wrapped file key, and raw
  ChaCha20. Header/Ogg checksums and Opus stream selection precede WAV publication.
- `make install` signs the installed Mac binary with a stable certificate-backed
  identity when exactly one is available. Old ad-hoc Keychain entries were recreated
  from a private backup; access partitions now use the signing team, not build hashes.

## Evidence

The baseline Mac build failed on Linux-only D-Bus dependencies. Failing discovery,
codec-vector, handshake, storage, response-correlation, file-decryption, and Ogg
regressions preceded the corresponding fixes. Tests use synthetic RSA keys, generated
silence, and independently generated cipher/container vectors.

On the real Pro, a fresh encrypted connection authenticated and returned the device
name. The deliberately recorded test clip listed as48640bytes and downloaded locally.
The encrypted container decrypted to CRC-valid multiplexed Ogg. The final WAV is
16-bit PCM, mono16kHz,11.16seconds. Original ASR data is retained. Three consecutive
Keychain token reads took0.01seconds each after access-rule repair; a subsequent
signed rebuild retained access.

## Boundaries

BLE listing is the upstream delta protocol. Some original device-info fields remain
placeholders. File decoding is restricted to the observed continuous, mono profile.
Wi-Fi Fast Transfer is a separate follow-up requested by the user.

## Stressors

Linux regressions; Bluetooth permission; phone connection contention; omitted scan
names; delayed advertisement updates; missing CMake; unavailable CUDA; stale Keychain
build hashes; mismatched RSA pairs; fragmented handshakes; replayed notifications;
unsolicited control messages; corrupt headers; multiplexed Ogg metadata; nonzero
initial granules; interrupted publication; unsupported future recording layouts.

## Files

`crates/plaud-auth/src/pro.rs`; `crates/plaud-transport-ble/src/crypto.rs` and
`encrypted_file.rs`; BLE backend/session; CLI auth/backend/files/decode; Makefile;
macOS CI and regression fixtures; docs/usage/macos.md; docs/protocol/note-pro.md.
