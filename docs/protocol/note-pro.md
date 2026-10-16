# Note Pro encrypted BLE session

Observed on the owner's Note Pro using Plaud Android 3.30.0. Derived independently
from the owner's HCI capture and the installed SDK call paths. Raw captures,
account credentials, and decompiled app code are kept outside this repository.

## Existing paired credentials

The SDK's `action/sendGlobalData` passes signed serial (`snSignature`) and an
existing RSA public/private pair. The bind token is supplied to `connectBle`.
Reusing this exact pair preserves the phone's expected recipient key. Generating
or replacing a device key is not part of this implementation.

## Pre-handshake

1. Send decoded signed serial in fragments: `10 fe total index data...`, each
   carrying up to 100 bytes. `index` is zero based.
2. A `11 fe` response requests the existing public key. Send its PEM UTF-8 bytes
   with fragment header `12 fe total index`.
3. A cached key can instead produce `12 fe` response fragments directly.
4. Reassemble `12 fe total index ciphertext...` and RSA-decrypt using PKCS#1 v1.5.
5. The decrypted result contains key[32], nonce[12], AAD[12], followed by an AEAD
   ciphertext. Authenticate/decrypt the latter and require the marker `PLAUD.AI`.

The SDK paths are `r3.J3` / `r3.N3`, `y4.onCharacteristicChanged`, and `wi.m` in
Android 3.30.0. `0xfe20` is selected by `isForceClear`; never use it for normal
connection or credential import.

## Encrypted command channel

Prepend a little-endian 32-bit sequence number to each existing vendor frame,
then encrypt/authenticate with ChaCha20-Poly1305 using the negotiated nonce and
AAD. The SDK starts outbound sequence at 1 and increments before sending, so
its first command uses 2. Decrypted notifications have the same four-byte prefix.
Ignore authenticated duplicate/older sequences; fail closed on invalid tags.

The original `0x0001` binding-token exchange runs inside this channel. The existing
session/protocol code then handles control frames and bulk transfers. Unsolicited
control notifications can arrive between replies; correlate by requested opcode
under a fixed timeout rather than treating the next notification as the reply.

## Validation

Tests use synthetic RSA keys and a cipher vector generated with Python's separate
cryptography implementation. No production keys or captured user frames are fixtures.
A live Mac connection completed the fresh RSA exchange, binding-token authentication,
and GetDeviceName after importing the paired Android credentials.

## Observed encrypted recording container

The test recording has a 512-byte version 1 header and starts with `PLAUD.AI`.
The header size is little-endian u16 at offset 10. Its checksum at offset 12 is a little-endian
u32 containing CRC16/CCITT-FALSE over bytes 16..512 (poly 0x1021, initial 0xffff).
The nonce occupies 132..144; the RSA-wrapped 32-byte file key occupies 256..512.
Decrypt the latter using the existing owner key with PKCS#1 v1.5, then decrypt
bytes 512..EOF using raw IETF ChaCha20 counter 0. This is distinct from the
ChaCha20-Poly1305 BLE session cipher.

The observed continuous-stream layout has zero reserved bytes 144..256. Other
layouts are rejected until segmented parameters are mapped. The plaintext is
multiplexed Ogg: one mono Opus stream and a separate Plaud metadata stream.
Select Opus by its OpusHead packet, check page CRCs, respect pre-skip/end
granules, and account for a nonzero initial audio granule. Preserve the original
container; write the final 16 kHz mono WAV only after decoding succeeds.

## Capability exchange

After secure setup, a feature push `01 8a 00 flags` is acknowledged once with
`01 8a 00 ff`, encrypted through the normal BLE sequence. Its reply is consumed
internally, preventing an acknowledgement loop. The shared `flags & 0x08` bit
selects AES-GCM for the independent Wi-Fi fork; BLE always retains ChaCha.
See [Wi-Fi transfer](wifi-fast-transfer.md). This affects transport negotiation,
not pairing keys, recording deletion or cloud synchronization state.
