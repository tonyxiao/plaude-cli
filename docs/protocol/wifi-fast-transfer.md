# Wi-Fi Fast Transfer — Note Pro

## Status

The Rust Wi-Fi transport now implements encrypted WebSocket hello/auth,
listing, strict file assembly, heartbeat handling, and bounded requests. The
Mac CLI selects it with `--backend wifi`, using Bluetooth setup and native
CoreWLAN association/restoration. Loopback tests exercise real WebSocket I/O.

A live Note Pro probe on 2026-10-16 joined the hotspot, verified encrypted
SayHello, and authenticated using the existing binding token. The device reported
`pVer: 20`; the account API separately reported `prot_version: 0`. Requesting a
fresh eight-byte ASCII password produced a matching password in the open reply.
Close Wi-Fi returned status 0 and the original Mac network was restored.
Native Rust AES-GCM download is now verified end to end on the owner's Note Pro.
A fresh recording transferred 31,744 encrypted bytes in 77 ms (connection setup
excluded), decrypted to a 31,232-byte Ogg and decoded to 7.2 seconds of mono
16 kHz PCM. An independent Bluetooth download matched byte for byte. The official
phone app subsequently imported the recording, and it appeared in Plaud cloud
with its transcript ready. The phone's Ogg also exactly matched the Mac copy.
The Mac's original Wi-Fi was restored after the transfer.

The earlier already-imported test returned zero size and download status 8.
Keep the original ASR/Ogg because the recorder may no longer offer an imported
file through the sync API. The small test validates transport functionality,
not sustained large-file throughput or connection-setup latency.

## Bluetooth setup

After the [encrypted Pro handshake](note-pro.md), send `01 0a 00 00`:
control opcode `0x000a`, mode 0 for normal transfer. Mode 1 is OTA and is not
needed. An optional eight-byte ASCII password can follow the mode. The reply has
a status byte at offset 3 and may include an eight-byte password at offset 4.
Close Wi-Fi uses control opcode `0x000d`. The tested unit acknowledged it on
opcode 13; the SDK also registers opcode 10 for its close operation. Mode-switch
notifications can share opcode 10, so open requires the requested password echo.

The encrypted Pro control channel acknowledges the first feature request
`01 8a 00 flags` with the SDK reply `01 8a 00 ff`. Bit `0x08` selects AES-GCM for
Wi-Fi; BLE remains ChaCha20-Poly1305. Wi-Fi receive also tries the other AEAD
algorithm, as the SDK does, and always requires a valid authentication tag. An
independent Python-generated AES vector and replay/algorithm tests cover this.
The live Pro advertised `flags: 255` and used AES-GCM on Wi-Fi.

For models 881/883 with protocol version at least 20, the SDK derives the hotspot
SSID as `Plaud` plus the final four characters of the serial. Confirm the actual
SSID, security, password, and DHCP behavior before relying on that convention.

## Connection direction and encryption

The downloading phone/computer joins the recorder's hotspot and listens as a
WebSocket server on TCP 8081. The recorder connects as the WebSocket client.
This is not an HTTP file server on the recorder.

The SDK reuses BLE session key material for encrypted binary WebSocket messages.
Pro models use separate Wi-Fi sequence counters initialized outbound 1 and
inbound -1. The SDK also contains an AES-GCM mode; the cipher selected by a given
firmware must be verified rather than assumed from the BLE transport alone.

Before encryption, the packet layout is:

```text
totalLength:u24 LE | pduVersion:u8 | opcode:u16 LE | jsonLength:u16 LE
JSON bytes | optional binary file bytes
```

The device sends SayHello opcode 2 with JSON `token` and `pVer`. The SDK checks
the device identity, then sends auth opcode 1 with
`{"token": "<binding-token>", "stamp": <epoch-seconds>}`.

## Recording operations

| Opcode | Operation | JSON fields |
| --- | --- | --- |
| 11 | List | `uid`, `start`, `single` |
| 12 | Start/resume sync | `session`, `scene`, `start`, `end` |
| 13 | File data response | `session`, `offset`, `length`, `last`; bytes follow JSON |
| 15 | Stop sync | See SDK stop request |

Wi-Fi opcode 14 deletes recordings and must not be used during download probes.
These WebSocket opcodes are separate from Bluetooth control opcodes.

File-list entries are ten bytes: ID:u32 LE, size:u32 LE, file_type:u16 LE.
The file type is opaque metadata, not the download scene. The Android
`FlutterDeviceManager.syncWifiFile` explicitly passes stream scene 0. Exact-id
lookup uses `start: ID, single: 1`, since the general listing can be a delta.
Zero sizes are treated as unknown; reads remain bounded by the 512 MiB limit.

Downloaded Pro containers can use the existing encrypted-container and Ogg/Opus
pipeline. The implementation checks identity, authentication, PDU lengths/versions,
replay counters, file session/offsets, terminal chunks, and expected sizes. A
failed transfer must reconnect before another read. Only validated file progress
resets the idle deadline; an overall four-hour ceiling bounds the session. Joining the hotspot changes the Mac's Wi-Fi connection;
verify a reliable network restore path before a live Mac transfer.

## Vendor cipher constraint

The observed SDK reuses the session nonce/key across messages and transports.
This is a vendor protocol limitation: replay counters do not repair AEAD nonce
reuse. The implementation follows that wire format for interoperability, uses a
fresh hotspot password, checks the recorder serial digest, restricts accepted
peers to the verified hotspot /24 subnet, and closes the hotspot promptly.
Do not describe the vendor cipher as a strong security boundary against an
attacker who can capture the traffic.

## Evidence sources

Derived from the owner's installed Android SDK: `qi.d0` / `ri.g0` (open),
`ri.k` (close), `BleDevice.n` (SSID), `vi.t` / `vi.t0` (WebSocket server,
encryption and authentication), and `si` / `ti` request/response classes.
Private credentials, captures, and decompiled application code stay outside
this repository.

The WebSocket listener upgrades connections concurrently with Wi-Fi association.
It verifies SayHello first, then withholds the binding token until the command
checks that the actual TCP peer is on the new hotspot subnet. This avoids losing
the recorder's short WebSocket upgrade window while waiting for DHCP.

The temporary hotspot profile is forgotten before association and after restore.
This avoids reusing a cached macOS DHCP association that failed to trigger the
recorder's connection. Native validation observed Mac `192.168.43.100`, recorder
`192.168.43.1`, and no DHCP router option. The DHCP server identifies the hotspot
peer subnet when no default route is supplied.
