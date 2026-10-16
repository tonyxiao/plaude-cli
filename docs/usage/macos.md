# macOS and Note Pro setup

Requirements: Rust 1.85+, Xcode Command Line Tools, and CMake (`brew install cmake`).

```sh
make install
plaude battery
```

The installer uses the unique available code-signing identity on macOS. With
multiple identities, select one explicitly:

```sh
make install CODESIGN_IDENTITY="Apple Development: Your Name (TEAMID)"
```

The signed tool is installed at `~/.cargo/bin/plaude`. Use that installed path
for real Keychain access. Cargo's debug executables have changing ad-hoc identities;
"Always Allow" grants can stop matching after each rebuild. `make install` signs
with the stable identifier `com.tonyxiao.plaude-cli`. A new identity may require one
initial grant for each credential entry. Entries created by older ad-hoc binaries
can retain build-hash access rules. After verifying a private credential backup,
clear and re-import those entries using the signed installed tool. Without a signing certificate, installation
still works, but Keychain grants may need renewing after rebuilds.

Allow Bluetooth access for the terminal/application when macOS asks. Keep the
recorder nearby and disconnect the Plaud phone app before connecting.

## Note Pro

The Pro uses RSA and ChaCha20-Poly1305 session setup. A plaintext token alone is
insufficient. Import the owner's existing paired app credentials once:

```sh
plaude auth import-pro /path/to/private-pro-credentials.json
plaude auth show
plaude device info
plaude files list
```

The JSON requires `snSignature` (base64), `userRSAPublicKey` (PEM),
`userRSAPrivateKey` (PKCS#8 PEM), and `token` (existing device binding token).
Import validates the RSA pair and stores the complete bundle in macOS Keychain.
`auth clear` removes the bundle and the legacy token. Explicit `--config-dir`
sandboxes use a private, atomically written `pro-credentials.json`; on Linux the
bundle also uses that file. Never commit the credentials or diagnostic captures.

The existing paired Android SDK supplies these fields through its
`action/sendGlobalData` method-channel calls. They can be obtained locally from
SDK diagnostics on the owner's phone; the encrypted Bluetooth capture alone does
not contain a plaintext token. Account JWTs and `/device/apply-token` licenses
are different credentials and cannot substitute for the binding token.

Pro connections replay the existing signed serial, reuse the owner's RSA pair,
and negotiate fresh session keys. They do not use the force-clear (`0xfe20`) flow.

## Compatibility and limits

- CoreBluetooth supports original Note and observed Note Pro discovery profiles.
- The Pro fallback requires manufacturer `0x005d` and discovery service `0x504c`
  when macOS omits its local name. Discovery watches updates for up to 15 seconds
  and returns as soon as a candidate is found.
- `files pull-one` preserves the encrypted Pro `.asr`, unwraps its file key,
  validates the header and Ogg pages, and atomically publishes a playable mono WAV.
  The observed version 1 continuous-stream format is supported; segmented or
  other header layouts fail explicitly and retain the original container.
- Transcription uses Metal; default builds include speaker diarization and LLM tools.
- `auth bootstrap` still uses Linux/BlueZ and impersonates the original Note.
- The existing BLE file-list command is a delta listing; files already synced by
  the phone may not appear. Keep the phone app closed when testing a new recording.
- Some original device-info fields remain placeholders or conservative estimates;
  do not use the displayed firmware/serial or recording count as authoritative inventory.

For the encrypted wire format, see [Note Pro protocol](../protocol/note-pro.md).

## Note Pro Wi-Fi fast transfer

Use `--backend wifi` for file listing and `files pull-one`. Bluetooth authenticates
and starts a temporary hotspot; bulk bytes use encrypted WebSocket messages.
`sync` and device mutations are not supported by this backend.

Create a private `wifi.json` alongside the normal configuration files (on macOS,
`~/Library/Application Support/plaude/wifi.json`; an explicit `--config-dir` uses
that directory). Example:

```json
{
  "serial": "YOUR_FULL_RECORDER_SERIAL",
  "interface": "en0",
  "restore_ssid": "YOUR_CURRENT_SAVED_WIFI",
  "restore_password_file": "/absolute/path/to/private-wifi-password"
}
```

The serial verifies the recorder's SayHello identity. The hotspot defaults to
`Plaud` plus the serial's last four characters; add `"ssid": "ACTUAL_HOTSPOT_NAME"`
for older firmware using `PLAUD` uppercase. The cloud account's `prot_version`
field does not reliably identify the live Bluetooth/Wi-Fi protocol version.

`restore_ssid` must already be a saved Mac network. When macOS hides the current
SSID for Location Services privacy, this explicit value is the trusted restore
target: confirm it matches the currently connected network. The password file is
required for reliable automatic restoration and must be mode 0600. Keep both files outside source control. The native
CoreWLAN restore helper receives passwords over stdin. Hotspot association uses
macOS `networksetup` with a fresh temporary hotspot password; that temporary
password can appear in process arguments until association completes. The installed Apple Swift interpreter
from Xcode Command Line Tools hosts that helper.

```sh
chmod 600 "$HOME/Library/Application Support/plaude/wifi.json"
plaude --backend wifi files list
plaude --backend wifi files pull-one RECORDING_ID -o ~/plaud-recordings
```

Keep the recorder powered and awake, with the phone app closed. The command
briefly replaces the Mac's Wi-Fi connection, then closes the hotspot and restores
the configured original network. It also attempts cleanup after failed setup,
Ctrl-C, SIGTERM, SIGHUP, and command panics. A forced kill or power failure cannot
run cleanup; reconnect the configured `restore_ssid` in macOS Wi-Fi settings.
Restoration errors are reported even when the audio downloaded successfully.

Automatic setup currently requires IPv4 DHCP and distinct home/hotspot /24
subnets. It uses the DHCP router or server when the isolated hotspot omits a
default route, and rejects ambiguous network state. If the recorder closes Bluetooth
before cleanup, hotspot closure cannot be confirmed and is reported. The signed
installed binary may require macOS firewall permission to accept the recorder's
incoming connection on TCP 8081. If native restoration cannot find the saved
network, cleanup retries and uses macOS `networksetup` as a recovery fallback;
that fallback passes the password through a process argument temporarily.

Pro downloads preserve the encrypted `.asr`, a lossless decrypted `.ogg`, the
playable `.wav`, and `.metadata.json` containing CRC-checked non-audio Ogg packets.
Hardware highlights may use embedded `PTAG` records; their bytes are preserved.
`hardware_mark_timestamps_decoded: false` explicitly means the proprietary timing
layout has not yet been validated. A WAV by itself does not preserve those marks.
See [hardware marks](../protocol/hardware-marks.md).

Downloads send neither delete nor mark-synced commands and preserve existing
pairing keys. Firmware can still change transfer state internally; phone/cloud
compatibility must be verified with a fresh recording before relying on both
paths. Do not equate a successful local download with a completed cloud import.

Live verification succeeded with a fresh 7.2-second recording: 31,744 encrypted
bytes transferred in 77 ms, excluding setup. The Bluetooth copy matched exactly.
The official phone app then imported it normally, and Plaud cloud listed the
recording with its transcript ready. The phone's Ogg matched the Mac's Ogg too.

This sample had no `PTAG` records in either copy, so saved-highlight timing has
not yet been validated. The unchanged originals and opaque metadata are retained.
See [hardware marks](../protocol/hardware-marks.md) for what is known and inferred.
