# Note Pro Wi-Fi download design

## Goal and user interface

Add `--backend wifi` for Note Pro file listing and downloads on this Mac. Reuse
`files list`, `files pull-one`, and the existing encrypted-container decoder.
Bluetooth remains the default. Wi-Fi selection is explicit because joining the
recorder hotspot temporarily replaces the Mac's normal Wi-Fi connection.

## Approach

Implement the existing `plaud-transport-wifi` crate as an encrypted WebSocket
server and a transport adapter. Authenticate Bluetooth with the owner's existing
credentials, start a TCP 8081 listener, request normal-mode Wi-Fi using BLE opcode
0x000a, join the hotspot, validate the recorder's SayHello identity, authenticate
with the existing binding token, and transfer recording bytes. Wi-Fi gets its own
sequence counters using negotiated session material. Confirm the selected cipher
and framing with the device rather than treating SDK findings as live evidence.

Keep protocol framing, authenticated session handling, file assembly, and macOS
network association in separate modules. The CLI provider coordinates these
modules and retains the authenticated Bluetooth connection for hotspot cleanup.
Use bounded messages, checked lengths, fixed request deadlines, and explicit
errors for unsupported operations. Tokens and session material must not appear
in logs. Do not broaden Keychain access or replace pairing keys.

## Network lifecycle

Before switching networks, record the current network and verify an actionable
restore method. Abort before switching if that cannot be established. Bind the
listener before opening the hotspot. Verify hotspot identity and negotiate a
password if supported; do not assume that the observed response supplies one.

On success, failure, timeout, and Ctrl-C: stop the active transfer, close the
hotspot with BLE opcode 0x000d, and restore the original Mac network. Report any
cleanup failure explicitly. Ensure cancellation does not drop the cleanup work
before it finishes. A process killed forcibly cannot guarantee application-level
cleanup; provide a concrete manual network restore instruction in that case.

## Cloud compatibility

Downloads copy data without issuing delete or mark-synced commands. Preserve the
original encrypted ASR and publish the decoded WAV atomically, using the existing
pipeline. Never invoke Wi-Fi opcode 14 (delete). Do not change the device owner,
RSA key pair, or binding token.

Firmware may update transfer state implicitly. Therefore cloud compatibility is
an acceptance check, not an assumption: after downloading a fresh recording on
the Mac, reconnect the official phone app and verify that the recording can still
be imported and appears in the user's cloud account. If it disappears from the
phone's pending list or cannot import, investigate before claiming compatibility.
Do not silently work around that by deleting or rebinding anything.

## Alternatives considered

- Manual hotspot association: simpler, but leaves routine network recovery to the
  user. Keep manual association available as a diagnostic option if needed.
- Android app as transfer proxy: useful for protocol captures, but creates an
  unnecessary phone dependency for normal Mac downloads.
- Recommended: native Rust transport plus macOS association/restoration, with
  portable protocol tests and clear unsupported behavior on other platforms
  until their association adapters exist.

## Validation and completion

Write failing tests before implementing each protocol behavior. Exercise a fake
recorder over a real loopback WebSocket connection: hello/auth/list/download,
malformed lengths, wrong identity, bad authentication, replay, offset mismatch,
truncated transfer, timeout, and cancellation. Test network cleanup through an
injected network adapter, including setup failure and transfer failure.

Run workspace tests and `make lint`, install the signed CLI, and download the
existing test recording over Wi-Fi. Compare encrypted bytes with the known-good
Bluetooth download, decode the WAV, and report elapsed transfer time separately
from association time. Use a fresh recording for the phone/cloud acceptance
check. Update usage and protocol docs with measured behavior and limitations.

No commits, pushes, or PRs are included without an explicit request.
