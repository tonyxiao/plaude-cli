# Note Pro hardware highlights

The official app has two paths for hardware "mark a moment" data:

- Embedded Ogg `PTAG` records, scanned by `HardwareMarkService`. These travel
  with the recording, including through Wi-Fi. The WAV conversion contains only
  audio, so retain the original ASR and lossless Ogg.
- Bluetooth GetRecTags opcode 38 (`0x0026`), exposed by the Android bridge as
  `action/getRecordTags`. Dart string-pool evidence places this in recovery after
  reconnecting during an active recording. It is not a validated historical-file
  mark query and is not yet exposed as a CLI command.

## Local artifacts

`files pull-one` now publishes `.asr`, `.ogg`, `.wav`, and `.metadata.json` for
supported Pro containers. The metadata JSON exports non-audio packet bytes as
hex, stream serials, Ogg granule positions, and PTAG byte offsets within those
packets. It explicitly reports `hardware_mark_timestamps_decoded: false`.
PTAG fields/time units must be checked against an actual marked recording before
adding a decoded timeline. Zero PTAG occurrences in non-audio packets is not
proof that a recording has no marks; the complete original is preserved.

Two short test recordings contain a separate `PLAUD.AI` metadata stream with
zero-filled packets and no observed PTAG bytes. The latest 7.2-second sample was
supplied as a marked recording, but neither the complete Mac Ogg nor the official
phone's identical Ogg contained `PTAG`, `GATP`, or `ptag`. The phone's Oggpa and
Mac's ASR are retained too. This does not establish why no embedded tag appeared,
and does not prove the physical button was not pressed. Exact highlight timing
remains unvalidated; preserving raw bytes is not the same as decoding marks.

## SDK-derived GetRecTags layout

Request: `01 26 00 uid:u32 LE startTimestamp:u32 LE endTimestamp:u32 LE`.
The UID is echoed and checked by the SDK. Dart logging ties the operation to the
current recording session, but the exact UID mapping remains unvalidated.

Response full-frame layout:

| Offset | Field |
| --- | --- |
| 0 | Control type 1 |
| 1..3 | Opcode 38, little endian |
| 3..7 | UID bytes |
| 7..9 | Total, u16 LE |
| 9..11 | Page index, u16 LE |
| 11.. | Up to 20 eight-byte tag records |

Each tag contains `timestamp:u32 LE`, `type:u8`, `status:u8`, and two reserved
bytes. The SDK preserves those fields. Dart's live hardware-mark processing logs
millisecond positions and applies recording-relative checks, but that alone does
not establish the units/association of every historical GetRecTags response.
Dart strings explicitly skip this request when no recording is active, and use
elapsed millisecond windows when reconnecting. Our post-stop epoch-window probe
timed out, so it was not a valid way to infer that historical marks were absent.
Do not treat this command as a finished-recording tag reader or convert raw
timestamps without an independently confirmed marked-recording comparison.

Sources: `qi.w`, `ri.y`, FlutterDeviceManager's getRecordTags bridge, and Dart
HardwareMarkService/HardwareMarkBatchProcessor object-pool strings. Private
captures and decompiled application code remain outside this repository.
