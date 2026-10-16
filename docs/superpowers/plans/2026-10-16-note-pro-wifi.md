# Note Pro Wi-Fi implementation plan

Goal: implement the approved native Mac fast-download design in ../specs/2026-10-16-note-pro-wifi-design.md.
User approved implementation without further review gates and requested Claude reviews during implementation.
Work in existing checkout to retain the uncommitted working Mac/Pro support. No git operations.

- [x] Protocol: add bounded binary framing, list/data parsing and synthetic tests; demonstrate red then green.
- [x] Crypto: expose independent session cipher for Wi-Fi without exposing key material in logs; verify existing BLE behavior.
- [x] Session: encrypted WebSocket hello/auth/list/read with loopback tests, deadlines, replay handling, heartbeat and stop.
- [x] Mac network lifecycle: determine live SSID/restore capability; explicit setup and async cleanup, Ctrl-C, failure restoration tests.
- [x] CLI: integrate explicit Wi-Fi backend, reuse ASR/WAV pipeline; preserve cloud import and pairing.
- [x] Marker investigation: inspect metadata stream and SDK for hardware highlight timing; preserve/export available metadata.
- [x] Claude review of protocol/session and final integration; resolve findings.
- [x] Full automated checks and signed install: 505 passing tests, 2 physical-adapter tests explicitly ignored, Clippy/fmt passed. cargo-audit unavailable.
- [x] Native AES Wi-Fi hello/auth/list/exact-id lookup and Mac network restoration verified. Cloud import verified after local Bluetooth retrieval.
- [x] Fresh Wi-Fi payload: 31,744 bytes in 77 ms, 7.2-second WAV, Bluetooth byte comparison identical, original Mac network restored.
- [x] Official phone/cloud import after Wi-Fi download: cloud absent before phone import, present afterward with transcript ready; phone Ogg identical to Mac.
- [ ] Exact saved-highlight timing: supplied sample has no embedded PTAG in either Mac or phone Ogg. Raw originals/metadata retained; live GetRecTags semantics documented without claiming a finished-file decoder.
