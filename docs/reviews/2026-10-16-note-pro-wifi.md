# Note Pro Wi-Fi implementation review

Claude reviewed the design, protocol/session, network lifecycle, capability
cryptography, and adapter changes in successive read-only local Claude Code runs.
No commits or PRs were created.

Resolved findings include bounded framing, actual peer subnet validation before
token transmission, progress-based idle deadlines, an overall transfer ceiling,
explicit signal/panic cleanup, network restoration despite failed Bluetooth close,
scene/file-type separation, exact-id lookup for delta listings, atomic original
container publication, lossless Ogg/metadata export, and RIFF overflow checks.

Additional SDK tracing corrected an early review hypothesis: the file-list u16
is file type, while normal file sync always requests stream scene 0. A regression
test deliberately uses file_type 4 and asserts scene 0. Live status-only opcode 12
responses are accepted; data still requires exact ID, offset, length and terminal
size. Unknown sizes never create an empty range and remain bounded at 512 MiB.

Capability opcode 138 is acknowledged once and selects Wi-Fi AES-GCM from flag 0x08.
Claude found no high/medium crypto issues after checking the SDK and tests. Tests
include an independent Python AES vector, algorithm fallback, replay rejection,
and proof that the BLE path remains ChaCha-only.

The absent-hotspot-profile concern was checked on this Mac: removing an already
absent profile exits 0, so first use is supported. Actual permission failures are
reported rather than silently reusing a cached lease. The native association
recovery fallback can briefly expose its password in local process arguments;
this tradeoff is documented. Ambiguous IDs across file types deliberately fail
rather than guess a potentially wrong size/type. Concurrent cache insertions are
deduplicated. Wi-Fi `sync` is explicitly rejected until that pipeline supports
raw Pro containers correctly.

Hardware evidence now completes the Wi-Fi journey: a fresh 31,744-byte recording
transferred over AES-GCM in 77 ms (setup excluded), decoded to a valid 7.2-second
WAV, and matched an independent Bluetooth download byte for byte. The phone then
imported it and Plaud cloud reported its transcript ready. The phone's Ogg matched
the Mac copy. The original Mac Wi-Fi was restored.

505 automated tests, two physical-adapter tests ignored, Clippy/fmt passed, signed
release installed. No source code changed during final physical verification.
Dependency auditing was not performed because cargo-audit is not installed.

Highlight timing remains unvalidated: this supplied sample had no embedded PTAG
records in either copy. The existing SDK tag query is used for live reconnect
recovery according to Dart string-pool evidence; a post-stop epoch-window probe
is not a valid historical marker test. Raw originals and metadata are preserved.
