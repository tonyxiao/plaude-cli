//! `plaude files list` + `plaude files pull-one`.
//!
//! Both commands go through the authenticated [`TransportProvider`]
//! chain established in M6. `list` prints a table (text) or an array
//! (json). `pull-one` fetches the stereo PCM `.WAV` and the mono Opus
//! `.ASR` sidecar of a single recording, writes them to disk under
//! `<id>.wav` / `<id>.asr`, and reports progress via `indicatif`.
//!
//! Resume semantics in M7 are **idempotent skip**: if the target
//! file already exists with exactly the expected byte count, the
//! command is a no-op for that file. Mid-offset resume and streaming
//! writes are tracked for a later hardening milestone and require
//! range-reads on the `Transport` trait.

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use plaud_auth::DEFAULT_DEVICE_ID;
use plaud_domain::{AuthToken, Recording, RecordingId};
use plaud_transport::Transport;
use serde::Serialize;

use crate::{
    DispatchError,
    commands::{auth::build_store, backend::TransportProvider, output::OutputFormat},
};

/// Column header row for the text output of `files list`.
const TEXT_TABLE_HEADER: &str = "ID           KIND  STARTED              DURATION   SIZE";
/// Human-readable message emitted by `pull-one` when the target files
/// already exist at the expected sizes.
const ALREADY_UP_TO_DATE_MSG: &str = "already up to date";
/// Extension for the stereo PCM file.
const WAV_EXTENSION: &str = "wav";
/// Extension for the mono Opus sidecar.
const ASR_EXTENSION: &str = "asr";
/// Progress-bar template string passed to `indicatif`.
const PROGRESS_TEMPLATE: &str = "{spinner} {msg} [{bar:32.cyan/blue}] {bytes}/{total_bytes}";
/// Progress-bar progress-char string.
const PROGRESS_CHARS: &str = "=>-";
/// Error context used when a partial pre-existing file is rewritten
/// without `--resume` or rewritten from scratch during a retry.
const PARTIAL_FILE_REWRITE_CONTEXT: &str = "rewriting partial file";

/// `plaude files` subcommand tree.
#[derive(Debug, Subcommand)]
pub(crate) enum FilesCommand {
    /// List every recording on the connected device.
    List(ListArgs),
    /// Download a single recording (both `.WAV` and `.ASR`) to disk.
    PullOne(PullOneArgs),
}

/// Arguments for `plaude files list`.
#[derive(Debug, Args)]
pub(crate) struct ListArgs {
    /// Output format: `text` (default table) or `json`.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

/// Arguments for `plaude files pull-one`.
#[derive(Debug, Args)]
pub(crate) struct PullOneArgs {
    /// The recording id to pull. Matches the value printed in the
    /// `ID` column of `files list`.
    id: String,
    /// Output directory. Defaults to the current working directory.
    /// Created if missing.
    #[arg(short = 'o', long = "output-dir", value_name = "DIR")]
    output_dir: Option<PathBuf>,
    /// When set, skip files already present at the expected size.
    /// Without this flag, pre-existing files are overwritten.
    #[arg(long)]
    resume: bool,
}

/// Flat JSON projection of a [`Recording`].
#[derive(Debug, Serialize)]
struct RecordingJson {
    id: String,
    kind: String,
    started_at_unix_seconds: i64,
    wav_size: u64,
    asr_size: u64,
}

/// Entry point dispatched from `main::dispatch`.
pub(crate) async fn run(cmd: FilesCommand, provider: &dyn TransportProvider, config_dir: Option<&Path>) -> Result<(), DispatchError> {
    match cmd {
        FilesCommand::List(args) => list(args, provider, config_dir).await,
        FilesCommand::PullOne(args) => pull_one(args, provider, config_dir).await,
    }
}

async fn list(args: ListArgs, provider: &dyn TransportProvider, config_dir: Option<&Path>) -> Result<(), DispatchError> {
    let transport = authenticated_transport(provider, config_dir).await?;
    let recordings = transport
        .list_recordings()
        .await
        .map_err(|e| DispatchError::from_transport_error(&e))?;
    print_list(&recordings, args.output)
}

async fn pull_one(args: PullOneArgs, provider: &dyn TransportProvider, config_dir: Option<&Path>) -> Result<(), DispatchError> {
    let recording_id = RecordingId::new(args.id.clone()).map_err(|e| DispatchError::Usage(format!("invalid recording id: {e}")))?;
    let transport = authenticated_transport(provider, config_dir).await?;
    // Try to find the recording in the device listing. For BLE delta
    // protocol, the listing may be empty even if the recording exists.
    // If not found, attempt the download anyway with size=0 (unknown).
    let listing = transport.list_recordings().await.unwrap_or_default();
    let meta = listing.iter().find(|r| r.id() == &recording_id).cloned();
    let dir = args.output_dir.unwrap_or_else(|| PathBuf::from("."));
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| DispatchError::Runtime(format!("failed to create output dir {}: {e}", dir.display())))?;
    let wav_path = dir.join(format!("{}.{WAV_EXTENSION}", recording_id.as_str()));
    let asr_path = dir.join(format!("{}.{ASR_EXTENSION}", recording_id.as_str()));
    let wav_size = meta.as_ref().map_or(0, |m| m.wav_size());
    let asr_size = meta.as_ref().map_or(0, |m| m.asr_size());

    let primary = if args.resume
        && (file_is_already_complete(&wav_path, wav_size).await?
            || (wav_size == 0 && converted_wav_is_complete(&wav_path, &asr_path, asr_size).await))
    {
        None
    } else {
        Some(download_bytes(transport.as_ref(), &recording_id, FileKind::Wav, wav_size).await?)
    };
    let wav_written = primary.is_some();
    let raw_audio = primary.as_ref().is_some_and(|bytes| {
        plaud_transport_ble::encrypted_file::is_encrypted(bytes) || bytes.starts_with(b"OggS") || is_likely_opus(bytes)
    });
    let asr_written = if raw_audio {
        if let Some(bytes) = &primary {
            publish_wav(&asr_path, bytes.clone()).await?;
        }
        true
    } else {
        pull_file(transport.as_ref(), &recording_id, FileKind::Asr, asr_size, &asr_path, args.resume)
            .await
            .unwrap_or_default()
    };
    if let Some(raw) = primary {
        let wav = if plaud_transport_ble::encrypted_file::is_encrypted(&raw) {
            let credentials = plaud_auth::pro::load(config_dir)
                .await
                .map_err(|e| DispatchError::Runtime(e.to_string()))?
                .ok_or_else(|| DispatchError::Runtime("Pro recording decryption requires imported paired credentials".to_owned()))?;
            let ogg = plaud_transport_ble::encrypted_file::decrypt(&raw, &credentials.private_key)
                .map_err(|e| DispatchError::Runtime(e.to_string()))?;
            export_ogg_artifacts(&wav_path, &ogg).await?;
            super::decode::ogg_to_wav(&ogg).map_err(DispatchError::Runtime)?
        } else if raw.starts_with(b"OggS") {
            export_ogg_artifacts(&wav_path, &raw).await?;
            super::decode::ogg_to_wav(&raw).map_err(DispatchError::Runtime)?
        } else if is_likely_opus(&raw) {
            super::decode::opus_to_wav(&raw).map_err(DispatchError::Runtime)?
        } else {
            raw
        };
        publish_wav(&wav_path, wav).await?;
    }

    if !wav_written && !asr_written {
        println!("{} {}", recording_id.as_str(), ALREADY_UP_TO_DATE_MSG);
    }
    Ok(())
}

async fn authenticated_transport(provider: &dyn TransportProvider, config_dir: Option<&Path>) -> Result<Box<dyn Transport>, DispatchError> {
    let token = load_token(config_dir).await?;
    provider
        .connect_authenticated(token)
        .await
        .map_err(|e| DispatchError::from_transport_error(&e))
}

async fn load_token(config_dir: Option<&Path>) -> Result<AuthToken, DispatchError> {
    let store = build_store(config_dir)?;
    let stored = store
        .get_token(DEFAULT_DEVICE_ID)
        .await
        .map_err(|e| DispatchError::Runtime(format!("failed to read token store: {e}")))?;
    stored.ok_or(DispatchError::AuthRequired)
}

/// Returns `Ok(true)` if the file was written (or rewritten) and
/// `Ok(false)` if the existing on-disk file was kept thanks to
/// `--resume`. Any I/O or transport failure surfaces through
/// `DispatchError`.
async fn pull_file(
    transport: &dyn Transport,
    id: &RecordingId,
    kind: FileKind,
    expected_size: u64,
    path: &Path,
    resume: bool,
) -> Result<bool, DispatchError> {
    if resume && file_is_already_complete(path, expected_size).await? {
        return Ok(false);
    }
    let bytes = download_bytes(transport, id, kind, expected_size).await?;

    if tokio::fs::try_exists(path).await.unwrap_or(false) {
        tokio::fs::remove_file(path)
            .await
            .map_err(|e| DispatchError::Runtime(format!("{PARTIAL_FILE_REWRITE_CONTEXT} {}: {e}", path.display())))?;
    }
    tokio::fs::write(path, &bytes)
        .await
        .map_err(|e| DispatchError::Runtime(format!("failed to write {}: {e}", path.display())))?;
    Ok(true)
}

async fn download_bytes(transport: &dyn Transport, id: &RecordingId, kind: FileKind, expected_size: u64) -> Result<Vec<u8>, DispatchError> {
    // Show a progress bar during download. For BLE transfers this can
    // take minutes; for USB/sim it's instant.
    let bar = ProgressBar::new(expected_size);
    if let Ok(style) = ProgressStyle::with_template(PROGRESS_TEMPLATE) {
        bar.set_style(style.progress_chars(PROGRESS_CHARS));
    }
    bar.set_message(format!("{} {}", id.as_str(), kind.label()));
    if expected_size == 0 {
        bar.set_style(ProgressStyle::default_spinner());
    }
    bar.enable_steady_tick(std::time::Duration::from_millis(200));

    let bytes = match kind {
        FileKind::Wav => transport.read_recording(id).await,
        FileKind::Asr => transport.read_recording_asr(id).await,
    };
    let bytes = bytes.map_err(|e| {
        bar.abandon();
        DispatchError::from_transport_error(&e)
    })?;
    bar.set_length(bytes.len() as u64);
    bar.set_position(bytes.len() as u64);
    bar.finish();

    Ok(bytes)
}

async fn export_ogg_artifacts(wav_path: &Path, ogg: &[u8]) -> Result<(), DispatchError> {
    let metadata = super::decode::recording_metadata(ogg).map_err(DispatchError::Runtime)?;
    publish_wav(&wav_path.with_extension("ogg"), ogg.to_vec()).await?;
    let json = serde_json::to_vec_pretty(&metadata).map_err(|e| DispatchError::Runtime(e.to_string()))?;
    publish_wav(&wav_path.with_extension("metadata.json"), json).await
}

async fn publish_wav(path: &Path, bytes: Vec<u8>) -> Result<(), DispatchError> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        use std::io::Write;
        let parent = path.parent().ok_or_else(|| std::io::Error::other("missing output directory"))?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.write_all(&bytes)?;
        temporary.persist(path).map_err(|e| e.error)?;
        Ok(())
    })
    .await
    .map_err(|_| DispatchError::Runtime("file publication task failed".to_owned()))?
    .map_err(|e| DispatchError::Runtime(format!("failed to publish file: {e}")))
}

async fn converted_wav_is_complete(wav: &Path, asr: &Path, expected_asr_size: u64) -> bool {
    let Ok(metadata) = tokio::fs::metadata(asr).await else {
        return false;
    };
    if metadata.len() == 0 || (expected_asr_size > 0 && metadata.len() != expected_asr_size) {
        return false;
    }
    let wav = wav.to_owned();
    tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let Ok(mut file) = std::fs::File::open(wav) else {
            return false;
        };
        let Ok(metadata) = file.metadata() else {
            return false;
        };
        let mut header = [0; 44];
        if file.read_exact(&mut header).is_err() {
            return false;
        }
        let data_size = u32::from_le_bytes([header[40], header[41], header[42], header[43]]);
        let riff_size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        &header[..4] == b"RIFF"
            && &header[8..12] == b"WAVE"
            && &header[36..40] == b"data"
            && data_size > 0
            && u64::from(data_size) + 44 == metadata.len()
            && u64::from(riff_size) + 8 == metadata.len()
    })
    .await
    .unwrap_or(false)
}

/// Heuristic: check if data looks like raw Opus frames (each 80 bytes,
/// first byte is a valid Opus TOC with config >= 16 = CELT modes).
fn is_likely_opus(data: &[u8]) -> bool {
    if data.is_empty() || data.len() % 80 != 0 {
        return false;
    }
    let toc = data[0];
    let config = (toc >> 3) & 0x1F;
    // Opus configs 16..31 are CELT-only modes (the Plaud uses config 23)
    config >= 16
}

async fn file_is_already_complete(path: &Path, expected_size: u64) -> Result<bool, DispatchError> {
    match tokio::fs::metadata(path).await {
        Ok(meta) if meta.len() == expected_size => Ok(true),
        Ok(_) | Err(_) => Ok(false),
    }
}

fn print_list(recordings: &[Recording], output: OutputFormat) -> Result<(), DispatchError> {
    match output {
        OutputFormat::Text => {
            println!("{TEXT_TABLE_HEADER}");
            for r in recordings {
                let datetime = format_unix_timestamp(r.started_at_unix_seconds());
                let duration = estimate_duration(r);
                let size = display_size(r);
                println!(
                    "{:<12} {:<5} {:<20} {:<10} {}",
                    r.id().as_str(),
                    r.kind().name(),
                    datetime,
                    duration,
                    size,
                );
            }
            Ok(())
        }
        OutputFormat::Json => {
            let payload: Vec<RecordingJson> = recordings.iter().map(RecordingJson::from).collect();
            let rendered = serde_json::to_string(&payload).map_err(|e| DispatchError::Runtime(format!("json encode: {e}")))?;
            println!("{rendered}");
            Ok(())
        }
    }
}

/// Format a Unix timestamp as `YYYY-MM-DD HH:MM:SS` in the system's
/// local timezone. Cross-platform via the `jiff` crate.
fn format_unix_timestamp(epoch_secs: i64) -> String {
    let Ok(ts) = jiff::Timestamp::from_second(epoch_secs) else {
        return format!("{epoch_secs}");
    };
    let zdt = ts.to_zoned(jiff::tz::TimeZone::system());
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        zdt.year(),
        zdt.month(),
        zdt.day(),
        zdt.hour(),
        zdt.minute(),
        zdt.second(),
    )
}

/// Estimate recording duration from file sizes.
/// BLE ASR: each 80-byte Opus frame = 20ms.
/// USB WAV: PCM 16-bit mono 16kHz = 32000 bytes/sec.
fn estimate_duration(r: &Recording) -> String {
    let total_secs = if r.asr_size() > 0 {
        // Opus: 80 bytes per 20ms frame
        (r.asr_size() as f64 / 80.0) * 0.02
    } else if r.wav_size() > 0 {
        // PCM: 16-bit mono 16kHz = 32000 B/s, minus ~512 byte header
        let data = r.wav_size().saturating_sub(512);
        data as f64 / 32000.0
    } else {
        return "—".to_owned();
    };
    let mins = total_secs as u64 / 60;
    let secs = total_secs as u64 % 60;
    if mins > 0 {
        format!("{mins}m {secs:02}s")
    } else {
        format!("{secs}s")
    }
}

/// Show the available file size — only the non-zero one.
fn display_size(r: &Recording) -> String {
    if r.wav_size() > 0 && r.asr_size() > 0 {
        format!("{} wav, {} asr", format_bytes(r.wav_size()), format_bytes(r.asr_size()))
    } else if r.wav_size() > 0 {
        format!("{} wav", format_bytes(r.wav_size()))
    } else if r.asr_size() > 0 {
        format!("{} asr", format_bytes(r.asr_size()))
    } else {
        "—".to_owned()
    }
}

/// Human-readable byte size.
fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

impl From<&Recording> for RecordingJson {
    fn from(r: &Recording) -> Self {
        Self {
            id: r.id().as_str().to_owned(),
            kind: r.kind().name().to_owned(),
            started_at_unix_seconds: r.started_at_unix_seconds(),
            wav_size: r.wav_size(),
            asr_size: r.asr_size(),
        }
    }
}

/// Identifies which of the two paired files we're pulling right now.
#[derive(Debug, Clone, Copy)]
enum FileKind {
    Wav,
    Asr,
}

impl FileKind {
    fn label(self) -> &'static str {
        match self {
            Self::Wav => WAV_EXTENSION,
            Self::Asr => ASR_EXTENSION,
        }
    }
}

#[cfg(test)]
mod tests {
    use plaud_domain::{Recording, RecordingId, RecordingKind};
    use serde_json::Value;

    use super::converted_wav_is_complete;
    use super::{ALREADY_UP_TO_DATE_MSG, ASR_EXTENSION, RecordingJson, TEXT_TABLE_HEADER, WAV_EXTENSION};

    const BASENAME: &str = "1775393534";
    const WAV_SIZE: u64 = 128;
    const ASR_SIZE: u64 = 64;

    fn sample() -> Recording {
        Recording::new(RecordingId::new(BASENAME).expect("valid"), RecordingKind::Note, WAV_SIZE, ASR_SIZE)
    }

    #[test]
    fn recording_json_schema_has_stable_keys() {
        let payload = RecordingJson::from(&sample());
        let rendered = serde_json::to_string(&payload).expect("encode");
        let parsed: Value = serde_json::from_str(&rendered).expect("parse");
        assert_eq!(parsed["id"], BASENAME);
        assert_eq!(parsed["wav_size"], WAV_SIZE);
        assert_eq!(parsed["asr_size"], ASR_SIZE);
        assert!(parsed.get("kind").is_some());
        assert!(parsed.get("started_at_unix_seconds").is_some());
    }

    #[test]
    fn text_table_header_and_file_extensions_are_stable() {
        assert!(TEXT_TABLE_HEADER.starts_with("ID"));
        assert!(TEXT_TABLE_HEADER.contains("KIND"));
        assert!(TEXT_TABLE_HEADER.contains("DURATION"));
        assert!(TEXT_TABLE_HEADER.contains("SIZE"));
        assert_eq!(WAV_EXTENSION, "wav");
        assert_eq!(ASR_EXTENSION, "asr");
        assert!(ALREADY_UP_TO_DATE_MSG.contains("up to date"));
    }
    #[tokio::test]
    async fn resume_recognizes_converted_wav_using_preserved_container_size() {
        let dir = tempfile::tempdir().expect("output");
        let wav = dir.path().join("recording.wav");
        let asr = dir.path().join("recording.asr");
        std::fs::write(&asr, b"container").expect("ASR");
        let header: [u8; 48] = [
            82, 73, 70, 70, 40, 0, 0, 0, 87, 65, 86, 69, 102, 109, 116, 32, 16, 0, 0, 0, 1, 0, 1, 0, 128, 62, 0, 0, 0, 125, 0, 0, 2, 0, 16,
            0, 100, 97, 116, 97, 4, 0, 0, 0, 0, 0, 0, 0,
        ];
        std::fs::write(&wav, header).expect("WAV");
        assert!(converted_wav_is_complete(&wav, &asr, 9).await);
        assert!(!converted_wav_is_complete(&wav, &asr, 10).await);
        assert!(converted_wav_is_complete(&wav, &asr, 0).await);
        std::fs::write(&wav, b"not a WAV").expect("corrupt WAV");
        assert!(!converted_wav_is_complete(&wav, &asr, 9).await);
    }
}
