//! Decode raw Opus frames (as received over BLE) into a PCM WAV file.
//!
//! The Plaud device sends recordings over BLE as raw Opus frames —
//! 80 bytes each, CELT-only 20 ms, mono 16 kHz. This module decodes
//! them to standard PCM WAV (16-bit, mono, 16 kHz).

use opus_decoder::OpusDecoder;

/// Number of samples per Opus frame at 16 kHz / 20 ms.
const SAMPLES_PER_FRAME: usize = 320;

/// Sample rate for Plaud recordings.
const SAMPLE_RATE: u32 = 16_000;

/// Bits per PCM sample.
const BITS_PER_SAMPLE: u16 = 16;

/// Mono channel count.
const NUM_CHANNELS: u16 = 1;

/// Size of each raw Opus frame from the BLE bulk transfer.
const OPUS_FRAME_SIZE: usize = 80;

/// Decode raw Opus frames into a WAV byte vector.
///
/// `raw_opus` is the concatenated 80-byte Opus frames from the BLE
/// bulk transfer. Returns a complete WAV file (RIFF header + PCM data)
/// or an error description.
pub(crate) fn opus_to_wav(raw_opus: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = OpusDecoder::new(SAMPLE_RATE, NUM_CHANNELS as usize).map_err(|e| format!("opus init: {e}"))?;

    let frame_count = raw_opus.len() / OPUS_FRAME_SIZE;
    let mut pcm_samples: Vec<i16> = Vec::with_capacity(frame_count * SAMPLES_PER_FRAME);
    let mut frame_buf = vec![0i16; SAMPLES_PER_FRAME * 2]; // generous buffer

    for (i, chunk) in raw_opus.chunks_exact(OPUS_FRAME_SIZE).enumerate() {
        let decoded = decoder
            .decode(chunk, &mut frame_buf, false)
            .map_err(|e| format!("opus decode frame {i}: {e}"))?;
        pcm_samples.extend_from_slice(&frame_buf[..decoded]);
    }

    build_wav(&pcm_samples)
}

/// Decode the Opus logical stream from CRC-checked Ogg pages, ignoring metadata streams.
pub(crate) fn ogg_to_wav(ogg: &[u8]) -> Result<Vec<u8>, String> {
    let mut reader = ogg::reading::PacketReader::new(std::io::Cursor::new(ogg));
    let mut stream = None;
    let mut decoder = None;
    let mut expect_tags = false;
    let mut skip = 0;
    let mut end = None;
    let mut initial_granule_offset = None;
    let mut pcm = Vec::new();
    let mut frame_buf = vec![0_i16; 1920]; // maximum120ms at16kHz mono
    while let Some(packet) = reader.read_packet().map_err(|e| format!("invalid Ogg recording: {e}"))? {
        if stream.is_none() {
            if !packet.data.starts_with(b"OpusHead") {
                continue;
            }
            if packet.data.len() < 19 || packet.data[8] != 1 || packet.data[9] != 1 || packet.data[18] != 0 {
                return Err("unsupported Opus channel mapping/version (expected mono)".to_owned());
            }
            skip = usize::from(u16::from_le_bytes([packet.data[10], packet.data[11]])) / 3;
            stream = Some(packet.stream_serial());
            decoder = Some(OpusDecoder::new(SAMPLE_RATE, 1).map_err(|e| format!("opus init: {e}"))?);
            expect_tags = true;
            continue;
        }
        if Some(packet.stream_serial()) != stream {
            continue;
        }
        if expect_tags {
            if !packet.data.starts_with(b"OpusTags") {
                return Err("Opus tags packet is missing".to_owned());
            }
            expect_tags = false;
            continue;
        }
        let decoder = decoder.as_mut().ok_or_else(|| "Opus decoder was not initialized".to_owned())?;
        let decoded = decoder
            .decode(&packet.data, &mut frame_buf, false)
            .map_err(|e| format!("Opus packet decode failed: {e}"))?;
        pcm.extend_from_slice(&frame_buf[..decoded]);
        if packet.last_in_page() && !packet.last_in_stream() && initial_granule_offset.is_none() && packet.absgp_page() != u64::MAX {
            let granule = usize::try_from(packet.absgp_page() / 3).map_err(|_| "invalid Opus granule position".to_owned())?;
            initial_granule_offset = Some(granule.saturating_sub(pcm.len()));
        }
        if packet.last_in_stream() {
            end = Some(usize::try_from(packet.absgp_page() / 3).map_err(|_| "invalid Opus granule position".to_owned())?);
            break;
        }
    }
    let end = end
        .ok_or_else(|| "incomplete Ogg Opus stream".to_owned())?
        .saturating_sub(initial_granule_offset.unwrap_or(0));
    if end > pcm.len() || skip > end {
        return Err("Opus granule exceeds decoded audio".to_owned());
    }
    build_wav(&pcm[skip..end])
}

/// Build a minimal WAV file from PCM i16 samples.
fn checked_wav_size(sample_count: usize) -> Result<u32, String> {
    sample_count
        .checked_mul(2)
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n <= u32::MAX - 36)
        .ok_or_else(|| "decoded recording exceeds RIFF WAV size limit; original ASR/Ogg retained".to_owned())
}

fn build_wav(samples: &[i16]) -> Result<Vec<u8>, String> {
    let data_size = checked_wav_size(samples.len())?;
    let byte_rate = SAMPLE_RATE * u32::from(NUM_CHANNELS) * u32::from(BITS_PER_SAMPLE) / 8;
    let block_align = NUM_CHANNELS * BITS_PER_SAMPLE / 8;
    let file_size = 36 + data_size;

    let mut wav = Vec::with_capacity(44 + data_size as usize);
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&file_size.to_le_bytes());
    wav.extend_from_slice(b"WAVE");
    wav.extend_from_slice(b"fmt ");
    wav.extend_from_slice(&16u32.to_le_bytes());
    wav.extend_from_slice(&1u16.to_le_bytes()); // PCM
    wav.extend_from_slice(&NUM_CHANNELS.to_le_bytes());
    wav.extend_from_slice(&SAMPLE_RATE.to_le_bytes());
    wav.extend_from_slice(&byte_rate.to_le_bytes());
    wav.extend_from_slice(&block_align.to_le_bytes());
    wav.extend_from_slice(&BITS_PER_SAMPLE.to_le_bytes());
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&data_size.to_le_bytes());
    for &sample in samples {
        wav.extend_from_slice(&sample.to_le_bytes());
    }
    Ok(wav)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_wav_produces_valid_riff_header() {
        let samples = vec![0i16; 320];
        let wav = build_wav(&samples).unwrap();
        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
        assert_eq!(&wav[12..16], b"fmt ");
        assert_eq!(&wav[36..40], b"data");
    }
    #[test]
    fn ogg_decoder_selects_audio_and_trims_preskip_and_padding() {
        let ogg = include_bytes!("../../tests/fixtures/pro-multiplexed-silence.ogg");
        let wav = ogg_to_wav(ogg).expect("multiplexed Ogg");
        assert_eq!(&wav[..4], b"RIFF");
        assert_eq!(wav.len(), 44 + 1920 * 2);
        assert_eq!(&wav[24..28], &16_000_u32.to_le_bytes());
    }

    #[test]
    fn ogg_decoder_rejects_corrupt_audio_pages() {
        let mut ogg = include_bytes!("../../tests/fixtures/pro-multiplexed-silence.ogg").to_vec();
        let last = ogg.len() - 1;
        ogg[last] ^= 1;
        assert!(ogg_to_wav(&ogg).is_err());
    }
    #[test]
    fn ogg_decoder_accounts_for_nonzero_initial_audio_granule() {
        let ogg = include_bytes!("../../tests/fixtures/pro-offset-silence.ogg");
        let wav = ogg_to_wav(ogg).expect("offset granule");
        assert_eq!(wav.len(), 44 + 19_200 * 2);
    }
}

#[cfg(test)]
mod metadata_tests {
    #[test]
    fn exports_non_audio_packets_without_discarding_hardware_mark_bytes() {
        let fixture = include_bytes!("../../tests/fixtures/pro-multiplexed-silence.ogg");
        let meta = super::recording_metadata(fixture).unwrap();
        assert!(!meta["non_audio_packets"].as_array().unwrap().is_empty());
        assert_eq!(meta["hardware_mark_timestamps_decoded"], false);
        let mut corrupt = fixture.to_vec();
        corrupt[30] ^= 1;
        assert!(super::recording_metadata(&corrupt).is_err());
    }
}

/// Export CRC-checked non-audio Ogg packets without guessing proprietary tag layout.
pub(crate) fn recording_metadata(ogg: &[u8]) -> Result<serde_json::Value, String> {
    use std::collections::HashSet;
    let mut reader = ogg::reading::PacketReader::new(std::io::Cursor::new(ogg));
    let mut audio = HashSet::new();
    let mut packets = Vec::new();
    let mut ptag_count = 0;
    while let Some(packet) = reader.read_packet().map_err(|e| format!("invalid Ogg metadata: {e}"))? {
        if packet.data.starts_with(b"OpusHead") {
            audio.insert(packet.stream_serial());
        }
        if audio.contains(&packet.stream_serial()) {
            continue;
        }
        let ptag_offsets: Vec<usize> = packet
            .data
            .windows(4)
            .enumerate()
            .filter_map(|(i, w)| (w == b"PTAG").then_some(i))
            .collect();
        ptag_count += ptag_offsets.len();
        let hex: String = packet.data.iter().map(|b| format!("{b:02x}")).collect();
        packets.push(serde_json::json!({"stream_serial":packet.stream_serial(),"granule_position":packet.absgp_page(),"data_hex":hex,"ptag_offsets":ptag_offsets}));
    }
    Ok(
        serde_json::json!({"format_version":1,"non_audio_packets":packets,"ptag_occurrences":ptag_count,"hardware_mark_timestamps_decoded":false,"note":"Proprietary hardware marks are preserved in the original ASR and lossless Ogg; PTAG timestamps require further format validation."}),
    )
}

#[cfg(test)]
mod wav_size_tests {
    #[test]
    fn rejects_riff_overflow_without_allocating_audio() {
        assert_eq!(super::checked_wav_size(16000).unwrap(), 32000);
        assert!(super::checked_wav_size(usize::MAX).is_err());
        assert!(super::checked_wav_size((u32::MAX as usize) / 2).is_err());
    }
}
