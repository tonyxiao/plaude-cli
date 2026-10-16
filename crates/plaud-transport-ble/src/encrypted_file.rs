//! Note Pro encrypted recording container support.

use plaud_transport::{Error, Result};

/// Recognize the Pro recording header.
#[must_use]
pub fn is_encrypted(data: &[u8]) -> bool {
    data.starts_with(b"PLAUD.AI")
}

/// Unwrap the file key and decrypt the observed continuous-stream container.
/// The returned Ogg stream must be CRC-checked by the audio decoder.
///
/// # Errors
/// Rejects unsupported/corrupt headers, invalid RSA envelopes, or invalid plaintext.
pub fn decrypt(data: &[u8], private_key: &str) -> Result<Vec<u8>> {
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use rsa::pkcs8::DecodePrivateKey;
    if data.len() < 512 || !is_encrypted(data) {
        return Err(Error::Protocol("invalid Pro recording header".to_owned()));
    }
    if data[8..10] != [1, 0] || data[10..12] != [0, 2] || data[144..256].iter().any(|byte| *byte != 0) {
        return Err(Error::Unsupported {
            capability: "unsupported Pro recording header/segmented encryption",
        });
    }
    let expected_crc = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    if expected_crc != u32::from(header_crc(&data[16..512])) {
        return Err(Error::Protocol("Pro recording header checksum mismatch".to_owned()));
    }
    let private = rsa::RsaPrivateKey::from_pkcs8_pem(private_key).map_err(|_| Error::Protocol("invalid Pro RSA private key".to_owned()))?;
    let key = zeroize::Zeroizing::new(
        private
            .decrypt_blinded(&mut rsa::rand_core::OsRng, rsa::Pkcs1v15Encrypt, &data[256..512])
            .map_err(|_| Error::Protocol("cannot unwrap Pro recording key".to_owned()))?,
    );
    if key.len() != 32 {
        return Err(Error::Protocol("invalid Pro recording key length".to_owned()));
    }
    let mut plaintext = data[512..].to_vec();
    let mut cipher = chacha20::ChaCha20::new_from_slices(&key, &data[132..144])
        .map_err(|_| Error::Protocol("invalid Pro recording cipher parameters".to_owned()))?;
    cipher
        .try_apply_keystream(&mut plaintext)
        .map_err(|_| Error::Protocol("Pro recording exceeds cipher length limit".to_owned()))?;
    if !plaintext.starts_with(b"OggS") {
        return Err(Error::Protocol("Pro recording decryption did not produce Ogg audio".to_owned()));
    }
    Ok(plaintext)
}

fn header_crc(data: &[u8]) -> u16 {
    let mut crc = 0xffff_u16;
    for byte in data {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypts_independently_generated_container() {
        let data = include_bytes!("../tests/fixtures/pro-test-recording.asr");
        let private = include_str!("../tests/fixtures/pro-test-private.pem");
        assert_eq!(
            decrypt(data, private).expect("Pro file"),
            b"OggSsynthetic plaintext for encryption fixture"
        );
    }

    #[test]
    fn rejects_corrupt_container_header() {
        let mut data = include_bytes!("../tests/fixtures/pro-test-recording.asr").to_vec();
        data[20] ^= 1;
        let private = include_str!("../tests/fixtures/pro-test-private.pem");
        assert!(decrypt(&data, private).is_err());
    }
}
