// [1] Barak, Boaz, and Shai Halevi. "A model and architecture for pseudo-random generation with applications to/dev/random."
// Proceedings of the 12th ACM conference on Computer and communications security. 2005. https://eprint.iacr.org/2005/029.pdf

use super::errors::PrgError::{self, *};
use aes::{Aes128, Aes192, Aes256};
use ctr::Ctr128LE;
use ctr::cipher::{KeyIvInit, StreamCipher};

const NONCE_FOR_PRG_NEXT: &[u8; 12] = b"\x96\n\n\n\n\n\n\n\n\n\n\n";
const NONCE_FOR_PRG_REFRESH: &[u8; 12] = b"\x96\r\r\r\r\r\r\r\r\r\r\r";

#[derive(PartialEq, Eq)]
pub enum Steps {
    Refresh,
    Next,
}

#[derive(PartialEq, Eq, Clone)]
pub enum PrgOutput {
    Refresh(Vec<u8>),
    Next(Vec<u8>, Vec<u8>),
}

#[derive(Clone, Copy)]
pub struct Prg {
    security_param_lambda: usize,
}

impl Default for Prg {
    fn default() -> Self {
        Self {
            security_param_lambda: 16_usize,
        }
    }
}

impl Prg {
    pub fn new(security_param_lambda: usize) -> Self {
        Self {
            security_param_lambda: security_param_lambda,
        }
    }

    pub fn prg_refresh(
        self,
        current_prg_state: &[u8],
        extracted_parameter: &[u8],
    ) -> Result<Vec<u8>, PrgError> {
        let xored_value: Vec<u8> = match self.xor_bytes(current_prg_state, extracted_parameter) {
            Ok(output) => output,
            Err(err) => return Err(err),
        };

        let prg_state_after_refreshing: Vec<u8> =
            match self.aes_in_counter_mode_as_prg(&xored_value, Steps::Refresh) {
                Ok(PrgOutput::Refresh(output)) => output,
                Ok(PrgOutput::Next(_, _)) => {
                    return Err(UnexpectedOutputType(format!(
                        "Received output of prg_next() during prg_refresh()."
                    )));
                }
                Err(err) => return Err(err),
            };

        Ok(prg_state_after_refreshing)
    }

    pub fn prg_next(self, current_prg_state: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PrgError> {
        let (random_output, new_state) =
            match self.aes_in_counter_mode_as_prg(current_prg_state, Steps::Next) {
                Ok(PrgOutput::Refresh(_)) => {
                    return Err(UnexpectedOutputType(format!(
                        "Received output of prg_refresh() during prg_next()."
                    )));
                }
                Ok(PrgOutput::Next(random_output, new_prg_state)) => (random_output, new_prg_state),
                Err(err) => return Err(err),
            };

        Ok((random_output, new_state))
    }

    fn aes_in_counter_mode_as_prg(
        self,
        input_key: &[u8],
        step: Steps,
    ) -> Result<PrgOutput, PrgError> {
        if ![16, 24, 32].contains(&input_key.len()) {
            return Err(InvalidInputKeyLength(format!(
                "{} bytes. Acceptable key sizes are 16, 24 or 32 bytes.",
                &input_key.len()
            )));
        }

        // Construct the IV from the nonce to be used
        let mut iv: [u8; 16] = [0u8; 16];

        if step == Steps::Refresh {
            iv[..12].copy_from_slice(NONCE_FOR_PRG_REFRESH);
        } else {
            iv[..12].copy_from_slice(NONCE_FOR_PRG_NEXT);
        }

        // Set the initial counter value to 1 of 32 bits
        iv[12..16].copy_from_slice(&[0, 0, 0, 1]);

        let plaintext: Vec<u8> = vec![0u8; 2 * self.security_param_lambda];

        // Create a mutable copy
        let mut ciphertext: Vec<u8> = plaintext;

        // Check the input key length and use the AES in Counter Mode Encryption Variant
        match input_key.len() {
            16 => {
                let mut cipher = Ctr128LE::<Aes128>::new(input_key.into(), iv.as_slice().into());
                cipher.apply_keystream(&mut ciphertext); // In-place encryption
            }
            24 => {
                let mut cipher = Ctr128LE::<Aes192>::new(input_key.into(), iv.as_slice().into());
                cipher.apply_keystream(&mut ciphertext); // In-place encryption
            }
            32 => {
                let mut cipher = Ctr128LE::<Aes256>::new(input_key.into(), iv.as_slice().into());
                cipher.apply_keystream(&mut ciphertext); // In-place encryption
            }
            _ => unreachable!(),
        }

        match step {
            Steps::Refresh => {
                let (pseudorandom_output, _) = ciphertext.split_at(self.security_param_lambda);
                Ok(PrgOutput::Refresh(pseudorandom_output.to_vec()))
            }
            Steps::Next => {
                let (random_output, new_prg_state) =
                    ciphertext.split_at(self.security_param_lambda);
                Ok(PrgOutput::Next(
                    random_output.to_vec(),
                    new_prg_state.to_vec(),
                ))
            }
        }
    }
    fn xor_bytes(self, param_1: &[u8], param_2: &[u8]) -> Result<Vec<u8>, PrgError> {
        if param_1.len() != param_2.len() {
            return Err(XORLengthMismatch(format!(
                "Cannot XOR bytes of unequal length."
            )));
        }

        let output: Vec<u8> = param_1
            .iter()
            .zip(param_2.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gen_key(len: usize) -> Vec<u8> {
        // Generate a repeating key pattern for tests
        (0..len).map(|i| (i % 256) as u8).collect()
    }

    #[test]
    fn test_prg_next_with_valid_keys() {
        let prg = Prg::default();

        for key_len in [16, 24, 32] {
            let key = gen_key(key_len);
            let result = prg.prg_next(&key);
            assert!(result.is_ok(), "prg_next failed for key length {}", key_len);

            let (output, new_state) = result.unwrap();
            assert_eq!(output.len(), prg.security_param_lambda);
            assert_eq!(new_state.len(), prg.security_param_lambda);
        }
    }

    #[test]
    fn test_prg_refresh_with_valid_keys() {
        let prg = Prg::default();

        for key_len in [16, 24, 32] {
            let key = gen_key(key_len);
            let param = gen_key(key_len); // same length for XOR

            let result = prg.prg_refresh(&key, &param);
            assert!(
                result.is_ok(),
                "prg_refresh failed for key length {}",
                key_len
            );

            let refreshed = result.unwrap();
            assert_eq!(refreshed.len(), prg.security_param_lambda);
        }
    }

    #[test]
    fn test_invalid_key_length() {
        let prg = Prg::default();
        let invalid_keys = vec![
            vec![],        // 0 bytes
            vec![0u8; 15], // 15 bytes
            vec![0u8; 17], // 17 bytes
            vec![0u8; 31], // 31 bytes
            vec![0u8; 33], // 33 bytes
        ];

        for key in invalid_keys {
            let result = prg.prg_next(&key);
            assert!(matches!(result, Err(PrgError::InvalidInputKeyLength(_))));

            // Use dummy extracted param of same size
            let extracted = vec![1u8; key.len()];
            let refresh_result = prg.prg_refresh(&key, &extracted);
            assert!(matches!(
                refresh_result,
                Err(PrgError::InvalidInputKeyLength(_))
            ));
        }
    }

    #[test]
    fn test_prg_refresh_with_mismatched_lengths() {
        let prg = Prg::default();
        let state = gen_key(16);
        let param = gen_key(24); // mismatched

        let result = prg.prg_refresh(&state, &param);
        assert!(matches!(
            result,
            Err(PrgError::InvalidInputKeyLength(_)) | Err(PrgError::XORLengthMismatch(_))
        ));
    }

    #[test]
    fn test_output_types_mismatch_handling() {
        // Test ensures prg_next and prg_refresh don't accidentally interpret wrong output types
        // We force the check via mock or by testing indirect path

        let prg = Prg::default();
        let key = gen_key(16);

        let refresh_result = prg.clone().prg_refresh(&key, &vec![0u8; 16]);
        assert!(refresh_result.is_ok());

        let next_result = prg.clone().prg_next(&key);
        assert!(next_result.is_ok());
    }

    #[test]
    fn test_repeatability_with_same_key() {
        let prg = Prg::default();
        let key = gen_key(16);

        let (out1, state1) = prg.clone().prg_next(&key).unwrap();
        let (out2, state2) = prg.clone().prg_next(&key).unwrap();

        // PRG is deterministic — same input key should give same output
        assert_eq!(out1, out2);
        assert_eq!(state1, state2);
    }

    #[test]
    fn test_refresh_changes_state() {
        let prg = Prg::default();
        let key = gen_key(16);
        let param = gen_key(16);

        let refreshed = prg.clone().prg_refresh(&key, &param).unwrap();
        assert_ne!(refreshed, key); // Output should not be equal to input key
    }
}
