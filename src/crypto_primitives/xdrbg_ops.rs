// [1] Kelsey, John, Stefan Lucks, and Stephan Müller. "XDRBG: A Proposed Deterministic Random Bit Generator Based on Any XOF."
// IACR Transactions on Symmetric Cryptology 2024.1 (2024): 5-34. https://tosc.iacr.org/index.php/ToSC/article/view/11399

use super::errors::Errors::{self, *};
use ascon_hash::AsconXof128;
use sha3::{
    Shake128, Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

const MAX_LEN_ALPHA: usize = 84;

#[derive(Clone, Copy, Debug)]
pub enum XdrbgOps {
    Instantiate,
    Reseed,
}

#[derive(Clone, Copy, Debug)]
pub enum Xof {
    Shake128,
    Shake256,
    Ascon,
}

impl Xof {
    pub fn state_size(&self) -> usize {
        match self {
            Self::Shake128 => 32,
            Self::Shake256 => 64,
            Self::Ascon => 32,
        }
    }

    pub fn are_params_okay(&self, seed: &[u8], alpha: &[u8], ops: XdrbgOps) -> Result<(), Errors> {
        match ops {
            XdrbgOps::Instantiate => {
                self.check_size_of_seed(seed, self.min_seed_size_instantiate(), ops)?;
                self.check_size_of_alpha(alpha)
            }
            XdrbgOps::Reseed => {
                self.check_size_of_seed(seed, self.min_seed_size_reseed(), ops)?;
                self.check_size_of_alpha(alpha)
            }
        }
    }

    pub fn is_output_length_okay(&self, output_key_length: usize) -> Result<(), Errors> {
        if (output_key_length + self.state_size()) > self.max_total_output_size() {
            return Err(InvalidLength(format!(
                "Requested output and XOF state size: {} + {} = {} bytes. Acceptable length is <= {} bytes for the XOF {:?}.",
                output_key_length,
                self.state_size(),
                output_key_length + self.state_size(),
                self.max_total_output_size(),
                self,
            )));
        }

        Ok(())
    }

    fn min_seed_size_instantiate(&self) -> usize {
        match self {
            Self::Shake128 => 24,
            Self::Shake256 => 48,
            Self::Ascon => 24,
        }
    }

    fn min_seed_size_reseed(&self) -> usize {
        match self {
            Self::Shake128 => 16,
            Self::Shake256 => 32,
            Self::Ascon => 16,
        }
    }

    fn max_total_output_size(&self) -> usize {
        match self {
            Self::Shake128 => 304,
            Self::Shake256 => 344,
            Self::Ascon => 256,
        }
    }

    fn check_size_of_seed(
        &self,
        seed: &[u8],
        min_seed_len: usize,
        ops: XdrbgOps,
    ) -> Result<(), Errors> {
        if seed.len() < min_seed_len {
            return Err(InvalidLength(format!(
                "Provided a seed of {} bytes. Minimum seed length is {} bytes for {:?} XOF during {:?}.",
                seed.len(),
                min_seed_len,
                self,
                ops
            )));
        }

        Ok(())
    }

    fn check_size_of_alpha(&self, alpha: &[u8]) -> Result<(), Errors> {
        if alpha.len() > MAX_LEN_ALPHA {
            return Err(InvalidLength(format!(
                "Provided alpha of {} bytes. Maximum length can be {} bytes",
                alpha.len(),
                MAX_LEN_ALPHA
            )));
        }

        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct Xdrbg {
    xof: Xof,
}

impl Xdrbg {
    pub fn new(chosen_xof: Xof) -> Self {
        Self { xof: chosen_xof }
    }

    pub fn xdrbg_instantiate(
        &self,
        seed: &[u8],
        alpha: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, Errors> {
        let aplha_val: Vec<u8> = alpha.unwrap_or(b"".to_vec());

        match self
            .xof
            .are_params_okay(seed, &aplha_val, XdrbgOps::Instantiate)
        {
            Ok(_) => {
                let encoded_bytes: Vec<u8> = self.encode(seed, &aplha_val, 0_usize);

                let init_state: Vec<u8> =
                    self.generate_output(&encoded_bytes, self.xof.state_size());

                Ok(init_state)
            }
            Err(err) => return Err(err),
        }
    }

    pub fn xdrbg_reseed(
        &self,
        current_xdrbg_state: &[u8],
        seed: &[u8],
        alpha: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, Errors> {
        let aplha_val: Vec<u8> = alpha.unwrap_or(b"".to_vec());

        match self.xof.are_params_okay(seed, &aplha_val, XdrbgOps::Reseed) {
            Ok(_) => {
                let input_bytes: Vec<u8> = [current_xdrbg_state, seed].concat();

                let encoded_bytes: Vec<u8> = self.encode(&input_bytes, &aplha_val, 1_usize);

                let reseeded_state: Vec<u8> =
                    self.generate_output(&encoded_bytes, self.xof.state_size());

                Ok(reseeded_state)
            }
            Err(err) => return Err(err),
        }
    }

    pub fn xdrbg_generate(
        &self,
        current_xdrbg_state: &[u8],
        output_key_length: usize,
        alpha: Option<Vec<u8>>,
    ) -> Result<(Vec<u8>, Vec<u8>), Errors> {
        let aplha_val: Vec<u8> = alpha.unwrap_or(b"".to_vec());

        match self.xof.is_output_length_okay(output_key_length) {
            Ok(_) => {
                let encoded_bytes: Vec<u8> = self.encode(current_xdrbg_state, &aplha_val, 2_usize);

                let total_output: Vec<u8> =
                    self.generate_output(&encoded_bytes, output_key_length + self.xof.state_size());

                let (new_xdrbg_state, random_output) = total_output.split_at(self.xof.state_size());

                Ok((new_xdrbg_state.to_vec(), random_output.to_vec()))
            }
            Err(err) => return Err(err),
        }
    }

    fn encode(&self, seed: &[u8], alpha: &[u8], value_n: usize) -> Vec<u8> {
        let computed_param: usize = value_n * 85_usize + alpha.len();

        let num_bytes: usize = if computed_param == 0 {
            1
        } else {
            ((usize::BITS - computed_param.leading_zeros() + 7) / 8) as usize
        };

        let mut param_bytes: Vec<u8> = vec![0u8; num_bytes];
        for (i, b) in param_bytes.iter_mut().enumerate() {
            *b = ((computed_param >> (8 * (num_bytes - i - 1))) & 0xFF) as u8;
        }

        let mut encoded_value: Vec<u8> =
            Vec::with_capacity(seed.len() + alpha.len() + param_bytes.len());
        encoded_value.extend_from_slice(seed);
        encoded_value.extend_from_slice(alpha);
        encoded_value.extend_from_slice(&param_bytes);

        encoded_value
    }

    fn generate_output(&self, encoded_bytes: &[u8], total_output_length: usize) -> Vec<u8> {
        match self.xof {
            Xof::Shake128 => {
                let mut xof_instance = Shake128::default();

                xof_instance.update(encoded_bytes);
                let mut xof_digest_reader = xof_instance.finalize_xof();

                let mut xof_output_buffer: Vec<u8> = vec![0u8; total_output_length];
                xof_digest_reader.read(&mut xof_output_buffer);

                xof_output_buffer
            }
            Xof::Shake256 => {
                let mut xof_instance = Shake256::default();

                xof_instance.update(encoded_bytes);
                let mut xof_digest_reader = xof_instance.finalize_xof();

                let mut xof_output_buffer: Vec<u8> = vec![0u8; total_output_length];
                xof_digest_reader.read(&mut xof_output_buffer);

                xof_output_buffer
            }
            Xof::Ascon => {
                let mut xof_instance = AsconXof128::default();

                xof_instance.update(encoded_bytes);
                let mut xof_digest_reader = xof_instance.finalize_xof();

                let mut xof_output_buffer: Vec<u8> = vec![0u8; total_output_length];
                xof_digest_reader.read(&mut xof_output_buffer);

                xof_output_buffer
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_seed(len: usize) -> Vec<u8> {
        (0..len as u8).collect()
    }

    #[test]
    fn test_state_size() {
        assert_eq!(Xof::Shake128.state_size(), 32);
        assert_eq!(Xof::Shake256.state_size(), 64);
        assert_eq!(Xof::Ascon.state_size(), 32);
    }

    #[test]
    fn test_are_params_okay_valid() {
        let seed = make_seed(24);
        let alpha = vec![1, 2, 3];
        assert!(
            Xof::Shake128
                .are_params_okay(&seed, &alpha, XdrbgOps::Instantiate)
                .is_ok()
        );
    }

    #[test]
    fn test_are_params_okay_invalid_seed() {
        let seed = make_seed(10); // too short
        let alpha = vec![];
        let res = Xof::Shake256.are_params_okay(&seed, &alpha, XdrbgOps::Instantiate);
        assert!(res.is_err());
    }

    #[test]
    fn test_are_params_okay_invalid_alpha() {
        let seed = make_seed(24);
        let alpha = vec![0u8; MAX_LEN_ALPHA + 1]; // too long
        let res = Xof::Ascon.are_params_okay(&seed, &alpha, XdrbgOps::Instantiate);
        assert!(res.is_err());
    }

    #[test]
    fn test_is_output_length_okay() {
        assert!(Xof::Shake128.is_output_length_okay(200).is_ok());
        assert!(Xof::Shake128.is_output_length_okay(1000).is_err());
    }

    #[test]
    fn test_xdrbg_instantiate_success() {
        let xdrbg = Xdrbg::new(Xof::Shake128);
        let seed = make_seed(24);
        let result = xdrbg.xdrbg_instantiate(&seed, None);
        assert!(result.is_ok());
        let state = result.unwrap();
        assert_eq!(state.len(), xdrbg.xof.state_size());
    }

    #[test]
    fn test_xdrbg_instantiate_fail() {
        let xdrbg = Xdrbg::new(Xof::Shake256);
        let seed = make_seed(10); // too short
        let result = xdrbg.xdrbg_instantiate(&seed, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_xdrbg_reseed_success() {
        let xdrbg = Xdrbg::new(Xof::Shake128);
        let seed = make_seed(24);
        let state = xdrbg.xdrbg_instantiate(&seed, None).unwrap();
        let reseeded = xdrbg.xdrbg_reseed(&state, &seed, None);
        assert!(reseeded.is_ok());
        assert_eq!(reseeded.unwrap().len(), xdrbg.xof.state_size());
    }

    #[test]
    fn test_xdrbg_generate_success() {
        let xdrbg = Xdrbg::new(Xof::Shake128);
        let seed = make_seed(24);
        let state = xdrbg.xdrbg_instantiate(&seed, None).unwrap();
        let (new_state, output) = xdrbg.xdrbg_generate(&state, 64, None).unwrap();
        assert_eq!(new_state.len(), xdrbg.xof.state_size());
        assert_eq!(output.len(), 64);
    }

    #[test]
    fn test_xdrbg_generate_fail_too_large_output() {
        let xdrbg = Xdrbg::new(Xof::Shake128);
        let seed = make_seed(24);
        let state = xdrbg.xdrbg_instantiate(&seed, None).unwrap();
        let result = xdrbg.xdrbg_generate(&state, 10_000, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_functionality() {
        let xdrbg = Xdrbg::new(Xof::Ascon);
        let seed = make_seed(5);
        let alpha = vec![9, 9, 9];
        let encoded = xdrbg.encode(&seed, &alpha, 2);
        assert!(encoded.len() >= seed.len() + alpha.len());
        assert!(encoded.ends_with(&[(2 * 85 + 3) as u8]));
    }
}
