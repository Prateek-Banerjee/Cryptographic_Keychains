// [1] Krawczyk, Hugo. "Cryptographic extraction and key derivation: The HKDF scheme."
// Annual Cryptology Conference. Berlin, Heidelberg: Springer Berlin Heidelberg, 2010.

use super::errors::Errors::{self, *};
use hkdf::{Hkdf, HkdfExtract};
use sha2::{Sha256, Sha512, digest::Digest};
use sha3::{Sha3_256, Sha3_512};

#[derive(Clone, Copy, Debug)]
pub enum HashFunc {
    Sha256,
    Sha512,
    Sha3_256,
    Sha3_512,
}

impl HashFunc {
    pub fn output_size(&self) -> usize {
        match self {
            Self::Sha256 => Sha256::output_size(),
            Self::Sha512 => Sha512::output_size(),
            Self::Sha3_256 => Sha3_256::output_size(),
            Self::Sha3_512 => Sha3_512::output_size(),
        }
    }

    fn check_and_get_salt(&self, extractor_salt: Option<Vec<u8>>) -> Result<Vec<u8>, Errors> {
        let digest_size: usize = self.output_size();
        let default_salt: Vec<u8>;
        let salt: Vec<u8> = match extractor_salt {
            Some(val) => {
                if val.len() > digest_size {
                    return Err(InvalidLength(format!(
                        "Provided salt of {} bytes. Acceptable length is <= {} bytes for the hash function {:?}",
                        val.len(),
                        digest_size,
                        self
                    )));
                }
                val
            }
            None => {
                default_salt = vec![0u8; digest_size];
                default_salt
            }
        };

        Ok(salt)
    }

    fn is_output_length_okay(&self, total_output_length: usize) -> Result<(), Errors> {
        let digest_size: usize = self.output_size();
        if total_output_length > (255 * digest_size) {
            return Err(InvalidLength(format!(
                "Total requested output size: {} bytes. Acceptable length is <= {} bytes for the hash function {:?}",
                total_output_length,
                (255 * digest_size),
                self
            )));
        }

        Ok(())
    }
}

macro_rules! hkdf_extract {
    ($hash_algo:ty, $salt:expr, $source_key_material:expr) => {{
        let mut hkdf_inst = HkdfExtract::<$hash_algo>::new(Some(&$salt));
        hkdf_inst.input_ikm($source_key_material);
        let (pseudo_random_key, _) = hkdf_inst.finalize();
        pseudo_random_key.to_vec()
    }};
}

macro_rules! hkdf_expand {
    ($hash_algo:ty, $pseudo_random_key:expr, $info_param:expr, $total_output:expr) => {{
        let hkdf_inst =
            Hkdf::<$hash_algo>::from_prk($pseudo_random_key).expect("Invalid (length of) PRK.");
        hkdf_inst
            .expand(&$info_param, &mut $total_output)
            .expect("Expansion Failed");
        $total_output
    }};
}

#[derive(Clone, Copy)]
pub struct HkdfWrap {
    hash_func: HashFunc,
}

impl Default for HkdfWrap {
    fn default() -> Self {
        Self {
            hash_func: HashFunc::Sha256,
        }
    }
}

impl HkdfWrap {
    pub fn new(hash_func: HashFunc) -> Self {
        Self {
            hash_func: hash_func,
        }
    }

    pub fn hkdf_extract(
        self,
        extractor_salt: Option<Vec<u8>>,
        source_key_material: &[u8],
    ) -> Result<Vec<u8>, Errors> {
        let salt: Vec<u8> = self.hash_func.check_and_get_salt(extractor_salt)?;

        match self.hash_func {
            HashFunc::Sha256 => Ok(hkdf_extract!(Sha256, salt, source_key_material)),
            HashFunc::Sha512 => Ok(hkdf_extract!(Sha512, salt, source_key_material)),
            HashFunc::Sha3_256 => Ok(hkdf_extract!(Sha3_256, salt, source_key_material)),
            HashFunc::Sha3_512 => Ok(hkdf_extract!(Sha3_512, salt, source_key_material)),
        }
    }

    pub fn hkdf_expand(
        self,
        pseudo_random_key: &[u8],
        info_param: Option<Vec<u8>>,
        total_output_length: usize,
    ) -> Result<Vec<u8>, Errors> {
        let mut total_output: Vec<u8> = vec![0u8; total_output_length];
        let info: Vec<u8> = info_param.unwrap_or(b"".to_vec());

        match self.hash_func.is_output_length_okay(total_output_length) {
            Ok(_) => match self.hash_func {
                HashFunc::Sha256 => Ok(hkdf_expand!(Sha256, pseudo_random_key, info, total_output)),
                HashFunc::Sha512 => Ok(hkdf_expand!(Sha512, pseudo_random_key, info, total_output)),
                HashFunc::Sha3_256 => Ok(hkdf_expand!(
                    Sha3_256,
                    pseudo_random_key,
                    info,
                    total_output
                )),
                HashFunc::Sha3_512 => Ok(hkdf_expand!(
                    Sha3_512,
                    pseudo_random_key,
                    info,
                    total_output
                )),
            },
            Err(err) => return Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_input() -> Vec<u8> {
        b"example input key material".to_vec()
    }

    fn sample_salt(len: usize) -> Vec<u8> {
        vec![0x0b; len]
    }

    #[test]
    fn test_extract_sha256_with_valid_salt() {
        let hkdf = HkdfWrap::new(HashFunc::Sha256);
        let salt = Some(sample_salt(32)); // SHA256 output size
        let ikm = sample_input();

        let result = hkdf.hkdf_extract(salt, &ikm);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_extract_sha512_with_default_salt() {
        let hkdf = HkdfWrap::new(HashFunc::Sha512);
        let ikm = sample_input();

        let result = hkdf.hkdf_extract(None, &ikm);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 64);
    }

    #[test]
    fn test_extract_fails_with_invalid_salt_length() {
        let hkdf = HkdfWrap::new(HashFunc::Sha256);
        let ikm = sample_input();
        let long_salt = Some(sample_salt(64)); // longer than SHA256 output

        let result = hkdf.hkdf_extract(long_salt, &ikm);
        assert!(matches!(result, Err(InvalidLength(_))));
    }

    #[test]
    fn test_expand_sha256_success() {
        let hkdf = HkdfWrap::new(HashFunc::Sha256);
        let ikm = sample_input();

        let prk = hkdf.hkdf_extract(None, &ikm).unwrap();
        let output = hkdf.hkdf_expand(&prk, None, 64);

        assert!(output.is_ok());
        assert_eq!(output.unwrap().len(), 64);
    }

    #[test]
    fn test_expand_fails_with_excessive_output_length() {
        let hkdf = HkdfWrap::new(HashFunc::Sha3_256);
        let ikm = sample_input();

        let prk = hkdf.hkdf_extract(None, &ikm).unwrap();
        let result = hkdf.hkdf_expand(&prk, None, 255 * 32 + 1); // Just over the allowed limit

        assert!(matches!(result, Err(InvalidLength(_))));
    }

    #[test]
    fn test_expand_with_info() {
        let hkdf = HkdfWrap::new(HashFunc::Sha3_512);
        let ikm = sample_input();
        let prk = hkdf.hkdf_extract(None, &ikm).unwrap();

        let info = Some(b"contextual-info".to_vec());
        let output = hkdf.hkdf_expand(&prk, info, 128);

        assert!(output.is_ok());
        assert_eq!(output.unwrap().len(), 128);
    }

    #[test]
    fn test_extract_and_expand_sha3_256() {
        let hkdf = HkdfWrap::new(HashFunc::Sha3_256);
        let ikm = sample_input();
        let salt = Some(sample_salt(32));

        let prk = hkdf.hkdf_extract(salt, &ikm).unwrap();
        let output = hkdf.hkdf_expand(&prk, None, 64).unwrap();

        assert_eq!(output.len(), 64);
    }

    #[test]
    fn test_default_hash_function_is_sha256() {
        let hkdf = HkdfWrap::default();
        let ikm = sample_input();

        let prk = hkdf.hkdf_extract(None, &ikm).unwrap();
        assert_eq!(prk.len(), 32);
    }
}
