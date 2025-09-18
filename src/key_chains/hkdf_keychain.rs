use crate::crypto_primitives::{
    errors::HkdfError,
    hkdf_wrap_ops::{
        HashFunc::{self, *},
        HkdfWrap,
    },
};

use sha2::{Digest, Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};

#[derive(Clone, Copy)]
pub struct HkdfKeyChain {
    hkdf_obj: HkdfWrap,
    output_length: usize,
    state_length: usize,
    store_persistently: bool,
}

impl HkdfKeyChain {
    pub fn new(
        hash_func: HashFunc,
        output_length: Option<usize>,
        store_persistently: Option<bool>,
    ) -> Self {
        let hkdf_obj: HkdfWrap = HkdfWrap::new(hash_func);

        let (output_len, state_len) = Self::get_output_size(hash_func, output_length);

        Self {
            hkdf_obj: hkdf_obj,
            output_length: output_len,
            state_length: state_len,
            store_persistently: store_persistently.unwrap_or(false),
        }
    }

    pub fn key_chain_instantiate(
        self,
        initial_skm: &[u8],
        extractor_salt: Option<Vec<u8>>,
        info_param: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, HkdfError> {
        let pseudo_random_key: Vec<u8> = match extractor_salt {
            Some(salt) =>
                self.hkdf_obj.hkdf_extract(Some(salt), initial_skm)?,
            None => {
                self.hkdf_obj.hkdf_extract(None, initial_skm)?
            }
        };

        let initial_state: Vec<u8> = match info_param {
            Some(info) => 
                    self.hkdf_obj
                        .hkdf_expand(&pseudo_random_key, Some(info), self.state_length)?,
            None => 
                    self.hkdf_obj
                        .hkdf_expand(&pseudo_random_key, None, self.state_length)?
        };

        Ok(initial_state)
    }

    pub fn key_chain_update(
        self,
        arbitrary_input_param: &[u8],
        keychain_state: &[u8],
        extractor_salt: Option<Vec<u8>>,
        info_param: Option<Vec<u8>>,
    ) -> Result<(Vec<u8>, Vec<u8>), HkdfError> {
        let source_key_material: Vec<u8> = [arbitrary_input_param, keychain_state].concat();

        let pseudo_random_key = match extractor_salt {
            Some(salt) => self
                .hkdf_obj
                .hkdf_extract(Some(salt), &source_key_material)?,
            None => self.hkdf_obj.hkdf_extract(None, &source_key_material)?,
        };

        let result = self.hkdf_obj.hkdf_expand(
            &pseudo_random_key,
            info_param,
            self.state_length + self.output_length,
        );

        match result {
            Ok(total_output) => {
                let (new_state_of_key_chain, random_output) = total_output.split_at(self.state_length);

                if self.store_persistently {
                    todo!(); // Still needs implementation
                }
                Ok((new_state_of_key_chain.to_vec(), random_output.to_vec()))
            },
            Err(err) => Err(err),
        }
    }

    fn get_output_size(hash_func: HashFunc, output_length: Option<usize>) -> (usize, usize) {
        let state_len: usize;

        match hash_func {
            SHA256 => {
                state_len = Sha256::output_size();
            }
            SHA512 => {
                state_len = Sha512::output_size();
            }
            SHA3_256 => {
                state_len = Sha3_256::output_size();
            }
            SHA3_512 => {
                state_len = Sha3_512::output_size();
            }
        }

        match output_length {
            Some(output_len) => (output_len, state_len),
            None => (state_len, state_len),
        }
    }
}
