use super::{InitialState, NewState, RandomOutput};
use crate::crypto_primitives::{
    errors::Errors,
    hkdf_wrap_ops::{HashFunc, HkdfWrap},
};

#[derive(Clone, Copy)]
pub struct HkdfKeyChain {
    hkdf_obj: HkdfWrap,
    output_key_length: usize,
    state_length: usize,
    store_persistently: bool,
}

impl HkdfKeyChain {
    pub fn new(
        hash_func: HashFunc,
        output_key_length: Option<usize>,
        store_persistently: Option<bool>,
    ) -> Self {
        let hkdf_obj: HkdfWrap = HkdfWrap::new(hash_func);

        Self {
            hkdf_obj: hkdf_obj,
            output_key_length: output_key_length.unwrap_or(hash_func.output_size()),
            state_length: hash_func.output_size(),
            store_persistently: store_persistently.unwrap_or(false),
        }
    }

    pub fn key_chain_instantiate(
        &self,
        initial_skm: &[u8],
        extractor_salt: Option<Vec<u8>>,
        info_param: Option<Vec<u8>>,
    ) -> Result<InitialState, Errors> {
        let pseudo_random_key: Vec<u8> = self.hkdf_obj.hkdf_extract(extractor_salt, initial_skm)?;

        let initial_state: Vec<u8> =
            self.hkdf_obj
                .hkdf_expand(&pseudo_random_key, info_param, self.state_length)?;

        Ok(initial_state)
    }

    pub fn key_chain_update(
        &self,
        arbitrary_input_param: &[u8],
        keychain_state: &[u8],
        extractor_salt: Option<Vec<u8>>,
        info_param: Option<Vec<u8>>,
    ) -> Result<(NewState, RandomOutput), Errors> {
        let source_key_material: Vec<u8> = [arbitrary_input_param, keychain_state].concat();

        let pseudo_random_key = self
            .hkdf_obj
            .hkdf_extract(extractor_salt, &source_key_material)?;

        let result: Result<Vec<u8>, Errors> = self.hkdf_obj.hkdf_expand(
            &pseudo_random_key,
            info_param,
            self.state_length + self.output_key_length,
        );

        match result {
            Ok(total_output) => {
                let (new_state_of_key_chain, random_output) =
                    total_output.split_at(self.state_length);

                if self.store_persistently {
                    todo!(); // TODO: Still needs implementation
                }
                Ok((new_state_of_key_chain.to_vec(), random_output.to_vec()))
            }
            Err(err) => Err(err),
        }
    }
}
