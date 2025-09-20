use super::{InitialState, NewState, RandomOutput};
use crate::crypto_primitives::{
    errors::Errors,
    xdrbg_ops::{Xdrbg, Xof},
};

#[derive(Clone, Copy)]
pub struct XdrbgKeyChain {
    xdrbg_obj: Xdrbg,
    output_key_length: usize,
    store_persistently: bool,
}

impl XdrbgKeyChain {
    pub fn new(
        chosen_xof: Xof,
        output_key_length: Option<usize>,
        store_persistently: Option<bool>,
    ) -> Self {
        let xdrbg_obj: Xdrbg = Xdrbg::new(chosen_xof);

        Self {
            xdrbg_obj,
            output_key_length: output_key_length.unwrap_or(chosen_xof.state_size()),
            store_persistently: store_persistently.unwrap_or(false),
        }
    }

    pub fn key_chain_instantiate(
        &self,
        seed: &[u8],
        alpha: Option<Vec<u8>>,
    ) -> Result<InitialState, Errors> {
        let initial_state: Vec<u8> = match self.xdrbg_obj.xdrbg_instantiate(seed, alpha) {
            Ok(xdrbg_init_state) => xdrbg_init_state,
            Err(err) => return Err(err),
        };

        Ok(initial_state)
    }

    pub fn key_chain_update(
        &self,
        arbitrary_input_param: &[u8],
        keychain_state: &[u8],
        alpha_reseed: Option<Vec<u8>>,
        alpha_generate: Option<Vec<u8>>,
    ) -> Result<(NewState, RandomOutput), Errors> {
        let reseeded_xdrbg_state: Vec<u8> =
            match self
                .xdrbg_obj
                .xdrbg_reseed(keychain_state, arbitrary_input_param, alpha_reseed)
            {
                Ok(reseeded_state) => reseeded_state,
                Err(err) => return Err(err),
            };

        let (new_state_of_key_chain, random_output) = match self.xdrbg_obj.xdrbg_generate(
            &reseeded_xdrbg_state,
            self.output_key_length,
            alpha_generate,
        ) {
            Ok(total_output) => total_output,
            Err(err) => return Err(err),
        };

        if self.store_persistently {
            todo!(); // TODO: Still needs implementation
        }

        Ok((new_state_of_key_chain, random_output))
    }
}
