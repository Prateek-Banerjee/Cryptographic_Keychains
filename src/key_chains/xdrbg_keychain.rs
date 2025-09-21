use super::{InitialState, NewState, RandomOutput, storage_handler::Storage};
use crate::{
    crypto_primitives::xdrbg_ops::{Xdrbg, Xof},
    errors::Errors::{self, UninitializedStorage},
};
use std::sync::Arc;

#[derive(Clone)]
pub struct XdrbgKeyChain {
    xdrbg_obj: Xdrbg,
    output_key_length: usize,
    store_persistently: bool,
    storage: Option<Arc<dyn Storage<()>>>,
}

impl XdrbgKeyChain {
    pub fn new(
        chosen_xof: Xof,
        output_key_length: Option<usize>,
        store_persistently: Option<bool>,
        storage: Option<Arc<dyn Storage<()>>>,
    ) -> Result<Self, Errors> {
        let xdrbg_obj: Xdrbg = Xdrbg::new(chosen_xof);

        let store_persistently: bool = store_persistently.unwrap_or(false);

        let storage_choice: Option<Arc<dyn Storage<()>>> = if store_persistently {
            if let Some(storage) = storage {
                Some(storage)
            } else {
                return Err(UninitializedStorage(format!(
                    "Xdrbg keychain storage not initialized."
                )));
            }
        } else {
            None
        };

        Ok(Self {
            xdrbg_obj,
            output_key_length: output_key_length.unwrap_or(chosen_xof.state_size()),
            store_persistently: store_persistently,
            storage: storage_choice,
        })
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
            if let Some(storage) = &self.storage {
                storage.store_state_for_xdrbg_keychain(
                    &new_state_of_key_chain,
                    self.xdrbg_obj.get_chosen_xof(),
                );
            }
        }

        Ok((new_state_of_key_chain, random_output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_primitives::xdrbg_ops::Xof;
    use crate::errors::Errors;
    use crate::key_chains::storage_handler::{DefaultStorage, KeyChainType, Storage};
    use std::sync::Arc;

    fn sample_seed(xof: Xof) -> Vec<u8> {
        // Use minimum seed size for each XOF
        match xof {
            Xof::Shake128 => vec![0x11; 24],
            Xof::Shake256 => vec![0x22; 48],
            Xof::Ascon => vec![0x33; 24],
        }
    }

    #[test]
    fn test_instantiate_without_storage() {
        let xof = Xof::Shake128;
        let keychain = XdrbgKeyChain::new(xof, None, Some(false), None).unwrap();
        let initial_state = keychain
            .key_chain_instantiate(&sample_seed(xof), None)
            .unwrap();
        assert_eq!(initial_state.len(), xof.state_size());
    }

    #[test]
    fn test_instantiate_with_missing_storage() {
        let xof = Xof::Shake256;
        let err = XdrbgKeyChain::new(xof, None, Some(true), None);
        match err {
            Err(Errors::UninitializedStorage(msg)) => {
                assert!(msg.contains("Xdrbg keychain storage not initialized"))
            }
            _ => panic!("Expected UninitializedStorage error"),
        }
    }

    #[test]
    fn test_update_and_persistent_storage() {
        let xof = Xof::Ascon;
        let storage = Arc::new(DefaultStorage::new(KeyChainType::XdrbgKeyChain));
        let keychain = XdrbgKeyChain::new(xof, None, Some(true), Some(storage.clone())).unwrap();

        let initial_state = keychain
            .key_chain_instantiate(&sample_seed(xof), None)
            .unwrap();

        let (new_state, random_output) = keychain
            .key_chain_update(&sample_seed(xof), &initial_state, None, None)
            .unwrap();

        assert_eq!(new_state.len(), xof.state_size());
        assert_eq!(random_output.len(), xof.state_size());

        // Check that state is stored in storage
        let fetched = storage.fetch_xdrbg_keychain_state(xof).unwrap();
        assert_eq!(fetched, new_state);
    }

    #[test]
    fn test_update_non_persistent_storage() {
        let xof = Xof::Shake128;
        let keychain = XdrbgKeyChain::new(xof, None, Some(false), None).unwrap();
        let initial_state = keychain
            .key_chain_instantiate(&sample_seed(xof), None)
            .unwrap();

        let (new_state, random_output) = keychain
            .key_chain_update(&sample_seed(xof), &initial_state, None, None)
            .unwrap();

        assert_eq!(new_state.len(), xof.state_size());
        assert_eq!(random_output.len(), xof.state_size());
    }

    #[test]
    fn test_storage_fetch_error() {
        let storage = Arc::new(DefaultStorage::new(KeyChainType::XdrbgKeyChain));
        let err = storage
            .fetch_xdrbg_keychain_state(Xof::Shake256)
            .unwrap_err();
        match err {
            Errors::NoStoredState(msg) => assert!(msg.contains("No Xdrbg state found")),
            _ => panic!("Expected NoStoredState error"),
        }
    }
}
