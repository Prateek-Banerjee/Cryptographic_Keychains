use super::{InitialState, NewState, RandomOutput, storage_handler::Storage};
use crate::{
    crypto_primitives::hkdf_wrap_ops::{HashFunc, HkdfWrap},
    errors::Errors::{self, UninitializedStorage},
};
use std::sync::Arc;

#[derive(Clone)]
pub struct HkdfKeyChain {
    hkdf_obj: HkdfWrap,
    output_key_length: usize,
    state_length: usize,
    store_persistently: bool,
    storage: Option<Arc<dyn Storage>>,
}

impl HkdfKeyChain {
    pub fn new(
        hash_func: HashFunc,
        output_key_length: Option<usize>,
        store_persistently: Option<bool>,
        storage: Option<Arc<dyn Storage>>,
    ) -> Result<Self, Errors> {
        let hkdf_obj: HkdfWrap = HkdfWrap::new(hash_func);

        let store_persistently: bool = store_persistently.unwrap_or(false);

        let storage_choice: Option<Arc<dyn Storage>> = if store_persistently {
            if let Some(storage) = storage {
                Some(storage)
            } else {
                return Err(UninitializedStorage(format!(
                    "Hkdf keychain storage not initialized."
                )));
            }
        } else {
            None
        };

        Ok(Self {
            hkdf_obj: hkdf_obj,
            output_key_length: output_key_length.unwrap_or(hash_func.output_size()),
            state_length: hash_func.output_size(),
            store_persistently: store_persistently,
            storage: storage_choice,
        })
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
                    if let Some(storage) = &self.storage {
                        storage.store_state_for_hkdf_keychain(
                            new_state_of_key_chain,
                            self.hkdf_obj.get_chosen_hash_func(),
                        );
                    }
                }
                Ok((new_state_of_key_chain.to_vec(), random_output.to_vec()))
            }
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_primitives::hkdf_wrap_ops::HashFunc;
    use crate::key_chains::storage_handler::{DefaultStorage, KeyChainType, Storage};
    use std::sync::Arc;

    fn sample_input() -> Vec<u8> {
        b"test input".to_vec()
    }

    #[test]
    fn test_instantiate_without_storage() {
        let keychain = HkdfKeyChain::new(HashFunc::Sha256, None, Some(false), None).unwrap();
        let initial_state = keychain
            .key_chain_instantiate(&sample_input(), None, None)
            .unwrap();
        assert_eq!(initial_state.len(), HashFunc::Sha256.output_size());
    }

    #[test]
    fn test_instantiate_with_missing_storage() {
        let err = HkdfKeyChain::new(HashFunc::Sha256, None, Some(true), None);
        match err {
            Err(Errors::UninitializedStorage(msg)) => {
                assert!(msg.contains("Hkdf keychain storage not initialized"))
            }
            _ => panic!("Expected UninitializedStorage error"),
        }
    }

    #[test]
    fn test_update_and_persistent_storage() {
        let storage = Arc::new(DefaultStorage::new(KeyChainType::HkdfKeyChain));
        let keychain =
            HkdfKeyChain::new(HashFunc::Sha256, None, Some(true), Some(storage.clone())).unwrap();

        let initial_state = keychain
            .key_chain_instantiate(&sample_input(), None, None)
            .unwrap();

        let (new_state, random_output) = keychain
            .key_chain_update(b"update", &initial_state, None, None)
            .unwrap();

        // Check output lengths
        assert_eq!(new_state.len(), HashFunc::Sha256.output_size());
        assert_eq!(random_output.len(), HashFunc::Sha256.output_size());

        // Check that state is stored in storage
        let fetched = storage.fetch_hkdf_keychain_state(HashFunc::Sha256).unwrap();
        assert_eq!(fetched, new_state);
    }

    #[test]
    fn test_update_non_persistent_storage() {
        let keychain = HkdfKeyChain::new(HashFunc::Sha256, None, Some(false), None).unwrap();
        let initial_state = keychain
            .key_chain_instantiate(&sample_input(), None, None)
            .unwrap();

        let (new_state, random_output) = keychain
            .key_chain_update(b"update", &initial_state, None, None)
            .unwrap();

        assert_eq!(new_state.len(), HashFunc::Sha256.output_size());
        assert_eq!(random_output.len(), HashFunc::Sha256.output_size());
    }

    #[test]
    fn test_storage_fetch_error() {
        let storage = Arc::new(DefaultStorage::new(KeyChainType::HkdfKeyChain));
        let err = storage
            .fetch_hkdf_keychain_state(HashFunc::Sha512)
            .unwrap_err();
        match err {
            Errors::NoStoredState(msg) => assert!(msg.contains("No Hkdf state found")),
            _ => panic!("Expected NoStoredState error"),
        }
    }
}
