use super::{InitialState, NewState, RandomOutput, storage_handler::Storage};
use crate::{
    crypto_primitives::prg_ops::Prg,
    errors::Errors::{self, UninitializedStorage},
};
use std::sync::Arc;

#[derive(Clone)]
pub struct PrgKeyChain {
    prg_obj: Prg,
    store_persistently: bool,
    init_state: InitialState,
    storage: Option<Arc<dyn Storage>>,
}

impl PrgKeyChain {
    pub fn new(
        security_param_lambda: usize,
        store_persistently: Option<bool>,
        storage: Option<Arc<dyn Storage>>,
    ) -> Result<Self, Errors> {
        let prg_obj: Prg = Prg::new(security_param_lambda);

        let store_persistently: bool = store_persistently.unwrap_or(false);

        let storage_choice: Option<Arc<dyn Storage>> = if store_persistently {
            if let Some(storage) = storage {
                Some(storage)
            } else {
                return Err(UninitializedStorage(format!(
                    "Prg keychain storage not initialized."
                )));
            }
        } else {
            None
        };

        Ok(Self {
            prg_obj: prg_obj,
            store_persistently: store_persistently,
            init_state: vec![0u8; security_param_lambda],
            storage: storage_choice,
        })
    }

    pub fn key_chain_instantiate(
        &self,
        seed_for_prg_refreshing: &[u8],
    ) -> Result<InitialState, Errors> {
        let initial_state: Vec<u8> = match self
            .prg_obj
            .prg_refresh(&self.init_state, seed_for_prg_refreshing)
        {
            Ok(prg_state_after_refreshing) => prg_state_after_refreshing,
            Err(err) => return Err(err),
        };

        Ok(initial_state)
    }

    pub fn key_chain_update(
        &self,
        arbitrary_input_param: &[u8],
        keychain_state: &[u8],
    ) -> Result<(NewState, RandomOutput), Errors> {
        let refreshed_prg_state: Vec<u8> = match self
            .prg_obj
            .prg_refresh(keychain_state, arbitrary_input_param)
        {
            Ok(prg_state_after_refreshing) => prg_state_after_refreshing,
            Err(err) => return Err(err),
        };

        let (random_output, new_state_of_key_chain) =
            match self.prg_obj.prg_next(&refreshed_prg_state) {
                Ok(total_output) => total_output,
                Err(err) => return Err(err),
            };

        if self.store_persistently {
            if let Some(storage) = &self.storage {
                storage.store_state_for_prg_keychain(
                    &new_state_of_key_chain,
                    self.prg_obj.get_chosen_security_param_lambda(),
                );
            }
        }

        Ok((new_state_of_key_chain, random_output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::Errors;
    use crate::key_chains::storage_handler::{DefaultStorage, KeyChainType, Storage};
    use std::sync::Arc;

    fn sample_seed(lambda: usize) -> Vec<u8> {
        (0..lambda).map(|i| (i % 256) as u8).collect()
    }

    #[test]
    fn test_instantiate_without_storage() {
        let lambda = 16;
        let keychain = PrgKeyChain::new(lambda, Some(false), None).unwrap();
        let initial_state = keychain
            .key_chain_instantiate(&sample_seed(lambda))
            .unwrap();
        assert_eq!(initial_state.len(), lambda);
    }

    #[test]
    fn test_instantiate_with_missing_storage() {
        let lambda = 16;
        let err = PrgKeyChain::new(lambda, Some(true), None);
        match err {
            Err(Errors::UninitializedStorage(msg)) => {
                assert!(msg.contains("Prg keychain storage not initialized"))
            }
            _ => panic!("Expected UninitializedStorage error"),
        }
    }

    #[test]
    fn test_update_and_persistent_storage() {
        let lambda = 16;
        let storage = Arc::new(DefaultStorage::new(KeyChainType::PrgKeyChain));
        let keychain = PrgKeyChain::new(lambda, Some(true), Some(storage.clone())).unwrap();

        let initial_state = keychain
            .key_chain_instantiate(&sample_seed(lambda))
            .unwrap();

        let (new_state, random_output) = keychain
            .key_chain_update(&sample_seed(lambda), &initial_state)
            .unwrap();

        assert_eq!(new_state.len(), lambda);
        assert_eq!(random_output.len(), lambda);

        // Check that state is stored in storage
        let fetched_state = storage.fetch_prg_keychain_state(lambda).unwrap();
        assert_eq!(fetched_state, new_state);
    }

    #[test]
    fn test_update_non_persistent_storage() {
        let lambda = 16;
        let keychain = PrgKeyChain::new(lambda, Some(false), None).unwrap();
        let initial_state = keychain
            .key_chain_instantiate(&sample_seed(lambda))
            .unwrap();

        let (new_state, random_output) = keychain
            .key_chain_update(&sample_seed(lambda), &initial_state)
            .unwrap();

        assert_eq!(new_state.len(), lambda);
        assert_eq!(random_output.len(), lambda);
    }

    #[test]
    fn test_storage_fetch_error() {
        let storage = Arc::new(DefaultStorage::new(KeyChainType::PrgKeyChain));
        let err = storage.fetch_prg_keychain_state(42).unwrap_err();
        match err {
            Errors::NoStoredState(msg) => assert!(msg.contains("No Prg state found")),
            _ => panic!("Expected NoStoredState error"),
        }
    }
}
