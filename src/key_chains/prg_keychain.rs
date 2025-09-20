use super::{InitialState, NewState, RandomOutput};
use crate::crypto_primitives::{errors::Errors, prg_ops::Prg};

#[derive(Clone)]
pub struct PrgKeyChain {
    prg_obj: Prg,
    store_persistently: bool,
    init_state: InitialState,
}

impl PrgKeyChain {
    pub fn new(security_param_lambda: usize, store_persistently: Option<bool>) -> Self {
        let prg_obj: Prg = Prg::new(security_param_lambda);

        Self {
            prg_obj: prg_obj,
            store_persistently: store_persistently.unwrap_or(false),
            init_state: vec![0u8; security_param_lambda],
        }
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
            todo!(); // TODO: Still needs implementation
        }

        Ok((new_state_of_key_chain, random_output))
    }
}
