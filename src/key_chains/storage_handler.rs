use crate::{
    HashFunc, Xof,
    errors::Errors::{self, NoStoredState, UninitializedStorage},
    key_chains::NewState,
};
use std::{collections::HashMap, sync::Mutex};

pub trait Storage<T> {
    fn store_state_for_hkdf_keychain(&self, state_of_key_chain: &[u8], hash_func: HashFunc);
    fn store_state_for_prg_keychain(&self, state_of_key_chain: &[u8], security_param_lambda: usize);
    fn store_state_for_xdrbg_keychain(&self, state_of_key_chain: &[u8], xof: Xof);

    fn fetch_hkdf_keychain_state(&self, hash_func: HashFunc) -> Result<NewState, Errors>;
    fn fetch_prg_keychain_state(&self, security_param_lambda: usize) -> Result<NewState, Errors>;
    fn fetch_xdrbg_keychain_state(&self, xof: Xof) -> Result<NewState, Errors>;
}

pub struct DefaultStorage {
    hkdf_map: Option<Mutex<HashMap<HashFunc, NewState>>>,
    prg_map: Option<Mutex<HashMap<usize, NewState>>>,
    xdrbg_map: Option<Mutex<HashMap<Xof, NewState>>>,
}

pub enum KeyChainType {
    HkdfKeyChain,
    PrgKeyChain,
    XdrbgKeyChain,
}

impl DefaultStorage {
    pub fn new(key_chain_type: KeyChainType) -> Self {
        match key_chain_type {
            KeyChainType::HkdfKeyChain => Self {
                hkdf_map: Some(Mutex::new(HashMap::new())),
                prg_map: None,
                xdrbg_map: None,
            },
            KeyChainType::PrgKeyChain => Self {
                hkdf_map: None,
                prg_map: Some(Mutex::new(HashMap::new())),
                xdrbg_map: None,
            },
            KeyChainType::XdrbgKeyChain => Self {
                hkdf_map: None,
                prg_map: None,
                xdrbg_map: Some(Mutex::new(HashMap::new())),
            },
        }
    }
}

impl Storage<()> for DefaultStorage {
    fn store_state_for_hkdf_keychain(&self, state_of_key_chain: &[u8], hash_func: HashFunc) {
        if let Some(ref map_mutex) = self.hkdf_map {
            let mut map = map_mutex.lock().unwrap();
            map.insert(hash_func, state_of_key_chain.to_vec());
        }
    }

    fn store_state_for_prg_keychain(
        &self,
        state_of_key_chain: &[u8],
        security_param_lambda: usize,
    ) {
        if let Some(ref map_mutex) = self.prg_map {
            let mut map = map_mutex.lock().unwrap();
            map.insert(security_param_lambda, state_of_key_chain.to_vec());
        }
    }

    fn store_state_for_xdrbg_keychain(&self, state_of_key_chain: &[u8], xof: Xof) {
        if let Some(ref map_mutex) = self.xdrbg_map {
            let mut map = map_mutex.lock().unwrap();
            map.insert(xof, state_of_key_chain.to_vec());
        }
    }

    fn fetch_hkdf_keychain_state(&self, hash_func: HashFunc) -> Result<NewState, Errors> {
        if let Some(ref map_mutex) = self.hkdf_map {
            let map = map_mutex.lock().unwrap();
            map.get(&hash_func)
                .cloned()
                .ok_or_else(|| NoStoredState(format!("No Hkdf state found for {:?}", hash_func)))
        } else {
            Err(UninitializedStorage(format!(
                "Hkdf Keychain storage not initialized"
            )))
        }
    }

    fn fetch_prg_keychain_state(&self, security_param_lambda: usize) -> Result<NewState, Errors> {
        if let Some(ref map_mutex) = self.prg_map {
            let map = map_mutex.lock().unwrap();
            map.get(&security_param_lambda).cloned().ok_or_else(|| {
                NoStoredState(format!(
                    "No Prg state found for lambda {}",
                    security_param_lambda
                ))
            })
        } else {
            Err(UninitializedStorage(format!(
                "Prg keychain storage not initialized"
            )))
        }
    }

    fn fetch_xdrbg_keychain_state(&self, xof: Xof) -> Result<NewState, Errors> {
        if let Some(ref map_mutex) = self.xdrbg_map {
            let map = map_mutex.lock().unwrap();
            map.get(&xof)
                .cloned()
                .ok_or_else(|| NoStoredState(format!("No Xdrbg state found for {:?}", xof)))
        } else {
            Err(UninitializedStorage(format!(
                "Xdrbg keychain storage not initialized"
            )))
        }
    }
}
