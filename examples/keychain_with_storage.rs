use keychains_rs::{
    HashFunc::Sha256,
    key_chains::{
        hkdf_keychain::HkdfKeyChain,
        storage_handler::{DefaultStorage, KeyChainType, Storage},
    },
};
use rand::{RngCore, rngs::OsRng};
use std::sync::Arc;

fn main() {
    let storage: Arc<DefaultStorage> = Arc::new(DefaultStorage::new(KeyChainType::HkdfKeyChain));

    let output_length: usize = 64;
    let hkdf_kc_obj: HkdfKeyChain = HkdfKeyChain::new(
        Sha256,
        Some(output_length),
        Some(true),
        Some(storage.clone()),
    )
    .unwrap();

    let mut initial_skm: [u8; 32] = [0u8; 32];
    OsRng::fill_bytes(&mut OsRng, &mut initial_skm);

    let kci_salt: [u8; 18] = *b"I use the kci salt";

    let kc_init_state: Vec<u8> = hkdf_kc_obj
        .key_chain_instantiate(&initial_skm, Some(kci_salt.to_vec()), None)
        .unwrap();

    let kcu_info_1: [u8; 20] = *b"The first info param";

    let mut input_param_1: [u8; 45] = [0u8; 45];
    OsRng::fill_bytes(&mut OsRng, &mut input_param_1);

    let (new_state_1, output_key_1) = hkdf_kc_obj
        .key_chain_update(
            &input_param_1,
            &kc_init_state,
            None,
            Some(kcu_info_1.to_vec()),
        )
        .unwrap();

    assert_eq!(output_key_1.len(), output_length);

    let state_from_storage: Vec<u8> = storage.fetch_hkdf_keychain_state(Sha256).unwrap();

    assert_eq!(new_state_1, state_from_storage);

    println!(
        "First Key in the key chain using {:?}: {:?}",
        Sha256, output_key_1
    );

    let kcu_salt_1: [u8; 19] = *b"I use some kcu salt";

    let mut input_param_2: [u8; 32] = [0u8; 32];
    OsRng::fill_bytes(&mut OsRng, &mut input_param_2);

    let (new_state_2, output_key_2) = hkdf_kc_obj
        .key_chain_update(
            &input_param_2,
            &new_state_1,
            Some(kcu_salt_1.to_vec()),
            None,
        )
        .unwrap();

    assert_eq!(output_key_2.len(), output_length);

    let state_from_storage: Vec<u8> = storage.fetch_hkdf_keychain_state(Sha256).unwrap();

    assert_eq!(new_state_2, state_from_storage);

    println!(
        "Second Key in the key chain using {:?}: {:?}",
        Sha256, output_key_2
    );
}
