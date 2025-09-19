use keychains_rs::{HashFunc::*, key_chains::hkdf_keychain::HkdfKeyChain};
use rand::{RngCore, rngs::OsRng};

fn main() {
    let output_length: usize = 40;
    let hkdf_kc_obj: HkdfKeyChain = HkdfKeyChain::new(Sha256, Some(output_length), None);

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

    println!("First Key in the key chain{:?}", output_key_1);

    let kcu_salt_1: [u8; 19] = *b"I use some kcu salt";

    let mut input_param_2: [u8; 32] = [0u8; 32];
    OsRng::fill_bytes(&mut OsRng, &mut input_param_2);

    let (_new_state_2, output_key_2) = hkdf_kc_obj
        .key_chain_update(
            &input_param_2,
            &new_state_1,
            Some(kcu_salt_1.to_vec()),
            None,
        )
        .unwrap();

    assert_eq!(output_key_2.len(), output_length);

    println!("Second Key in the key chain{:?}", output_key_2);
}
