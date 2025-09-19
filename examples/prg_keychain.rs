use keychains_rs::key_chains::prg_keychain::PrgKeyChain;
use rand::{RngCore, rngs::OsRng};

fn main() {
    const SEC_PAR_LAMBDA: usize = 32;

    let prg_kc_obj: PrgKeyChain = PrgKeyChain::new(SEC_PAR_LAMBDA, None);

    let mut initial_seed: [u8; SEC_PAR_LAMBDA] = [0u8; SEC_PAR_LAMBDA];
    OsRng::fill_bytes(&mut OsRng, &mut initial_seed);

    let kc_init_state: Vec<u8> = prg_kc_obj.key_chain_instantiate(&initial_seed).unwrap();

    let mut input_param_1: [u8; SEC_PAR_LAMBDA] = [0u8; SEC_PAR_LAMBDA];
    OsRng::fill_bytes(&mut OsRng, &mut input_param_1);

    let (new_state_1, output_key_1) = prg_kc_obj
        .key_chain_update(&input_param_1, &kc_init_state)
        .unwrap();

    assert_eq!(output_key_1.len(), SEC_PAR_LAMBDA);

    println!("First Key in the key chain{:?}", output_key_1);

    let mut input_param_2: [u8; SEC_PAR_LAMBDA] = [0u8; SEC_PAR_LAMBDA];
    OsRng::fill_bytes(&mut OsRng, &mut input_param_2);

    let (_new_state_2, output_key_2) = prg_kc_obj
        .key_chain_update(&input_param_1, &new_state_1)
        .unwrap();

    assert_eq!(output_key_2.len(), SEC_PAR_LAMBDA);

    println!("Second Key in the key chain{:?}", output_key_2);
}
