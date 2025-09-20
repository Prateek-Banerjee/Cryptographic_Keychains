use keychains_rs::key_chains::prg_keychain::PrgKeyChain;
use rand::{RngCore, rngs::OsRng};

fn main() {
    const SEC_PAR_LAMBDA: [usize; 3] = [16, 24, 32];

    for sec_param in SEC_PAR_LAMBDA.iter() {
        let prg_kc_obj: PrgKeyChain = PrgKeyChain::new(*sec_param, None);

        let mut initial_seed: Vec<u8> = vec![0u8; *sec_param];
        OsRng::fill_bytes(&mut OsRng, &mut initial_seed);

        let kc_init_state: Vec<u8> = prg_kc_obj.key_chain_instantiate(&initial_seed).unwrap();

        let mut input_param_1: Vec<u8> = vec![0u8; *sec_param];
        OsRng::fill_bytes(&mut OsRng, &mut input_param_1);

        let (new_state_1, output_key_1) = prg_kc_obj
            .key_chain_update(&input_param_1, &kc_init_state)
            .unwrap();

        assert_eq!(output_key_1.len(), *sec_param);

        println!(
            "First Key in the key chain using lambda = {}: {:?}",
            sec_param, output_key_1
        );

        let mut input_param_2: Vec<u8> = vec![0u8; *sec_param];
        OsRng::fill_bytes(&mut OsRng, &mut input_param_2);

        let (_new_state_2, output_key_2) = prg_kc_obj
            .key_chain_update(&input_param_1, &new_state_1)
            .unwrap();

        assert_eq!(output_key_2.len(), *sec_param);

        println!(
            "Second Key in the key chain using lambda = {}: {:?}",
            sec_param, output_key_2
        );
    }
}
