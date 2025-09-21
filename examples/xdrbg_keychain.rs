use keychains_rs::{Xof::*, key_chains::xdrbg_keychain::XdrbgKeyChain};
use rand::{RngCore, rngs::OsRng};

fn main() {
    for xof in [Shake128, Shake256, Ascon].iter() {
        let output_length: usize = 64;
        let xdrbg_kc_obj: XdrbgKeyChain =
            XdrbgKeyChain::new(*xof, Some(output_length), None, None).unwrap();

        let mut seed_instantiate: [u8; 64] = [0u8; 64];
        OsRng::fill_bytes(&mut OsRng, &mut seed_instantiate);

        let alpha_instantiate: [u8; 26] = *b"The alpha for instantiate.";

        let kc_init_state: Vec<u8> = xdrbg_kc_obj
            .key_chain_instantiate(&seed_instantiate, Some(alpha_instantiate.to_vec()))
            .unwrap();

        let mut arbitrary_input_param_1: [u8; 32] = [0u8; 32];
        OsRng::fill_bytes(&mut OsRng, &mut arbitrary_input_param_1);

        let alpha_reseed: [u8; 21] = *b"The alpha for reseed.";

        let (new_state_1, output_key_1) = xdrbg_kc_obj
            .key_chain_update(
                &arbitrary_input_param_1,
                &kc_init_state,
                Some(alpha_reseed.to_vec()),
                None,
            )
            .unwrap();

        assert_eq!(output_key_1.len(), output_length);

        println!(
            "First Key in the key chain using {:?}: {:?}",
            xof, output_key_1
        );

        let mut arbitrary_input_param_2: [u8; 32] = [0u8; 32];
        OsRng::fill_bytes(&mut OsRng, &mut arbitrary_input_param_2);

        let alpha_generate: [u8; 23] = *b"The alpha for generate.";

        let (_new_state_2, output_key_2) = xdrbg_kc_obj
            .key_chain_update(
                &arbitrary_input_param_2,
                &new_state_1,
                None,
                Some(alpha_generate.to_vec()),
            )
            .unwrap();

        assert_eq!(output_key_2.len(), output_length);

        println!(
            "Second Key in the key chain using {:?}: {:?}",
            xof, output_key_2
        );
    }
}
