# Description

The implementation of cryptographic key chains using three primitives, i.e., HKDF, PRG, and XDRBG, in Rust.

## Usage

```bash
use keychains_rs::{HashFunc::Sha256, key_chains::hkdf_keychain::HkdfKeyChain};
use rand::{RngCore, rngs::OsRng};

fn main() {
    let output_length: usize = 64;
    let hkdf_kc_obj: HkdfKeyChain = HkdfKeyChain::new(Sha256, Some(output_length), None, None).unwrap();

    let mut initial_skm: [u8; 32] = [0u8; 32];
    OsRng::fill_bytes(&mut OsRng, &mut initial_skm);

    let kc_init_state: Vec<u8> = hkdf_kc_obj.key_chain_instantiate(&initial_skm, None, None).unwrap();

    let mut input_param_1: [u8; 45] = [0u8; 45];
    OsRng::fill_bytes(&mut OsRng, &mut input_param_1);

    let (new_state_1, output_key_1) = hkdf_kc_obj.key_chain_update(&input_param_1, &kc_init_state, None, None).unwrap();

    println!("First Key in the key chain using {:?}: {:?}",Sha256, output_key_1);

    let mut input_param_2: [u8; 32] = [0u8; 32];
    OsRng::fill_bytes(&mut OsRng, &mut input_param_2);

    let (_new_state_2, output_key_2) = hkdf_kc_obj.key_chain_update(&input_param_2, &new_state_1, None, None).unwrap();

    println!("Second Key in the key chain using {:?}: {:?}",Sha256, output_key_2);

    // Similarly generate more output keys in the key chain
}
```

For more insights, see [examples](https://github.com/Prateek-Banerjee/Cryptographic_Keychains/tree/master/examples).

### The Storage Solution

The package comes with a default HashMap-based storage for quick prototyping. But a user should implement the **Storage** trait for their choice of storage backend.

### Some Key References Used for This Work
[1] [Krawczyk, Hugo. "Cryptographic extraction and key derivation: The HKDF scheme." Annual Cryptology Conference. Berlin, Heidelberg: Springer Berlin Heidelberg, 2010.](https://eprint.iacr.org/2010/264.pdf)

[2] [Kelsey, John, Stefan Lucks, and Stephan Müller. "XDRBG: A Proposed Deterministic Random Bit Generator Based on Any XOF." IACR Transactions on Symmetric Cryptology 2024.1 (2024):5-34.](https://tosc.iacr.org/index.php/ToSC/article/view/11399)

[3] [Barak, Boaz, and Shai Halevi. "A model and architecture for pseudo-random generation with applications to/dev/random." Proceedings of the 12th ACM conference on Computer and communications security. 2005.](https://eprint.iacr.org/2005/029.pdf)
