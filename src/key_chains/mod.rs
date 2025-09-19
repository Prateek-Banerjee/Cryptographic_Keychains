pub mod hkdf_keychain;
pub mod prg_keychain;
pub mod xdrbg_keychain;

type InitialState = Vec<u8>;
type NewState = Vec<u8>;
type RandomOutput = Vec<u8>;
