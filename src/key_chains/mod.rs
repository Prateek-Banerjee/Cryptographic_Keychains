pub mod hkdf_keychain;
pub mod prg_keychain;
pub mod storage_handler;
pub mod xdrbg_keychain;

pub type InitialState = Vec<u8>;
pub type NewState = Vec<u8>;
pub type RandomOutput = Vec<u8>;
