use super::errors::PrgError::{self, XORLengthMismatch};

pub fn xor_bytes(param_1: &[u8], param_2: &[u8]) -> Result<Vec<u8>, PrgError> {
    if param_1.len() != param_2.len() {
        return Err(XORLengthMismatch(format!(
            "Cannot XOR bytes of unequal length."
        )));
    }

    let output: Vec<u8> = param_1
        .iter()
        .zip(param_2.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    Ok(output)
}
