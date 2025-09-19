use thiserror::Error;

#[derive(Error, Debug)]
pub enum HkdfError {
    #[error("Invalid Salt Length: {0}")]
    InvalidSaltLength(String),

    #[error("Requested Output Length: {0}")]
    ExcessiveTotalOutputLength(String),
}

#[derive(Error, Debug)]
pub enum PrgError {
    #[error("{0}")]
    XORLengthMismatch(String),

    #[error("Invalid AES Input Key Length: {0}")]
    InvalidInputKeyLength(String),

    #[error("{0}")]
    UnexpectedOutputType(String),
}
