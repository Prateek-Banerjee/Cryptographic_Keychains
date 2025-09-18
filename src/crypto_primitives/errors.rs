use thiserror::Error;

#[derive(Error, Debug)]
pub enum HkdfError {
    #[error("Invalid Salt Length: {0}")]
    InvalidSaltLength(String),

    #[error("Invalid Output Length: {0}")]
    InvalidOutputLength(String),

}