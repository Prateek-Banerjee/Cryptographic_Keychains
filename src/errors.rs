use thiserror::Error;

#[derive(Error, Debug)]
pub enum Errors {
    #[error("Invalid Length: {0}")]
    InvalidLength(String),

    #[error("{0}")]
    UnexpectedOutputType(String),

    #[error("{0}")]
    ParamNotProvided(String),

    #[error("{0}")]
    UninitializedStorage(String),

    #[error("{0}")]
    NoStoredState(String),
}
