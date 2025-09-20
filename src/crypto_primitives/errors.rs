use thiserror::Error;

#[derive(Error, Debug)]
pub enum Errors {
    #[error("Invalid Length: {0}")]
    InvalidLength(String),

    #[error("{0}")]
    UnexpectedOutputType(String),

    #[error("{0}")]
    ParamNotProvided(String),
}
