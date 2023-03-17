use crate::core::ics02_client::error::ClientError;
use crate::prelude::*;
use displaydoc::Display;

#[derive(Debug, Display)]
pub enum Error {
    /// missing latest height
    MissingLatestHeight,
    /// decode error: `{0}`
    Decode(prost::DecodeError),
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self {
            Self::Decode(e) => Some(e),
            _ => None,
        }
    }
}

impl From<Error> for ClientError {
    fn from(e: Error) -> Self {
        Self::ClientSpecific {
            description: e.to_string(),
        }
    }
}
