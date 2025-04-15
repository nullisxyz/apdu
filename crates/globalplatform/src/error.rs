use nexum_apdu_core::{error::ApduExecutorErrors, prelude::*};
use thiserror::Error;

use crate::commands::{delete::DeleteError, external_authenticate::ExternalAuthenticateError, get_response::GetResponseError, get_status::GetStatusError, initialize_update::InitializeUpdateError, install::InstallError, load::LoadError, put_key::PutKeyError, select::SelectError, store_data::StoreDataError};

/// Result type for GlobalPlatform operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for GlobalPlatform operations
#[derive(Debug, Error)]
pub enum Error {
    /// Secure Channel errors
    #[error(transparent)]
    SecureChannel(#[from] nexum_apdu_core::secure_channel::SecureChannelError),
    
    /// Transport-related errors
    #[error(transparent)]
    Transport(#[from] TransportError),

    /// Command-related errors
    #[error(transparent)]
    Command(#[from] nexum_apdu_core::command::error::CommandError),

    /// Response-related errors
    #[error(transparent)]
    Response(#[from] nexum_apdu_core::response::error::ResponseError),

    /// Status errors (for status words)
    #[error(transparent)]
    Status(#[from] nexum_apdu_core::response::error::StatusError),

    /// Processor-related errors
    #[error(transparent)]
    Processor(#[from] nexum_apdu_core::processor::error::ProcessorError),

    /// Secure protocol related errors
    #[error(transparent)]
    SecureProtocol(#[from] nexum_apdu_core::processor::error::SecureProtocolError),

    /// Secure channel not established
    #[error("Secure channel not established")]
    NoSecureChannel,

    /// Cryptographic operation failed
    #[error("Cryptographic error: {0}")]
    Crypto(&'static str),

    /// Invalid or unsupported data format
    #[error("Invalid data format: {0}")]
    InvalidFormat(&'static str),

    /// Wrong data length
    #[error("Invalid length: expected {expected}, got {actual}")]
    InvalidLength {
        /// Expected length
        expected: usize,
        /// Actual length
        actual: usize,
    },

    /// Card authentication failed
    #[error("Card authentication failed: {0}")]
    AuthenticationFailed(&'static str),

    /// Invalid challenge
    #[error("Invalid challenge: {0}")]
    InvalidChallenge(&'static str),

    /// Invalid response
    #[error("Invalid response: {0}")]
    InvalidResponse(&'static str),

    /// Unsupported SCP version
    #[error("Unsupported SCP version: {0}")]
    UnsupportedScpVersion(u8),

    /// CAP file error
    #[error("CAP file error: {0}")]
    CapFile(&'static str),

    /// I/O error with CAP file
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Response indicates an error condition
    #[error("Card returned error status: {0}")]
    CardStatus(StatusWord),

    /// Other error
    #[error("{0}")]
    Other(&'static str),

    // Errors associated with commands
    #[error(transparent)]
    DeleteError(#[from] DeleteError),

    #[error(transparent)]
    ExternalAuthenticateError(#[from] ExternalAuthenticateError),

    #[error(transparent)]
    GetResponseError(#[from] GetResponseError),

    #[error(transparent)]
    GetStatusError(#[from] GetStatusError),

    #[error(transparent)]
    InitializeUpdateError(#[from] InitializeUpdateError),

    #[error(transparent)]
    InstallError(#[from] InstallError),

    #[error(transparent)]
    LoadError(#[from] LoadError),

    #[error(transparent)]
    PutKeyError(#[from] PutKeyError),

    #[error(transparent)]
    SelectError(#[from] SelectError),

    #[error(transparent)]
    StoreDataError(#[from] StoreDataError),
}

// Implement for our default error type
impl ApduExecutorErrors for Error {
    type Error = Self;
}

// Allow converting from any executor's error type to our Error type
impl<E: ApduExecutorErrors> From<E::Error> for Error {
    fn from(err: E::Error) -> Self {
        // Convert via the nexum_apdu_core::Error intermediate type 
        let core_error: nexum_apdu_core::Error = err.into();
        match core_error {
            nexum_apdu_core::Error::Transport(e) => Error::Transport(e),
            nexum_apdu_core::Error::Response(e) => Error::Response(e),
            nexum_apdu_core::Error::Processor(e) => Error::Processor(e),
            nexum_apdu_core::Error::SecureProtocol(e) => Error::SecureProtocol(e),
            _ => Error::Other("External error"),
        }
    }
}

// Implement conversion from our Error to nexum_apdu_core::Error
impl From<Error> for nexum_apdu_core::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::Transport(e) => nexum_apdu_core::Error::Transport(e),
            Error::Response(e) => nexum_apdu_core::Error::Response(e),
            Error::Processor(e) => nexum_apdu_core::Error::Processor(e),
            Error::SecureProtocol(e) => nexum_apdu_core::Error::SecureProtocol(e),
            // For all other error types, convert to Other with static string
            _ => nexum_apdu_core::Error::Other("GlobalPlatform error"),
        }
    }
}