//! Core traits and types for APDU (Application Protocol Data Unit) operations
//!
//! This crate provides the foundational types and traits for working with smart card
//! APDU commands and responses according to ISO/IEC 7816-4.
//!
//! ## Overview
//!
//! APDU (Application Protocol Data Unit) is the communication format used by smart cards.
//! This crate provides abstractions for:
//!
//! - Creating and parsing APDU commands and responses
//! - Communicating with smart cards through different transport layers
//! - Handling secure communication channels
//! - Error handling and status word interpretation
//!
//! The crate is designed to be flexible and extensible while supporting both std and no_std environments.
#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![forbid(unsafe_code)]
#![warn(missing_docs, rustdoc::missing_crate_level_docs)]

// Re-export bytes for convenience
pub use bytes::{Bytes, BytesMut};

// Main modules
pub mod command;
pub mod error;
pub mod executor;
pub mod processor;
pub mod response;
pub mod transport;

pub use command::{ApduCommand, Command};
pub use error::Error;
pub use executor::ext::{ResponseAwareExecutor, SecureChannelExecutor};
pub use executor::{ApduExecutorErrors, CardExecutor, Executor};
pub use response::status::StatusWord;
pub use response::{ApduResponse, Response, utils};
pub use transport::CardTransport;

/// Prelude module containing commonly used traits and types
pub mod prelude {
    // Core types
    pub use crate::{Bytes, BytesMut, Error};

    // Command related
    pub use crate::{
        Command,
        command::{ApduCommand, CommandResult, ExpectedLength},
    };

    // Response related
    pub use crate::{
        Response,
        response::status::{StatusWord, common as status},
        response::{ApduResponse, utils as response_utils},
    };

    // Transport layer
    pub use crate::transport::{CardTransport, TransportError};

    // Processor layer
    pub use crate::processor::{
        CommandProcessor, GetResponseProcessor, IdentityProcessor, ProcessorError,
        secure::{SecureChannel, SecureChannelProvider, SecurityLevel},
    };

    // Executor layer
    pub use crate::{
        executor::ext::{ResponseAwareExecutor, SecureChannelExecutor},
        executor::{ApduExecutorErrors, CardExecutor, Executor},
    };
}
#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    // Test the basic types are re-exported correctly
    #[test]
    fn test_reexports() {
        let cmd = Command::new(0x00, 0xA4, 0x04, 0x00);
        assert_eq!(cmd.class(), 0x00);
        assert_eq!(cmd.instruction(), 0xA4);
        assert_eq!(cmd.p1(), 0x04);
        assert_eq!(cmd.p2(), 0x00);

        let data = Bytes::from_static(&[0x01, 0x02, 0x03]);
        let resp = Response::success(Some(data.clone()));
        assert!(resp.is_success());
        assert_eq!(resp.payload(), &Some(data));
        assert_eq!(resp.status(), StatusWord::new(0x90, 0x00));
    }
}
