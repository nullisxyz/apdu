//! Executor for APDU command execution
//!
//! This module provides traits and error types for APDU command execution.
//! The actual card executor implementation is in the `card` module.

pub mod response_aware;

use std::fmt;

use crate::command::{ApduCommand, Command};
use crate::error::Error;
use crate::{CardTransport, Response};
use bytes::Bytes;
use tracing::{debug, instrument, trace};

// Re-export extension traits
pub use response_aware::ResponseAwareExecutor;

/// Trait for APDU command execution
pub trait Executor: Send + Sync + fmt::Debug {
    /// The transport type used by this executor
    type Transport: CardTransport;

    /// Get a reference to the underlying transport
    fn transport(&self) -> &Self::Transport;

    /// Get a mutable reference to the underlying transport
    fn transport_mut(&mut self) -> &mut Self::Transport;

    /// Transmit a raw APDU command
    ///
    /// This is the lowest level public transmission method.
    #[instrument(level = "trace", skip(self), fields(executor = std::any::type_name::<Self>()))]
    fn transmit_raw(&mut self, command: &[u8]) -> Result<Bytes, Error> {
        trace!(command = ?hex::encode(command), "Transmitting raw command");
        let response = self.do_transmit_raw(command);
        match &response {
            Ok(bytes) => {
                trace!(response = ?hex::encode(bytes), "Received raw response");
            }
            Err(err) => {
                debug!(error = ?err, "Error during raw transmission");
            }
        }
        response
    }

    /// Internal implementation of transmit_raw
    fn do_transmit_raw(&mut self, command: &[u8]) -> Result<Bytes, Error>;

    /// Transmit a generic Command and return a Response
    ///
    /// This is the mid-level transmission method that works with Command and Response objects.
    fn transmit(&mut self, command: &Command) -> Result<Response, Error> {
        trace!(command = ?command, "Transmitting command");
        let command_bytes = command.to_bytes();
        let response_bytes = self.transmit_raw(&command_bytes)?;
        let response = Response::from_bytes(&response_bytes)
            .map_err(|e| e.with_context("Failed to parse response bytes"))?;
        trace!(response = ?response, "Received response");
        Ok(response)
    }

    /// Execute a typed APDU command and return the command's success type
    ///
    /// This method returns the command's Success type directly for more
    /// idiomatic error handling with the ? operator. The error type is the command's
    /// own error type, allowing commands to define their own error handling.
    fn execute<C>(&mut self, command: &C) -> Result<C::Success, C::Error>
    where
        C: ApduCommand;

    /// Reset the executor, including the transport
    fn reset(&mut self) -> Result<(), Error>;
}
