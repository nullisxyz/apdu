//! Extension traits for APDU executors
//!
//! This module provides additional traits that extend the core Executor trait
//! with functionality needed for specialized operations.

use crate::{
    Bytes, Error, Result, executor::Executor, processor::secure::SecureChannelProvider,
    transport::CardTransport,
};

/// Extension trait for executors that support access to the last response
pub trait ResponseAwareExecutor: Executor {
    /// Get the last response received
    ///
    /// Returns the raw bytes of the last response received from the card.
    /// This is useful for protocols that need to access the raw response
    /// for cryptographic operations.
    fn last_response(&self) -> Result<&Bytes>;
}

/// Extension trait for executors that support secure channels
pub trait SecureChannelExecutor: Executor {
    /// Open a secure channel with the card
    ///
    /// This establishes a secure channel using the provided secure channel provider
    /// and the requested security level.
    fn open_secure_channel(&mut self, provider: &dyn SecureChannelProvider) -> Result<()>;
}

// Implementation for CardExecutor
impl<T: CardTransport> ResponseAwareExecutor for super::CardExecutor<T> {
    fn last_response(&self) -> Result<&Bytes> {
        self.last_response()
            .ok_or_else(|| Error::Other("No last response available".to_string()))
    }
}

impl<T: CardTransport> SecureChannelExecutor for super::CardExecutor<T> {
    fn open_secure_channel(&mut self, provider: &dyn SecureChannelProvider) -> Result<()> {
        Self::open_secure_channel(self, provider)
    }
}
