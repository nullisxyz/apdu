//! Secure channel abstractions
//!
//! This module provides traits and types for secure channel protocols
//! like SCP02 and SCP03.

use crate::error::Error;
use crate::transport::CardTransport;

/// Security level for a secure channel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SecurityLevel {
    /// Command encryption
    pub command_encryption: bool,
    /// Command MAC protection
    pub command_mac: bool,
    /// Response encryption
    pub response_encryption: bool,
    /// Response MAC protection
    pub response_mac: bool,
}

impl SecurityLevel {
    /// Create a new security level
    pub const fn new(
        command_encryption: bool,
        command_mac: bool,
        response_encryption: bool,
        response_mac: bool,
    ) -> Self {
        Self {
            command_encryption,
            command_mac,
            response_encryption,
            response_mac,
        }
    }

    /// Create a security level with no protection
    pub const fn none() -> Self {
        Self::new(false, false, false, false)
    }

    /// Create a security level with command and response MAC protection
    pub const fn mac() -> Self {
        Self::new(false, true, false, true)
    }

    /// Create a security level with command encryption and MAC protection
    pub const fn enc_mac() -> Self {
        Self::new(true, true, false, true)
    }

    /// Create a security level with full protection
    pub const fn full() -> Self {
        Self::new(true, true, true, true)
    }

    /// Check if this security level satisfies the required level
    ///
    /// A security level satisfies another if it has at least the same
    /// protection mechanisms enabled.
    pub fn satisfies(&self, required: &Self) -> bool {
        (self.command_encryption || !required.command_encryption)
            && (self.command_mac || !required.command_mac)
            && (self.response_encryption || !required.response_encryption)
            && (self.response_mac || !required.response_mac)
    }

    /// Check if this security level has any protection
    pub fn is_none(&self) -> bool {
        !self.command_encryption
            && !self.command_mac
            && !self.response_encryption
            && !self.response_mac
    }
}

/// Trait for secure channel implementations
pub trait SecureChannel: CardTransport + Sized {
    /// Underlying transport
    type UnderlyingTransport: CardTransport;

    /// Get the inner transport
    fn transport(&self) -> &Self::UnderlyingTransport;

    /// Get the mutable inner transport
    fn transport_mut(&mut self) -> &mut Self::UnderlyingTransport;

    /// Establish secure channel
    fn establish(&mut self) -> Result<(), Error>;

    /// Check if secure channel is established
    fn is_established(&self) -> bool;

    /// Close secure channel
    fn close(&mut self) -> Result<(), Error>;

    /// Get current security level
    fn security_level(&self) -> SecurityLevel;

    /// Upgrade security level
    fn upgrade(&mut self, level: SecurityLevel) -> Result<(), Error>;
}

/// Blanket implementation of CardTransport for all SecureChannel
impl<T: CardTransport> SecureChannel for T {
    type UnderlyingTransport = T;

    fn transport(&self) -> &Self::UnderlyingTransport {
        self
    }

    fn transport_mut(&mut self) -> &mut Self::UnderlyingTransport {
        self
    }

    fn establish(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn is_established(&self) -> bool {
        true
    }

    fn close(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn security_level(&self) -> SecurityLevel {
        SecurityLevel::none()
    }

    fn upgrade(&mut self, _level: SecurityLevel) -> Result<(), Error> {
        Ok(())
    }
}
