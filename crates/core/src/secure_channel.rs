//! Secure channel abstractions
//!
//! This module provides traits and types for secure channel protocols
//! like SCP02 and SCP03.

use crate::error::Error;
use crate::transport::CardTransport;

/// Security level for a secure channel
///
/// Represents the security properties applied to the transport (SecureChannel)
/// without distinguishing between command and response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SecurityLevel {
    /// Whether encryption is enabled
    pub encryption: bool,
    /// Whether integrity (MAC) is enabled
    pub integrity: bool,
    /// Whether authentication is enabled
    pub authentication: bool,
}

impl SecurityLevel {
    /// Create a new security level
    pub const fn new(encryption: bool, integrity: bool, authentication: bool) -> Self {
        Self {
            encryption,
            integrity,
            authentication,
        }
    }

    /// Create a security level with no protection
    pub const fn none() -> Self {
        Self::new(false, false, false)
    }

    /// Create a security level with only MAC protection (integrity)
    pub const fn mac() -> Self {
        Self::new(false, true, false)
    }

    /// Create a security level with MAC protection (integrity) and encryption
    pub const fn enc_mac() -> Self {
        Self::new(true, true, false)
    }

    /// Create a security level with authentication and MAC protection (integrity)
    pub const fn auth_mac() -> Self {
        Self::new(false, true, true)
    }

    /// Create a security level with authentication and MAC protection (integrity)
    /// (Alias for auth_mac() for backward compatibility)
    pub const fn authenticated_mac() -> Self {
        Self::auth_mac()
    }

    /// Create a security level with full protection (encryption, integrity, and authentication)
    pub const fn full() -> Self {
        Self::new(true, true, true)
    }

    /// Create a security level with MAC protection (integrity) only
    pub const fn mac_protected() -> Self {
        Self::mac()
    }

    /// Check if this security level satisfies the required level
    ///
    /// A security level satisfies another if it has at least the same
    /// protection mechanisms enabled.
    pub fn satisfies(&self, required: &Self) -> bool {
        (self.encryption || !required.encryption)
            && (self.integrity || !required.integrity)
            && (self.authentication || !required.authentication)
    }

    /// Check if this security level has any protection
    pub fn is_none(&self) -> bool {
        !self.encryption && !self.integrity && !self.authentication
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
    fn open(&mut self) -> Result<(), Error>;

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

    fn open(&mut self) -> Result<(), Error> {
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
