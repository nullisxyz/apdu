//! Secure channel implementation for GlobalPlatform
//!
//! This module provides the SecureChannel type that wraps card communication
//! with SCP02 security.

use std::fmt;

use bytes::{BufMut, Bytes, BytesMut};
use cipher::{Iv, Key};

use nexum_apdu_core::prelude::*;
use nexum_apdu_core::processor::SecureProtocolError;
use nexum_apdu_core::secure_channel::{SecureChannel, SecureChannelError, SecurityLevel};
use nexum_apdu_core::transport::CardTransport;
use rand::RngCore;
use tracing::debug;

use crate::Error;
use crate::commands::external_authenticate::ExternalAuthenticateOk;
use crate::commands::initialize_update::InitializeUpdateOk;
use crate::commands::{ExternalAuthenticateCommand, InitializeUpdateCommand};
use crate::crypto::{HostChallenge, Scp02};
use crate::crypto::{encrypt_icv, mac_full_3des};
use crate::session::{Keys, Session};

/// SCP02 command wrapper
#[allow(missing_debug_implementations)]
#[derive(Clone)]
pub struct SCP02Wrapper {
    /// MAC key
    mac_key: Key<Scp02>,
    /// Initial chaining vector
    icv: Iv<Scp02>,
}

impl SCP02Wrapper {
    /// Create a new SCP02 wrapper with the specified MAC key
    pub fn new(key: Key<Scp02>) -> Self {
        Self {
            mac_key: key,
            icv: Default::default(),
        }
    }

    /// Wrap an APDU command by adding a MAC
    pub fn wrap_command(&mut self, command: &Command) -> Command {
        // Prepare data for MAC calculation
        let mut mac_data = BytesMut::with_capacity(5 + command.data().map_or(0, |d| d.len()));

        // Set CLA byte with secure messaging bit
        let cla = command.class() | 0x04;
        mac_data.put_u8(cla);
        mac_data.put_u8(command.instruction());
        mac_data.put_u8(command.p1());
        mac_data.put_u8(command.p2());

        // Lc is data length + 8 (for MAC)
        let data_len = command.data().map_or(0, |d| d.len());
        mac_data.put_u8((data_len + 8) as u8);

        // Add command data
        if let Some(data) = command.data() {
            mac_data.put_slice(data);
        }

        // Encrypt the ICV if it's not default
        let icv_for_mac = if self.icv == Default::default() {
            self.icv
        } else {
            encrypt_icv(&self.mac_key, &self.icv)
        };

        // Calculate the MAC
        let mac = mac_full_3des(&self.mac_key, &icv_for_mac, &mac_data);

        // Save MAC as ICV for next command
        self.icv.copy_from_slice(&mac);

        // Create new command with MAC appended
        let mut new_data = BytesMut::with_capacity(data_len + 8);
        if let Some(data) = command.data() {
            new_data.put_slice(data);
        }
        new_data.put_slice(&mac);

        // Create new command
        let mut new_cmd = Command::new(cla, command.instruction(), command.p1(), command.p2());

        new_cmd = new_cmd.with_data(new_data.freeze());

        // Set Le if original command had it
        if let Some(le) = command.expected_length() {
            new_cmd = new_cmd.with_le(le);
        }

        new_cmd
    }

    /// Get the current ICV
    pub const fn icv(&self) -> &Iv<Scp02> {
        &self.icv
    }

    /// Encrypt the ICV for the next operation
    pub fn encrypt_icv(&mut self) -> Result<(), Error> {
        let encrypted = encrypt_icv(&self.mac_key, &self.icv);
        self.icv.copy_from_slice(&encrypted);
        Ok(())
    }
}

/// GPSecureChannel implements the SecureChannel trait for SCP02
pub struct GPSecureChannel<T: CardTransport> {
    /// Session containing keys and state - this will be initialized during establish()
    session: Option<Session>,
    /// Command wrapper for SCP02
    wrapper: Option<SCP02Wrapper>,
    /// Whether the channel is established
    established: bool,
    /// Current security level
    security_level: SecurityLevel,
    /// The underlying transport
    transport: T,
    /// Keys for establishing the session
    keys: Keys,
}

impl<T: CardTransport> fmt::Debug for GPSecureChannel<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GPSecureChannel")
            .field("established", &self.established)
            .field("security_level", &self.security_level)
            .finish()
    }
}

impl<T: CardTransport> GPSecureChannel<T> {
    /// Create a new secure channel with the specified transport and keys
    pub fn new(transport: T, keys: Keys) -> Self {
        // Simple constructor that just stores the transport and keys
        // The session and wrapper will be initialized during establish()
        Self {
            session: None,
            wrapper: None,
            established: false,
            security_level: SecurityLevel::none(),
            transport,
            keys,
        }
    }

    /// Get a reference to the session
    ///
    /// This will return None if the session hasn't been established yet
    pub fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    /// Authenticate the secure channel using EXTERNAL AUTHENTICATE
    fn authenticate(&mut self) -> Result<(), SecureChannelError> {
        // Get session and wrapper (should be Some after establish was called)
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| SecureChannelError::General("Session not initialized".to_string()))?;

        let wrapper = self
            .wrapper
            .as_mut()
            .ok_or_else(|| SecureChannelError::General("Wrapper not initialized".to_string()))?;

        // Create EXTERNAL AUTHENTICATE command
        let auth_cmd = ExternalAuthenticateCommand::from_challenges(
            session.keys().enc(),
            session.sequence_counter(),
            session.card_challenge(),
            session.host_challenge(),
        );

        // Convert to Command
        let command = auth_cmd.to_command();

        // Wrap the command with MAC
        let wrapped_cmd = wrapper.wrap_command(&command);

        // Send wrapped command
        let response_bytes = self
            .transport
            .transmit_raw(&wrapped_cmd.to_bytes())
            .map_err(|e| SecureChannelError::Transport(e))?;

        // Parse response
        let auth_result = ExternalAuthenticateCommand::parse_response_raw(response_bytes);

        // Check if successful
        if !matches!(auth_result, Ok(ExternalAuthenticateOk::Success)) {
            self.established = false;
            return Err(SecureChannelError::General(
                "EXTERNAL AUTHENTICATE failed".to_string(),
            ));
        }

        // Set security level
        self.security_level = SecurityLevel::authenticated_mac();

        // Mark channel as established
        self.established = true;

        Ok(())
    }

    /// Helper to convert protocol errors to secure channel errors
    fn convert_error(error: SecureProtocolError) -> SecureChannelError {
        match error {
            SecureProtocolError::AuthenticationFailed(msg) => {
                SecureChannelError::General(format!("Authentication failed: {}", msg))
            }
            SecureProtocolError::Session(msg) => {
                SecureChannelError::General(format!("Session error: {}", msg))
            }
            SecureProtocolError::Response(e) => {
                SecureChannelError::General(format!("Response error: {}", e))
            }
            SecureProtocolError::Other(msg) => SecureChannelError::General(msg),
            SecureProtocolError::Protocol(msg) => {
                SecureChannelError::General(format!("Protocol error: {}", msg))
            }
            SecureProtocolError::InsufficientSecurityLevel => {
                SecureChannelError::InsufficientSecurityLevel(
                    "Required security level not met".to_string(),
                )
            }
        }
    }
}

/// Create a new GlobalPlatform secure channel with the given transport and keys
pub fn create_secure_channel<T: CardTransport>(transport: T, keys: Keys) -> GPSecureChannel<T> {
    GPSecureChannel::new(transport, keys)
}

impl<T: CardTransport> SecureChannel for GPSecureChannel<T> {
    type UnderlyingTransport = T;

    fn is_established(&self) -> bool {
        self.established
    }

    fn establish(&mut self) -> Result<(), SecureChannelError> {
        // Generate host challenge
        let mut host_challenge = HostChallenge::default();
        rand::rng().fill_bytes(&mut host_challenge);

        // Step 1: Send INITIALIZE UPDATE
        let init_cmd = InitializeUpdateCommand::with_challenge(host_challenge.to_vec());
        let response_bytes = self
            .transport
            .transmit_raw(&init_cmd.to_bytes())
            .map_err(|e| SecureChannelError::Transport(e))?;

        // Parse response
        let init_response = InitializeUpdateCommand::parse_response_raw(response_bytes);

        // Check for successful response
        if !matches!(init_response, Ok(InitializeUpdateOk::Success { .. })) {
            return Err(SecureChannelError::General(
                "INITIALIZE UPDATE failed".to_string(),
            ));
        }

        // Create session directly from response
        let new_session = Session::from_response(&self.keys, &init_response, host_challenge)
            .map_err(|e| SecureChannelError::General(e.to_string()))?;

        // Initialize the session and wrapper
        self.session = Some(new_session);
        self.wrapper = Some(SCP02Wrapper::new(
            *self.session.as_ref().unwrap().keys().mac(),
        ));

        // Step 2: Authenticate the channel (sends EXTERNAL AUTHENTICATE)
        self.authenticate()
    }

    fn close(&mut self) -> Result<(), SecureChannelError> {
        debug!("Closing GlobalPlatform SCP02 secure channel");
        self.established = false;
        self.security_level = SecurityLevel::none();
        Ok(())
    }

    fn security_level(&self) -> SecurityLevel {
        self.security_level
    }

    fn protect_command(&mut self, command: &[u8]) -> Result<Vec<u8>, SecureChannelError> {
        if !self.is_established() {
            return Err(SecureChannelError::NotEstablished);
        }

        let wrapper = self
            .wrapper
            .as_mut()
            .ok_or_else(|| SecureChannelError::General("Wrapper not initialized".to_string()))?;

        let cmd = Command::from_bytes(command)
            .map_err(|e| SecureChannelError::General(format!("Invalid command: {}", e)))?;

        let wrapped = wrapper.wrap_command(&cmd);
        Ok(wrapped.to_bytes().to_vec())
    }

    fn process_response(&mut self, response: &[u8]) -> Result<Bytes, SecureChannelError> {
        // For SCP02, no response processing is needed as the card doesn't secure responses
        // Just pass through the raw response
        Ok(Bytes::copy_from_slice(response))
    }

    fn underlying_transport(&self) -> &Self::UnderlyingTransport {
        &self.transport
    }

    fn underlying_transport_mut(&mut self) -> &mut Self::UnderlyingTransport {
        &mut self.transport
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // Test transport for secure channel tests
    #[derive(Debug)]
    struct TestMockTransport {
        commands: Vec<Vec<u8>>,
        responses: Vec<Vec<u8>>,
    }

    impl TestMockTransport {
        fn new() -> Self {
            Self {
                commands: Vec::new(),
                responses: Vec::new(),
            }
        }

        fn with_response(mut self, response: Vec<u8>) -> Self {
            self.responses.push(response);
            self
        }
    }

    impl CardTransport for TestMockTransport {
        fn do_transmit_raw(&mut self, command: &[u8]) -> Result<Bytes, TransportError> {
            self.commands.push(command.to_vec());

            // Return pre-configured responses or error if no more responses
            if !self.responses.is_empty() {
                let response = self.responses.remove(0);
                Ok(Bytes::copy_from_slice(&response))
            } else {
                Err(TransportError::Other("No more test responses".to_string()))
            }
        }

        fn is_connected(&self) -> bool {
            true
        }

        fn reset(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
    }

    fn create_test_session() -> Session {
        // Test keys - DON'T USE IN PRODUCTION
        let key_bytes = hex!("404142434445464748494A4B4C4D4E4F");
        let key = Key::<Scp02>::from_slice(&key_bytes);

        let keys = Keys::from_single_key(*key);

        // Create a dummy response for testing
        let dummy_response = Bytes::from_static(&[
            // Key diversification data (10 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Key version number
            0x01, // SCP identifier
            0x02, // Sequence counter
            0x00, 0x00, 0x00, // Card challenge
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Card cryptogram
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Status words
            0x90, 0x00,
        ]);
        let init_response = InitializeUpdateCommand::parse_response_raw(dummy_response);

        // Create test session with the test keys
        Session::from_response(&keys, &init_response, HostChallenge::default())
            .expect("Failed to create test session")
    }

    #[test]
    fn test_wrap_command() {
        let session = create_test_session();
        let mut wrapper = SCP02Wrapper::new(*session.keys().mac());

        // Test command: SELECT by AID
        let command = Command::new(0x00, 0xA4, 0x04, 0x00)
            .with_data(Bytes::copy_from_slice(&[
                0xA0, 0x00, 0x00, 0x01, 0x51, 0x00,
            ]))
            .with_le(0);

        let wrapped = wrapper.wrap_command(&command);

        // Verify class byte has secure messaging bit set
        assert_eq!(wrapped.class(), 0x04);

        // Verify data includes the command data plus MAC
        let wrapped_data = wrapped.data().expect("No data in wrapped command");
        assert_eq!(wrapped_data.len(), 14); // 6 bytes AID + 8 bytes MAC

        // Verify the first part of data is the original command data
        assert_eq!(&wrapped_data[0..6], &[0xA0, 0x00, 0x00, 0x01, 0x51, 0x00]);

        // Verify Le is preserved
        assert_eq!(wrapped.expected_length(), Some(0));
    }

    #[test]
    fn test_secure_channel_establish() {
        // Create mock transport with predefined responses for INITIALIZE UPDATE and EXTERNAL AUTHENTICATE
        let transport = TestMockTransport::new()
            // INITIALIZE UPDATE response
            .with_response(vec![
                // Key diversification data
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                // Key version number
                0x01, // SCP identifier
                0x02, // Sequence counter
                0x00, 0x00, 0x00, // Card challenge
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // Card cryptogram
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, // Status words
                0x90, 0x00,
            ])
            // EXTERNAL AUTHENTICATE response
            .with_response(vec![0x90, 0x00]);

        let key_bytes = hex!("404142434445464748494A4B4C4D4E4F");
        let key = Key::<Scp02>::from_slice(&key_bytes);
        let keys = Keys::from_single_key(*key);

        let mut secure_channel = GPSecureChannel::new(transport, keys);

        // Test establishment
        let result = secure_channel.establish();

        // For this test, we'll just verify the function call completes
        // In a real test, we would verify the cryptograms, but that requires more test setup
        assert!(result.is_err(), "Should fail with test mock cryptograms");
    }
}
