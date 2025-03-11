//! INITIALIZE UPDATE command for GlobalPlatform
//!
//! This command is used to start a secure channel session.

use apdu_macros::apdu_pair;

use crate::constants::{cla, ins, status};

/// Default host challenge length in bytes
pub const DEFAULT_HOST_CHALLENGE_LENGTH: usize = 8;

apdu_pair! {
    /// INITIALIZE UPDATE command for GlobalPlatform
    pub struct InitializeUpdate {
        command {
            cla: cla::GP,
            ins: ins::INITIALIZE_UPDATE,
            secure: false,

            builders {
                /// Create a new INITIALIZE UPDATE command with a host challenge
                pub fn with_challenge(host_challenge: impl Into<bytes::Bytes>) -> Self {
                    Self::new(0x00, 0x00).with_data(host_challenge.into()).with_le(0x00)
                }

                /// Create a new INITIALIZE UPDATE command with random host challenge
                pub fn with_random_challenge() -> Self {
                    let mut challenge = [0u8; DEFAULT_HOST_CHALLENGE_LENGTH];
                    rand::RngCore::fill_bytes(&mut rand::rng(), &mut challenge);
                    Self::with_challenge(challenge.to_vec())
                }
            }
        }

        response {
            variants {
                /// Success response (9000)
                #[sw(status::SUCCESS)]
                Success {
                    key_diversification_data: Vec<u8>,
                    key_info: Vec<u8>,
                    card_challenge: Vec<u8>,
                    card_cryptogram: Vec<u8>,
                },

                /// Security condition not satisfied (6982)
                #[sw(status::SECURITY_CONDITION_NOT_SATISFIED)]
                SecurityConditionNotSatisfied,

                /// Authentication method blocked (6983)
                #[sw(status::AUTHENTICATION_METHOD_BLOCKED)]
                AuthenticationMethodBlocked,

                /// Other error
                #[sw(_, _)]
                OtherError {
                    sw1: u8,
                    sw2: u8,
                }
            }

            parse_payload = |payload: &[u8], _sw: apdu_core::StatusWord, variant: &mut Self| -> Result<(), apdu_core::Error> {
                if let Self::Success {
                    key_diversification_data,
                    key_info,
                    card_challenge,
                    card_cryptogram
                } = variant {
                    if payload.len() < 28 {
                        return Err(apdu_core::Error::Parse("Response data too short"));
                    }

                    // Key diversification data (10 bytes)
                    key_diversification_data.extend_from_slice(&payload[0..10]);

                    // Key information (2 bytes)
                    key_info.extend_from_slice(&payload[10..12]);

                    // Card challenge (8 bytes)
                    card_challenge.extend_from_slice(&payload[12..20]);

                    // Card cryptogram (8 bytes)
                    card_cryptogram.extend_from_slice(&payload[20..28]);
                }

                Ok(())
            }

            methods {
                /// Get the SCP version
                pub fn scp_version(&self) -> Option<u8> {
                    match self {
                        Self::Success { key_info, .. } => {
                            if key_info.len() >= 2 {
                                Some(key_info[1])
                            } else {
                                None
                            }
                        },
                        _ => None,
                    }
                }

                /// Get the key version number
                pub fn key_version_number(&self) -> Option<u8> {
                    match self {
                        Self::Success { key_info, .. } => {
                            if key_info.len() >= 1 {
                                Some(key_info[0])
                            } else {
                                None
                            }
                        },
                        _ => None,
                    }
                }

                /// Get the sequence counter
                pub fn sequence_counter(&self) -> Option<&[u8]> {
                    match self {
                        Self::Success { card_challenge, .. } => {
                            if card_challenge.len() >= 2 {
                                Some(&card_challenge[0..2])
                            } else {
                                None
                            }
                        },
                        _ => None,
                    }
                }

                /// Get the security level supported by the card
                pub fn security_level(&self) -> Option<u8> {
                    match self {
                        Self::Success { key_info, .. } => {
                            if key_info.len() >= 1 {
                                let sec_level = key_info[0];
                                // Security level is the second byte of key info
                                Some(sec_level)
                            } else {
                                None
                            }
                        },
                        _ => None,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apdu_core::ApduCommand;
    use hex_literal::hex;

    #[test]
    fn test_initialize_update_command() {
        // Test with specific challenge
        let challenge = hex!("010203");
        let cmd = InitializeUpdateCommand::with_challenge(challenge.to_vec());

        assert_eq!(cmd.class(), cla::GP);
        assert_eq!(cmd.instruction(), ins::INITIALIZE_UPDATE);
        assert_eq!(cmd.p1(), 0x00);
        assert_eq!(cmd.p2(), 0x00);
        assert_eq!(cmd.data(), Some(challenge.as_ref()));
        assert_eq!(cmd.expected_length(), Some(0x00));

        // Test command serialization
        let raw = cmd.to_bytes();
        assert_eq!(raw.as_ref(), hex!("8050000003010203"));
    }

    #[test]
    fn test_initialize_update_response() {
        // Test successful response
        let response_data = hex!("000002650183039536622002000de9c62ba1c4c8e55fcb91b6654ce49000");

        let response = InitializeUpdateResponse::from_bytes(&response_data).unwrap();

        assert!(matches!(response, InitializeUpdateResponse::Success { .. }));
        assert_eq!(response.scp_version(), Some(0x02));
        assert_eq!(response.key_version_number(), Some(0x01));

        // Use .as_slice() to convert the array reference to a slice for comparison
        if let Some(counter) = response.sequence_counter() {
            assert_eq!(counter, &[0x00, 0x0d]);
        } else {
            panic!("Sequence counter should be present");
        }

        if let InitializeUpdateResponse::Success {
            key_diversification_data,
            key_info,
            card_challenge,
            card_cryptogram,
        } = response
        {
            assert_eq!(key_diversification_data, hex!("0000026501830395"));
            assert_eq!(key_info, hex!("3662"));
            assert_eq!(card_challenge, hex!("2002000de9c62ba1"));
            assert_eq!(card_cryptogram, hex!("c4c8e55fcb91b665"));
        }

        // Test error response
        let response_data = hex!("6982");
        let response = InitializeUpdateResponse::from_bytes(&response_data).unwrap();
        assert!(matches!(
            response,
            InitializeUpdateResponse::SecurityConditionNotSatisfied
        ));
    }
}
