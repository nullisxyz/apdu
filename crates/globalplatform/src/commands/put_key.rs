//! PUT KEY command for GlobalPlatform
//!
//! This command is used to load or replace keys on the card.

use nexum_apdu_macros::apdu_pair;

use crate::constants::{cla, ins, status};

apdu_pair! {
    /// PUT KEY command for GlobalPlatform
    pub struct PutKey {
        command {
            cla: cla::GP,
            ins: ins::PUT_KEY,
            required_security_level: SecurityLevel::mac_protected(),

            builders {
                /// Create a PUT KEY command for loading a new key version
                pub fn new_key_version(key_version: u8, key_data: impl Into<bytes::Bytes>) -> Self {
                    Self::new(0x00, key_version).with_data(key_data.into())
                }

                /// Create a PUT KEY command for replacing an existing key
                pub fn replace_key(key_version: u8, key_data: impl Into<bytes::Bytes>) -> Self {
                    Self::new(0x00, key_version).with_data(key_data.into())
                }

                /// Create a PUT KEY command with key derivation data
                pub fn with_derivation_data(key_version: u8, key_data: impl Into<bytes::Bytes>) -> Self {
                    Self::new(0x01, key_version).with_data(key_data.into())
                }

                /// Create a PUT KEY command for loading multiple keys
                pub fn multiple_keys(key_version: u8, key_data: impl Into<bytes::Bytes>) -> Self {
                    Self::new(0x02, key_version).with_data(key_data.into())
                }
            }
        }

        response {
            ok {
                /// Success response
                #[sw(status::SW_NO_ERROR)]
                Success,
            }

            errors {
                /// Referenced data not found
                #[sw(status::SW_REFERENCED_DATA_NOT_FOUND)]
                #[error("Referenced data not found")]
                ReferencedDataNotFound,

                /// Security status not satisfied
                #[sw(status::SW_SECURITY_STATUS_NOT_SATISFIED)]
                #[error("Security status not satisfied")]
                SecurityStatusNotSatisfied,

                /// Wrong data
                #[sw(status::SW_WRONG_DATA)]
                #[error("Wrong data")]
                WrongData,

                /// Other error
                #[sw(_, _)]
                #[error("Other error")]
                OtherError {
                    sw1: u8,
                    sw2: u8,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use nexum_apdu_core::ApduCommand;

    #[test]
    fn test_put_key_command() {
        // Sample key data
        let key_data = hex!("4F07A0000001510000");
        let cmd = PutKeyCommand::new_key_version(0x01, key_data.to_vec());

        assert_eq!(cmd.class(), cla::GP);
        assert_eq!(cmd.instruction(), ins::PUT_KEY);
        assert_eq!(cmd.p1(), 0x00);
        assert_eq!(cmd.p2(), 0x01);
        assert_eq!(cmd.data(), Some(key_data.as_ref()));

        // Test command serialization
        let raw = cmd.to_bytes();
        assert_eq!(raw.as_ref(), hex!("80D80001094F07A0000001510000"));
    }

    #[test]
    fn test_put_key_response() {
        // Test successful response
        let response_data = hex!("9000");
        let response = PutKeyResponse::from_bytes(&response_data).unwrap();
        assert!(matches!(response, PutKeyResponse::Success));

        // Test error response
        let response_data = hex!("6982");
        let response = PutKeyResponse::from_bytes(&response_data).unwrap();
        assert!(matches!(
            response,
            PutKeyResponse::SecurityStatusNotSatisfied
        ));
    }
}
