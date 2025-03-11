//! DELETE command for GlobalPlatform
//!
//! This command is used to delete applications, packages, and other objects.

use apdu_macros::apdu_pair;

use crate::constants::{cla, delete_p2, ins, status, tags};

apdu_pair! {
    /// DELETE command for GlobalPlatform
    pub struct Delete {
        command {
            cla: cla::GP,
            ins: ins::DELETE,
            secure: true,

            builders {
                /// Create a DELETE command for an object with specified parameters
                pub fn with_aid(aid: impl AsRef<[u8]>, p2: u8) -> Self {
                    // Build data field: tag + length + AID
                    let aid_data = aid.as_ref();
                    let mut data = Vec::with_capacity(2 + aid_data.len());
                    data.push(tags::DELETE_AID);
                    data.push(aid_data.len() as u8);
                    data.extend_from_slice(aid_data);

                    Self::new(0x00, p2).with_data(data)
                }

                /// Create a DELETE command for an object
                pub fn delete_object(aid: impl AsRef<[u8]>) -> Self {
                    Self::with_aid(aid, delete_p2::OBJECT)
                }

                /// Create a DELETE command for an object and related objects
                pub fn delete_object_and_related(aid: impl AsRef<[u8]>) -> Self {
                    Self::with_aid(aid, delete_p2::OBJECT_AND_RELATED)
                }
            }
        }

        response {
            variants {
                #[sw(0x90, 0x00)]
                Success,

                #[sw(status::REFERENCED_DATA_NOT_FOUND)]
                ReferencedDataNotFound,

                #[sw(status::SECURITY_CONDITION_NOT_SATISFIED)]
                SecurityConditionNotSatisfied,

                #[sw(_, _)]
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
    use apdu_core::ApduCommand;
    use hex_literal::hex;

    #[test]
    fn test_delete_command() {
        let aid = hex!("0102030405");
        let cmd = DeleteCommand::delete_object(&aid);

        assert_eq!(cmd.class(), cla::GP);
        assert_eq!(cmd.instruction(), ins::DELETE);
        assert_eq!(cmd.p1(), 0x00);
        assert_eq!(cmd.p2(), delete_p2::OBJECT);

        // Check data format (tag + length + AID)
        let expected_data = hex!("4F050102030405");
        assert_eq!(cmd.data(), Some(expected_data.as_ref()));

        // Test command serialization
        let raw = cmd.to_bytes();
        assert_eq!(raw.as_ref(), hex!("80E40000074F050102030405"));
    }

    #[test]
    fn test_delete_object_and_related() {
        let aid = hex!("A0000000030000");
        let cmd = DeleteCommand::delete_object_and_related(&aid);

        assert_eq!(cmd.p2(), delete_p2::OBJECT_AND_RELATED);

        // Check data format (tag + length + AID)
        let expected_data = hex!("4F07A0000000030000");
        assert_eq!(cmd.data(), Some(expected_data.as_ref()));
    }

    #[test]
    fn test_delete_response() {
        // Test successful response
        let response_data = hex!("9000");
        let response = DeleteResponse::from_bytes(&response_data).unwrap();
        assert!(matches!(response, DeleteResponse::Success));

        // Test error response
        let response_data = hex!("6A88");
        let response = DeleteResponse::from_bytes(&response_data).unwrap();
        assert!(matches!(response, DeleteResponse::ReferencedDataNotFound));
    }
}
