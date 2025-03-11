#![allow(missing_docs)]
//! Example of using the apdu_pair macro to define a Select command with custom payload parsing

use apdu_core::{ApduCommand, Bytes, Error, StatusWord};
use apdu_macros::apdu_pair;
use iso7816_tlv::simple::Tlv;

apdu_pair! {
    /// Select command for applications and files
    pub struct Select {
        command {
            cla: 0x00,
            ins: 0xA4,
            secure: false,

            builders {
                /// Select by name (AID)
                pub fn by_name(aid: impl Into<Bytes>) -> Self {
                    Self::new(0x04, 0x00).with_data(aid.into()).with_le(0)
                }

                /// Select by file ID
                pub fn by_file_id(file_id: impl Into<Bytes>) -> Self {
                    Self::new(0x00, 0x00).with_data(file_id.into()).with_le(0)
                }

                /// Select parent directory
                pub fn parent() -> Self {
                    Self::new(0x03, 0x00).with_le(0)
                }
            }
        }

        response {
            variants {
                // Normal success (90 00)
                #[sw(0x90, 0x00)]
                Success {
                    fci: Option<Vec<u8>>,
                },

                // File or application not found (6A 82)
                #[sw(0x6A, 0x82)]
                NotFound,

                // Incorrect parameters P1-P2 (6A 86)
                #[sw(0x6A, 0x86)]
                IncorrectParameters,

                // Unknown error
                #[sw(_, _)]
                OtherError {
                    sw1: u8,
                    sw2: u8,
                }
            }

            // Define custom payload parser as a closure
            parse_payload = |payload: &[u8], _: StatusWord, variant: &mut Self| -> Result<(), Error> {
                match variant {
                    Self::Success { fci } => {
                        if !payload.is_empty() {
                            // Store the raw FCI data
                            *fci = Some(payload.to_vec());

                            // Example validation
                            if let Some(data) = fci.as_ref() {
                                // Check if this looks like File Control Information
                                // (In real code, you might do more precise TLV parsing)
                                if data.len() < 2 || data[0] != 0x6F {
                                    return Err(Error::Parse("Invalid FCI format"));
                                }
                            }
                        }
                        Ok(())
                    },
                    _ => Ok(()) // No parsing for error variants
                }
            }

            methods {
                /// Returns true if selection was successful
                pub fn is_selected(&self) -> bool {
                    matches!(self, Self::Success { .. })
                }

                /// Get the application label if present in FCI
                pub fn application_label(&self) -> Option<Vec<u8>> {
                    if let Self::Success { fci: Some(data) } = self {
                        let mut remaining = data.as_slice();
                        while !remaining.is_empty() {
                            let (tlv_result, next_remaining) = Tlv::parse(remaining);
                            match tlv_result {
                                Ok(tlv) => {
                                    // Explicitly specify the type for the comparison
                                    if <iso7816_tlv::simple::Tag as Into<u8>>::into(tlv.tag()) == 0x50 {
                                        return Some(tlv.value().to_owned());
                                    }
                                    remaining = next_remaining;
                                },
                                Err(_) => break,
                            }
                        }
                        None
                    } else {
                        None
                    }
                }

                /// Get the status word
                pub fn status_word(&self) -> StatusWord {
                    match self {
                        Self::Success { .. } => StatusWord::new(0x90, 0x00),
                        Self::NotFound { .. } => StatusWord::new(0x6A, 0x82),
                        Self::IncorrectParameters { .. } => StatusWord::new(0x6A, 0x86),
                        Self::OtherError { sw1, sw2 } => StatusWord::new(*sw1, *sw2),
                    }
                }
            }
        }
    }
}

fn main() {
    // Example usage of the generated code:
    let select_cmd = SelectCommand::by_name([0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00].as_slice());

    println!(
        "Select command: CLA={:#04x}, INS={:#04x}, P1={:#04x}, P2={:#04x}",
        select_cmd.class(),
        select_cmd.instruction(),
        select_cmd.p1(),
        select_cmd.p2()
    );

    // In a real application, you would use an executor to send the command:
    // let response = executor.execute(&select_cmd).unwrap();
    // if response.is_selected() {
    //     println!("Application selected successfully!");
    //     if let Some(label) = response.application_label() {
    //         println!("Application label: {:?}", label);
    //     }
    // }
}
