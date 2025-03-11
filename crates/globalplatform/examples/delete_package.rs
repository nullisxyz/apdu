//! Example to delete a package from a GlobalPlatform-compatible card
//!
//! This example connects to a PC/SC reader, selects the ISD, opens a secure channel,
//! and deletes a package by AID.

use apdu_core::CardExecutor;
use apdu_globalplatform::GlobalPlatform;
use apdu_transport_pcsc::{PcscConfig, PcscDeviceManager};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Check command line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <package_aid_hex>", args[0]);
        return Ok(());
    }

    // Parse package AID
    let package_aid = match hex::decode(&args[1]) {
        Ok(aid) => aid,
        Err(_) => {
            println!("Invalid AID format. Please provide a valid hexadecimal AID.");
            return Ok(());
        }
    };

    // Create a PC/SC device manager
    let manager = PcscDeviceManager::new()?;

    // List available readers
    let readers = manager.list_readers()?;

    if readers.is_empty() {
        println!("No readers found!");
        return Ok(());
    }

    // Find a reader with a card
    let reader = match readers.iter().find(|r| r.has_card()) {
        Some(reader) => reader,
        None => {
            println!("No card found in any reader!");
            return Ok(());
        }
    };

    println!("Using reader: {}", reader.name());

    // Connect to the reader
    let config = PcscConfig::default();
    let transport = manager.open_reader_with_config(reader.name(), config)?;
    let executor = CardExecutor::new(transport);

    // Create GlobalPlatform instance
    let mut gp = GlobalPlatform::new(executor);

    // Select the Card Manager
    println!("Selecting Card Manager...");
    let select_response = gp.select_card_manager()?;
    if !select_response.is_success() {
        println!("Failed to select Card Manager!");
        return Ok(());
    }
    println!("Card Manager selected successfully.");

    // Open secure channel
    println!("Opening secure channel...");
    match gp.open_secure_channel() {
        Ok(_) => println!("Secure channel established."),
        Err(e) => {
            println!("Failed to open secure channel: {:?}", e);
            return Ok(());
        }
    }

    // Delete package and related objects
    println!(
        "Deleting package with AID: {}",
        hex::encode_upper(&package_aid)
    );
    match gp.delete_object_and_related(&package_aid) {
        Ok(_) => println!("Package deleted successfully."),
        Err(e) => {
            println!("Failed to delete package: {:?}", e);
            return Ok(());
        }
    }

    println!("Operation completed.");
    Ok(())
}
