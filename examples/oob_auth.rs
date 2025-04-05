// examples/oob_auth.rs

use qfe::{setup_qfe_pair}; // Import necessary items
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("--- QFE Out-of-Band (OOB) Authentication Example ---");
    println!("Simulates two parties establishing a shared state and verifying");
    println!("its authenticity via fingerprints before trusting the channel.");

    // --- Stage 1: SQS Establishment over (Simulated) Insecure Channel ---
    println!("\n[1] Participants attempt SQS establishment...");

    let setup_result = setup_qfe_pair(
        "Alice_OOB".to_string(),
        20250405, // Example seeds
        "Bob_OOB".to_string(),
        20250405,
    );

    let (alice, mut bob) = match setup_result {
        Ok(pair) => {
            println!("    SQS potentially established between Alice and Bob.");
            pair
        },
        Err(e) => {
            eprintln!("    ERROR: Failed to establish SQS: {}", e);
            return Err(Box::new(e));
        }
    };

    println!("    Alice Valid Status: {}", alice.is_valid());
    println!("    Bob Valid Status: {}", bob.is_valid());

    // --- Stage 2: Fingerprint Calculation ---
    println!("\n[2] Participants independently calculate SQS fingerprints...");

    let alice_fp = match alice.calculate_sqs_fingerprint() {
        Ok(fp) => {
            println!("    Alice calculates fingerprint: {}", fp);
            fp
        }
        Err(e) => {
             eprintln!("    ERROR: Alice failed to calculate fingerprint: {}", e);
             return Err(Box::new(e));
        }
    };

    let bob_fp = match bob.calculate_sqs_fingerprint() {
        Ok(fp) => {
             println!("    Bob calculates fingerprint:   {}", fp);
             fp
        }
         Err(e) => {
             eprintln!("    ERROR: Bob failed to calculate fingerprint: {}", e);
             return Err(Box::new(e));
        }
    };

    // --- Stage 3: Out-of-Band (OOB) Verification (Simulated) ---
    println!("\n[3] Participants compare fingerprints via a trusted channel (e.g., phone call)...");

    if alice_fp == bob_fp {
        println!("    SUCCESS: Fingerprints match! Participants confirmed they established");
        println!("             SQS with each other. MitM attack likely prevented.");
        println!("             They can now trust the channel for QFE communication.");

        // --- Stage 4: Secure Communication (Example) ---
        println!("\n[4] Example secure communication using verified SQS:");
        let message = "This message is secured by verified QFE!";
        println!("    Alice wants to send: '{}'", message);

        let encoded = alice.encode_str(message)?;
        println!("    Alice encodes message (length: {} units).", encoded.len());

        let decoded = bob.decode_to_str(&encoded)?;
        println!("    Bob decodes message: '{}'", decoded);

        assert_eq!(message, decoded);
        println!("    Message correctly decoded.");

    } else {
        // This branch shouldn't be hit in this example if establish_sqs worked correctly.
        eprintln!("    !!! FAILURE: Fingerprints DO NOT MATCH !!!");
        eprintln!("    !!! WARNING: Potential Man-in-the-Middle Attack Detected !!!");
        eprintln!("    !!! Participants should discard this SQS and not communicate !!!");
        // Mark frames invalid as a precaution (optional library feature?)
        // alice.validation_status = false; // Need method if field is private
        // bob.validation_status = false;
        return Err("OOB fingerprint verification failed!".into());
    }

    println!("\n--- OOB Authentication Example Complete ---");
    Ok(())
}
