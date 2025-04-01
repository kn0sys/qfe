// qfe/examples/hello.rs

// Import necessary items from the qfe library crate
use qfe::{setup_qfe_pair, QfeError}; // Use setup_qfe_pair and the error type
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> { // Use standard result type for main
    println!("--- QFE 'Hello, world!' Example ---");

    // 1. Setup communication pair using the simplified API
    println!("\n[1] Initializing Frames and establishing SQS...");
    let (frame_a, mut frame_b) = match setup_qfe_pair(
        "Frame_A".to_string(), // ID for Frame A
        20250330,             // Seed for Frame A
        "Frame_B".to_string(), // ID for Frame B
        115702,             // Seed for Frame B
    ) {
        Ok(pair) => {
            println!("    Frames A & B initialized and SQS established successfully.");
            pair
        }
        Err(e) => {
            eprintln!("    Error setting up QFE pair: {}", e);
            return Err(Box::new(e)); // Convert QfeError to Box<dyn Error>
        }
    };

    // Optional: Display some info about the frames/SQS
     println!("    Frame A Valid: {}", frame_a.is_valid());
     // println!("    Frame A SQS Components Hash: {:x}", {
     //     let mut hasher = std::collections::hash_map::DefaultHasher::new();
     //     frame_a.get_sqs().unwrap().components.hash(&mut hasher);
     //     hasher.finish()
     // });

    // 2. Define the message
    let original_message = "Hello, world!";
    println!("\n[2] Original Message: '{}'", original_message);

    // 3. Encode the message using Frame A's convenience method
    println!("\n[3] Frame A encoding message...");
    let encoded_signal = match frame_a.encode_str(original_message) {
        Ok(signal) => {
            println!("    Encoding successful. Signal length: {}", signal.len());
             if !signal.is_empty() {
                 // Display first unit hash for visualization
                 println!("    First Encoded Unit Hash: {:?}", signal[0].integrity_hash);
             }
            signal
        }
        Err(e) => {
            eprintln!("    Error during encoding: {}", e);
            return Err(Box::new(e));
        }
    };

    // 4. Decode the message using Frame B's convenience method
    println!("\n[4] Frame B decoding signal...");
    let decoded_message = match frame_b.decode_to_str(&encoded_signal) {
        Ok(msg) => {
            println!("    Decoding successful.");
            msg
        }
        Err(e) => {
            eprintln!("    Error during decoding: {}", e);
            // Even if decoding fails, check frame B's validity state
            println!("    Frame B Valid after failed decode attempt: {}", frame_b.is_valid());
            return Err(Box::new(e));
        }
    };
    println!("    Decoded Message: '{}'", decoded_message);

    // 5. Verify the result
    println!("\n[5] Verifying result...");
    assert_eq!(original_message, decoded_message, "Mismatch between original and decoded message!");
    println!("    Success! Decoded message matches original.");
    println!("    Frame B Valid after successful decode: {}", frame_b.is_valid());


    // 6. Tamper Detection Demonstration
    println!("\n[6] Tamper Detection Demo...");
    let mut tampered_signal = encoded_signal.clone();
    if !tampered_signal.is_empty() {
        println!("    Tampering with integrity hash of first signal unit...");
        tampered_signal[0].integrity_hash[0] ^= 0x01; // Corrupt hash
    }

    println!("    Frame B attempting to decode tampered signal...");
    match frame_b.decode_to_str(&tampered_signal) {
        Ok(msg) => {
             // This should NOT happen
             eprintln!("    ERROR: Decoding tampered signal succeeded unexpectedly! Decoded: '{}'", msg);
             return Err("Tamper detection failed!".into()); // Use basic error conversion
        }
        Err(e) => {
             println!("    Successfully detected tampering!");
             println!("    Decode error reported: {}", e);
             match e {
                 QfeError::DecodingFailed(_) => println!("    Error type is correctly DecodingFailed."),
                 _ => eprintln!("    WARNING: Incorrect error type reported for tamper detection: {:?}", e),
             }
             // Crucially, check if Frame B was marked invalid
             assert!(!frame_b.is_valid(), "Frame B should be marked invalid after detecting tampering");
             println!("    Frame B validation status correctly set to: {}", frame_b.is_valid());
        }
    }

    println!("\n--- QFE Example Complete ---");
    Ok(())
}
