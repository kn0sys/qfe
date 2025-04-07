// examples/qfe_comprehensive.rs

//! A comprehensive example demonstrating various QFE functionalities:
//! 1. SQS Establishment between two parties (Alice and Bob).
//! 2. AEAD Encryption/Decryption using ChaCha20-Poly1305.
//! 3. Examples of error handling for tampering and wrong context.

use qfe::{
    Frame,
    QfeError,
    establish_sqs_kem,
};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    // Get current date for context
    // Note: This uses chrono which might not be a dependency.
    // For simplicity, we'll just use a fixed string or skip it.
    // Alternatively, could use std::time, but that's more complex for formatting.
    // Let's use a placeholder date for the example output.
    let current_date_str = "2025-04-06"; // Placeholder for Sunday, April 6, 2025
    println!("--- QFE Comprehensive Example ({}) ---", current_date_str);

    // --- 1. Setup and SQS Establishment ---
    println!("\n[1] Initializing Frames and Establishing SQS...");
    let alice_id = "Alice";
    let bob_id = "Bob";
    // Use different seeds for Alice and Bob
    let mut frame_a = Frame::initialize(alice_id.to_string());
    let mut frame_b = Frame::initialize(bob_id.to_string());
    println!("    Initialized Frame for {} and {}", alice_id, bob_id);

    establish_sqs_kem(&mut frame_a, &mut frame_b, "hello")
        .map_err(|e| format!("SQS Establishment between {} and {} failed: {}", alice_id, bob_id, e))?;
    println!("    SQS established successfully between {} and {}.", alice_id, bob_id);
    assert!(frame_a.has_sqs() && frame_b.has_sqs());

    // --- 2. AEAD Encrypt (Alice) / Decrypt (Bob) ---
    println!("\n[2] Demonstrating AEAD Encryption/Decryption...");
    let plaintext1 = b"Secret message protected by AEAD!";
    let associated_data1 = Some(b"Context_ID_123" as &[u8]); // Optional authenticated data
    println!("    {} wants to send: '{}'", alice_id, String::from_utf8_lossy(plaintext1));
    println!("    Using Associated Data: '{}'", String::from_utf8_lossy(associated_data1.unwrap()));

    // Alice Encodes
    let encrypted_msg = frame_a.encode_aead(plaintext1, associated_data1)
        .map_err(|e| format!("{} failed to encode AEAD: {}", alice_id, e))?;
    println!("    {} encoded message (Nonce: {:x?}, Ciphertext+Tag length: {} bytes)",
        alice_id,
        &encrypted_msg.nonce[..4], // Show first few bytes of nonce
        encrypted_msg.ciphertext.len()
    );

    // Bob Decodes
    let decoded_plaintext = frame_b.decode_aead(&encrypted_msg, associated_data1)
         .map_err(|e| format!("{} failed to decode AEAD: {}", bob_id, e))?;
    println!("    {} decoded message: '{}'", bob_id, String::from_utf8_lossy(&decoded_plaintext));

    // Verify
    assert_eq!(plaintext1, decoded_plaintext.as_slice());
    println!("    SUCCESS: AEAD decoded message matches original plaintext.");
    assert!(frame_b.is_valid()); // Bob's frame should still be valid

    // --- 3. Error Handling Examples ---

    println!("\n[3] Error Example: Tampered AEAD Ciphertext...");
    let plaintext3 = b"Another secret";
    let mut encrypted_msg_tampered = frame_a.encode_aead(plaintext3, None)?;
    println!("    {} encoded message: (Nonce: {:x?}, CT Len: {})", alice_id, &encrypted_msg_tampered.nonce[..4], encrypted_msg_tampered.ciphertext.len());
    // Tamper
    if !encrypted_msg_tampered.ciphertext.is_empty() {
        encrypted_msg_tampered.ciphertext[0] ^= 0xFF; // Flip bits at start
        println!("    Ciphertext tampered!");
    }
    // Bob attempts decode
    let decode_tampered_res = frame_b.decode_aead(&encrypted_msg_tampered, None);
    assert!(decode_tampered_res.is_err());
    if let Err(QfeError::DecodingFailed(msg)) = decode_tampered_res {
         println!("    SUCCESS: {} correctly failed to decode tampered AEAD message: {}", bob_id, msg);
         assert!(!frame_b.is_valid(), "Bob's frame should be invalid after failed AEAD decode");
         println!("    {}'s frame validity: {}", bob_id, frame_b.is_valid());
    } else {
         panic!("Expected DecodingFailed error, got {:?}", decode_tampered_res.err());
    }

    println!("\n--- QFE Comprehensive Example Complete ---");
    Ok(())
}
