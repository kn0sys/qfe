// examples/qfe_comprehensive.rs

//! A comprehensive example demonstrating various QFE functionalities:
//! 1. SQS Establishment between two parties (Alice and Bob).
//! 2. Simulated Out-of-Band Fingerprint Verification.
//! 3. AEAD Encryption/Decryption using ChaCha20-Poly1305.
//! 4. Message Signing and Verification.
//! 5. Examples of error handling for tampering and wrong context.

use qfe::{
    Frame,
    QfeError,
    establish_sqs,
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
    let mut frame_a = Frame::initialize(alice_id.to_string(), 2025040601);
    let mut frame_b = Frame::initialize(bob_id.to_string(), 2025040602);
    println!("    Initialized Frame for {} and {}", alice_id, bob_id);

    establish_sqs(&mut frame_a, &mut frame_b)
        .map_err(|e| format!("SQS Establishment between {} and {} failed: {}", alice_id, bob_id, e))?;
    println!("    SQS established successfully between {} and {}.", alice_id, bob_id);
    assert!(frame_a.has_sqs() && frame_b.has_sqs());

    // --- 2. Simulated Fingerprint Verification (Out-of-Band Check) ---
    println!("\n[2] Simulating SQS Fingerprint Verification (OOB)...");
    let fp_a = frame_a.calculate_sqs_fingerprint()?;
    let fp_b = frame_b.calculate_sqs_fingerprint()?;
    println!("    {}'s SQS Fingerprint: {}", alice_id, fp_a);
    println!("    {}'s SQS Fingerprint: {}", bob_id, fp_b);
    if fp_a == fp_b {
        println!("    SUCCESS: Fingerprints match! (MitM check simulation passed)");
    } else {
        eprintln!("    ERROR: Fingerprints MISMATCH! MitM Attack Suspected!");
        // In a real application, terminate connection here.
        return Err("Fingerprint mismatch".into());
    }
    assert_eq!(fp_a, fp_b); // Assert for testability

    // --- 3. AEAD Encrypt (Alice) / Decrypt (Bob) ---
    println!("\n[3] Demonstrating AEAD Encryption/Decryption...");
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

    // --- 4. Sign (Alice) / Verify (Bob) ---
    println!("\n[4] Demonstrating Message Signing/Verification...");
    let message2 = b"Public message that needs integrity and authenticity.";
    println!("    {} wants to sign message: '{}'", alice_id, String::from_utf8_lossy(message2));

    // Alice Signs
    let signature = frame_a.sign_message(message2)
        .map_err(|e| format!("{} failed to sign: {}", alice_id, e))?;
    println!("    {} generated signature: {:x?}...", alice_id, &signature.value[..4]); // Show first few bytes

    // Bob Verifies
    frame_b.verify_signature(message2, &signature)
        .map_err(|e| format!("{} failed to verify signature: {}", bob_id, e))?;
    println!("    SUCCESS: {} successfully verified {}'s signature.", bob_id, alice_id);
    assert!(frame_b.is_valid()); // Bob's frame still valid

    // --- 5. Error Handling Examples ---

    // Example 5a: Tampered AEAD Ciphertext
    println!("\n[5a] Error Example: Tampered AEAD Ciphertext...");
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

    // Bob's frame is now invalid, let's reset for next test case
    // In real usage, invalid state might require re-establishing SQS or terminating.
    frame_b.validation_status = true; // Force valid for next example step
    println!("    (Resetting {}'s frame to valid for next test)", bob_id);

    // Example 5b: Tampered Signature
    println!("\n[5b] Error Example: Tampered Signature...");
    let message4 = b"Data for signing test";
    let mut signature_tampered = frame_a.sign_message(message4)?;
    println!("    {} signed message: (Sig: {:x?}...)", alice_id, &signature_tampered.value[..4]);
    // Tamper
    signature_tampered.value[5] ^= 0xFF; // Flip some bits in signature
    println!("    Signature tampered!");
    // Bob attempts verification
    let verify_tampered_res = frame_b.verify_signature(message4, &signature_tampered);
    assert!(verify_tampered_res.is_err());
    if let Err(QfeError::InvalidSignature) = verify_tampered_res {
        println!("    SUCCESS: {} correctly rejected tampered signature.", bob_id);
        // Note: verify_signature doesn't invalidate the frame currently
        assert!(frame_b.is_valid(), "Bob's frame should remain valid after failed verify");
        println!("    {}'s frame validity: {}", bob_id, frame_b.is_valid());
    } else {
        panic!("Expected InvalidSignature error, got {:?}", verify_tampered_res.err());
    }


    // Example 5c: Wrong SQS Context
    println!("\n[5c] Error Example: Wrong SQS Context...");
    // Setup Charlie and David with their own SQS
    let mut frame_c = Frame::initialize("Charlie".to_string(), 303030);
    let mut frame_d = Frame::initialize("David".to_string(), 404040);
    establish_sqs(&mut frame_c, &mut frame_d)?;
    println!("    Established separate SQS for Charlie and David.");
    assert!(frame_c.has_sqs());

    // Alice encodes/signs with Alice-Bob SQS
    let plaintext5 = b"Message only for Bob";
    let encrypted_for_bob = frame_a.encode_aead(plaintext5, None)?;
    let message6 = b"Another message signed by Alice";
    let signature_by_alice = frame_a.sign_message(message6)?;

    // Charlie tries to decode/verify using Charlie-David SQS (wrong key/context)
    println!("    Charlie attempting to decode Alice's AEAD message...");
    let decode_wrong_sqs_res = frame_c.decode_aead(&encrypted_for_bob, None);
    assert!(decode_wrong_sqs_res.is_err());
    if let Err(QfeError::DecodingFailed(msg)) = decode_wrong_sqs_res {
        println!("    SUCCESS: Charlie failed to decode AEAD with wrong SQS: {}", msg);
         assert!(!frame_c.is_valid(), "Charlie's frame invalid after failed decode");
    } else {
        panic!("Expected DecodingFailed error, got {:?}", decode_wrong_sqs_res.err());
    }
    frame_c.validation_status = true; // Reset Charlie for next check

    println!("    Charlie attempting to verify Alice's signature...");
    let verify_wrong_sqs_res = frame_c.verify_signature(message6, &signature_by_alice);
     assert!(verify_wrong_sqs_res.is_err());
     if let Err(QfeError::InvalidSignature) = verify_wrong_sqs_res {
         println!("    SUCCESS: Charlie rejected signature due to wrong SQS.");
          assert!(frame_c.is_valid(), "Charlie's frame still valid after failed verify");
     } else {
         panic!("Expected InvalidSignature error, got {:?}", verify_wrong_sqs_res.err());
     }


    println!("\n--- QFE Comprehensive Example Complete ---");
    Ok(())
}
