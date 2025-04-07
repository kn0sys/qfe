[![Rust](https://github.com/kn0sys/qfe/actions/workflows/rust.yml/badge.svg)](https://github.com/kn0sys/qfe/actions/workflows/rust.yml)

# Qualitative Frame Entanglement (QFE)

QFE establishessecure communication sessions by integrating standard, modern cryptographic primitives. Key
establishment leverages the NIST standard post-quantum key encapsulation mechanism ML-KEM-1024 (Kyber) to generate a shared secret resistant to known quantum computing attacks.


**Disclaimer:** This library is an experimental simulation based on conceptual principles. It has **not** undergone formal security analysis or peer review and should **not** be considered cryptographically secure or suitable for production use cases involving sensitive data.


## Features

* ML-KEM-1024 (Kyber): The NIST standard Key Encapsulation Mechanism for post-
quantum secure key establishment, protecting the initial shared secret against attacks from
both classical and future quantum computers.
* HKDF-SHA512: The standard HMAC-based Key Derivation Function (RFC 5869) to
derive specific cryptographic keys (e.g., for AEAD) from the master shared secret generated
by ML-KEM.
* ChaCha20-Poly1305: A standard, high-performance Authenticated Encryption with Asso-
ciated Data (AEAD) cipher (RFC 8439) providing confidentiality, data integrity, and message
authenticity for all communications subsequent to key establishment.
* SHA-512: Used for cryptographic hashing during Frame initialization, key derivation (within
HKDF), and potentially within Zero-Knowledge Proof components.


## Tests

``` bash
cargo test
```

## Usage Example

This example demonstrates setting up two frames, establishing the shared state (SQS), encoding a message, decoding it, and verifying tamper detection.

```bash
cargo run --example hello
```

```rust
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
```

## Status

This library is **experimental** and intended as a simulation and exploration of the underlying concepts. It lacks formal proofs, security audits, and is likely unsuitable for any real-world cryptographic applications. Use for educational or research purposes only.

## License

Licensed under

MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
