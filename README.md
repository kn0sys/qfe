# Qualitative Frame Entanglement (QFE)

This repository contains a Rust implementation simulating an experimental protocol for secure communication, referred to here as 'QFE'. The protocol relies on establishing a unique shared state (`SQS`) between two parties (represented as `Frame`s) and uses stateful, modulated encoding with built-in integrity checks designed to detect tampering.

**Disclaimer:** This library is an experimental simulation based on conceptual principles. It has **not** undergone formal security analysis or peer review and should **not** be considered cryptographically secure or suitable for production use cases involving sensitive data.

## Core Concepts

* **Frames:** Represent communication participants (`Frame` struct).
* **Shared Qualitative Structure (SQS):** A shared secret context (`SQS` struct) established between two Frames via an interactive process (`establish_sqs` or `setup_qfe_pair`). Contains secret components and synchronization parameters (like `shared_phase_lock`).
* **Stateful Encoding/Decoding:** Messages are encoded sequentially (`encode`/`encode_str`), where each output unit (`EncodedUnit`) depends on the previous state (phase) and the SQS. Decoding (`decode`/`decode_to_str`) reverses this process.
* **Integrity Verification:** Each `EncodedUnit` contains an integrity hash calculated using the original data and the `SQS` components. The decoding process verifies this hash, causing decoding to fail if tampering or context mismatch (wrong SQS) is detected.

## Features

* Initialization of participant `Frame`s.
* Establishment of a shared secret state (`SQS`) between two `Frame`s.
* Encoding of byte arrays (`&[u8]`) and string slices (`&str`).
* Decoding of encoded signals back into byte arrays or `String`s.
* Built-in detection of tampering via integrity checks during decoding.
* Structured error handling using the `QfeError` enum.
* Basic API for simplified setup (`setup_qfe_pair`).

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
// examples/hello.rs

// Import necessary items from the qfe library crate
use qfe::{setup_qfe_pair, QfeError}; // Use setup_qfe_pair and the error type
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> { // Use standard result type for main
    println!("--- QFE 'Hello, world!' Example ---");

    // 1. Setup communication pair using the simplified API
    println!("\n[1] Initializing Frames and establishing SQS...");
    let (mut frame_a, mut frame_b) = match setup_qfe_pair(
        "Frame_A".to_string(), // ID for Frame A
        20250330,             // Seed for Frame A (Example Seed)
        "Frame_B".to_string(), // ID for Frame B
        115702,             // Seed for Frame B (Example Seed)
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
    println!("    Frame A Valid: {}", frame_a.is_valid());

    // 2. Define the message
    let original_message = "Hello, world!";
    println!("\n[2] Original Message: '{}'", original_message);

    // 3. Encode the message using Frame A's convenience method
    println!("\n[3] Frame A encoding message...");
    let encoded_signal = match frame_a.encode_str(original_message) {
        Ok(signal) => {
            println!("    Encoding successful. Signal length: {}", signal.len());
             if !signal.is_empty() {
                 println!("    First Encoded Unit Hash: {:x}", signal[0].integrity_hash);
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
        tampered_signal[0].integrity_hash = tampered_signal[0].integrity_hash.wrapping_add(1); // Corrupt hash
    }

    println!("    Frame B attempting to decode tampered signal...");
    match frame_b.decode_to_str(&tampered_signal) {
        Ok(msg) => {
             eprintln!("    ERROR: Decoding tampered signal succeeded unexpectedly! Decoded: '{}'", msg);
             return Err("Tamper detection failed!".into());
        }
        Err(e) => {
             println!("    Successfully detected tampering!");
             println!("    Decode error reported: {}", e);
             match e {
                 QfeError::DecodingFailed(_) => println!("    Error type is correctly DecodingFailed."),
                 _ => eprintln!("    WARNING: Incorrect error type reported for tamper detection: {:?}", e),
             }
             assert!(!frame_b.is_valid(), "Frame B should be marked invalid after detecting tampering");
             println!("    Frame B validation status correctly set to: {}", frame_b.is_valid());
        }
    }

    println!("\n--- QFE Example Complete ---");
    Ok(())
}
```

## Status

This library is **experimental** and intended as a simulation and exploration of the underlying concepts. It lacks formal proofs, security audits, and is likely unsuitable for any real-world cryptographic applications. Use for educational or research purposes only.

## License

Licensed under

MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

## Contributing 1

Contributions are welcome! Please feel free to submit issues or pull requests.
