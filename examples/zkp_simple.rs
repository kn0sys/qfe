// examples/zkp_simple.rs

use qfe::{Frame, QfeError}; // Import base types
use qfe::zkp::{ // Import ZKP specific items
    establish_zkp_sqs,
    generate_zkp_challenge,
};
use sha2::{Sha512, Digest}; // For calculating H(W)
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("--- QFE Simple Validity ZKP Example ---");

    // --- Setup ---
    println!("\n[1] Setup Phase:");
    let mut prover = Frame::initialize("SimpleProver".to_string(), 202504041);
    let mut verifier = Frame::initialize("SimpleVerifier".to_string(), 202504042);
    println!("    Prover and Verifier Frames initialized.");

    // Define Witness & Public Statement H(W)
    let witness = b"my_secret_data_for_zkp".to_vec();
    let h_public: [u8; 64] = Sha512::digest(&witness).into();
    println!("    Witness defined (secretly held by Prover).");
    println!("    Public Statement H(W): {:x?}...", &h_public[..4]); // Show first few bytes

    // Prover stores witness
    prover.store_zkp_witness(&witness)?;
    println!("    Prover stored witness internally.");

    // Establish ZKP SQS context (both compute independently)
    let context = "simple_zkp_example_v1".to_string();
    let prover_sqs = establish_zkp_sqs(prover.id(), verifier.id(), &h_public, &context)?;
    let verifier_sqs = establish_zkp_sqs(prover.id(), verifier.id(), &h_public, &context)?;
    // Sanity check SQS are identical
    assert_eq!(prover_sqs, verifier_sqs, "Prover and Verifier SQS mismatch!");
    println!("    Prover and Verifier computed identical ZKP SQS context.");

    // --- Proof Generation ---
    println!("\n[2] Proof Phase:");
    // Verifier generates challenge
    let challenge = generate_zkp_challenge(32); // 32-byte challenge
    println!("    Verifier generated challenge: {:x?}...", &challenge.value[..4]);

    // Prover generates proof/response using correct witness
    println!("    Prover generating proof using correct witness...");
    let response = prover.generate_validity_proof(
        &challenge,
        &prover_sqs, // Prover uses its SQS
        &h_public,
    )?;
    println!("    Prover generated proof hash: {:x?}...", &response.validity_proof_hash[..4]);

    // --- Verification ---
    println!("\n[3] Verification Phase:");
    // Verifier verifies the response using its SQS
    println!("    Verifier verifying proof...");
    let verification_result = verifier.verify_validity_proof(
        &challenge,
        &response,
        &verifier_sqs, // Verifier uses its SQS
        &h_public,
    );

    match verification_result {
        Ok(_) => {
            println!("    SUCCESS! Verification passed for correct witness.");
            assert!(verifier.is_valid());
        }
        Err(e) => {
            eprintln!("    ERROR: Verification failed unexpectedly for correct witness: {}", e);
            println!("    Verifier Valid Status: {}", verifier.is_valid());
            return Err(Box::new(e));
        }
    }

    // --- Test Invalid Witness Scenario ---
    println!("\n[4] Testing Invalid Witness Scenario:");
    let mut bad_prover = Frame::initialize("BadProver".to_string(), 99999);
    let wrong_witness = b"i_do_not_know_the_secret".to_vec();
    bad_prover.store_zkp_witness(&wrong_witness)?;
    println!("    BadProver stored incorrect witness.");

    // V generates a new challenge
    let challenge2 = generate_zkp_challenge(32);
    println!("    Verifier generated new challenge: {:x?}...", &challenge2.value[..4]);

    // BadProver attempts to generate proof
    println!("    BadProver generating proof using incorrect witness...");
    let bad_response = bad_prover.generate_validity_proof(
        &challenge2,
        &prover_sqs, // Use the SQS established for the correct H_public
        &h_public,
    )?;
     println!("    BadProver generated proof hash: {:x?}...", &bad_response.validity_proof_hash[..4]);

    // Verifier tries to verify the bad proof
    println!("    Verifier verifying bad proof...");
    let bad_verification_result = verifier.verify_validity_proof(
        &challenge2,
        &bad_response,
        &verifier_sqs,
        &h_public,
    );

    match bad_verification_result {
        Ok(_) => {
             eprintln!("    ERROR: Verification succeeded unexpectedly for incorrect witness!");
             return Err("Soundness check failed!".into());
        }
        Err(e) => {
             println!("    SUCCESS! Verification correctly failed for incorrect witness.");
             println!("    Verification Error: {}", e);
             assert!(matches!(e, QfeError::DecodingFailed(_)));
             assert!(e.to_string().contains("Validity Proof Check Failed"));
             assert!(!verifier.is_valid(), "Verifier should be invalid after failed check.");
             println!("    Verifier Valid Status correctly set to: {}", verifier.is_valid());
        }
    }


    println!("\n--- Simple ZKP Example Complete ---");
    Ok(())
}
