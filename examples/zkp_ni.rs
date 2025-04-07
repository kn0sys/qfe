// examples/zkp_ni.rs

use qfe::{Frame, QfeError, Sha512Hash}; // Import base types and Sha512Hash
use qfe::zkp::{ // Import ZKP specific items
    establish_zkp_sqs,
    // Removed generate_zkp_challenge import
};
use sha2::{Sha512, Digest}; // For calculating H(W)
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("--- QFE Non-Interactive (NI) Validity ZKP Example ---");

    // --- Setup ---
    println!("\n[1] Setup Phase:");
    let mut prover = Frame::initialize("NI_Prover".to_string()); // Updated ID
    let mut verifier = Frame::initialize("NI_Verifier".to_string()); // Updated ID
    println!("    Prover and Verifier Frames initialized.");

    // Define Witness & Public Statement H(W)
    let witness = b"my_secret_data_for_noninteractive_zkp".to_vec(); // Updated witness data
    let h_public: Sha512Hash = Sha512::digest(&witness).into(); // Type alias usage
    println!("    Witness defined (secretly held by Prover).");
    println!("    Public Statement H(W): {:x?}...", &h_public[..4]); // Show first few bytes

    // Prover stores witness
    prover.store_zkp_witness(&witness)?;
    println!("    Prover stored witness internally.");

    // Establish ZKP SQS context (both compute independently using updated function)
    let context = "noninteractive_zkp_example_v1".to_string(); // Updated context
    let prover_sqs = establish_zkp_sqs(prover.id(), verifier.id(), &h_public, &context)?;
    let verifier_sqs = establish_zkp_sqs(prover.id(), verifier.id(), &h_public, &context)?;
    // Sanity check SQS are identical
    assert_eq!(prover_sqs, verifier_sqs, "Prover and Verifier SQS mismatch!");
    println!("    Prover and Verifier computed identical ZKP SQS context (using SHA-512).");

    // --- Proof Generation (Non-Interactive) ---
    println!("\n[2] Proof Phase (Non-Interactive):");
    // No challenge generation needed from Verifier
    println!("    Prover deriving challenge deterministically and generating proof...");
    let response = prover.generate_noninteractive_validity_proof(
        &prover_sqs, // Prover uses its SQS
        &h_public,
    )?;
    println!("    Prover generated non-interactive proof hash: {:x?}...", &response.validity_proof_hash[..4]);

    // --- Verification (Non-Interactive) ---
    println!("\n[3] Verification Phase (Non-Interactive):");
    // Verifier verifies the response using its SQS
    println!("    Verifier deriving challenge deterministically and verifying proof...");
    let verification_result = verifier.verify_noninteractive_validity_proof(
        // No challenge passing needed
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

    // --- Test Invalid Witness Scenario (Non-Interactive) ---
    println!("\n[4] Testing Invalid Witness Scenario (Non-Interactive):");
    let mut bad_prover = Frame::initialize("BadProverNI".to_string()); // Updated ID
    let wrong_witness = b"i_still_do_not_know_the_secret".to_vec(); // Updated wrong witness
    bad_prover.store_zkp_witness(&wrong_witness)?;
    println!("    BadProver stored incorrect witness.");

    // No challenge generation needed

    // BadProver attempts to generate non-interactive proof
    println!("    BadProver generating non-interactive proof using incorrect witness...");
    let bad_response = bad_prover.generate_noninteractive_validity_proof(
        // No challenge argument
        &prover_sqs, // Use the SQS established for the correct H_public
        &h_public,
    )?;
     println!("    BadProver generated proof hash: {:x?}...", &bad_response.validity_proof_hash[..4]);

    // Verifier tries to verify the bad proof (re-use the verifier frame)
    // Reset verifier state if necessary, or use a fresh one. Let's reset for demo.
    // NOTE: In a real scenario, you might use a fresh verifier instance or handle state differently.
    // For this example, we expect the verify call to mark it invalid. Let's check its state *before* the call.
    let verifier_state_before_bad_check = verifier.is_valid();
    println!("    Verifier state before checking bad proof: {}", verifier_state_before_bad_check);

    println!("    Verifier verifying bad proof...");
    let bad_verification_result = verifier.verify_noninteractive_validity_proof(
        // No challenge argument
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
             // Check the updated error message string
             assert!(e.to_string().contains("Non-Interactive Validity Proof Check Failed"), "Error message mismatch");
             assert!(!verifier.is_valid(), "Verifier should be invalid after failed check.");
             println!("    Verifier Valid Status correctly set to: {}", verifier.is_valid());
        }
    }

    println!("\n--- Non-Interactive ZKP Example Complete ---");
    Ok(())
}
