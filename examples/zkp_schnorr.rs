// examples/zkp_schnorr.rs

use qfe::{Frame, QfeError}; // Import Frame, Error
use qfe::zkp::{ // Import ZKP specific items
    establish_zkp_sqs,
    verify_schnorr_proof, // Standalone verifier function
    SchnorrProof, // Import the proof struct type
};
use qfe::Sqs; // Import Sqs if used for context

// Curve, hashing, and randomness imports
use curve25519_dalek::{
    scalar::Scalar,
    constants::RISTRETTO_BASEPOINT_POINT // The generator G
};
use rand::RngCore; // For generating secrets
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("--- QFE Schnorr NI ZKP Example ---");

    // --- Setup ---
    println!("\n[1] Setup Phase:");
    let mut prover = Frame::initialize("SchnorrProverExample".to_string());
    let verifier_id_for_sqs = "SchnorrVerifierExample_SQS_ID"; // Only needed if using SQS
    println!("    Prover Frame initialized.");

    // Prover generates secret key 'x' and public key 'P = xG'
    let mut data = [0u8; 32];
    rand::rng().fill_bytes(&mut data);
    let secret_x = Scalar::from_bytes_mod_order(data);
    let public_p = secret_x * RISTRETTO_BASEPOINT_POINT; // Corresponding public point P = xG
    println!("    Prover generated secret scalar x (kept secret).");
    println!("    Prover calculated public point P = xG: {:?}", public_p.compress()); // Show compressed P

    // Prover stores the secret scalar internally
    prover.store_zkp_scalar(secret_x)?;
    println!("    Prover stored secret scalar x internally.");

    // --- Optional: Establish SQS Context ---
    // We can bind the Schnorr proof to an SQS context if desired.
    // Let's create one based on P for this example.
    let context_string = "schnorr_example_context_v1";
    let zkp_sqs: Option<Sqs> = match establish_zkp_sqs(
        prover.id(),
        verifier_id_for_sqs, // An ID representing the verifier in this context
        public_p.compress().as_bytes(), // Use public key P as statement for SQS
        context_string
    ) {
        Ok(sqs) => {
            println!("    Successfully established optional ZKP SQS context.");
            Some(sqs)
        },
        Err(e) => {
            eprintln!("    Warning: Failed to establish ZKP SQS context: {}", e);
            None
        }
    };
    // We need a reference for the functions
    let sqs_ref: Option<&Sqs> = zkp_sqs.as_ref();

    // --- Proof Generation (Non-Interactive) ---
    println!("\n[2] Proof Phase (Non-Interactive):");
    println!("    Prover generating Schnorr proof for public point P...");
    // Pass the SQS context reference and the context string bytes to bind the proof
    let proof: SchnorrProof = prover.generate_schnorr_proof(
        &public_p,
        sqs_ref,
        Some(context_string.as_bytes()) // Pass context bytes for hashing consistency
    )?;
    println!("    Prover generated Proof:");
    println!("      Commitment R: {:?}", proof.r.compress());
    // Don't print scalar 's' usually, but fine for demo:
    // println!("      Response s: {:?}", proof.s);


    // --- Verification (Non-Interactive) ---
    println!("\n[3] Verification Phase (Non-Interactive):");
    println!("    Verifier verifying Schnorr proof using public P and context...");
    // Verifier uses the same public P, SQS context, and context string bytes
    let verification_result = verify_schnorr_proof(
        &proof,
        &public_p,
        sqs_ref,
        Some(context_string.as_bytes())
    );

    match verification_result {
        Ok(_) => {
            println!("    SUCCESS! Schnorr proof verification passed.");
        }
        Err(e) => {
            eprintln!("    ERROR: Schnorr proof verification failed unexpectedly: {}", e);
            return Err(Box::new(e)); // Treat unexpected failure as error
        }
    }

    // --- Test Failure Case: Verifying with Wrong Public Point ---
    println!("\n[4] Testing Failure Scenario: Wrong Public Point:");
    let wrong_public_p = RISTRETTO_BASEPOINT_POINT; // Use Basepoint G as wrong P'
    println!("    Verifier attempting to verify proof against wrong public point P' = G...");
    let wrong_p_verification_result = verify_schnorr_proof(
        &proof,
        &wrong_public_p, // Use the wrong public point P'
        sqs_ref,
        Some(context_string.as_bytes())
    );

    match wrong_p_verification_result {
        Ok(_) => {
             eprintln!("    ERROR: Verification succeeded unexpectedly with wrong public point!");
             return Err("Schnorr soundness check failed!".into());
        }
        Err(e) => {
             println!("    SUCCESS! Verification correctly failed with wrong public point.");
             println!("    Verification Error: {}", e);
             assert!(matches!(e, QfeError::DecodingFailed(_)));
             assert!(e.to_string().contains("Schnorr proof verification failed"));
        }
    }

     // --- Test Failure Case: Verifying with Wrong Context ---
     println!("\n[5] Testing Failure Scenario: Wrong Context String:");
     let wrong_context_string = "a_different_context";
     println!("    Verifier attempting to verify proof against correct P but wrong context string...");
     let wrong_ctx_verification_result = verify_schnorr_proof(
         &proof,
         &public_p,
         sqs_ref, // Correct SQS context (if used)
         Some(wrong_context_string.as_bytes()) // Use wrong context string bytes
     );

     match wrong_ctx_verification_result {
         Ok(_) => {
              eprintln!("    ERROR: Verification succeeded unexpectedly with wrong context string!");
              return Err("Schnorr context binding check failed!".into());
         }
         Err(e) => {
              println!("    SUCCESS! Verification correctly failed with wrong context string.");
              println!("    Verification Error: {}", e);
              assert!(matches!(e, QfeError::DecodingFailed(_)));
              assert!(e.to_string().contains("Schnorr proof verification failed"));
         }
     }


    println!("\n--- Schnorr NI ZKP Example Complete ---");
    Ok(())
}
