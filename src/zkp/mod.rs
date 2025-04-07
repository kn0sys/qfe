// src/zkp/mod.rs
//! This module contains experimental implementations related to Zero-Knowledge Proofs
//! using the QFE simulation framework, focusing on a simple **non-interactive**
//! validity proof scheme based on Fiat-Shamir.
//!
//! It provides structures and methods for:
//! - Establishing a shared context (`Sqs`) based on public proof parameters using SHA-512.
//! - Generating non-interactive validity proofs (`ZkpValidityResponse`).
//! - Verifying the validity proofs within the shared context.
//!
//! **Note:** This implementation is a simulation for conceptual exploration and is
//! **not** cryptographically secure for production use without formal analysis.
//! The security of the non-interactive version relies on the Random Oracle Model
//! assumption for the hash function used in the Fiat-Shamir transformation.

// Import necessary items from the parent module (src/lib.rs) or crate root
use crate::{Frame, Sqs, QfeError, PatternType, Sha512Hash};
use crate::{PHI, RESONANCE_FREQ};
// Removed unused imports: ZkpChallenge, generate_zkp_challenge related imports if no longer needed elsewhere
// use std::hash::{Hash, Hasher}; // No longer needed for DefaultHasher
// use std::collections::hash_map::DefaultHasher; // Removed DefaultHasher
use sha2::{Sha512, Digest};
// Removed rand::RngCore as generate_zkp_challenge is removed unless needed elsewhere

use curve25519_dalek::{
    ristretto::RistrettoPoint,
    scalar::Scalar,
    constants::RISTRETTO_BASEPOINT_POINT // The base point G
};
use rand::RngCore;

// --- ZKP Struct Definitions ---

// ZkpChallenge struct is removed as it's no longer needed for the non-interactive flow.

/// Represents the Prover's response in the non-interactive validity ZKP.
///
/// Contains a single hash derived from a deterministically generated challenge,
/// the SQS context, and the result of the Prover checking their witness
/// against the public statement.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ZkpValidityResponse {
    /// A hash proving the witness validity check was performed correctly relative
    /// to the deterministically derived challenge and SQS context. Calculated as:
    /// `Sha512(DomainSep || DerivedChallenge || ValidityBool || SQSContext || Constants)`
    pub validity_proof_hash: Sha512Hash, // [u8; 64]
}


// --- ZKP SQS Establishment ---

/// Establishes a shared ZKP context (SQS_ZKP) based purely on public information.
///
/// Both Prover and Verifier compute this independently using the same inputs
/// to arrive at the identical shared state (`Sqs`) needed for the ZKP interaction rounds.
/// This process does not involve message exchange for the SQS itself and is transparent.
/// Uses SHA-512 for deriving all components, including the phase lock value.
///
/// # Arguments
/// * `prover_id`: Identifier (`&str`) for the Prover Frame.
/// * `verifier_id`: Identifier (`&str`) for the Verifier Frame.
/// * `public_statement`: Byte representation (`&[u8]`) of the public statement being proven
///   (e.g., the target hash `H_public` for a hash preimage proof).
/// * `context_string`: A domain separation string (`&str`) unique to this specific proof
///   instance or protocol version to prevent cross-context attacks.
///
/// # Returns
/// * `Ok(Sqs)` containing the derived shared state (`Sqs` struct).
/// * `Err(QfeError::InternalError)` if the derived SQS components have an unexpected length
///   or if hash output conversion fails.
pub fn establish_zkp_sqs(
    prover_id: &str,
    verifier_id: &str,
    public_statement: &[u8],
    context_string: &str,
) -> Result<Sqs, QfeError> {
    // 1. Derive SQS components using SHA-512
    let mut components_hasher = Sha512::new();
    components_hasher.update(b"QFE_ZKP_SQS_COMPONENTS_V1");
    components_hasher.update(prover_id.as_bytes());
    components_hasher.update(verifier_id.as_bytes());
    components_hasher.update(public_statement);
    components_hasher.update(context_string.as_bytes());
    components_hasher.update(PHI.to_le_bytes());
    components_hasher.update(RESONANCE_FREQ.to_le_bytes());
    let sqs_components: Vec<u8> = components_hasher.finalize().to_vec();

    // Ensure components have expected length (SHA-512 output size)
    if sqs_components.len() != 64 {
        return Err(QfeError::InternalError(format!(
            "Derived ZKP SQS components have unexpected length: {}", sqs_components.len()
        )));
    }

    // 2. Derive shared phase lock using SHA-512 (replaced DefaultHasher)
    let mut phase_hasher = Sha512::new();
    phase_hasher.update(b"QFE_ZKP_SQS_PHASE_V1"); // Changed domain separator slightly
    phase_hasher.update(prover_id.as_bytes());
    phase_hasher.update(verifier_id.as_bytes());
    phase_hasher.update(public_statement);
    phase_hasher.update(context_string.as_bytes());
    phase_hasher.update(PHI.to_le_bytes()); // Use consistent byte representation
    phase_hasher.update(RESONANCE_FREQ.to_le_bytes()); // Use consistent byte representation
    let phase_hash_output: [u8; 64] = phase_hasher.finalize().into();

    // Convert first 8 bytes of hash to u64 and scale to [0, 2*PI) for phase lock
    let phase_bytes: [u8; 8] = phase_hash_output[0..8].try_into()
        .map_err(|_| QfeError::InternalError("Failed to slice phase hash bytes".to_string()))?;
    let phase_u64 = u64::from_le_bytes(phase_bytes);
    let shared_phase_lock = (phase_u64 as f64 / u64::MAX as f64) * 2.0 * std::f64::consts::PI;


    // 3. Construct the Sqs object
    let sqs = Sqs {
        pattern_type: PatternType::Sqs,
        components: sqs_components, // Use the derived components Vec<u8>
        shared_phase_lock,
        resonance_freq: RESONANCE_FREQ,
        validation: true, // Derived directly, assume valid structure
        ..Default::default()
    };

    Ok(sqs)
}

/// Represents a non-interactive Schnorr proof of knowledge of the discrete logarithm
/// for a public point P = xG.
#[derive(Debug, Clone)] // Add PartialEq, Eq, Hash, Serde features if needed later
pub struct SchnorrProof {
    pub r: RistrettoPoint, // Commitment point R = kG
    pub s: Scalar,         // Response scalar s = k + cx
}


/// Hashes public data and commitment point R into a challenge scalar c.
/// Uses SHA-512 and reduces modulo the curve order.
fn hash_to_scalar(
    public_point_p: &RistrettoPoint,
    commitment_point_r: &RistrettoPoint,
    zkp_sqs: Option<&Sqs>, // Optional SQS context integration
    context_string: Option<&[u8]>, // Optional domain separation
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"QFE_SCHNORR_CHALLENGE_V1"); // Domain separation for challenge
    hasher.update(RISTRETTO_BASEPOINT_POINT.compress().as_bytes()); // Base point G
    hasher.update(public_point_p.compress().as_bytes());     // Public point P = xG
    hasher.update(commitment_point_r.compress().as_bytes()); // Commitment R = kG

    // Optionally include SQS context from the QFE framework
    if let Some(sqs) = zkp_sqs {
        if sqs.validation { // Only use valid SQS context
             hasher.update(&sqs.components);
             hasher.update(sqs.shared_phase_lock.to_le_bytes());
             // Optionally add PHI/RESONANCE_FREQ if they are part of the intended context binding
             // hasher.update(PHI.to_le_bytes());
             // hasher.update(RESONANCE_FREQ.to_le_bytes());
        } else {
             // Handle invalid SQS? Log a warning, or perhaps don't include it.
             // For safety, maybe require SQS to be valid if provided.
             // Or define behavior clearly. Let's hash a placeholder if invalid for now.
             hasher.update(b"INVALID_SQS_CONTEXT");
        }
    }
    // Optionally include other arbitrary context
    if let Some(ctx) = context_string {
        hasher.update(ctx);
    }

    let hash_output: [u8; 64] = hasher.finalize().into();
    // Reduce the 512-bit hash modulo the group order to get a valid scalar
    Scalar::from_bytes_mod_order_wide(&hash_output)
}

// --- Helper function to derive Fiat-Shamir challenge ---

/// Derives the Fiat-Shamir challenge deterministically based on public context.
/// Both Prover and Verifier call this using identical inputs.
fn derive_fs_challenge(
    zkp_sqs: &Sqs,
    public_statement_h_public: &[u8],
) -> Vec<u8> {
     let mut challenge_hasher = Sha512::new();
     challenge_hasher.update(b"QFE_ZKP_FIAT_SHAMIR_CHALLENGE_V1"); // Domain separation for challenge derivation
     challenge_hasher.update(&zkp_sqs.components);
     challenge_hasher.update(zkp_sqs.shared_phase_lock.to_le_bytes());
     challenge_hasher.update(public_statement_h_public);
     // Include constants consistent with SQS derivation to bind challenge tightly to context
     challenge_hasher.update(PHI.to_le_bytes());
     challenge_hasher.update(RESONANCE_FREQ.to_le_bytes());
     challenge_hasher.finalize().to_vec() // Return the challenge bytes
}

// --- ZKP methods within Frame ---
impl Frame {

    /// Stores witness data within the Frame for ZKP operations.
    /// Overwrites any previously stored witness. This data is considered secret.
    /// (No change needed here)
    pub fn store_zkp_witness(&mut self, witness: &[u8]) -> Result<(), QfeError> {
        if !self.is_valid() { return Err(QfeError::FrameInvalid); }
        self.zkp_witness = Some(witness.to_vec());
        Ok(())
    }

    // --- Non-Interactive Simple Validity ZKP Prover Method ---

    /// Prover: Generates a **non-interactive** simple validity proof hash.
    ///
    /// This method implements the Prover's role in the Fiat-Shamir based non-interactive
    /// simple validity ZKP scheme. It retrieves the witness, checks its validity against
    /// the public statement (`H_public`), derives the challenge deterministically,
    /// and then computes the final proof hash incorporating the validity result,
    /// derived challenge, and shared SQS context.
    ///
    /// # Arguments
    /// * `zkp_sqs`: The shared ZKP context established via `establish_zkp_sqs`.
    /// * `public_statement_h_public`: The public statement `H = Hash(W)` being proven.
    ///
    /// # Returns
    /// * `Ok(ZkpValidityResponse)` containing the resulting non-interactive proof hash.
    /// * `Err(QfeError)` if errors occur (frame invalid, SQS invalid, witness not set).
    pub fn generate_noninteractive_validity_proof(
        &self,
        zkp_sqs: &Sqs,
        public_statement_h_public: &[u8],
    ) -> Result<ZkpValidityResponse, QfeError> {
        if !self.is_valid() { return Err(QfeError::FrameInvalid); }
        if !zkp_sqs.validation { return Err(QfeError::InternalError("Invalid ZKP SQS provided for proof".to_string())); }
        let witness_w = self.zkp_witness.as_ref().ok_or_else(|| QfeError::InternalError("ZKP witness not set for proof generation".to_string()))?;

        // 1. Calculate H(W)
        let calculated_hash_of_w: Sha512Hash = Sha512::digest(witness_w).into();

        // 2. Determine validity
        let is_valid_witness: bool = calculated_hash_of_w.as_slice() == public_statement_h_public;

        // 3. Derive challenge deterministically (Fiat-Shamir)
        let derived_challenge_value = derive_fs_challenge(zkp_sqs, public_statement_h_public);

        // 4. Compute the response hash: Hash(DomainSep || DerivedChallenge || Validity || SQS Context || Constants)
        let mut response_hasher = Sha512::new();
        response_hasher.update(b"QFE_ZKP_VALIDITY_PROOF_V1"); // Same domain separation for final proof
        response_hasher.update(&derived_challenge_value); // Use derived challenge
        response_hasher.update([is_valid_witness as u8]); // Hash the boolean result (as 1 or 0)
        response_hasher.update(&zkp_sqs.components);
        response_hasher.update(zkp_sqs.shared_phase_lock.to_le_bytes());
        response_hasher.update(PHI.to_le_bytes());
        response_hasher.update(RESONANCE_FREQ.to_le_bytes());

        let proof_hash: Sha512Hash = response_hasher.finalize().into();

        Ok(ZkpValidityResponse { validity_proof_hash: proof_hash })
    }

    // --- Non-Interactive Simple Validity ZKP Verifier Method ---

     /// Verifier: Verifies the **non-interactive** simple validity proof hash.
     ///
     /// This method implements the Verifier's role in the Fiat-Shamir based non-interactive
     /// simple validity ZKP scheme. It derives the challenge deterministically using public info,
     /// then recomputes the expected proof hash *assuming* the witness was valid (`is_valid = true`).
     /// It compares this expected hash to the hash received in the `response`.
     /// If the hashes do not match, the frame's `validation_status` is set to `false`.
     ///
     /// # Arguments
     /// * `response`: The `ZkpValidityResponse` received from the Prover.
     /// * `zkp_sqs`: The shared ZKP context established via `establish_zkp_sqs`.
     /// * `public_statement_h_public`: The public statement `H = Hash(W)`. Used for deriving
     ///   the challenge and potentially for context clarity.
     ///
     /// # Returns
     /// * `Ok(())` if the verification check passes.
     /// * `Err(QfeError::DecodingFailed)` if the validity proof check fails.
     /// * `Err(QfeError::FrameInvalid)` if the Verifier frame is already invalid.
     /// * `Err(QfeError::InternalError)` if the provided SQS is invalid.
     pub fn verify_noninteractive_validity_proof(
         &mut self, // Mutable to update validation status
         response: &ZkpValidityResponse,
         zkp_sqs: &Sqs,
         public_statement_h_public: &[u8],
     ) -> Result<(), QfeError> {
        if !self.is_valid() { return Err(QfeError::FrameInvalid); }
        if !zkp_sqs.validation { return Err(QfeError::InternalError("Invalid ZKP SQS provided for verification".to_string())); }

        // 1. Derive challenge deterministically (Fiat-Shamir) - Same way as Prover
        let derived_challenge_value = derive_fs_challenge(zkp_sqs, public_statement_h_public);

        // 2. Calculate the hash Verifier expects if Prover's witness was valid
        let expected_hash = {
             let mut response_hasher = Sha512::new();
             response_hasher.update(b"QFE_ZKP_VALIDITY_PROOF_V1"); // Same domain separation
             response_hasher.update(&derived_challenge_value); // Use derived challenge
             response_hasher.update([true as u8]); // Verifier *assumes* validity (true -> 1 byte)
             response_hasher.update(&zkp_sqs.components);
             response_hasher.update(zkp_sqs.shared_phase_lock.to_le_bytes());
             response_hasher.update(PHI.to_le_bytes());
             response_hasher.update(RESONANCE_FREQ.to_le_bytes());
             let hash: Sha512Hash = response_hasher.finalize().into();
             hash
        };

        // 3. Compare expected hash with the one received from Prover
        if response.validity_proof_hash != expected_hash {
             self.validation_status = false; // Mark invalid on failure
             return Err(QfeError::DecodingFailed(
                 "ZKP Non-Interactive Validity Proof Check Failed".to_string() // Updated msg
             ));
        }

        // If hash matches
        Ok(())
     }

     /// Stores the secret scalar x for Schnorr ZKP operations.
    /// Overwrites any previously stored scalar.
    ///
    /// # Arguments
    /// * `secret_x`: The secret scalar (`Scalar`) to store.
    ///
    /// # Errors
    /// * `QfeError::FrameInvalid` if the frame is already in an invalid state.
    pub fn store_zkp_scalar(&mut self, secret_x: Scalar) -> Result<(), QfeError> {
        if !self.is_valid() { return Err(QfeError::FrameInvalid); }
        self.zkp_secret_scalar = Some(secret_x);
        Ok(())
    }

    /// Prover: Generates a non-interactive Schnorr proof of knowledge for P = xG.
    ///
    /// Assumes the secret scalar `x` has been stored via `store_zkp_scalar`.
    ///
    /// # Arguments
    /// * `public_point_p`: The public point P for which knowledge of x is proven.
    /// * `zkp_sqs`: Optional shared ZKP SQS context to bind the proof to.
    /// * `context_string`: Optional domain separation string.
    ///
    /// # Returns
    /// * `Ok(SchnorrProof)` containing the proof (R, s).
    /// * `Err(QfeError)` if the secret scalar `x` is not set or frame is invalid.
    pub fn generate_schnorr_proof(
        &self,
        public_point_p: &RistrettoPoint,
        zkp_sqs: Option<&Sqs>,
        context_string: Option<&[u8]>,
    ) -> Result<SchnorrProof, QfeError> {
        if !self.is_valid() { return Err(QfeError::FrameInvalid); }
        let secret_x = self.zkp_secret_scalar.ok_or_else(|| QfeError::InternalError("ZKP secret scalar x not set".to_string()))?;

        // 1. Commitment: Generate random nonce k and compute R = kG
        let mut data = [0u8; 32];
        rand::rng().fill_bytes(&mut data);
        let k = Scalar::from_bytes_mod_order(data);
        let point_r = k * RISTRETTO_BASEPOINT_POINT; // Commitment R = kG

        // 2. Challenge: Derive challenge c = Hash(G, P, R, context...) using Fiat-Shamir
        let c = hash_to_scalar(public_point_p, &point_r, zkp_sqs, context_string);

        // 3. Response: Compute s = k + cx (mod curve order)
        let s = k + c * secret_x; // Scalar arithmetic is mod order by default

        Ok(SchnorrProof { r: point_r, s })
    }
} // end impl Frame

/// Verifier: Verifies a non-interactive Schnorr proof of knowledge for P = xG.
///
/// # Arguments
/// * `proof`: The `SchnorrProof { R, s }` received from the prover.
/// * `public_point_p`: The public point P that the proof pertains to.
/// * `zkp_sqs`: Optional shared ZKP SQS context the proof should be bound to.
/// * `context_string`: Optional domain separation string used during proof generation.
///
/// # Returns
/// * `Ok(())` if the proof is valid.
/// * `Err(QfeError::DecodingFailed)` if the proof verification fails.
pub fn verify_schnorr_proof(
    proof: &SchnorrProof,
    public_point_p: &RistrettoPoint,
    zkp_sqs: Option<&Sqs>,
    context_string: Option<&[u8]>,
) -> Result<(), QfeError> {

    // 1. Challenge: Re-derive challenge c = Hash(G, P, R, context...) exactly as Prover did
    // Use the R from the proof provided
    let c = hash_to_scalar(public_point_p, &proof.r, zkp_sqs, context_string);

    // 2. Verification Check: sG == R + cP
    // Calculate Left Hand Side: sG
    // Use vartime_double_scalar_mul_basepoint for potential speedup if verifying many proofs
    // For simplicity here, we do direct computation:
    let lhs = proof.s * RISTRETTO_BASEPOINT_POINT;

    // Calculate Right Hand Side: R + cP
    let rhs = proof.r + c * public_point_p; // Point addition and scalar * point multiplication

    // Compare LHS and RHS
    if lhs == rhs {
        Ok(()) // Proof is valid
    } else {
        Err(QfeError::DecodingFailed("Schnorr proof verification failed".to_string()))
    }
}

// --- Unit Tests for Non-Interactive Simple Validity ZKP ---
#[cfg(test)]
mod tests {
    use super::*; // Import items from outer scope (zkp module)
    use crate::{Frame}; // Import Frame from crate root
    use sha2::{Sha512, Digest}; // Import Sha512 for calculating H_public in tests

    // --- Test Setup Helper --- (No significant changes needed, just uses new SQS function)

    #[allow(dead_code)]
    struct SimpleZkpTestData {
        prover: Frame,
        verifier: Frame,
        zkp_sqs: Sqs,
        witness: Vec<u8>,
        h_public: Sha512Hash, // Public statement H(W)
        context: String,
    }

    /// Sets up Prover, Verifier, calculates H(W), stores W, establishes ZKP SQS for Validity Proof.
    fn setup_simple_zkp_test() -> SimpleZkpTestData {
        let mut prover = Frame::initialize("ValidityProverNI".to_string(), 20250406); // NI for NonInteractive
        let verifier = Frame::initialize("ValidityVerifierNI".to_string(), 20250406);
        let witness = b"a_valid_witness_for_noninteractive_zkp".to_vec();
        let h_public: Sha512Hash = Sha512::digest(&witness).into(); // Calculate H(W)
        prover.store_zkp_witness(&witness).expect("Failed to store witness");
        let context = "simple_validity_test_noninteractive_v1".to_string(); // Updated context
        let zkp_sqs = establish_zkp_sqs( // Uses the updated function
            prover.id(),
            verifier.id(),
            &h_public,
            &context,
        ).expect("Failed to establish ZKP SQS");
        let zkp_sqs_clone = zkp_sqs.clone();
        SimpleZkpTestData {
            prover,
            verifier,
            zkp_sqs: zkp_sqs_clone,
            witness,
            h_public,
            context,
        }
    }

    // --- Non-Interactive Simple Validity ZKP Tests ---

    #[test]
    fn test_ni_zkp_successful_proof() {
        let test_data = setup_simple_zkp_test();
        let prover = test_data.prover;
        let mut verifier = test_data.verifier; // Verifier needs mut for verify call
        let zkp_sqs = test_data.zkp_sqs;
        let h_public = test_data.h_public;

        // 1. Prover generates non-interactive validity proof response
        // No challenge generation/sending needed
        let response = prover.generate_noninteractive_validity_proof(
            &zkp_sqs,
            &h_public,
        ).expect("Prover failed to generate non-interactive validity proof");

        // 2. Verifier verifies the proof
        // No challenge passing needed
        let verification_result = verifier.verify_noninteractive_validity_proof(
            &response,
            &zkp_sqs,
            &h_public,
        );

        // Assert verification success
        assert!(verification_result.is_ok(), "Verification failed unexpectedly: {:?}", verification_result.err());
        assert!(verifier.is_valid(), "Verifier should remain valid after successful verification");
    }

    #[test]
    fn test_ni_zkp_invalid_witness() {
        let test_data = setup_simple_zkp_test();
        let mut prover = test_data.prover; // Need mut to store wrong witness
        let mut verifier = test_data.verifier;
        let zkp_sqs = test_data.zkp_sqs;
        let h_public = test_data.h_public; // Correct H(W)

        // Store WRONG witness
        let wrong_witness = b"this_is_the_wrong_witness_for_ni".to_vec();
        prover.store_zkp_witness(&wrong_witness).expect("Storing wrong witness failed");

        // Prover generates response using the wrong witness
        // This means the `is_valid_witness` flag inside generate_noninteractive_validity_proof will be false.
        let response = prover.generate_noninteractive_validity_proof(
            &zkp_sqs,
            &h_public,
        ).expect("Prover failed proof generation (using wrong witness)");

        // Verifier verifies response.
        // V derives challenge C and calculates expected hash assuming `is_valid=true`.
        // P derived same challenge C but calculated hash using `is_valid=false`. Hashes won't match.
        let verification_result = verifier.verify_noninteractive_validity_proof(
            &response,
            &zkp_sqs,
            &h_public,
        );

        // Assert failure
        assert!(verification_result.is_err(), "Verification should fail for invalid witness");
        let err = verification_result.unwrap_err();
        assert!(matches!(err, QfeError::DecodingFailed(_)), "Expected DecodingFailed, got {:?}", err);
        if let QfeError::DecodingFailed(msg) = err {
             assert!(msg.contains("Non-Interactive Validity Proof Check Failed"), "Expected NI Validity Proof failure message, got: {}", msg);
        }
        assert!(!verifier.is_valid(), "Verifier should become invalid after failed verification");
    }

    #[test]
    fn test_ni_zkp_tampered_response_hash() {
        let test_data = setup_simple_zkp_test();
        let prover = test_data.prover;
        let mut verifier = test_data.verifier;
        let zkp_sqs = test_data.zkp_sqs;
        let h_public = test_data.h_public;

        // P generates a valid response first
        let mut response = prover.generate_noninteractive_validity_proof(&zkp_sqs, &h_public)
            .expect("Prover failed proof generation");

        // Tamper with the validity proof hash
        response.validity_proof_hash[0] ^= 0xAA; // Flip some bits

        // V verifies tampered response
        let verification_result = verifier.verify_noninteractive_validity_proof(
            &response, // Pass tampered response
            &zkp_sqs,
            &h_public,
        );

        // Assert failure
        assert!(verification_result.is_err(), "Verification should fail for tampered validity proof hash");
        let err = verification_result.unwrap_err();
        assert!(matches!(err, QfeError::DecodingFailed(_)), "Expected DecodingFailed, got {:?}", err);
        if let QfeError::DecodingFailed(msg) = err {
             assert!(msg.contains("Non-Interactive Validity Proof Check Failed"), "Expected NI Validity Proof failure message, got: {}", msg);
        }
        assert!(!verifier.is_valid());
    }

    // Test for "Wrong Challenge" is no longer applicable as challenge is derived.

    #[test]
    fn test_ni_zkp_wrong_sqs() {
        // Verifier uses different SQS context for verification. This will cause both
        // challenge derivation and final hash check to use wrong context, ensuring failure.
        let test_data1 = setup_simple_zkp_test(); // P, V1, SQS1, H
        let prover = test_data1.prover;
        let zkp_sqs1 = test_data1.zkp_sqs;
        let h_public = test_data1.h_public;

        // Create V2 and SQS2 with different context
        let mut verifier2 = Frame::initialize("Verifier2_WrongSQS_NI".to_string(), 909091);
        let zkp_sqs2 = establish_zkp_sqs(
            prover.id(),
            verifier2.id(), // Different V ID
            &h_public,
            "a_completely_different_context_ni", // Different context string
        ).expect("Failed to establish ZKP SQS2");
        assert_ne!(zkp_sqs1.components, zkp_sqs2.components); // Ensure SQS differs

        // P generates response using SQS1
        let response = prover.generate_noninteractive_validity_proof(&zkp_sqs1, &h_public)
            .expect("Prover failed proof generation");

        // V2 verifies using SQS2
        let verification_result = verifier2.verify_noninteractive_validity_proof(
            &response,
            &zkp_sqs2, // Use wrong SQS2
            &h_public,
        );

        // Assert failure
        assert!(verification_result.is_err(), "Verification should fail when using wrong SQS");
        let err = verification_result.unwrap_err();
        assert!(matches!(err, QfeError::DecodingFailed(_)), "Expected DecodingFailed, got {:?}", err);
         if let QfeError::DecodingFailed(msg) = err {
             assert!(msg.contains("Non-Interactive Validity Proof Check Failed"), "Expected NI Validity Proof failure message, got: {}", msg);
         }
        assert!(!verifier2.is_valid());
    }

     #[test]
     fn test_ni_zkp_wrong_public_statement() {
         // Verifier uses a different H_public during verification than Prover used.
         // This should cause the derived challenge to differ, leading to failure.
         let test_data = setup_simple_zkp_test();
         let prover = test_data.prover;
         let mut verifier = test_data.verifier;
         let zkp_sqs = test_data.zkp_sqs; // Correct SQS derived with correct H_public
         let h_public_correct = test_data.h_public;

         // Create a wrong public statement
         let h_public_wrong: [u8; 64] = Sha512::digest(b"some other public data").try_into().unwrap();
         assert_ne!(h_public_correct.as_slice(), h_public_wrong.as_slice());

         // 1. Prover generates proof using correct H_public (implicitly via correct SQS)
         let response = prover.generate_noninteractive_validity_proof(
             &zkp_sqs,
             &h_public_correct, // Prover uses the correct one
         ).expect("Prover failed proof generation");

         // 2. Verifier verifies using the WRONG H_public
         // This will cause derive_fs_challenge to produce a different challenge than the Prover used.
         let verification_result = verifier.verify_noninteractive_validity_proof(
             &response,
             &zkp_sqs, // Verifier uses the SQS derived from the *correct* H_public
                       // but passes the *wrong* one into verification, affecting challenge derivation.
             &h_public_wrong, // Verifier uses WRONG H_public for challenge derivation
         );

         // Assert failure
         assert!(verification_result.is_err(), "Verification should fail when Verifier uses wrong H_public for challenge derivation");
         let err = verification_result.unwrap_err();
         assert!(matches!(err, QfeError::DecodingFailed(_)), "Expected DecodingFailed, got {:?}", err);
         if let QfeError::DecodingFailed(msg) = err {
              assert!(msg.contains("Non-Interactive Validity Proof Check Failed"), "Expected NI Validity Proof failure message, got: {}", msg);
         }
         assert!(!verifier.is_valid());
     }

} // end standard zkp tests module

#[cfg(test)]
mod schnorr_tests { // Use a nested module for organization
    use super::*; // Import items from outer scope (zkp module)
    use crate::{Frame, establish_zkp_sqs}; // Import Frame and SQS establishment
    use curve25519_dalek::{scalar::Scalar, constants::RISTRETTO_BASEPOINT_POINT};
    use rand::RngCore;

    // Helper to setup Schnorr test context
    fn setup_schnorr_test() -> (Frame, Scalar, RistrettoPoint, Option<Sqs>) {
        let mut prover = Frame::initialize("SchnorrProver".to_string(), 20250406);
        let verifier_id = "SchnorrVerifier"; // Only need ID for SQS context

        // Prover generates secret x and public P
        let mut data = [0u8; 32];
        rand::rng().fill_bytes(&mut data);
        let secret_x = Scalar::from_bytes_mod_order(data);
        let public_p = secret_x * RISTRETTO_BASEPOINT_POINT;

        // Prover stores x
        prover.store_zkp_scalar(secret_x).expect("Failed to store scalar");

        // Establish optional SQS context (using public P as part of statement)
        let sqs_context_string = "schnorr_sqs_test_v1";
        // Use P compressed bytes as the "public statement" for SQS derivation
        let sqs = establish_zkp_sqs(
            prover.id(),
            verifier_id,
            public_p.compress().as_bytes(),
            sqs_context_string
        ).expect("Failed to establish Schnorr SQS");

        (prover, secret_x, public_p, Some(sqs))
    }

    #[test]
    fn test_schnorr_proof_successful() {
        let (prover, _secret_x, public_p, sqs_opt) = setup_schnorr_test();
        let sqs_ref = sqs_opt.as_ref(); // Get Option<&Sqs>

        // Prover generates proof
        let proof = prover.generate_schnorr_proof(&public_p, sqs_ref, None)
            .expect("Prover failed to generate Schnorr proof");

        // Verifier verifies proof
        let verification_result = verify_schnorr_proof(&proof, &public_p, sqs_ref, None);

        assert!(verification_result.is_ok(), "Schnorr verification failed unexpectedly");
    }

    #[test]
    fn test_schnorr_proof_invalid_proof_s() {
        let (prover, _secret_x, public_p, sqs_opt) = setup_schnorr_test();
         let sqs_ref = sqs_opt.as_ref();

        // Prover generates proof
        let mut proof = prover.generate_schnorr_proof(&public_p, sqs_ref, None)
            .expect("Prover failed to generate Schnorr proof");

        // Tamper with s
        proof.s = proof.s + Scalar::ONE; // Add one to s

        // Verifier verifies tampered proof
        let verification_result = verify_schnorr_proof(&proof, &public_p, sqs_ref, None);

        assert!(verification_result.is_err(), "Schnorr verification should fail for tampered s");
        assert!(matches!(verification_result.unwrap_err(), QfeError::DecodingFailed(_)));
    }

     #[test]
    fn test_schnorr_proof_invalid_proof_r() {
        let (prover, _secret_x, public_p, sqs_opt) = setup_schnorr_test();
        let sqs_ref = sqs_opt.as_ref();

        // Prover generates proof
        let mut proof = prover.generate_schnorr_proof(&public_p, sqs_ref, None)
            .expect("Prover failed to generate Schnorr proof");

        // Tamper with R (replace with base point G) - this will cause challenge mismatch
        proof.r = RISTRETTO_BASEPOINT_POINT;

        // Verifier verifies tampered proof
        let verification_result = verify_schnorr_proof(&proof, &public_p, sqs_ref, None);

        assert!(verification_result.is_err(), "Schnorr verification should fail for tampered R");
        assert!(matches!(verification_result.unwrap_err(), QfeError::DecodingFailed(_)));
    }

    #[test]
    fn test_schnorr_proof_wrong_public_point() {
        let (prover, _secret_x, public_p, sqs_opt) = setup_schnorr_test();
        let sqs_ref = sqs_opt.as_ref();

        // Prover generates proof for correct P
        let proof = prover.generate_schnorr_proof(&public_p, sqs_ref, None)
            .expect("Prover failed to generate Schnorr proof");

        // Verifier tries to verify using a different public point P' = G
        let wrong_public_p = RISTRETTO_BASEPOINT_POINT;
        let verification_result = verify_schnorr_proof(&proof, &wrong_public_p, sqs_ref, None);

        assert!(verification_result.is_err(), "Schnorr verification should fail for wrong public point P");
        assert!(matches!(verification_result.unwrap_err(), QfeError::DecodingFailed(_)));
    }

     #[test]
    fn test_schnorr_proof_wrong_sqs_context() {
        let (prover, _secret_x, public_p, sqs_opt) = setup_schnorr_test();
        let sqs1_ref = sqs_opt.as_ref();

        // Prover generates proof using sqs1 context
        let proof = prover.generate_schnorr_proof(&public_p, sqs1_ref, None)
            .expect("Prover failed to generate Schnorr proof");

        // Create a different SQS context
        let sqs2 = establish_zkp_sqs(
            prover.id(),
            "VerifierWithDifferentSQS",
            public_p.compress().as_bytes(),
            "different_schnorr_context_v2"
        ).expect("Failed to establish SQS2");
        let sqs2_ref = Some(&sqs2);
        assert_ne!(sqs1_ref.unwrap().components, sqs2_ref.unwrap().components);

        // Verifier tries to verify using sqs2 context
        // This will cause hash_to_scalar to produce a different challenge 'c'
        let verification_result = verify_schnorr_proof(&proof, &public_p, sqs2_ref, None);

        assert!(verification_result.is_err(), "Schnorr verification should fail for wrong SQS context");
        assert!(matches!(verification_result.unwrap_err(), QfeError::DecodingFailed(_)));
    }

     #[test]
    fn test_schnorr_proof_missing_scalar() {
         let (mut prover_no_scalar, _secret_x, public_p, sqs_opt) = setup_schnorr_test();
         prover_no_scalar.zkp_secret_scalar = None; // Explicitly remove scalar
         let sqs_ref = sqs_opt.as_ref();

         let proof_result = prover_no_scalar.generate_schnorr_proof(&public_p, sqs_ref, None);

         assert!(proof_result.is_err(), "Proof generation should fail if scalar is not set");
         let err = proof_result.unwrap_err();
         assert!(matches!(err, QfeError::InternalError(_)), "Expected InternalError for missing scalar, got {:?}", err);
         if let QfeError::InternalError(msg) = err {
            assert!(msg.contains("ZKP secret scalar x not set"));
         }
    }

} // end schnorr_tests module
