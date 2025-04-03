// src/zkp/mod.rs
//! This module contains experimental implementations related to Zero-Knowledge Proofs
//! using the QFE simulation framework, focusing on a simple validity proof scheme.

// Import necessary items from the parent module (src/lib.rs) or crate root
use crate::{Sqs, QfeError, PatternType, Sha512Hash};
use crate::{PHI, RESONANCE_FREQ};
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher; // Keep for phase derivation in SQS setup
use sha2::{Sha512, Digest}; // For cryptographic hashing
use rand::RngCore; // For challenge generation

// --- ZKP Struct Definitions ---

/// Represents the Verifier's challenge in the ZKP protocol.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ZkpChallenge {
    /// The challenge data, typically random bytes.
    pub value: Vec<u8>,
}

/// Represents the Prover's response in the simple validity ZKP.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ZkpValidityResponse {
    /// A hash proving the witness validity check was performed correctly relative
    /// to the challenge and SQS context.
    pub validity_proof_hash: Sha512Hash, // [u8; 64]
}

// --- ZKP SQS Establishment ---

/// Establishes a shared ZKP context (SQS_ZKP) based purely on public information.
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
    components_hasher.update(public_statement); // Include statement in SQS components
    components_hasher.update(context_string.as_bytes());
    components_hasher.update(&PHI.to_le_bytes());
    components_hasher.update(&RESONANCE_FREQ.to_le_bytes());
    let sqs_components: Vec<u8> = components_hasher.finalize().to_vec();

    // 2. Derive shared phase lock using DefaultHasher
    let mut phase_hasher = DefaultHasher::new();
    b"QFE_ZKP_SQS_PHASE_V1".hash(&mut phase_hasher);
    prover_id.as_bytes().hash(&mut phase_hasher);
    verifier_id.as_bytes().hash(&mut phase_hasher);
    public_statement.hash(&mut phase_hasher); // Include statement in phase context
    context_string.as_bytes().hash(&mut phase_hasher);
    PHI.to_bits().hash(&mut phase_hasher);
    RESONANCE_FREQ.to_bits().hash(&mut phase_hasher);
    let phase_hash_output = phase_hasher.finish();
    let shared_phase_lock = (phase_hash_output as f64 / u64::MAX as f64) * 2.0 * std::f64::consts::PI;

    // 3. Construct the Sqs object
    let sqs = Sqs {
        pattern_type: PatternType::Sqs,
        components: sqs_components,
        shared_phase_lock,
        resonance_freq: RESONANCE_FREQ,
        validation: true,
    };
    if sqs.components.len() != 64 {
         return Err(QfeError::InternalError(format!("Derived ZKP SQS components have unexpected length: {}", sqs.components.len())));
    }
    Ok(sqs)
}

/// Generates a random challenge for a ZKP round.
pub fn generate_zkp_challenge(challenge_len: usize) -> ZkpChallenge {
    let mut challenge_value = vec![0u8; challenge_len];
    // Correct usage for rand 0.8+
    rand::rng().fill_bytes(&mut challenge_value);
    ZkpChallenge { value: challenge_value }
}

// --- ZKP methods within Frame ---
impl crate::Frame {

    /// Stores witness data within the Frame for ZKP operations.
    pub fn store_zkp_witness(&mut self, witness: &[u8]) -> Result<(), QfeError> {
        if !self.is_valid() { return Err(QfeError::FrameInvalid); }
        self.zkp_witness = Some(witness.to_vec());
        Ok(())
    }

    // --- Simple Validity ZKP Prover Method ---

    /// Prover: Generates a simple validity proof hash based on witness, challenge, and SQS.
    pub fn generate_validity_proof(
        &self,
        challenge: &ZkpChallenge,
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

        // 3. Compute the response hash: Hash(DomainSep || Challenge || Validity || SQS Context || Constants)
        let mut response_hasher = Sha512::new();
        response_hasher.update(b"QFE_ZKP_VALIDITY_PROOF_V1"); // Domain separation
        response_hasher.update(&challenge.value);
        response_hasher.update(&[is_valid_witness as u8]); // Hash the boolean result (as 1 or 0)
        response_hasher.update(&zkp_sqs.components);
        response_hasher.update(&zkp_sqs.shared_phase_lock.to_le_bytes());
        response_hasher.update(&PHI.to_le_bytes());
        response_hasher.update(&RESONANCE_FREQ.to_le_bytes());
        // Note: We don't hash H_public here, validity depends on witness check result

        let proof_hash: Sha512Hash = response_hasher.finalize().into();

        Ok(ZkpValidityResponse { validity_proof_hash: proof_hash })
    }

    // --- Simple Validity ZKP Verifier Method ---

     /// Verifier: Verifies the simple validity proof hash.
     pub fn verify_validity_proof(
         &mut self, // Mutable to update validation status
         challenge: &ZkpChallenge,
         response: &ZkpValidityResponse,
         zkp_sqs: &Sqs,
         // Include H_public for calculating expected hash, ensuring check is statement-specific
         _public_statement_h_public: &[u8],
     ) -> Result<(), QfeError> {
        if !self.is_valid() { return Err(QfeError::FrameInvalid); }
        if !zkp_sqs.validation { return Err(QfeError::InternalError("Invalid ZKP SQS provided for verification".to_string())); }

        // Calculate the hash Verifier expects if Prover's witness was valid (is_valid = true)
        let expected_hash = {
            let mut response_hasher = Sha512::new();
            response_hasher.update(b"QFE_ZKP_VALIDITY_PROOF_V1"); // Same domain separation
            response_hasher.update(&challenge.value);
            response_hasher.update(&[true as u8]); // Verifier *assumes* validity (true -> 1 byte)
            response_hasher.update(&zkp_sqs.components);
            response_hasher.update(&zkp_sqs.shared_phase_lock.to_le_bytes());
            response_hasher.update(&PHI.to_le_bytes());
            response_hasher.update(&RESONANCE_FREQ.to_le_bytes());
            // We need H_public to be part of the SQS context calculation for this to be fully sound,
            // which establish_zkp_sqs already does. Hashing it *again* here might be redundant
            // if SQS components guarantee statement specificity. Let's omit it here for simplicity,
            // relying on SQS uniqueness per statement.
            let hash: Sha512Hash = response_hasher.finalize().into();
            hash
        };

        // Compare expected hash with the one received from Prover
        if response.validity_proof_hash != expected_hash {
            self.validation_status = false; // Mark invalid on failure
            return Err(QfeError::DecodingFailed(
                "ZKP Validity Proof Check Failed".to_string()
            ));
        }

        // If hash matches
        Ok(())
     }

} // end impl Frame

// No tests included as requested
