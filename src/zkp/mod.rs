// src/zkp/mod.rs
//! This module contains experimental implementations related to Zero-Knowledge Proofs
//! using the QFE (Qualitative Frame Entanglement) simulation framework.
//! It uses a Commit-Challenge-Response structure with placeholder verification logic.

// Import necessary items from the parent module (src/lib.rs) or crate root
use crate::{Sqs, QfeError, PatternType, Sha512Hash}; // Use crate:: for items in lib.rs
use crate::{PHI, RESONANCE_FREQ}; // Import constants from lib.rs
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher; // For placeholder phase derivation
use sha2::{Sha512, Digest}; // For cryptographic hashing
// rand is not needed directly in this file if nonces/challenges are generated externally

// --- ZKP Struct Definitions ---

/// Represents the Verifier's challenge in a single round of the ZKP protocol.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ZkpChallenge {
    /// The challenge data, typically random bytes.
    pub value: Vec<u8>,
}

/// Represents the Prover's commitment, typically Hash(Witness, Nonce).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ZkpCommitment {
    /// The commitment hash value (e.g., SHA-512).
    pub value: Sha512Hash, // [u8; 64]
}

/// Represents the Prover's response in the ZKP round.
#[derive(Debug, Clone, PartialEq)] // Cannot derive Eq due to f64
pub struct ZkpResponse {
    /// The commitment made by the prover for this round.
    pub commitment: ZkpCommitment,

    /// The random nonce `r` (as bytes) used by the prover to generate the commitment.
    /// Revealed here to allow the Verifier to perform checks based on it.
    pub nonce: Vec<u8>,

    /// The resulting phase state ([0, 2PI)) calculated by the Prover.
    /// This value's coherence is checked by the Verifier based on placeholder logic.
    pub response_phase: f64,

    /// An integrity hash (SHA-512) calculated over the *commitment value*,
    /// relative to the SQS_ZKP components.
    pub integrity_hash: Sha512Hash, // [u8; 64]
}


// --- ZKP Helper Functions ---
// (phase_from_data is removed as phase is calculated differently now)


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
    components_hasher.update(public_statement);
    components_hasher.update(context_string.as_bytes());
    components_hasher.update(&PHI.to_le_bytes());
    components_hasher.update(&RESONANCE_FREQ.to_le_bytes());
    let sqs_components: Vec<u8> = components_hasher.finalize().to_vec();

    // 2. Derive shared phase lock using DefaultHasher
    let mut phase_hasher = DefaultHasher::new();
    b"QFE_ZKP_SQS_PHASE_V1".hash(&mut phase_hasher);
    prover_id.as_bytes().hash(&mut phase_hasher);
    verifier_id.as_bytes().hash(&mut phase_hasher);
    public_statement.hash(&mut phase_hasher);
    context_string.as_bytes().hash(&mut phase_hasher);
    PHI.to_bits().hash(&mut phase_hasher);
    RESONANCE_FREQ.to_bits().hash(&mut phase_hasher);
    let phase_hash_output = phase_hasher.finish();
    let shared_phase_lock = (phase_hash_output as f64 / u64::MAX as f64) * 2.0 * std::f64::consts::PI;

    // 3. Construct the Sqs object
    let sqs = Sqs {
        pattern_type: PatternType::Sqs, // Or PatternType::ZkpSqs if defined
        components: sqs_components,
        shared_phase_lock,
        resonance_freq: RESONANCE_FREQ,
        validation: true, // Derived directly, assume valid
    };
    if sqs.components.len() != 64 {
         return Err(QfeError::InternalError(format!("Derived ZKP SQS components have unexpected length: {}", sqs.components.len())));
    }
    Ok(sqs)
}

/// Calculates a base phase component deterministically from public/shared ZKP round data.
/// Used by both Prover and Verifier as a common starting point for phase calculations.
fn calculate_base_phase(
    sqs: &Sqs,
    challenge: &ZkpChallenge,
    commitment: &ZkpCommitment,
    public_statement_h_public: &[u8],
    // Add other non-secret context if needed (e.g., IDs)
) -> f64 {
    let mut hasher = DefaultHasher::new();
    b"QFE_ZKP_BASE_PHASE_V1".hash(&mut hasher); // Domain separation
    commitment.hash(&mut hasher);
    challenge.hash(&mut hasher);
    public_statement_h_public.hash(&mut hasher);
    sqs.shared_phase_lock.to_bits().hash(&mut hasher);
    sqs.components.hash(&mut hasher);
    (hasher.finish() as f64 / u64::MAX as f64) * 2.0 * std::f64::consts::PI // Normalize
}

/// Calculates a phase adjustment based on a hash digest.
/// Used to incorporate the witness validity check result into the phase.
/// Returns a value in [0, PI) - smaller range for adjustment? Or full [0, 2PI)? Let's use full for now.
fn phase_adjustment_from_hash(hash_diff: &Sha512Hash) -> f64 {
    let mut hasher = DefaultHasher::new();
     b"QFE_ZKP_PHASE_ADJUST_V1".hash(&mut hasher); // Domain separation
    hash_diff.hash(&mut hasher); // Hash the input hash digest
    (hasher.finish() as f64 / u64::MAX as f64) * 2.0 * std::f64::consts::PI // Normalize
}

// --- ZKP methods within Frame ---
impl crate::Frame {

    /// Stores witness data within the Frame for ZKP operations.
    pub fn store_zkp_witness(&mut self, witness: &[u8]) -> Result<(), QfeError> {
        if !self.is_valid() { return Err(QfeError::FrameInvalid); }
        self.zkp_witness = Some(witness.to_vec());
        Ok(())
    }

    /// Calculates a SHA-512 hash over data relative to SQS components for integrity checks.
    fn calculate_zkp_integrity_hash(data: &[u8], sqs_components: &[u8]) -> Sha512Hash {
        let mut hasher = Sha512::new();
        hasher.update(b"QFE_ZKP_INTEGRITY_V1"); // Consistent domain separation
        hasher.update(data);
        hasher.update(sqs_components);
        hasher.update(&RESONANCE_FREQ.to_le_bytes());
        hasher.update(&PHI.to_le_bytes());
        hasher.finalize().into()
   }

    // --- ZKP Prover Methods (Using STARK-inspired Placeholder Phase Logic) ---

    /// Prover: Generates the commitment `Hash(Witness, Nonce)`.
    ///
    /// # Arguments
    /// * `nonce`: A random byte slice, unique for this proof round.
    ///
    /// # Returns
    /// * `Ok(ZkpCommitment)` containing the calculated commitment hash.
    /// * `Err(QfeError)` if the frame is invalid or no witness is stored.
    pub fn generate_zkp_commitment(
        &self,
        nonce: &[u8],
    ) -> Result<ZkpCommitment, QfeError> {
        if !self.is_valid() { return Err(QfeError::FrameInvalid); }
        let witness = self.zkp_witness.as_ref().ok_or_else(|| QfeError::InternalError("ZKP witness not set for commitment".to_string()))?;

        // Commitment = Hash(Witness || Nonce)
        let mut hasher = Sha512::new();
        hasher.update(b"QFE_ZKP_COMMIT_V1"); // Domain separation
        hasher.update(witness);
        hasher.update(nonce);
        let commit_value: Sha512Hash = hasher.finalize().into();

        Ok(ZkpCommitment { value: commit_value })
    }

    /// Prover: Generates the response using the refined phase calculation logic.
    pub fn generate_zkp_response(
        &self,
        nonce: &[u8],
        challenge: &ZkpChallenge,
        zkp_sqs: &Sqs,
        public_statement_h_public: &[u8],
    ) -> Result<ZkpResponse, QfeError> {
         if !self.is_valid() { return Err(QfeError::FrameInvalid); }
         if !zkp_sqs.validation { return Err(QfeError::InternalError("Invalid ZKP SQS provided for response".to_string())); }
         let witness_w = self.zkp_witness.as_ref().ok_or_else(|| QfeError::InternalError("ZKP witness not set for response generation".to_string()))?;

         // 1. Compute commitment Hash(W, nonce)
         let commitment = self.generate_zkp_commitment(nonce)?;

         // 2. Calculate H(W) to check validity against H_public
         let actual_hash_of_w: Sha512Hash = Sha512::digest(witness_w).into();

         // 3. Calculate hash difference: Hash(H(W) || H_public)
         //    This difference will be predictable iff H(W) == H_public.
         let hash_diff: Sha512Hash = {
             let mut hasher = Sha512::new();
             hasher.update(b"QFE_ZKP_VALIDITY_DIFF_V1"); // Domain separation
             hasher.update(&actual_hash_of_w);
             hasher.update(public_statement_h_public);
             hasher.finalize().into()
         };

         // 4. Calculate Base Phase Component (depends only on public/shared info for this round)
         let base_phase_component = calculate_base_phase(
             zkp_sqs,
             challenge,
             &commitment,
             public_statement_h_public,
         );

         // 5. Calculate Validity Phase Adjustment (depends on hash_diff)
         let validity_phase_adjustment = phase_adjustment_from_hash(&hash_diff);

         // 6. Calculate Final Response Phase
         let response_phase = (base_phase_component + validity_phase_adjustment)
                                .rem_euclid(2.0 * std::f64::consts::PI);

         // 7. Calculate Integrity Hash (over commitment value relative to SQS)
         let integrity_hash = Self::calculate_zkp_integrity_hash(&commitment.value, &zkp_sqs.components);

         // 8. Construct Response
         Ok(ZkpResponse {
             commitment,
             nonce: nonce.to_vec(), // Reveal nonce used
             response_phase,
             integrity_hash,
         })
    }

    // --- UPDATED Verifier Response Verification ---

     /// Verifier: Verifies the ZKP response using the refined phase coherence check.
     pub fn verify_zkp_response(
         &mut self,
         challenge: &ZkpChallenge,
         response: &ZkpResponse,
         zkp_sqs: &Sqs,
         public_statement_h_public: &[u8],
     ) -> Result<(), QfeError> {
        if !self.is_valid() { return Err(QfeError::FrameInvalid); }
        if !zkp_sqs.validation { return Err(QfeError::InternalError("Invalid ZKP SQS provided for verification".to_string())); }

        // --- Verification Checks ---

        // 1. Verify Integrity Hash of Commitment: Hash(CommitmentValue, SQS)
        let expected_integrity_hash = Self::calculate_zkp_integrity_hash(
            &response.commitment.value, // Use commitment from response
            &zkp_sqs.components
        );
        if expected_integrity_hash != response.integrity_hash {
            self.validation_status = false;
            return Err(QfeError::DecodingFailed(
                "ZKP Response Integrity Check Failed".to_string()
            ));
        }

        // Note: We removed the check `t == Hash(r, SQS)` because `t` is now `Hash(W,r)`.
        // The integrity hash check above implicitly verifies that the commitment received
        // in the response corresponds to the one whose integrity was hashed relative to the SQS.

        // 2. Verify Phase Coherence:
        //    V calculates the expected phase *assuming a valid witness was used*.
        //    This means calculating the expected hash difference and expected adjustment.

        // Calculate the expected hash difference IF witness was valid: Hash(H_public || H_public)
        let expected_hash_diff_for_valid: Sha512Hash = {
             let mut hasher = Sha512::new();
             hasher.update(b"QFE_ZKP_VALIDITY_DIFF_V1"); // Same domain sep as Prover
             hasher.update(public_statement_h_public); // Use H_public for first part
             hasher.update(public_statement_h_public); // Use H_public for second part
             hasher.finalize().into()
        };

        // Calculate expected adjustment based on the hash diff for a *valid* witness
        let expected_validity_adjustment = phase_adjustment_from_hash(&expected_hash_diff_for_valid);

        // Calculate the base phase component using public/shared info from this round
        let base_phase_component = calculate_base_phase(
            zkp_sqs,
            challenge,
            &response.commitment, // Use commitment from response
            public_statement_h_public,
        );

        // Calculate the final expected phase Verifier anticipates for a valid proof
        let expected_phase = (base_phase_component + expected_validity_adjustment)
                                .rem_euclid(2.0 * std::f64::consts::PI);

        // Compare expected phase with the phase received in the response
        let phase_diff = (response.response_phase - expected_phase)
                             .rem_euclid(2.0 * std::f64::consts::PI);
        let phase_tolerance = 1e-9;
        let min_diff = phase_diff.min(2.0 * std::f64::consts::PI - phase_diff);

        if min_diff > phase_tolerance {
              self.validation_status = false;
              return Err(QfeError::DecodingFailed(format!(
                  "ZKP Response Phase Coherence Check Failed (diff: {:.4} > tolerance)", min_diff
              )));
        }

        // If all checks pass
        Ok(())
     }

} // end impl Frame
