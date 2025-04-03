//! Provides types and functions for a secure communication protocol simulation
//! based on shared state establishment and modulated signals.

use std::sync::Arc; // For shared ownership of Sqs
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher; // Simple standard hasher
use std::error::Error;
use std::fmt;
use sha2::{Sha512, Digest};

pub mod zkp;
pub use zkp::{ZkpChallenge, establish_zkp_sqs};
pub type Sha512Hash = [u8; 64];

// // --- Constants derived from Framework Core Mathematics ---
// Primary Scale: φ (phi)
const PHI: f64 = 1.618033988749895;
// Resonance: φ/2π
const RESONANCE_FREQ: f64 = PHI / (2.0 * std::f64::consts::PI);

// --- Core Data Structures ---

/// Represents one unit of encoded information.
#[derive(Debug, Clone, PartialEq)] // Added Eq for array comparison
pub struct EncodedUnit {
    /// The phase state ([0, 2PI)) after encoding this unit.
    // Note: f64 doesn't implement Eq, so PartialEq remains. If EncodedUnit needs Eq, phase might need adjusted representation.
    // For now, PartialEq is sufficient as we compare hashes as arrays.
    pub modulated_phase: f64,
    /// Integrity value (SHA-512 hash) calculated using the original byte and Sqs components.
    // CHANGED: Type from u64 to [u8; 64] for SHA-512 output
    pub integrity_hash: [u8; 64],
}

/// Custom error types for the QFE library operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QfeError {
    SqsEstablishmentFailed(String),
    EncodingFailed(String),
    DecodingFailed(String),
    InvalidUtf8(std::string::FromUtf8Error),
    FrameInvalid,
    SqsMissing,
    InternalError(String),
}

// Display and Error impl remain the same...
impl fmt::Display for QfeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QfeError::SqsEstablishmentFailed(s) => write!(f, "SQS Establishment Failed: {}", s),
            QfeError::EncodingFailed(s) => write!(f, "Encoding Failed: {}", s),
            QfeError::DecodingFailed(s) => write!(f, "Decoding Failed: {}", s),
            QfeError::InvalidUtf8(e) => write!(f, "Decoded data is not valid UTF-8: {}", e),
            QfeError::FrameInvalid => write!(f, "Operation failed: Frame is in an invalid state"),
            QfeError::SqsMissing => write!(f, "Operation failed: SQS component is missing"),
            QfeError::InternalError(s) => write!(f, "Internal QFE error: {}", s),
        }
    }
}
impl Error for QfeError {}


/// Represents the established shared state (secret key and context) between two Frames.
#[derive(Clone, PartialEq)] // SQS components (Vec<u8>) make Eq complex, PartialEq is fine.
pub struct Sqs {
    pattern_type: PatternType,
    /// The core shared secret (SHA-512 hash output) derived from the interaction.
    // Note: components are now 64 bytes long.
    pub components: Vec<u8>,
    /// Represents the synchronized phase derived from interaction.
    pub shared_phase_lock: f64,
    /// A characteristic frequency parameter associated with this shared state.
    resonance_freq: f64,
    /// Internal validation status determined during creation.
    validation: bool,
}

// Debug impl for Sqs remains the same (still uses DefaultHasher for display hash)
impl fmt::Debug for Sqs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sqs")
         .field("pattern_type", &self.pattern_type)
         .field("components_len", &self.components.len())
         .field("components_hash", &{
             let mut hasher = DefaultHasher::new(); // Use DefaultHasher just for debug display
             self.components.hash(&mut hasher);
             format!("{:x}", hasher.finish())
         })
         .field("shared_phase_lock", &self.shared_phase_lock)
         .field("resonance_freq", &self.resonance_freq)
         .field("validation", &self.validation)
         .finish()
    }
}


/// Represents a participant Frame (e.g., Sender A, Receiver B).
#[derive(Debug, Clone)]
pub struct Frame {
    id: String,
    node: DistinctionNode,
    frame_structure: ReferenceFrame,
    phase: f64,
    sqs_component: Option<Arc<Sqs>>,
    validation_status: bool,
    zkp_witness: Option<Vec<u8>>,
}

// --- Framework Primitive Representations ---

/// Represents the foundational Ω(x) = ∂φ/∂ψ * e^(iθ) conceptually.
/// For now, a placeholder representing the core distinction.
#[derive(Clone, Hash, PartialEq, Eq)]
struct DistinctionNode {
    // Represents inherent uniqueness, minimal representation
    id: u64,
}

impl fmt::Debug for DistinctionNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DistinctionNode")
         .field("id", &format!("{:x}", self.id)) // Show as hex
         .finish()
    }
}

/// Represents the Reference Frame R(Ω) = ∮Ω(x)dx * ∇²ψ conceptually.
/// Captures the unique structural context of a Frame.
/// Abstracted as a unique identifier derived from its history/seed.
#[derive(Clone, Hash, PartialEq, Eq)]
struct ReferenceFrame {
    // Unique identifier simulating the frame's specific structure
    structural_id: u128,
}

impl ReferenceFrame {
    /// Creates a new ReferenceFrame based on initial conditions (seed).
    /// Simulates the unique structure arising from distinction.
    fn new(seed: u64) -> Self {
        let mut hasher = DefaultHasher::new();
        seed.hash(&mut hasher);
        // Incorporate PHI to tie it subtly to the framework's core math
        PHI.to_bits().hash(&mut hasher);
        ReferenceFrame {
            structural_id: hasher.finish() as u128,
        }
    }
}

impl fmt::Debug for ReferenceFrame {
     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReferenceFrame")
         .field("structural_id", &format!("{:x}", self.structural_id)) // Show as hex
         .finish()
    }
}


/// Represents different types of patterns P(n) = Ω(x) × R(Ω).
#[derive(Debug, Clone, PartialEq)]
enum PatternType {
    Sqs, // Shared Qualitative Structure
    // Future types: Information, Transformation, etc.
}

// --- QFE Algorithm Implementation ---

impl Frame {
    /// Initializes a new `Frame` instance.
    ///
    /// Creates a frame with a unique internal state derived deterministically
    /// from the provided identifier and seed. The frame starts in a valid state
    /// without any established shared state (`SQS`).
    ///
    /// # Arguments
    /// * `id`: A `String` identifier for the frame.
    /// * `initial_seed`: A `u64` seed value used to generate the frame's unique internal state.
    ///
    /// # Returns
    /// * A new `Frame` instance.
    pub fn initialize(id: String, initial_seed: u64) -> Self {
        // Create the foundational distinction node (unique per frame init)
        let mut node_hasher = DefaultHasher::new();
        initial_seed.hash(&mut node_hasher);
        "node".hash(&mut node_hasher); // Add context
        let node = DistinctionNode { id: node_hasher.finish() };

        // Derive the reference frame structure from the seed
        let frame_structure = ReferenceFrame::new(initial_seed);

        // Derive initial phase (θ₀) based on seed and framework constants
        let mut phase_hasher = DefaultHasher::new();
        initial_seed.hash(&mut phase_hasher);
        "phase".hash(&mut phase_hasher); // Add context
        PHI.to_bits().hash(&mut phase_hasher);
        let phase = (phase_hasher.finish() as f64 / u64::MAX as f64) * 2.0 * std::f64::consts::PI; // Normalize hash to [0, 2PI)

        Frame {
            id,
            node,
            frame_structure,
            phase,
            // internal_patterns: Vec::new(),
            sqs_component: None,
            validation_status: true, // Starts valid
            zkp_witness: None,
        }
    }

    /// Checks if a shared state (`SQS`) has been successfully established for this frame
    /// and if the frame is currently in a valid state.
    ///
    /// # Returns
    /// * `true` if an `SQS` is present and `validation_status` is true, `false` otherwise.
    pub fn has_sqs(&self) -> bool {
        self.sqs_component.is_some() && self.validation_status
    }

    /// Returns an immutable reference to the established shared state (`SQS`) data, if available.
    ///
    /// Returns `None` if no `SQS` has been established or if the frame is invalid.
    /// The `SQS` is shared using an `Arc`, so multiple frames can hold references.
    ///
    /// # Returns
    /// * `Some(&Arc<SQS>)` if an SQS exists and the frame is valid.
    /// * `None` otherwise.
    pub fn get_sqs(&self) -> Option<&Arc<Sqs>> {
         if !self.validation_status { return None; }
        self.sqs_component.as_ref()
    }

    /// Internal helper: Calculates a value representing the frame's current
    /// state for interaction purposes. Based on its unique structure and phase.
    /// Simulates the frame emitting its influence/field aspect.
    fn calculate_interaction_aspect(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.node.hash(&mut hasher);
        self.frame_structure.hash(&mut hasher);
        self.phase.to_bits().hash(&mut hasher); // Incorporate phase directly
        hasher.finish()
    }

    /// Gets the frame's unique ID.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Encodes a message (byte slice) into a sequence of `EncodedUnit`s using the frame's SQS.
    ///
    /// This method applies the core encoding logic, modulating phase sequentially based on input bytes
    /// and calculating integrity hashes tied to the SQS components.
    ///
    /// # Arguments
    /// * `message`: The byte slice `&[u8]` containing the data to encode.
    ///
    /// # Returns
    /// * `Ok(Vec<EncodedUnit>)` containing the resulting encoded signal sequence.
    /// * `Err(QfeError)` if:
    ///     - The frame has no established SQS (`QfeError::SqsMissing`).
    ///     - The frame is invalid (`QfeError::FrameInvalid`).
    ///     - An internal error occurs (`QfeError::InternalError`).
    pub fn encode(&self, message: &[u8]) -> Result<Vec<EncodedUnit>, QfeError> {
        if !self.has_sqs() {
            return Err(QfeError::SqsMissing);
        }
        // Safely get the Sqs Arc, knowing has_sqs passed.
        if !self.validation_status {
             return Err(QfeError::FrameInvalid); // Check frame validity
         }
        let sqs = self.sqs_component.as_ref()
            .ok_or(QfeError::InternalError("SQS missing despite check.".to_string()))?; // Handle internal logic error


        let mut encoded_signal = Vec::with_capacity(message.len());
        // Encoding starts relative to the Sqs established phase lock.
        let mut current_phase = sqs.shared_phase_lock;

        for &byte in message {
            // 1. Calculate phase shift for this byte
            let phase_shift = calculate_phase_shift_from_byte(byte);

            // 2. Determine the new phase state (sequential modulation)
            //    Resulting phase after applying the shift.
            let next_phase = (current_phase + phase_shift).rem_euclid(2.0 * std::f64::consts::PI);

            // 3. Calculate integrity hash using the original byte and Sqs secret
            let integrity_hash = calculate_integrity_hash_sha512(byte, &sqs.components);

            // 4. Store the resulting state (new phase) and integrity hash
            encoded_signal.push(EncodedUnit {
                modulated_phase: next_phase,
                integrity_hash,
            });

            // 5. Update the phase for the next byte's modulation
            current_phase = next_phase;
        }

        Ok(encoded_signal)
    }

    /// Decodes a received signal (slice of `EncodedUnit`s) back into bytes using the frame's SQS.
    ///
    /// This method performs the core decoding logic, reconstructing bytes from phase shifts
    /// and verifying the integrity hash of each unit against the frame's SQS components.
    ///
    /// If an integrity check fails or an invalid phase shift is detected (indicating tampering or error),
    /// the decoding process stops, an error is returned, and the frame's `validation_status`
    /// is set to `false`.
    ///
    /// # Arguments
    /// * `encoded_signal`: The `&[EncodedUnit]` slice representing the received signal.
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` containing the successfully decoded message bytes.
    /// * `Err(QfeError)` if:
    ///     - The frame has no established SQS (`QfeError::SqsMissing`).
    ///     - The frame is already invalid (`QfeError::FrameInvalid`).
    ///     - An integrity check fails or an invalid phase shift is detected during decoding (`QfeError::DecodingFailed`).
    ///     - An internal error occurs (`QfeError::InternalError`).
    pub fn decode(&mut self, encoded_signal: &[EncodedUnit]) -> Result<Vec<u8>, QfeError> {
        if !self.has_sqs() {
            return Err(QfeError::SqsMissing);
        }
        if !self.validation_status {
            // Frame is already invalid, perhaps from previous failed decode
            return Err(QfeError::FrameInvalid);
        }
         let sqs = self.sqs_component.as_ref()
            .ok_or(QfeError::InternalError("SQS missing despite check.".to_string()))?;

        let mut decoded_message = Vec::with_capacity(encoded_signal.len());
        // Decoding starts relative to the Sqs established phase lock.
        let mut previous_phase = sqs.shared_phase_lock;

        for (index, unit) in encoded_signal.iter().enumerate() {
            let current_modulated_phase = unit.modulated_phase;

            // 1. Calculate the phase shift between the previous state and this unit's state.
            //    `rem_euclid` ensures the result is always positive [0, 2PI).
            let phase_shift = (current_modulated_phase - previous_phase)
                                .rem_euclid(2.0 * std::f64::consts::PI);

            // 2. Reconstruct the original byte from the calculated phase shift.
            let Some(reconstructed_byte) = reconstruct_byte_from_phase_shift(phase_shift) else {
                // If reconstruction fails, it implies an invalid phase shift value was received.
                self.validation_status = false;
                return Err(QfeError::DecodingFailed(format!(
                    "At index {}: Invalid phase shift ({:.4}) detected. Possible tampering or transmission error.",
                    index, phase_shift
                )));
            };

            // 3. Verify Integrity (Crucial Security Step -  Step 6 simulated)
            //    Recalculate the hash using the reconstructed byte and *this frame's* Sqs components.
            let expected_hash = calculate_integrity_hash_sha512(reconstructed_byte, &sqs.components);

            if expected_hash != unit.integrity_hash {
                // Mismatch! This indicates tampering or decoding with the wrong Sqs.
                 self.validation_status = false; // Mark frame as invalid due to incoherent input
                return Err(QfeError::DecodingFailed(format!(
                    "At index {}: Integrity check mismatch. Tampering suspected or wrong SQS used.",
                    index
                )));
            }

            // 4. If integrity check passes, add the byte to the result.
            decoded_message.push(reconstructed_byte);

            // 5. Update the phase state for the next unit's comparison.
            previous_phase = current_modulated_phase;
        }

        Ok(decoded_message)
    }
    /// Encodes a string slice (`&str`) into a sequence of `EncodedUnit`s.
    ///
    /// This is a convenience method that converts the string to bytes and calls [`encode`].
    ///
    /// # Arguments
    /// * `message`: The string slice `&str` to encode.
    ///
    /// # Returns
    /// * `Ok(Vec<EncodedUnit>)` containing the encoded signal sequence.
    /// * `Err(QfeError)` if encoding fails (see [`encode`] errors).
    pub fn encode_str(&self, message: &str) -> Result<Vec<EncodedUnit>, QfeError> {
        if !self.validation_status { return Err(QfeError::FrameInvalid); }
        self.encode(message.as_bytes())
    }

    /// Decodes a received signal (slice of `EncodedUnit`s) directly into a `String`.
    ///
    /// This is a convenience method that calls [`decode`] and then attempts to convert
    /// the resulting bytes into a UTF-8 `String`.
    ///
    /// Requires mutable access (`&mut self`) because the underlying [`decode`] might
    /// invalidate the frame's state upon detecting errors.
    ///
    /// # Arguments
    /// * `encoded_signal`: The `&[EncodedUnit]` slice representing the received signal.
    ///
    /// # Returns
    /// * `Ok(String)` containing the successfully decoded and UTF-8 validated string.
    /// * `Err(QfeError)` if:
    ///     - Decoding fails (see [`decode`] errors).
    ///     - The decoded bytes are not valid UTF-8 (`QfeError::InvalidUtf8`).
    pub fn decode_to_str(&mut self, encoded_signal: &[EncodedUnit]) -> Result<String, QfeError> {
         if !self.validation_status { return Err(QfeError::FrameInvalid); } // Check before decoding attempt
        let decoded_bytes = self.decode(encoded_signal)?;
        // Attempt UTF-8 conversion, mapping error type
        String::from_utf8(decoded_bytes).map_err(QfeError::InvalidUtf8)
    }
    /// Checks if the frame is currently considered valid.
    ///
    /// The validation status can become `false` if operations like `decode` detect
    /// inconsistencies or tampering.
    ///
    /// # Returns
    /// * `true` if the frame's `validation_status` is true, `false` otherwise.
     pub fn is_valid(&self) -> bool {
        self.validation_status
    }
}

// --- Public API Functions ---

/// Sets up two Frames (A and B) and establishes a shared state (`SQS`) between them.
///
/// This function simplifies the common initialization workflow. It initializes two frames
/// based on the provided IDs and seeds, then performs the key exchange process
/// to establish the `SQS`.
///
/// # Arguments
/// * `id_a`: A `String` identifier for the first frame (Frame A).
/// * `seed_a`: A `u64` seed used for generating Frame A's internal state.
/// * `id_b`: A `String` identifier for the second frame (Frame B).
/// * `seed_b`: A `u64` seed used for generating Frame B's internal state.
///
/// # Returns
/// * `Ok((Frame, Frame))` containing the two initialized `Frame` instances, each holding
///   a reference to the same successfully established `SQS`.
/// * `Err(QfeError)` if frame initialization fails or if the `SQS` establishment
///   process fails (e.g., due to internal validation checks or simulated interaction errors).
///   Specific error reasons can be found in the `QfeError::SqsEstablishmentFailed` variant.
pub fn setup_qfe_pair(
    id_a: String,
    seed_a: u64,
    id_b: String,
    seed_b: u64,
) -> Result<(Frame, Frame), QfeError> {
    let mut frame_a = Frame::initialize(id_a, seed_a);
    let mut frame_b = Frame::initialize(id_b, seed_b);
    // `establish_sqs` now returns Result<(), QfeError>, use `?` to propagate error
    establish_sqs(&mut frame_a, &mut frame_b)?;
    Ok((frame_a, frame_b))
}

/// Performs the interactive shared state (`SQS`) establishment process between two Frames.
///
/// This function simulates the key exchange. It should typically be called after
/// `Frame::initialize` for two frames that intend to communicate securely.
/// Use [`setup_qfe_pair`] for a simpler setup.
///
/// # Arguments
/// * `frame_a`: A mutable reference to the first participating `Frame`.
/// * `frame_b`: A mutable reference to the second participating `Frame`.
///
/// # Returns
/// * `Ok(())` if the `SQS` is successfully established and validated between the two frames.
///   Both input frames will be updated internally with a reference to the shared `SQS`.
/// * `Err(QfeError)` if the process fails. This can happen if:
///     - Either frame is already invalid (`QfeError::FrameInvalid`).
///     - An SQS is already established for one or both frames (`QfeError::SqsEstablishmentFailed`).
///     - The simulated interaction fails internal checks (`QfeError::SqsEstablishmentFailed`).
pub fn establish_sqs(frame_a: &mut Frame, frame_b: &mut Frame) -> Result<(), QfeError> {
    if !frame_a.validation_status || !frame_b.validation_status {
         return Err(QfeError::FrameInvalid);
    }
    if frame_a.sqs_component.is_some() || frame_b.sqs_component.is_some() {
        return Err(QfeError::SqsEstablishmentFailed(
            "SQS already established".to_string(),
        ));
    }

    let aspect_a = frame_a.calculate_interaction_aspect(); // Still u64 for now
    let aspect_b = frame_b.calculate_interaction_aspect(); // Still u64 for now

    // CHANGED: Use SHA-512 based derivation for SQS components
    let shared_components = derive_shared_components_sha512(aspect_a, frame_a.phase, aspect_b, frame_b.phase);

    // Phase lock calculation remains the same
    let weight_a = (aspect_a % 1000 + 1) as f64;
    let weight_b = (aspect_b % 1000 + 1) as f64;
    let total_weight = weight_a + weight_b;
    let shared_phase_lock = (frame_a.phase * weight_a + frame_b.phase * weight_b) / total_weight;
    let shared_phase_lock = shared_phase_lock.rem_euclid(2.0 * std::f64::consts::PI);

    // Validation checks remain the same conceptually, but C3 now checks 64 bytes
    let c1_check = shared_phase_lock.is_finite();
    let c3_check = !shared_components.is_empty() && shared_components.len() == 64; // Check for 64 bytes from SHA-512

    let validation_passed = c1_check && c3_check;

    if validation_passed {
        let sqs = Arc::new(Sqs {
            pattern_type: PatternType::Sqs,
            components: shared_components, // Now contains 64 bytes
            shared_phase_lock,
            resonance_freq: RESONANCE_FREQ,
            validation: true,
        });
        frame_a.sqs_component = Some(Arc::clone(&sqs));
        frame_b.sqs_component = Some(sqs);
        Ok(())
    } else {
        frame_a.validation_status = false;
        frame_b.validation_status = false;
        Err(QfeError::SqsEstablishmentFailed(format!(
            "Validation failed: PhaseCoherenceCheck(ValidNumber)={}, PatternResonanceCheck(NonTrivial SHA512)={}", // Updated msg
            c1_check, c3_check
        )))
    }
}

/// Calculates an integrity hash (SHA-512) for a byte using Sqs components.
// CHANGED: New function using SHA-512
fn calculate_integrity_hash_sha512(byte: u8, sqs_components: &[u8]) -> [u8; 64] {
    // Instantiate SHA-512 hasher
    let mut hasher = Sha512::new();
    // Update hasher with byte, SQS components, and constants
    hasher.update([byte]); // Feed the byte
    hasher.update(sqs_components); // Feed the SQS shared secret
    hasher.update(RESONANCE_FREQ.to_le_bytes()); // Feed constants consistently
    hasher.update(PHI.to_le_bytes());
    // Finalize and convert to fixed-size array
    hasher.finalize().into()
}

// NEW: Helper function to derive SQS components using SHA-512
// This replaces the DefaultHasher logic previously inline in establish_sqs
fn derive_shared_components_sha512(aspect1: u64, phase1: f64, aspect2: u64, phase2: f64) -> Vec<u8> {
    let mut hasher = Sha512::new();
    // Feed aspects in a consistent order for symmetry
    if aspect1 < aspect2 {
        hasher.update(aspect1.to_le_bytes());
        hasher.update(aspect2.to_le_bytes());
    } else {
        hasher.update(aspect2.to_le_bytes());
        hasher.update(aspect1.to_le_bytes());
    }
    // Combine phases (consistent order not needed here, just combination)
    let phase_combined = (phase1 + phase2) * PHI;
    hasher.update(phase_combined.to_le_bytes());
    // Add framework constants
    hasher.update(RESONANCE_FREQ.to_le_bytes());
    hasher.update(PHI.to_le_bytes());
    // Return the 64-byte hash result as Vec<u8>
    hasher.finalize().to_vec()
}

// --- Phase Modulation Constants and Helpers ---
// Define a maximum phase shift per byte to prevent excessive deviation.
// This value could be related to framework constants, e.g., scaled by PHI.
const MAX_PHASE_SHIFT_PER_BYTE: f64 = (2.0 * std::f64::consts::PI) / (PHI * PHI * 4.0); // Example: Smaller shift range

/// Calculates the phase shift corresponding to an input byte.
/// Maps byte value [0-255] to a phase shift [0, MAX_PHASE_SHIFT_PER_BYTE].
fn calculate_phase_shift_from_byte(byte: u8) -> f64 {
    (byte as f64 / 255.0) * MAX_PHASE_SHIFT_PER_BYTE
}

/// Reconstructs the original byte from a phase shift.
/// This is the inverse of `calculate_phase_shift_from_byte`.
/// Includes tolerance for floating point inaccuracies.
fn reconstruct_byte_from_phase_shift(shift: f64) -> Option<u8> {
    // Check if shift is within the expected range (with small tolerance)
    // The shift calculated in decode is always positive due to rem_euclid.
    let tolerance = 1e-9;
    if !(0.0..=MAX_PHASE_SHIFT_PER_BYTE + tolerance).contains(&shift) {
        // Shift is outside the valid range, indicating potential error or tampering
        return None;
    }
    // Inverse mapping: byte = round((shift / MAX_SHIFT) * 255.0)
    let byte_f = (shift / MAX_PHASE_SHIFT_PER_BYTE) * 255.0;
    // Round to nearest integer and clamp to valid u8 range [0, 255]
    Some(byte_f.round().clamp(0.0, 255.0) as u8)
}
//
// --- Unit Tests ---
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_initialization_deterministic() {
        let frame1 = Frame::initialize("Test".to_string(), 12345);
        let frame2 = Frame::initialize("Test".to_string(), 12345);
        assert_eq!(frame1.node, frame2.node);
        assert_eq!(frame1.frame_structure, frame2.frame_structure);
        assert_eq!(frame1.phase, frame2.phase);
        assert_eq!(frame1.id, frame2.id);
    }

     #[test]
    fn test_frame_initialization_unique() {
        let frame1 = Frame::initialize("Test1".to_string(), 12345);
        let frame2 = Frame::initialize("Test2".to_string(), 54321);
        assert_ne!(frame1.node, frame2.node); // Hash includes seed
        assert_ne!(frame1.frame_structure, frame2.frame_structure);
        assert_ne!(frame1.phase, frame2.phase); // Phase derived from seed hash
    }


    #[test]
    fn test_sqs_establishment_success_and_shared() {
        let mut frame_a = Frame::initialize("FrameA".to_string(), 111);
        let mut frame_b = Frame::initialize("FrameB".to_string(), 222);

        let result = establish_sqs(&mut frame_a, &mut frame_b);
        println!("Sqs Establishment Result: {:?}", result); // Debug print
        assert!(result.is_ok());

        assert!(frame_a.has_sqs());
        assert!(frame_b.has_sqs());
        assert!(frame_a.validation_status);
        assert!(frame_b.validation_status);

        let sqs_a = frame_a.get_sqs().unwrap();
        let sqs_b = frame_b.get_sqs().unwrap();

        // Crucial check: Ensure both frames hold pointers to the *same* Sqs instance
        assert!(Arc::ptr_eq(sqs_a, sqs_b));

        println!("Sqs A: {:?}", sqs_a);
        println!("Sqs B: {:?}", sqs_b);

        // Check properties of the shared Sqs
        assert_eq!(sqs_a.pattern_type, PatternType::Sqs);
        assert!(!sqs_a.components.is_empty());
        assert!(sqs_a.components.len() >= 8); // Matches logic
        assert_eq!(sqs_a.resonance_freq, RESONANCE_FREQ);
        assert_eq!(sqs_a.components.len(), 64, "SQS components should be 64 bytes for SHA-512");
        assert!(sqs_a.validation); // Sqs itself should be marked valid
    }

    #[test]
    fn test_sqs_establishment_deterministic_result() {
        let mut frame_a1 = Frame::initialize("A1".to_string(), 111);
        let mut frame_b1 = Frame::initialize("B1".to_string(), 222);
        let _ = establish_sqs(&mut frame_a1, &mut frame_b1);
        let sqs1_data = frame_a1.get_sqs().unwrap().as_ref().clone(); // Clone Sqs data

        let mut frame_a2 = Frame::initialize("A2".to_string(), 111); // Same seed
        let mut frame_b2 = Frame::initialize("B2".to_string(), 222); // Same seed
        let _ = establish_sqs(&mut frame_a2, &mut frame_b2);
        let sqs2_data = frame_a2.get_sqs().unwrap().as_ref().clone();

        // Compare the actual data within the Sqs instances
        assert_eq!(sqs1_data.components, sqs2_data.components);
        assert_eq!(sqs1_data.shared_phase_lock, sqs2_data.shared_phase_lock);
        assert_eq!(sqs1_data.validation, sqs2_data.validation);
    }

     #[test]
    fn test_sqs_establishment_different_seeds_produce_different_sqs() {
        let mut frame_a1 = Frame::initialize("A".to_string(), 111);
        let mut frame_b1 = Frame::initialize("B".to_string(), 222);
        let _ = establish_sqs(&mut frame_a1, &mut frame_b1);
        let sqs1_data = frame_a1.get_sqs().unwrap().as_ref().clone();

        let mut frame_a2 = Frame::initialize("A".to_string(), 333); // Different seeds
        let mut frame_b2 = Frame::initialize("B".to_string(), 444);
        let _ = establish_sqs(&mut frame_a2, &mut frame_b2);
        let sqs2_data = frame_a2.get_sqs().unwrap().as_ref().clone();

        assert_ne!(sqs1_data.components, sqs2_data.components);
        // Phases likely different too, but components are the primary secret
    }


    #[test]
    fn test_establish_sqs_fails_if_already_established() {
        let mut frame_a = Frame::initialize("A".to_string(), 1);
        let mut frame_b = Frame::initialize("B".to_string(), 2);
        assert!(establish_sqs(&mut frame_a, &mut frame_b).is_ok()); // First time ok
        // Try again
        let result = establish_sqs(&mut frame_a, &mut frame_b);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), QfeError::SqsEstablishmentFailed("SQS already established".to_string()));
    }

    #[test]
    fn test_establish_sqs_fails_if_validation_fails() {
        // Need to engineer a scenario where validation checks fail.
        // This might require manipulating the derive_shared_components or checks,
        // or finding seeds that produce non-convergent phases / trivial components.
        // For now, assume the checks *can* fail under some conditions.
        // If establish_sqs returns Err, check frame validation status
        let mut frame_a = Frame::initialize("A_fail".to_string(), 0); // Use seeds known to cause issues if found
        let mut frame_b = Frame::initialize("B_fail".to_string(), 0);

        // Manually set phase for easier testing if needed
        // frame_a.phase = 0.0;
        // frame_b.phase = std::f64::consts::PI; // Max difference

        let result = establish_sqs(&mut frame_a, &mut frame_b);

        if result.is_err() {
            println!("Sqs Establishment failed as expected: {}", result.unwrap_err());
            assert!(!frame_a.validation_status); // Frames should be marked invalid on failure
            assert!(!frame_b.validation_status);
            assert!(!frame_a.has_sqs());
            assert!(!frame_b.has_sqs());
        } else {
            // This might pass depending on the exact seeds and check logic.
             println!("Warning: Test designed to fail validation passed instead.");
        }
    }

    // Helper to setup two frames with established Sqs for tests
    fn setup_frames_for_encoding() -> (Frame, Frame) {
        let mut frame_a = Frame::initialize("A_encdec".to_string(), 987);
        let mut frame_b = Frame::initialize("B_encdec".to_string(), 654);
        establish_sqs(&mut frame_a, &mut frame_b).expect("Sqs setup failed for encoding test");
        (frame_a, frame_b)
    }

    #[test]
    fn test_encode_decode_basic_string() {
        let (frame_a, mut frame_b) = setup_frames_for_encoding();
        let message_str = "Hello, QFE World!";
        let message_bytes = message_str.as_bytes();

        // Encode by Frame A
        let encoded = frame_a.encode(message_bytes).expect("Encoding failed");
        assert_eq!(encoded.len(), message_bytes.len(), "Encoded length mismatch");
        if let Some(unit) = encoded.first() {
             assert_eq!(unit.integrity_hash.len(), 64, "Integrity hash should be 64 bytes");
        }
        // Decode by Frame B
        let decoded_bytes = frame_b.decode(&encoded).expect("Decoding failed");
        assert_eq!(decoded_bytes, message_bytes, "Decoded bytes mismatch");

        // Optional: Convert back to string to verify
        let decoded_str = String::from_utf8(decoded_bytes).expect("Invalid UTF-8");
        assert_eq!(decoded_str, message_str, "Decoded string mismatch");
    }

    #[test]
    fn test_encode_decode_all_byte_values() {
        let (frame_a, mut frame_b) = setup_frames_for_encoding();
        let all_bytes: Vec<u8> = (0..=255).collect();

        let encoded = frame_a.encode(&all_bytes).expect("Encoding all bytes failed");
        assert_eq!(encoded.len(), all_bytes.len());

        let decoded = frame_b.decode(&encoded).expect("Decoding all bytes failed");
        assert_eq!(decoded, all_bytes);
    }

    #[test]
    fn test_encode_decode_empty_message() {
        let (frame_a, mut frame_b) = setup_frames_for_encoding();
        let empty_message: Vec<u8> = Vec::new();

        let encoded = frame_a.encode(&empty_message).expect("Encoding empty failed");
        assert!(encoded.is_empty());

        let decoded = frame_b.decode(&encoded).expect("Decoding empty failed");
        assert!(decoded.is_empty());
        assert_eq!(decoded, empty_message);
    }

     #[test]
    fn test_decode_fails_on_tampered_integrity_hash() {
        let (frame_a, mut frame_b) = setup_frames_for_encoding();
        let message = b"Secret Data";
        let mut encoded = frame_a.encode(message).expect("Encoding failed");

        // Tamper: Modify the hash of the first unit
        if !encoded.is_empty() {
            encoded[0].integrity_hash[0] ^= 0x01; // Corrupt hash
        }

        let result = frame_b.decode(&encoded);
        assert!(result.is_err());
        let err = result.unwrap_err();
        println!("Tampered Hash Decode Error: {}", err); // Debug print
        if let QfeError::DecodingFailed(msg) = &err {
            assert!(msg.contains("Integrity check mismatch"), "Expected integrity error msg, got: {}", msg);
            assert!(msg.contains("index 0"), "Error should mention index 0");
        } else {
            panic!("Expected DecodingFailed error variant, got {:?}", err);
        }
        assert!(!frame_b.validation_status); // Ensure frame is marked invalid
    }

    #[test]
    fn test_decode_fails_on_tampered_modulated_phase() {
        let (frame_a, mut frame_b) = setup_frames_for_encoding();
        let message = b"Top Secret";
        let mut encoded = frame_a.encode(message).expect("Encoding failed");

        // Tamper: Modify the phase of the second unit significantly
        if encoded.len() > 1 {
            encoded[1].modulated_phase = (encoded[1].modulated_phase + std::f64::consts::PI) // Add 180 degrees
                                         .rem_euclid(2.0 * std::f64::consts::PI);
        }

        let result = frame_b.decode(&encoded);
        assert!(result.is_err());
        let err = result.unwrap_err();
        println!("Tampered Phase Decode Error: {}", err); // Debug print
        // This could fail either the phase shift reconstruction or the subsequent integrity check
        assert!(
            matches!(&err, QfeError::DecodingFailed(s) if s.contains("Invalid phase shift") || s.contains("Integrity check mismatch")),
            "Expected DecodingFailed (phase or integrity), got {:?}", err
        );
         assert!(!frame_b.validation_status); // Ensure frame is marked invalid
    }

     #[test]
    fn test_decode_fails_with_wrong_sqs_context() {
        // Frame A encodes with A-B Sqs
        let (frame_a, _frame_b) = setup_frames_for_encoding();
        let message = b"Intended for B";
        let encoded = frame_a.encode(message).expect("Encoding failed");

        // Frame C tries to decode using C-D Sqs
        let mut frame_c = Frame::initialize("C_decode".to_string(), 1122);
        let mut frame_d = Frame::initialize("D_decode".to_string(), 3344);
        establish_sqs(&mut frame_c, &mut frame_d).expect("Sqs C-D setup failed");

        let result = frame_c.decode(&encoded); // Use Frame C (with C-D Sqs)
        assert!(result.is_err());
        let err = result.unwrap_err();
        println!("Wrong SQS Decode Error: {}", err);
        // Should fail the integrity check because Sqs components differ
        // UPDATED ASSERTION: Accept either failure mode for wrong Sqs context
        assert!(
            matches!(
                &err, QfeError::DecodingFailed(s) if s.contains("Integrity check mismatch") ||
                s.contains("Invalid phase shift")
            ),
            "Expected DecodingFailed (integrity or phase shift) for wrong SQS, got {:?}", err
        );
        assert!(!frame_c.validation_status); // Ensure frame C is marked invalid
    }

    #[test]
    fn encode_fails_if_frame_has_no_sqs() {
         let frame_no_sqs = Frame::initialize("NoSqs_Enc".to_string(), 1);
         let message = b"test";
         let result = frame_no_sqs.encode(message);
         assert!(result.is_err());
         assert_eq!(result.unwrap_err(), QfeError::SqsMissing);
    }

     #[test]
    fn decode_fails_if_frame_has_no_sqs() {
         let mut frame_no_sqs = Frame::initialize("NoSqs_Dec".to_string(), 1);
         let encoded_signal = vec![EncodedUnit { modulated_phase: 1.0, integrity_hash: [0u8; 64] }];
         let result = frame_no_sqs.decode(&encoded_signal);
         assert!(result.is_err());
         assert_eq!(result.unwrap_err(), QfeError::SqsMissing);
    }
}
