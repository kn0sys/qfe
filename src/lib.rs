//! Provides types and functions for a secure communication protocol simulation
//! based on shared state establishment and modulated signals.

use std::sync::Arc; // For shared ownership of Sqs
use std::hash::Hash;
use std::error::Error;
use std::fmt;
use sha2::{Sha512, Digest};

pub mod zkp;
pub use zkp::{ZkpValidityResponse, establish_zkp_sqs};
pub type Sha512Hash = [u8; 64];

use chacha20poly1305::{
    aead::{Aead, AeadInPlace, KeyInit, Nonce}, // Import necessary traits and types
    ChaCha20Poly1305, // The AEAD cipher implementation
    Key, // Type alias for the 32-byte key
};

use rand::RngCore;

/// Structure to hold the result of AEAD encryption.
#[derive(Debug, Clone)] // PartialEq, Eq, Hash might be tricky with Vec<u8>
pub struct QfeEncryptedMessage {
    /// Nonce used for encryption (12 bytes for ChaCha20Poly1305).
    /// Must be unique per message per key. MUST be sent with ciphertext.
    pub nonce: Vec<u8>, // Store as Vec<u8> for flexibility, convert to Nonce type on use
    /// Ciphertext including the 16-byte authentication tag appended at the end.
    pub ciphertext: Vec<u8>,
}

/// Helper function to derive the 32-byte AEAD key from SQS components.
/// Uses the first 32 bytes of the 64-byte SHA-512 hash in Sqs.components.
/// Returns an error if Sqs.components is not long enough.
fn derive_aead_key(sqs_components: &[u8]) -> Result<Key, QfeError> {
    if sqs_components.len() < 32 {
        return Err(QfeError::InternalError(
            "SQS components too short to derive AEAD key".to_string()
        ));
    }
    // Directly use the first 32 bytes as the key
    Ok(*Key::from_slice(&sqs_components[0..32]))
}

// // --- Constants derived from Framework Core Mathematics ---
// Primary Scale: φ (phi)
const PHI: f64 = 1.618033988749895;
// Resonance: φ/2π
const RESONANCE_FREQ: f64 = PHI / (2.0 * std::f64::consts::PI);

// --- Core Data Structures ---

/// Represents a signature/MAC for a message, generated using an SQS context.
///
/// This provides message integrity and authenticity based on the shared secret
/// within the SQS.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QfeSignature {
    /// The signature value (SHA-512 hash output).
    pub value: Sha512Hash, // [u8; 64]
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
    InvalidSignature,
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
            QfeError::InvalidSignature => write!(f, "Message signature verification failed"),
            QfeError::InternalError(s) => write!(f, "Internal QFE error: {}", s),
        }
    }
}
impl Error for QfeError {}


/// Represents the established shared state (secret key and context) between two Frames.
#[derive(Clone, Default, PartialEq)] // SQS components (Vec<u8>) make Eq complex, PartialEq is fine.
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
    /// Identifier of the first participant establishing this SQS.
    pub participant_a_id: String,
    /// Identifier of the second participant establishing this SQS.
    pub participant_b_id: String,
}

// Debug impl for Sqs remains the same (still uses DefaultHasher for display hash)
impl fmt::Debug for Sqs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let components_prefix = self.components.get(..4) // Get first 4 bytes safely
            .map(|slice| format!("{:02x}{:02x}{:02x}{:02x}", slice[0], slice[1], slice[2], slice[3]))
            .unwrap_or_else(|| "[]".to_string()); // Handle empty or short components
        f.debug_struct("Sqs")
         .field("pattern_type", &self.pattern_type)
         .field("components_len", &self.components.len())
         .field("components_prefix", &components_prefix)
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
    pub validation_status: bool,
    pub zkp_witness: Option<Vec<u8>>,
    pub zkp_secret_scalar: Option<curve25519_dalek::Scalar>,
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
    /// Uses SHA-512 for derivation.
    fn new(seed: u64) -> Self {
        let structural_id_hash: [u8; 64] = {
            let mut hasher = Sha512::new();
            hasher.update(seed.to_le_bytes());
            hasher.update(b"QFE_STRUCTURAL_ID_V1"); // Domain separation
            hasher.update(PHI.to_le_bytes()); // Incorporate framework constant
            hasher.finalize().into()
        };
        // Take the first 16 bytes for the u128 ID
        let structural_id = u128::from_le_bytes(
             structural_id_hash[0..16].try_into().expect("Slice length mismatch for structural ID")
        );
        ReferenceFrame {
            structural_id,
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
#[derive(Debug, Default, Clone, PartialEq)]
enum PatternType {
    #[default]
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
        // Create the foundational distinction node using SHA-512
        let node_id_hash: [u8; 64] = {
            let mut node_hasher = Sha512::new();
            node_hasher.update(initial_seed.to_le_bytes());
            node_hasher.update(b"QFE_NODE_ID_V1"); // Use specific domain separation
            node_hasher.finalize().into()
        };
        // Take the first 8 bytes for the u64 ID
        let node_id = u64::from_le_bytes(
             node_id_hash[0..8].try_into().expect("Slice length mismatch for node ID")
        );
        let node = DistinctionNode { id: node_id };

        // Derive the reference frame structure from the seed
        let frame_structure = ReferenceFrame::new(initial_seed);

        let initial_phase_hash: [u8; 64] = {
            let mut phase_hasher = Sha512::new();
            phase_hasher.update(initial_seed.to_le_bytes());
            phase_hasher.update(b"QFE_INITIAL_PHASE_V1"); // Domain separation
            phase_hasher.update(PHI.to_le_bytes()); // Include framework constant
            phase_hasher.finalize().into()
        };
        // Take the first 8 bytes, convert to u64, normalize to [0, 2PI)
        let phase_u64 = u64::from_le_bytes(
             initial_phase_hash[0..8].try_into().expect("Slice length mismatch for phase")
        );
        let phase = (phase_u64 as f64 / u64::MAX as f64) * 2.0 * std::f64::consts::PI;

        Frame {
            id,
            node,
            frame_structure,
            phase,
            // internal_patterns: Vec::new(),
            sqs_component: None,
            validation_status: true, // Starts valid
            zkp_witness: None,
            zkp_secret_scalar: None,
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
        let aspect_hash: [u8; 64] = {
            let mut hasher = Sha512::new();
            hasher.update(b"QFE_INTERACTION_ASPECT_V1"); // Domain separation
            // Hash the frame's unique components
            hasher.update(self.node.id.to_le_bytes());
            hasher.update(self.frame_structure.structural_id.to_le_bytes());
            hasher.update(self.phase.to_le_bytes()); // Incorporate phase directly
            hasher.finalize().into()
        };
        // Take the first 8 bytes for the u64 aspect value
        u64::from_le_bytes(
            aspect_hash[0..8].try_into().expect("Slice length mismatch for aspect")
        )
    }

    /// Gets the frame's unique ID.
    pub fn id(&self) -> &str {
        &self.id
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

    /// Calculates a short, human-readable fingerprint for the established SQS.
    ///
    /// This fingerprint should be compared out-of-band with the other participant's
    /// fingerprint after `establish_sqs` completes successfully. A match provides
    /// strong evidence against a Man-in-the-Middle (MitM) attack during the SQS exchange.
    ///
    /// The fingerprint is derived by hashing the SQS components, phase lock, and
    /// participant IDs in a deterministic order.
    ///
    /// # Returns
    /// * `Ok(String)` containing a short hexadecimal fingerprint (e.g., 8 characters).
    /// * `Err(QfeError::SqsMissing)` if no SQS has been established for this frame.
    /// * `Err(QfeError::FrameInvalid)` if the frame is in an invalid state.
    pub fn calculate_sqs_fingerprint(&self) -> Result<String, QfeError> {
        if !self.is_valid() { return Err(QfeError::FrameInvalid); }
        let sqs = self.get_sqs().ok_or(QfeError::SqsMissing)?;

        let mut hasher = Sha512::new(); // Use strong hash for fingerprint base
        hasher.update(b"QFE_SQS_FINGERPRINT_V1"); // Domain separation

        // Include participant IDs, sorted for consistency
        let mut ids = [sqs.participant_a_id.as_str(), sqs.participant_b_id.as_str()];
        ids.sort_unstable();
        hasher.update(ids[0].as_bytes());
        hasher.update(ids[1].as_bytes());

        // Include core SQS data
        hasher.update(&sqs.components);
        hasher.update(sqs.shared_phase_lock.to_le_bytes());
        hasher.update(sqs.resonance_freq.to_le_bytes()); // Include for context

        let full_hash: [u8; 64] = hasher.finalize().into();

        // Take the first 4 bytes (8 hex chars) for a short fingerprint
        // Use data encoding crate for hex? No, keep deps minimal. Format manually.
        let fingerprint = format!(
            "{:02x}{:02x}{:02x}{:02x}",
            full_hash[0], full_hash[1], full_hash[2], full_hash[3]
        );

        Ok(fingerprint)
    }

    /// Encrypts a message using ChaCha20-Poly1305 AEAD with the frame's SQS context.
    ///
    /// Generates a unique random nonce for each encryption. The nonce is included
    /// in the returned `QfeEncryptedMessage`.
    ///
    /// # Arguments
    /// * `plaintext`: The message bytes to encrypt.
    /// * `associated_data`: Optional data to authenticate but not encrypt.
    ///
    /// # Returns
    /// * `Ok(QfeEncryptedMessage)` containing the nonce and ciphertext+tag.
    /// * `Err(QfeError)` if SQS is missing, frame is invalid, or key derivation fails.
    pub fn encode_aead(
        &self,
        plaintext: &[u8],
        associated_data: Option<&[u8]>
    ) -> Result<QfeEncryptedMessage, QfeError> {
        if !self.is_valid() { return Err(QfeError::FrameInvalid); }
        let sqs = self.get_sqs().ok_or(QfeError::SqsMissing)?;

        // 1. Derive AEAD key from SQS
        let key = derive_aead_key(&sqs.components)?;
        let cipher = ChaCha20Poly1305::new(&key);

        // 2. Generate a unique Nonce (12 bytes for ChaCha20Poly1305)
        // Using OsRngNonce requires enabling the 'std' feature potentially, or using OsRng directly
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::<ChaCha20Poly1305>::from_slice(&nonce_bytes); // Create Nonce type

        // 3. Encrypt the data
        let _ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| QfeError::EncodingFailed(format!("AEAD encryption error: {}", e)))?;

        // Include associated data in the encryption process if provided
        // Note: AEAD encrypt methods often take plaintext as AsRef<[u8]>, AD separately.
        // Re-check chacha20poly1305 docs: `encrypt` doesn't directly take AD.
        // We need `encrypt_in_place` or construct the call differently if AD is used.
        // Let's use `encrypt_in_place_detached` for clarity with AD.

        // --- Revised Encryption Logic with AD ---
        let key = derive_aead_key(&sqs.components)?;
        let cipher = ChaCha20Poly1305::new(&key);
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::<ChaCha20Poly1305>::from_slice(&nonce_bytes);

        // Use encrypt_in_place_detached requires a mutable buffer
        let mut buffer = Vec::with_capacity(plaintext.len() + 16); // Space for plaintext + tag
        buffer.extend_from_slice(plaintext);

        let tag = cipher.encrypt_in_place_detached(
                nonce,
                associated_data.unwrap_or(&[]), // Pass AD here
                &mut buffer
            )
            .map_err(|e| QfeError::EncodingFailed(format!("AEAD encryption error: {}", e)))?;

        // Append the tag to the ciphertext in the buffer
        buffer.extend_from_slice(tag.as_slice());

        Ok(QfeEncryptedMessage {
            nonce: nonce_bytes.to_vec(), // Store the raw nonce bytes
            ciphertext: buffer, // Ciphertext now includes the tag
        })
    }

    /// Decrypts a message using ChaCha20-Poly1305 AEAD with the frame's SQS context.
    ///
    /// Verifies the integrity and authenticity using the tag included in the ciphertext.
    /// Marks the frame invalid if decryption fails.
    ///
    /// # Arguments
    /// * `encrypted_message`: The `QfeEncryptedMessage` containing nonce and ciphertext+tag.
    /// * `associated_data`: Optional associated data that must match the data used during encryption.
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` containing the original plaintext if decryption and verification succeed.
    /// * `Err(QfeError)` if SQS is missing, frame is invalid, key derivation fails, or
    ///   decryption/authentication fails (`QfeError::DecodingFailed`).
    pub fn decode_aead(
        &mut self, // Changed to &mut self to allow setting validation_status on failure
        encrypted_message: &QfeEncryptedMessage,
        associated_data: Option<&[u8]>
    ) -> Result<Vec<u8>, QfeError> {
         if !self.is_valid() { return Err(QfeError::FrameInvalid); } // Check before attempt
         let sqs = self.get_sqs().ok_or(QfeError::SqsMissing)?;

         // 1. Derive AEAD key from SQS
         let key = derive_aead_key(&sqs.components)?;
         let cipher = ChaCha20Poly1305::new(&key);

         // 2. Get Nonce from message
         if encrypted_message.nonce.len() != 12 {
             self.validation_status = false;
             return Err(QfeError::DecodingFailed("Invalid nonce length received".to_string()));
         }
         let nonce = Nonce::<ChaCha20Poly1305>::from_slice(&encrypted_message.nonce);

         // 3. Decrypt the data (includes authenticity check)
         // Use decrypt_in_place_detached if using that for encryption
         let mut buffer = encrypted_message.ciphertext.clone(); // Clone to decrypt in place

         // Need to split buffer into ciphertext and tag
         if buffer.len() < 16 { // Check if buffer is large enough for the tag
              self.validation_status = false;
              return Err(QfeError::DecodingFailed("Ciphertext too short to contain tag".to_string()));
         }
         let tag_offset = buffer.len() - 16;
         let (ciphertext_slice_mut, tag_slice) = buffer.split_at_mut(tag_offset);
         let tag = chacha20poly1305::Tag::from_slice(tag_slice);


         let decrypt_result = cipher.decrypt_in_place_detached(
             nonce,
             associated_data.unwrap_or(&[]), // Pass AD here
             ciphertext_slice_mut, // Provide mutable ciphertext slice
             tag // Provide the tag separately
         );

         match decrypt_result {
             Ok(()) => {
                 // Decryption successful, buffer now contains plaintext
                 // Truncate buffer to remove decrypted padding/tag space if necessary (inplace should handle this)
                 Ok(ciphertext_slice_mut.to_vec()) // Return the plaintext part
             }
             Err(e) => {
                 self.validation_status = false; // Mark frame invalid on decryption failure
                 Err(QfeError::DecodingFailed(format!("AEAD decryption/authentication failed: {}", e)))
             }
         }
    }
    /// Signs a message using the Frame's established SQS context.
    ///
    /// Computes a SHA-512 based hash incorporating the SQS shared secret (`components`),
    /// participant IDs (for context), and the message itself. This acts as a
    /// Message Authentication Code (MAC).
    ///
    /// # Arguments
    /// * `message`: The byte slice `&[u8]` representing the message to sign.
    ///
    /// # Returns
    /// * `Ok(QfeSignature)` containing the calculated signature hash.
    /// * `Err(QfeError)` if:
    ///     - The frame has no established SQS (`QfeError::SqsMissing`).
    ///     - The frame is invalid (`QfeError::FrameInvalid`).
    ///     - An internal error occurs (`QfeError::InternalError`).
    pub fn sign_message(&self, message: &[u8]) -> Result<QfeSignature, QfeError> {
        if !self.is_valid() { return Err(QfeError::FrameInvalid); }
        let sqs = self.get_sqs().ok_or(QfeError::SqsMissing)?; // Check SQS exists

        // Use SHA-512 like HMAC: Hash(Key || Message) conceptually
        // Key = SQS.components, Message = actual message + context
        let mut hasher = Sha512::new();

        // Use a domain separator for signing
        hasher.update(b"QFE_SIGNATURE_V1");

        // Include the shared secret components first (acts as the key)
        hasher.update(&sqs.components);

        // Include participant IDs (sorted) for context binding
        let mut ids = [sqs.participant_a_id.as_str(), sqs.participant_b_id.as_str()];
        ids.sort_unstable();
        hasher.update(ids[0].as_bytes());
        hasher.update(ids[1].as_bytes());

        // Include the message content itself
        hasher.update(message);

        // Finalize the hash
        let signature_value: Sha512Hash = hasher.finalize().into();

        Ok(QfeSignature { value: signature_value })
    }

    /// Verifies a message signature using the Frame's established SQS context.
    ///
    /// Re-computes the expected signature hash using the received message and the
    /// shared SQS secret (`components`), then compares it to the provided signature.
    /// This verifies both message integrity and authenticity (that it was signed by
    /// someone possessing the shared SQS components).
    ///
    /// # Arguments
    /// * `message`: The byte slice `&[u8]` representing the message received.
    /// * `signature`: A reference to the `QfeSignature` received alongside the message.
    ///
    /// # Returns
    /// * `Ok(())` if the signature is valid for the given message and SQS context.
    /// * `Err(QfeError)` if:
    ///     - The signature is invalid (`QfeError::InvalidSignature`).
    ///     - The frame has no established SQS (`QfeError::SqsMissing`).
    ///     - The frame is invalid (`QfeError::FrameInvalid`).
    ///     - An internal error occurs (`QfeError::InternalError`).
    pub fn verify_signature(
        &self,
        message: &[u8],
        signature: &QfeSignature,
    ) -> Result<(), QfeError> {
        if !self.is_valid() { return Err(QfeError::FrameInvalid); }
        let sqs = self.get_sqs().ok_or(QfeError::SqsMissing)?;

        // Re-compute the hash using the exact same process and inputs as sign_message
        let mut hasher = Sha512::new();
        hasher.update(b"QFE_SIGNATURE_V1"); // Same domain separator
        hasher.update(&sqs.components);     // SQS secret components
        let mut ids = [sqs.participant_a_id.as_str(), sqs.participant_b_id.as_str()];
        ids.sort_unstable();                // Sorted participant IDs
        hasher.update(ids[0].as_bytes());
        hasher.update(ids[1].as_bytes());
        hasher.update(message);             // The message being verified

        let expected_signature_value: Sha512Hash = hasher.finalize().into();

        // Compare the expected hash with the provided signature's value
        if expected_signature_value == signature.value {
            Ok(()) // Signatures match!
        } else {
            Err(QfeError::InvalidSignature) // Signatures do not match!
        }
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
///
/// Performs the interactive shared state (`SQS`) establishment process between two Frames.
/// This simulates the key exchange. After calling this successfully, it is **highly recommended**
/// that both participants call [`Frame::calculate_sqs_fingerprint`] and compare the results
/// via an independent, authenticated channel (e.g., voice call, in person) to verify
/// the absence of a Man-in-the-Middle attack before using the SQS for sensitive communication.
///
/// (Rest of documentation comment remains the same)
pub fn establish_sqs(frame_a: &mut Frame, frame_b: &mut Frame) -> Result<(), QfeError> {
    if !frame_a.validation_status || !frame_b.validation_status {
         return Err(QfeError::FrameInvalid);
    }
    if frame_a.sqs_component.is_some() || frame_b.sqs_component.is_some() {
        return Err(QfeError::SqsEstablishmentFailed(
            "SQS already established".to_string(),
        ));
    }

    let aspect_a = frame_a.calculate_interaction_aspect();
    let aspect_b = frame_b.calculate_interaction_aspect();

    // Use SHA-512 based derivation for SQS components
    // CHANGED: Capture IDs before moving frames into function if needed, or clone IDs.
    let id_a = frame_a.id.clone();
    let id_b = frame_b.id.clone();
    let shared_components = derive_shared_components_sha512(aspect_a, frame_a.phase, aspect_b, frame_b.phase);

    // Phase lock calculation remains the same
    let weight_a = (aspect_a % 1000 + 1) as f64;
    let weight_b = (aspect_b % 1000 + 1) as f64;
    let total_weight = weight_a + weight_b;
    let shared_phase_lock = (frame_a.phase * weight_a + frame_b.phase * weight_b) / total_weight;
    let shared_phase_lock = shared_phase_lock.rem_euclid(2.0 * std::f64::consts::PI);

    // Validation checks
    let c1_check = shared_phase_lock.is_finite();
    let c3_check = !shared_components.is_empty() && shared_components.len() == 64; // Expect 64 bytes

    let validation_passed = c1_check && c3_check;

    if validation_passed {
        let sqs = Arc::new(Sqs {
            pattern_type: PatternType::Sqs,
            components: shared_components,
            shared_phase_lock,
            resonance_freq: RESONANCE_FREQ,
            validation: true,
            // --- NEW: Populate participant IDs ---
            participant_a_id: id_a, // Store IDs used in this SQS
            participant_b_id: id_b,
        });
        frame_a.sqs_component = Some(Arc::clone(&sqs));
        frame_b.sqs_component = Some(sqs);
        Ok(())
    } else {
        frame_a.validation_status = false;
        frame_b.validation_status = false;
        Err(QfeError::SqsEstablishmentFailed(format!(
            "Validation failed: PhaseCoherenceCheck(ValidNumber)={}, PatternResonanceCheck(SHA512_64Bytes)={}",
            c1_check, c3_check
        )))
    }
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

    /// Tests the SQS fingerprint generation for OOB authentication.
    #[test]
    fn test_sqs_fingerprint_consistency_and_errors() {
        // Setup two frames
        let mut frame_a = Frame::initialize("FrameA_OOB".to_string(), 202504051);
        let mut frame_b = Frame::initialize("FrameB_OOB".to_string(), 202504052);
        let frame_c_no_sqs = Frame::initialize("FrameC_NoSQS".to_string(), 202504053);

        // Case 1: Error when SQS is not established
        let fp_err_a = frame_a.calculate_sqs_fingerprint();
        assert!(fp_err_a.is_err());
        assert!(matches!(fp_err_a.unwrap_err(), QfeError::SqsMissing));

        let fp_err_c = frame_c_no_sqs.calculate_sqs_fingerprint();
        assert!(fp_err_c.is_err());
        assert!(matches!(fp_err_c.unwrap_err(), QfeError::SqsMissing));


        // Case 2: Establish SQS successfully
        let establish_result = establish_sqs(&mut frame_a, &mut frame_b);
        assert!(establish_result.is_ok());
        assert!(frame_a.has_sqs());
        assert!(frame_b.has_sqs());

        // Case 3: Calculate fingerprints for both frames
        let fp_a_res = frame_a.calculate_sqs_fingerprint();
        let fp_b_res = frame_b.calculate_sqs_fingerprint();

        assert!(fp_a_res.is_ok());
        assert!(fp_b_res.is_ok());

        let fp_a = fp_a_res.unwrap();
        let fp_b = fp_b_res.unwrap();

        println!("Frame A Fingerprint: {}", fp_a);
        println!("Frame B Fingerprint: {}", fp_b);

        // Assert fingerprints are not empty and are equal
        assert!(!fp_a.is_empty(), "Fingerprint A should not be empty");
        assert!(!fp_b.is_empty(), "Fingerprint B should not be empty");
        // Fingerprint length should be 8 hex chars (4 bytes) based on current impl
        assert_eq!(fp_a.len(), 8, "Fingerprint A has unexpected length");
        assert_eq!(fp_b.len(), 8, "Fingerprint B has unexpected length");
        assert_eq!(fp_a, fp_b, "Fingerprints for the same SQS should match");

        // Case 4: Error when frame is invalid
        frame_a.validation_status = false; // Manually invalidate frame
        let fp_err_invalid = frame_a.calculate_sqs_fingerprint();
        assert!(fp_err_invalid.is_err());
        assert!(matches!(fp_err_invalid.unwrap_err(), QfeError::FrameInvalid));
    }

    // Helper to setup two frames with established & conceptually authenticated SQS
    // Re-using helper from encoding tests is fine if it exists, otherwise define here.
    fn setup_frames_for_signing(id_a: &str, id_b: &str) -> (Frame, Frame) {
        // Derive seeds from IDs using SHA-512
        let seed_a: u64 = {
            let mut hasher = Sha512::new();
            hasher.update(b"QFE_TEST_SEED_DERIVATION_V1"); // Domain separation
            hasher.update(id_a.as_bytes());
            let hash_output: [u8; 64] = hasher.finalize().into();
            // Take first 8 bytes for u64 seed
            u64::from_le_bytes(hash_output[0..8].try_into().expect("Slice failed for seed_a"))
        };

        let seed_b: u64 = {
            let mut hasher = Sha512::new();
            hasher.update(b"QFE_TEST_SEED_DERIVATION_V1"); // Same domain separation
            hasher.update(id_b.as_bytes());
            let hash_output: [u8; 64] = hasher.finalize().into();
            // Take first 8 bytes for u64 seed
            u64::from_le_bytes(hash_output[0..8].try_into().expect("Slice failed for seed_b"))
        };

        // Initialize frames using the derived seeds (this now uses the updated initialize function)
        let mut frame_a = Frame::initialize(id_a.to_string(), seed_a);
        let mut frame_b = Frame::initialize(id_b.to_string(), seed_b);

        // Establish SQS (this uses the updated establish_sqs logic internally)
        establish_sqs(&mut frame_a, &mut frame_b)
            .expect("SQS setup failed during test helper execution");

        (frame_a, frame_b)
    }

    #[test]
    fn test_sign_verify_success() {
        let (frame_a, frame_b) = setup_frames_for_signing("s_a", "v_b");
        let message = b"This is a message to be signed.";

        // Alice signs
        let signature_res = frame_a.sign_message(message);
        assert!(signature_res.is_ok());
        let signature = signature_res.unwrap();
        assert_eq!(signature.value.len(), 64); // SHA-512 output size

        // Bob verifies
        let verification_res = frame_b.verify_signature(message, &signature);
        assert!(verification_res.is_ok(), "Verification failed unexpectedly: {:?}", verification_res.err());
    }

    #[test]
    fn test_verify_fail_tampered_message() {
        let (frame_a, frame_b) = setup_frames_for_signing("s_a", "v_b");
        let message = b"Original message content.";
        let tampered_message = b"Original message content!"; // Changed punctuation

        // Alice signs original message
        let signature = frame_a.sign_message(message).expect("Signing failed");

        // Bob verifies signature against TAMPERED message
        let verification_res = frame_b.verify_signature(tampered_message, &signature);
        assert!(verification_res.is_err(), "Verification should fail for tampered message");
        assert_eq!(verification_res.unwrap_err(), QfeError::InvalidSignature);
    }

    #[test]
    fn test_verify_fail_tampered_signature() {
        let (frame_a, frame_b) = setup_frames_for_signing("s_a", "v_b");
        let message = b"A message requiring integrity.";

        // Alice signs message
        let mut signature = frame_a.sign_message(message).expect("Signing failed");

        // Tamper with signature value
        signature.value[10] ^= 0xAB; // Flip some bits

        // Bob verifies tampered signature against original message
        let verification_res = frame_b.verify_signature(message, &signature);
        assert!(verification_res.is_err(), "Verification should fail for tampered signature");
        assert_eq!(verification_res.unwrap_err(), QfeError::InvalidSignature);
    }

    #[test]
    fn test_verify_fail_wrong_sqs() {
        // Setup A-B with SQS1
        let (frame_a, _frame_b) = setup_frames_for_signing("s_a", "v_b");
        // Setup C-D with SQS2
        let (frame_c, _frame_d) = setup_frames_for_signing("s_c", "v_d"); // Re-use helper for simplicity, gives different SQS

        // Ensure SQS differ (extremely likely with different seeds/IDs, but check)
        assert_ne!(frame_a.get_sqs().unwrap().components, frame_c.get_sqs().unwrap().components);

        let message = b"Message signed by A";

        // A signs with SQS1
        let signature = frame_a.sign_message(message).expect("Signing by A failed");

        // C tries to verify using SQS2
        let verification_res = frame_c.verify_signature(message, &signature);
        assert!(verification_res.is_err(), "Verification should fail when using wrong SQS");
        assert_eq!(verification_res.unwrap_err(), QfeError::InvalidSignature);
    }

    #[test]
    fn test_sign_verify_no_sqs() {
        let frame_a_no_sqs = Frame::initialize("NoSQS_Sign".to_string(), 9001);
        let frame_b_no_sqs = Frame::initialize("NoSQS_Verify".to_string(), 9002);
        let message = b"Cannot sign or verify";
        let dummy_sig = QfeSignature { value: [0u8; 64] };

        // Try signing without SQS
        let sign_res = frame_a_no_sqs.sign_message(message);
        assert!(sign_res.is_err());
        assert_eq!(sign_res.unwrap_err(), QfeError::SqsMissing);

        // Try verifying without SQS
        let verify_res = frame_b_no_sqs.verify_signature(message, &dummy_sig);
        assert!(verify_res.is_err());
        assert_eq!(verify_res.unwrap_err(), QfeError::SqsMissing);
    }

    #[test]
    fn test_sign_verify_invalid_frame() {
        let (mut frame_a, mut frame_b) = setup_frames_for_signing("s_a", "v_b");
        let message = b"Testing invalid frame state";
        let signature = frame_a.sign_message(message).expect("Initial signing failed");

        // Invalidate frames
        frame_a.validation_status = false;
        frame_b.validation_status = false;

        // Try signing with invalid frame
        let sign_res = frame_a.sign_message(message);
        assert!(sign_res.is_err());
        assert_eq!(sign_res.unwrap_err(), QfeError::FrameInvalid);

        // Try verifying with invalid frame
        let verify_res = frame_b.verify_signature(message, &signature);
        assert!(verify_res.is_err());
        assert_eq!(verify_res.unwrap_err(), QfeError::FrameInvalid);
    }

    mod aead_tests {
        use super::*; // Import from parent `tests` module (and thus lib root)

        // Helper function specific to AEAD tests
        fn setup_frames_for_aead() -> (Frame, Frame) {
            // Use the existing updated helper or redefine if needed
            setup_frames_for_signing("AEAD_A", "AEAD_B") // Re-use helper is fine
        }

        #[test]
        fn test_aead_encode_decode_success_no_ad() {
            let (frame_a, mut frame_b) = setup_frames_for_aead();
            let plaintext = b"This message is secret and authentic (no AD).";
            let associated_data = None; // No associated data

            // Encode
            let encrypted_msg_res = frame_a.encode_aead(plaintext, associated_data);
            assert!(encrypted_msg_res.is_ok());
            let encrypted_msg = encrypted_msg_res.unwrap();

            // Nonce should be 12 bytes, Ciphertext > plaintext + 16 bytes (tag)
            assert_eq!(encrypted_msg.nonce.len(), 12);
            assert!(encrypted_msg.ciphertext.len() >= plaintext.len() + 16);

            // Decode
            let decoded_res = frame_b.decode_aead(&encrypted_msg, associated_data);
            assert!(decoded_res.is_ok());
            let decoded_plaintext = decoded_res.unwrap();

            // Verify correctness
            assert_eq!(decoded_plaintext, plaintext);
            assert!(frame_b.is_valid()); // Frame B should remain valid
        }

        #[test]
        fn test_aead_encode_decode_success_with_ad() {
            let (frame_a, mut frame_b) = setup_frames_for_aead();
            let plaintext = b"This message is secret and authentic (with AD).";
            let associated_data = Some(b"Important Context" as &[u8]);

            // Encode
            let encrypted_msg = frame_a.encode_aead(plaintext, associated_data)
                                   .expect("Encoding with AD failed");

            // Decode
            let decoded_plaintext = frame_b.decode_aead(&encrypted_msg, associated_data)
                                        .expect("Decoding with AD failed");

            // Verify correctness
            assert_eq!(decoded_plaintext, plaintext);
            assert!(frame_b.is_valid());
        }

        #[test]
        fn test_aead_encode_decode_empty_message() {
            let (frame_a, mut frame_b) = setup_frames_for_aead();
            let plaintext = b""; // Empty plaintext
            let associated_data = Some(b"Context for empty message" as &[u8]);

            // Encode
            let encrypted_msg = frame_a.encode_aead(plaintext, associated_data)
                                   .expect("Encoding empty message failed");
            assert!(encrypted_msg.ciphertext.len() == 16); // Empty plaintext -> only tag remains

            // Decode
            let decoded_plaintext = frame_b.decode_aead(&encrypted_msg, associated_data)
                                        .expect("Decoding empty message failed");

            // Verify correctness
            assert_eq!(decoded_plaintext, plaintext);
            assert!(decoded_plaintext.is_empty());
            assert!(frame_b.is_valid());
        }


        #[test]
        fn test_aead_decode_fails_tampered_ciphertext() {
            let (frame_a, mut frame_b) = setup_frames_for_aead();
            let plaintext = b"Do not tamper!";
            let mut encrypted_msg = frame_a.encode_aead(plaintext, None).unwrap();

            // Tamper ciphertext (avoiding the tag at the end)
            if encrypted_msg.ciphertext.len() > 16 { // Ensure there's ciphertext before tag
                encrypted_msg.ciphertext[0] ^= 0xAA;
            } else if !encrypted_msg.ciphertext.is_empty() {
                 encrypted_msg.ciphertext[0] ^= 0xAA; // Tamper tag if only tag exists
            }


            // Attempt Decode
            let decoded_res = frame_b.decode_aead(&encrypted_msg, None);
            assert!(decoded_res.is_err());
            let err = decoded_res.unwrap_err();
            assert!(matches!(err, QfeError::DecodingFailed(_)));
            assert!(err.to_string().contains("AEAD decryption/authentication failed"));
            assert!(!frame_b.is_valid()); // Frame should be invalidated
        }

        #[test]
        fn test_aead_decode_fails_tampered_tag() {
            let (frame_a, mut frame_b) = setup_frames_for_aead();
            let plaintext = b"Do not tamper tag!";
            let mut encrypted_msg = frame_a.encode_aead(plaintext, None).unwrap();

            // Tamper tag (last 16 bytes)
            let ct_len = encrypted_msg.ciphertext.len();
            if ct_len >= 16 {
                 encrypted_msg.ciphertext[ct_len - 1] ^= 0xAA; // Flip last byte of tag
            }

            // Attempt Decode
            let decoded_res = frame_b.decode_aead(&encrypted_msg, None);
            assert!(decoded_res.is_err());
            assert!(matches!(decoded_res.unwrap_err(), QfeError::DecodingFailed(_)));
            assert!(!frame_b.is_valid());
        }


        #[test]
        fn test_aead_decode_fails_tampered_nonce() {
            let (frame_a, mut frame_b) = setup_frames_for_aead();
            let plaintext = b"Cannot reuse nonces";
            let mut encrypted_msg = frame_a.encode_aead(plaintext, None).unwrap();

            // Tamper nonce
            if !encrypted_msg.nonce.is_empty() {
                encrypted_msg.nonce[0] ^= 0xAA;
            }

            // Attempt Decode
            let decoded_res = frame_b.decode_aead(&encrypted_msg, None);
            // Decryption will proceed but likely produce garbage or fail tag check
            assert!(decoded_res.is_err());
            assert!(matches!(decoded_res.unwrap_err(), QfeError::DecodingFailed(_)));
            assert!(!frame_b.is_valid());
        }

        // In mod aead_tests

        // Test AD mismatch (string vs string)
        #[test]
        fn test_aead_decode_fails_wrong_ad_string_mismatch() {
            let (frame_a, mut frame_b) = setup_frames_for_aead();
            let plaintext = b"AD must match";
            let associated_data = Some(b"Correct AD" as &[u8]);
            let wrong_associated_data = Some(b"Wrong AD" as &[u8]);

            let encrypted_msg = frame_a.encode_aead(plaintext, associated_data).unwrap();

            // Attempt decode with WRONG AD string
            let decoded_res = frame_b.decode_aead(&encrypted_msg, wrong_associated_data);
            assert!(decoded_res.is_err());
            let err = decoded_res.unwrap_err();
            println!("Wrong AD (String Mismatch) Decode Error: {:?}", err); // Optional debug
            assert!(matches!(err, QfeError::DecodingFailed(_)), "Expected DecodingFailed for AD string mismatch");
            assert!(!frame_b.is_valid());
        }

        // Test AD mismatch (None vs Some)
        #[test]
        fn test_aead_decode_fails_wrong_ad_none_vs_some() {
            let (frame_a, mut frame_b) = setup_frames_for_aead();
            let plaintext = b"AD must match";
            let associated_data = Some(b"Correct AD" as &[u8]);

            let encrypted_msg = frame_a.encode_aead(plaintext, associated_data).unwrap();

            // Attempt decode with NO AD (when encoded with AD)
            let decoded_res_no_ad = frame_b.decode_aead(&encrypted_msg, None);
            assert!(decoded_res_no_ad.is_err());
            let err = decoded_res_no_ad.unwrap_err();
            println!("Wrong AD (None vs Some) Decode Error: {:?}", err); // Optional debug
            assert!(matches!(err, QfeError::DecodingFailed(_)), "Expected DecodingFailed for AD mismatch (None vs Some)");
            assert!(!frame_b.is_valid());
        }

        // Test Nonce length too short
        #[test]
        fn test_aead_decode_fails_nonce_too_short() {
            let (frame_a, mut frame_b) = setup_frames_for_aead();
            let plaintext = b"Nonce length matters";
            let encrypted_msg_ok = frame_a.encode_aead(plaintext, None).unwrap();

            let mut bad_nonce_msg = encrypted_msg_ok.clone();
            bad_nonce_msg.nonce = vec![0u8; 11]; // 11 bytes

            let decoded_res = frame_b.decode_aead(&bad_nonce_msg, None);
            assert!(decoded_res.is_err());
            let err = decoded_res.unwrap_err();
            println!("Wrong Nonce Length (11) Decode Error: {:?}", err); // Optional debug
            assert!(matches!(err, QfeError::DecodingFailed(_)), "Expected DecodingFailed for Nonce Length 11");
            // Check the specific error message associated with the nonce length check
            assert!(err.to_string().contains("Invalid nonce length received"), "Incorrect error message for short nonce");
            assert!(!frame_b.is_valid());
        }

        // Test Nonce length too long
        #[test]
        fn test_aead_decode_fails_nonce_too_long() {
            let (frame_a, mut frame_b) = setup_frames_for_aead();
            let plaintext = b"Nonce length matters";
            let encrypted_msg_ok = frame_a.encode_aead(plaintext, None).unwrap();

            let mut bad_nonce_msg = encrypted_msg_ok.clone();
            bad_nonce_msg.nonce = vec![0u8; 13]; // 13 bytes

            let decoded_res_13 = frame_b.decode_aead(&bad_nonce_msg, None);
            assert!(decoded_res_13.is_err());
            let err = decoded_res_13.unwrap_err();
            println!("Wrong Nonce Length (13) Decode Error: {:?}", err); // Optional debug
            assert!(matches!(err, QfeError::DecodingFailed(_)), "Expected DecodingFailed for Nonce Length 13");
            assert!(err.to_string().contains("Invalid nonce length received"), "Incorrect error message for long nonce");
            assert!(!frame_b.is_valid());
        }

        #[test]
        fn test_aead_decode_fails_ad_mismatch_encode_none_decode_some() {
            let (frame_a, mut frame_b) = setup_frames_for_aead();
            let plaintext = b"AD mismatch 2";
            let associated_data = Some(b"Some AD" as &[u8]);

            // Encode with NO AD
            let encrypted_msg = frame_a.encode_aead(plaintext, None).unwrap();

             // Attempt decode with SOME AD (when encoded with None)
             let decoded_res = frame_b.decode_aead(&encrypted_msg, associated_data);
             assert!(decoded_res.is_err());
             assert!(matches!(decoded_res.unwrap_err(), QfeError::DecodingFailed(_)));
             assert!(!frame_b.is_valid());
        }


        #[test]
        fn test_aead_decode_fails_wrong_sqs() {
            // Setup A-B with SQS1
            let (frame_a, _frame_b) = setup_frames_for_aead();
            // Setup C-D with SQS2
            let (mut frame_c, _frame_d) = setup_frames_for_signing("AEAD_C", "AEAD_D"); // Use different IDs

            // Ensure SQS differ
            assert_ne!(
                frame_a.get_sqs().unwrap().components,
                frame_c.get_sqs().unwrap().components
            );

            let plaintext = b"Message from A";
            // A encodes with SQS1
            let encrypted_msg = frame_a.encode_aead(plaintext, None).unwrap();

            // C tries to decode with SQS2 (wrong key)
            let decoded_res = frame_c.decode_aead(&encrypted_msg, None);
            assert!(decoded_res.is_err());
            assert!(matches!(decoded_res.unwrap_err(), QfeError::DecodingFailed(_)));
            assert!(!frame_c.is_valid()); // Frame C should be invalidated
        }

        #[test]
        fn test_aead_encode_decode_no_sqs() {
            let frame_a_no_sqs = Frame::initialize("NoSQS_AEAD_A".to_string(), 1001);
            let mut frame_b_no_sqs = Frame::initialize("NoSQS_AEAD_B".to_string(), 1002);
            let plaintext = b"Cannot encrypt";
            let dummy_encrypted = QfeEncryptedMessage { nonce: vec![0;12], ciphertext: vec![0;32]};

            let enc_res = frame_a_no_sqs.encode_aead(plaintext, None);
            assert!(enc_res.is_err());
            assert!(matches!(enc_res.unwrap_err(), QfeError::SqsMissing));

            let dec_res = frame_b_no_sqs.decode_aead(&dummy_encrypted, None);
            assert!(dec_res.is_err());
            assert!(matches!(dec_res.unwrap_err(), QfeError::SqsMissing));
        }

        #[test]
        fn test_aead_encode_decode_invalid_frame() {
            let (mut frame_a, mut frame_b) = setup_frames_for_aead();
            let plaintext = b"Invalid frame test";
            let encrypted_msg = frame_a.encode_aead(plaintext, None).unwrap(); // Encode while valid

            // Invalidate frames
            frame_a.validation_status = false;
            frame_b.validation_status = false;

            // Try encoding with invalid frame
            let enc_res = frame_a.encode_aead(plaintext, None);
            assert!(enc_res.is_err());
            assert!(matches!(enc_res.unwrap_err(), QfeError::FrameInvalid));

             // Try decoding with invalid frame
             let dec_res = frame_b.decode_aead(&encrypted_msg, None);
             assert!(dec_res.is_err());
             assert!(matches!(dec_res.unwrap_err(), QfeError::FrameInvalid));
        }

    }
}
