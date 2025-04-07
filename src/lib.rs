#![crate_name = "qfe"]
//! # Qualitative Frame Entanglement (QFE) - Experimental Secure Communication Framework
//!
//! **Current Version Date:** April 7, 2025
//!
//! **NOTE:** This library is an experimental simulation framework. While it now incorporates
//! standard, vetted cryptographic primitives for core security functions (PQC KEM, HKDF, AEAD),
//! the overall integrated system has not undergone formal security audits. Use with caution
//! and primarily for research or educational purposes.
//!
//! ## Overview
//!
//! The QFE framework provides Rust types and functions to simulate secure communication
//! between participants represented as `Frame` instances. Originally conceived from
//! foundational principles, the implementation has evolved significantly to prioritize robust
//! security using modern cryptographic standards.
//!
//! The core security flow involves:
//! 1.  **Frame Initialization:** Participants create `Frame` instances with unique internal
//!     states derived deterministically from IDs and seeds using SHA-512.
//! 2.  **Post-Quantum Key Establishment:** A shared secret context (`Sqs`) is established
//!     using the `establish_sqs_kem` function. This function simulates key exchange
//!     using the **ML-KEM-1024 (Kyber)** algorithm (a NIST standard for Post-Quantum
//!     Cryptography), providing resistance against known quantum computer attacks for the
//!     initial shared secret.
//! 3.  **Key Derivation:** The **HKDF-SHA512** key derivation function is used with the
//!     ML-KEM shared secret (and contextual information like participant IDs) to derive
//!     robust session keys, including a specific key for authenticated encryption. These
//!     keys are stored within the `Sqs` struct shared between the participant `Frame`s.
//! 4.  **Authenticated Encryption:** Subsequent communication requiring confidentiality,
//!     integrity, and authenticity is handled by the `encode_aead` and `decode_aead`
//!     methods. These methods utilize the **ChaCha20-Poly1305 AEAD** cipher, keyed with
//!     the key derived during the HKDF step. Correct usage requires generating a **unique
//!     nonce** for each message.
//! 5.  **Zero-Knowledge Proofs (Optional):** The library includes experimental ZKP
//!     features within the `zkp` module (e.g., Schnorr's protocol) that can be bound
//!     to the established session context.
//!
//! ## Security Model
//!
//! The security of this revised QFE implementation relies directly on the standard
//! cryptographic hardness assumptions of the underlying primitives:
//! - **ML-KEM-1024:** Security based on the hardness of the Module-LWE problem (Post-Quantum Secure).
//! - **HKDF-SHA512:** Security as a standard Key Derivation Function based on HMAC-SHA512.
//! - **ChaCha20-Poly1305:** Standard AEAD security (Confidentiality, Integrity, Authenticity).
//! - **SHA-512:** Standard hash function properties.
//!
//! **Important Considerations:**
//! - **Nonce Reuse:** Nonce uniqueness *must* be maintained for AEAD security. Reusing a nonce with the same key breaks ChaCha20-Poly1305 security guarantees. The current implementation uses random nonces.
//! - **Key Exchange MitM:** The base ML-KEM protocol requires the public key and ciphertext to be exchanged. This exchange is vulnerable to Man-in-the-Middle (MitM) attacks if performed over an insecure channel. Protection against MitM requires either an underlying authenticated channel or out-of-band verification (e.g., comparing `Sqs` fingerprints after establishment).
//! - **Experimental Status:** As mentioned, the integrated system requires further analysis and review.
//!
//! ## Example Workflow
//!
//! ```rust,no_run
//! use qfe::{Frame, establish_sqs_kem, setup_qfe_pair}; // Assuming setup_qfe_pair uses KEM
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // 1. Setup Frames and SQS using KEM + HKDF
//!     let alice_id = "Alice_Main".to_string();
//!     let bob_id = "Bob_Main".to_string();
//!     let context = "example_session_v1";
//!     // Use setup_qfe_pair (assuming it's updated for KEM and context)
//!     let (mut frame_a, mut frame_b) = setup_qfe_pair(
//!         alice_id.clone(), // Seed for Alice's Frame init
//!         bob_id.clone(),   // Seed for Bob's Frame init
//!         context                 // Context string for HKDF salt
//!     )?;
//!
//!     // (Optional but Recommended) Compare SQS fingerprints out-of-band
//!     let fp_a = frame_a.calculate_sqs_fingerprint()?;
//!     let fp_b = frame_b.calculate_sqs_fingerprint()?;
//!     assert_eq!(fp_a, fp_b, "Fingerprint mismatch indicates potential MitM!");
//!     println!("SQS Fingerprints match: {}", fp_a);
//!
//!     // 2. Alice Encrypts a message for Bob
//!     let plaintext = b"Secret message from Alice!";
//!     let associated_data = Some(b"message_id_001" as &[u8]);
//!     let encrypted_msg = frame_a.encode_aead(plaintext, associated_data)?;
//!     println!("Alice sends encrypted message (len: {})", encrypted_msg.ciphertext.len());
//!
//!     // 3. Bob Decrypts the message
//!     let decoded_plaintext = frame_b.decode_aead(&encrypted_msg, associated_data)?;
//!     println!("Bob received: {}", String::from_utf8_lossy(&decoded_plaintext));
//!     assert_eq!(plaintext.as_slice(), decoded_plaintext.as_slice());
//!
//!     Ok(())
//! }
//! ```

use std::sync::Arc; // For shared ownership of Sqs
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
use pqcrypto::kem::mlkem1024;
use pqcrypto::traits::kem::SharedSecret;
use hkdf::Hkdf;
use rand::RngCore;

const SQS_COMPONENTS_V2_INFO: &[u8] = b"QFE_SQS_COMPONENTS_V2";
const SQS_AEAD_KEY_V1_INFO: &[u8] = b"QFE_AEAD_KEY_V1";
const SQS_SALT_CONTEXT_V1: &[u8] = b"QFE_SQS_SALT_CONTEXT_V1";

/// Structure to hold the result of AEAD encryption.
#[derive(Debug, Clone)] // PartialEq, Eq, Hash might be tricky with Vec<u8>
pub struct QfeEncryptedMessage {
    /// Nonce used for encryption (12 bytes for ChaCha20Poly1305).
    /// Must be unique per message per key. MUST be sent with ciphertext.
    pub nonce: Vec<u8>, // Store as Vec<u8> for flexibility, convert to Nonce type on use
    /// Ciphertext including the 16-byte authentication tag appended at the end.
    pub ciphertext: Vec<u8>,
}

// // --- Constants derived from Framework Core Mathematics ---
// Primary Scale: φ (phi)
const PHI: f64 = 1.618033988749895;

// --- Core Data Structures ---

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
    /// Specific 32-byte key for AEAD (ChaCha20Poly1305) derived via HKDF-SHA512.
    pub aead_key: Key, // Key is [u8; 32]
    pattern_type: PatternType,
    /// The core shared secret (SHA-512 hash output) derived from the interaction.
    // Note: components are now 64 bytes long.
    pub components: Vec<u8>,
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
        let aead_key_prefix = format!("{:02x}{:02x}..", self.aead_key[0], self.aead_key[1]);
        f.debug_struct("Sqs")
         .field("aead_key_prefix", &aead_key_prefix)
         .field("pattern_type", &self.pattern_type)
         .field("components_len", &self.components.len())
         .field("components_prefix", &components_prefix)
         .field("validation", &self.validation)
         .finish()
    }
}


/// Represents a participant Frame (e.g., Sender A, Receiver B).
#[derive(Debug, Clone)]
pub struct Frame {
    id: String,
    sqs_component: Option<Arc<Sqs>>,
    pub validation_status: bool,
    pub zkp_witness: Option<Vec<u8>>,
    pub zkp_secret_scalar: Option<curve25519_dalek::Scalar>,
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
    pub fn initialize(id: String) -> Self {
        Frame {
            id,
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
        let key = &sqs.aead_key;
        let cipher = ChaCha20Poly1305::new(key);

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
        let key = &sqs.aead_key;
        let cipher = ChaCha20Poly1305::new(key);
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
         let key = &sqs.aead_key;
         let cipher = ChaCha20Poly1305::new(key);

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

        let full_hash: [u8; 64] = hasher.finalize().into();

        // Take the first 4 bytes (8 hex chars) for a short fingerprint
        // Use data encoding crate for hex? No, keep deps minimal. Format manually.
        let fingerprint = format!(
            "{:02x}{:02x}{:02x}{:02x}",
            full_hash[0], full_hash[1], full_hash[2], full_hash[3]
        );

        Ok(fingerprint)
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
///   Sets up two Frames (A and B) and establishes a shared state (`SQS`) using ML-KEM.
pub fn setup_qfe_pair(
    id_a: String,
    id_b: String,
    context_string: &str, // Add context string needed for KDF salt
) -> Result<(Frame, Frame), QfeError> {
    let mut frame_a = Frame::initialize(id_a);
    let mut frame_b = Frame::initialize(id_b);
    // Use the new KEM-based establishment function
    establish_sqs_kem(&mut frame_a, &mut frame_b, context_string)?;
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
#[deprecated(since="0.3.0", note="Use establish_sqs_kem for secure key establishment.")]
pub fn establish_sqs(_frame_a: &mut Frame, _frame_b: &mut Frame) -> Result<(), QfeError> {
    // Keep the old implementation here, or just return an error/panic
     Err(QfeError::InternalError("establish_sqs is deprecated, use establish_sqs_kem".to_string()))
    // Or copy the old implementation if needed for compatibility during transition
}

/// Establishes a shared state (SQS) using ML-KEM-1024 key exchange and HKDF.
/// This replaces the previous custom SQS establishment logic.
///
/// Simulates the KEM process:
/// 1. Alice generates a keypair (pk_A, sk_A).
/// 2. Bob uses pk_A to encapsulate -> (ciphertext_C, shared_secret_ss_B).
/// 3. Alice uses sk_A to decapsulate ciphertext_C -> shared_secret_ss_A.
/// 4. Both parties use the shared secret (ss_A == ss_B) as IKM for HKDF-SHA512.
/// 5. HKDF derives the final `Sqs.components`.
///
/// # Arguments
/// * `frame_a` (Alice): Mutable reference to the initiating frame.
/// * `frame_b` (Bob): Mutable reference to the responding frame.
/// * `context_string`: A string for domain separation used in HKDF salt.
///
/// # Returns
/// * `Ok(())` on success, updating both frames with the derived `Arc<Sqs>`.
/// * `Err(QfeError)` on failure (e.g., frame invalid, KEM error, HKDF error).
pub fn establish_sqs_kem(
    frame_a: &mut Frame, // Alice
    frame_b: &mut Frame, // Bob
    context_string: &str // Context for HKDF salt
) -> Result<(), QfeError> {
    if !frame_a.validation_status || !frame_b.validation_status {
        return Err(QfeError::FrameInvalid);
    }
    if frame_a.sqs_component.is_some() || frame_b.sqs_component.is_some() {
        return Err(QfeError::SqsEstablishmentFailed(
            "SQS already established".to_string(),
        ));
    }

    // --- Simulate ML-KEM Exchange ---
    // 1. Alice generates keypair
    // In a real protocol, sk_a is kept secret, pk_a is sent to Bob.
    let (pk_a, sk_a) = mlkem1024::keypair();

    // 2. Bob receives pk_a, encapsulates -> (shared_secret_b, ciphertext)
    // In a real protocol, Bob receives pk_a over the network.
    // Encapsulate returns Result, handle potential errors.
    let (shared_secret_ss_b, ciphertext_c) = mlkem1024::encapsulate(&pk_a);

    // 3. Alice receives ciphertext_c, decapsulates -> shared_secret_a
    // In a real protocol, Alice receives ciphertext_c over the network.
    // Decapsulate returns Result, handle potential errors.
    let shared_secret_ss_a = mlkem1024::decapsulate(&ciphertext_c, &sk_a);

    // --- Verification (Crucial!) ---
    // Check that the shared secrets match. In theory they always should if KEM is correct.
    // The pqcrypto shared secret types should implement PartialEq.
    if shared_secret_ss_a != shared_secret_ss_b {
        // This indicates a critical failure in the KEM library or logic.
        frame_a.validation_status = false;
        frame_b.validation_status = false;
        return Err(QfeError::SqsEstablishmentFailed(
            "CRITICAL: ML-KEM shared secrets mismatch!".to_string()
        ));
    }
    // Use ss_a (or ss_b) as the Input Keying Material (IKM) for HKDF
    let ikm = shared_secret_ss_a.as_bytes();

    // --- HKDF for SQS Components Derivation ---
    // 1. Derive Salt for HKDF
    let mut salt_hasher = Sha512::new();
    salt_hasher.update(SQS_SALT_CONTEXT_V1);
    let mut ids = [frame_a.id().as_bytes(), frame_b.id().as_bytes()];
    ids.sort_unstable();
    salt_hasher.update(ids[0]);
    salt_hasher.update(ids[1]);
    salt_hasher.update(context_string.as_bytes());
    let salt = salt_hasher.finalize();

    // 2. HKDF-Extract using SHA-512 -> Pseudorandom Key (PRK)
    let hk = Hkdf::<Sha512>::new(Some(salt.as_slice()), ikm);

    // 3. HKDF-Expand for SQS components (64 bytes)
    let mut sqs_components_okm = [0u8; 64];
    hk.expand(SQS_COMPONENTS_V2_INFO, &mut sqs_components_okm)
        .map_err(|e| QfeError::SqsEstablishmentFailed(format!("HKDF-Expand error for components: {}", e)))?;

    // 4. HKDF-Expand for AEAD key (32 bytes) using DIFFERENT info
    let mut aead_key_okm = Key::default(); // Key is [u8; 32]
    hk.expand(SQS_AEAD_KEY_V1_INFO, &mut aead_key_okm)
        .map_err(|e| QfeError::SqsEstablishmentFailed(format!("HKDF-Expand error for AEAD key: {}", e)))?;


    // --- Create and Store SQS ---
    let sqs = Arc::new(Sqs {
        pattern_type: PatternType::Sqs,
        components: sqs_components_okm.to_vec(),
        aead_key: aead_key_okm, // Store the derived AEAD key
        validation: true,
        participant_a_id: frame_a.id.clone(),
        participant_b_id: frame_b.id.clone(),
    });

    frame_a.sqs_component = Some(Arc::clone(&sqs));
    frame_b.sqs_component = Some(sqs);

    Ok(())
}

//
// --- Unit Tests ---
#[cfg(test)]
mod tests {
    use super::*;

    // Helper to setup two frames with established & conceptually authenticated SQS
    // Re-using helper from encoding tests is fine if it exists, otherwise define here.
    fn setup_frames_for_signing(id_a: &str, id_b: &str) -> (Frame, Frame) {
        // Initialize frames using the derived seeds (this now uses the updated initialize function)
        let mut frame_a = Frame::initialize(id_a.to_string());
        let mut frame_b = Frame::initialize(id_b.to_string());

        // Establish SQS (this uses the updated establish_sqs logic internally)
        establish_sqs_kem(&mut frame_a, &mut frame_b, "test_context")
            .expect("SQS setup failed during test helper execution");

        (frame_a, frame_b)
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
            let frame_a_no_sqs = Frame::initialize("NoSQS_AEAD_A".to_string());
            let mut frame_b_no_sqs = Frame::initialize("NoSQS_AEAD_B".to_string());
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
