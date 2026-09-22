use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use secp256k1::ecdsa::Signature;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, ecdh::SharedSecret};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Represents a secure package sent over the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurePackage {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>, // AES-GCM Nonce (12 bytes)
    pub timestamp: u64,
    pub signature: Signature,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BroadcastPackage {
    pub text: Vec<u8>,  // The serialized payload (e.g., SignerPayload or TracerPayload)
    pub nonce: Vec<u8>, // Random nonce for uniqueness (12 bytes)
    pub timestamp: u64, // Replay protection
    pub signature: Signature, // Signature over (text || nonce || timestamp)
}

/// Gets current Unix timestamp.
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// derives a 32-byte AES key from (My_SK, Their_PK) using ECDH.
fn derive_aes_key(my_sk: &SecretKey, their_pk: &PublicKey) -> Key<Aes256Gcm> {
    // 1. Compute Shared Secret (ECDH)
    // This creates a point P = my_sk * their_pk
    let shared_point = SharedSecret::new(their_pk, my_sk);

    // 2. Hash it to get a uniform 32-byte key
    // SharedSecret implements AsRef<[u8]>, which gives the X-coordinate hash usually.
    // To be perfectly explicit/safe, we hash the bytes provided by the library.
    let mut hasher = Sha256::new();
    hasher.update(shared_point.as_ref());
    *Key::<Aes256Gcm>::from_slice(hasher.finalize().as_slice())
}

/// Encrypts data using AES-256-GCM + ECDH.
pub(crate) fn encrypt_package(
    sender_sk: &SecretKey,
    receiver_pk: &PublicKey,
    plain_bytes: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    // Returns (Ciphertext, Nonce)

    // 1. Derive Shared Key
    let key = derive_aes_key(sender_sk, receiver_pk);
    let cipher = Aes256Gcm::new(&key);

    //println!("Key: {:?}", key);

    // 2. Generate unique Nonce (96-bits / 12 bytes)
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    //println!("[Crypto] Generated Nonce: {:?}", nonce);

    // 3. Encrypt
    let ciphertext = cipher
        .encrypt(&nonce, plain_bytes)
        .expect("Encryption failure!");

    //println!("[Crypto] Encrypted package ({:?} bytes)", ciphertext);

    (ciphertext, nonce.to_vec())
}

/// Decrypts data using AES-256-GCM + ECDH.
///
/// Returns an error rather than panicking: a node must not be killable by
/// anyone who can send it a wrong-key or tampered package.
pub(crate) fn decrypt_package(
    receiver_sk: &SecretKey,
    sender_pk: &PublicKey,
    ciphertext: &[u8],
    nonce_bytes: &[u8],
) -> Result<Vec<u8>, DecryptError> {
    if nonce_bytes.len() != 12 {
        return Err(DecryptError);
    }

    // 1. Derive SAME Shared Key (ECDH is symmetric: a*B = b*A)
    let key = derive_aes_key(receiver_sk, sender_pk);
    let cipher = Aes256Gcm::new(&key);

    // 2. Decrypt
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext).map_err(|_| DecryptError)
}

/// Authenticated decryption failed: wrong key, wrong nonce, or tampered data.
/// Deliberately carries no detail, so it cannot become an oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecryptError;

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "decryption failed: invalid key or tampered data")
    }
}

impl std::error::Error for DecryptError {}

/// Signs the package contents (Ciphertext + Nonce + Timestamp).
pub(crate) fn sign_package(
    signer_sk: &SecretKey,
    ciphertext: &[u8],
    nonce: &[u8],
    timestamp: u64,
) -> Signature {
    let secp = Secp256k1::new();

    let mut buffer = Vec::new();
    buffer.extend_from_slice(ciphertext);
    buffer.extend_from_slice(nonce); // Must sign nonce too!
    buffer.extend_from_slice(&timestamp.to_be_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let msg = Message::from_digest(hasher.finalize().into());

    secp.sign_ecdsa(msg, signer_sk)
}

/// Verifies origin, integrity, and freshness.
pub(crate) fn verify_package(
    sender_pk: &PublicKey,
    package: &SecurePackage,
    max_age_seconds: u64,
) -> bool {
    let secp = Secp256k1::new();

    // 1. Check Timestamp
    let now = current_timestamp();
    if package.timestamp > now || (now - package.timestamp) > max_age_seconds {
        println!("[Crypto] Message expired or invalid time.");
        return false;
    }

    // 2. Reconstruct Message
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&package.ciphertext);
    buffer.extend_from_slice(&package.nonce);
    buffer.extend_from_slice(&package.timestamp.to_be_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let msg = Message::from_digest(hasher.finalize().into());

    secp.verify_ecdsa(msg, &package.signature, sender_pk)
        .is_ok()
}

pub(crate) fn verify_broadcast_package(
    sender_pk: &PublicKey,
    package: &BroadcastPackage,
    max_age_seconds: u64,
) -> bool {
    let secp = Secp256k1::new();

    // 1. Check Timestamp
    let now = current_timestamp();
    if package.timestamp > now || (now - package.timestamp) > max_age_seconds {
        println!("[Crypto] Message expired or invalid time.");
        return false;
    }

    // 2. Reconstruct Message
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&package.text);
    buffer.extend_from_slice(&package.nonce);
    buffer.extend_from_slice(&package.timestamp.to_be_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let msg = Message::from_digest(hasher.finalize().into());

    secp.verify_ecdsa(msg, &package.signature, sender_pk)
        .is_ok()
}

#[derive(Debug, Clone)]
pub struct IdentityKeyPair {
    sk: SecretKey,     // Private
    pub pk: PublicKey, // Public (Known to everyone)
}

impl IdentityKeyPair {
    pub fn new() -> Self {
        let secp = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut secp256k1::rand::rng());
        IdentityKeyPair { sk, pk }
    }

    pub fn sign_data(&self, text: &[u8], nonce: &[u8], timestamp: u64) -> Signature {
        sign_package(&self.sk, text, nonce, timestamp)
    }

    pub fn verify_data(pk: &PublicKey, package: &SecurePackage) -> bool {
        verify_package(pk, package, 60)
    }

    pub fn verify_broadcast_data(pk: &PublicKey, package: &BroadcastPackage) -> bool {
        verify_broadcast_package(pk, package, 60)
    }
}

#[derive(Debug, Clone)]
pub struct TransportKeyPair {
    sk: SecretKey,     // Private: Only accessible inside crypto.rs
    pub pk: PublicKey, // Public: Accessible everywhere
}

impl TransportKeyPair {
    pub fn new() -> Self {
        let secp = Secp256k1::new();
        let (sk, pk) = secp.generate_keypair(&mut secp256k1::rand::rng());
        TransportKeyPair { sk, pk }
    }

    /// Encrypts data for a specific receiver using this keypair's SecretKey.
    pub fn encrypt_to(&self, receiver_pk: &PublicKey, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // Calls the internal helper function
        encrypt_package(&self.sk, receiver_pk, data)
    }

    /// Decrypts a package sent to this keypair.
    pub fn decrypt_from(
        &self,
        sender_pk: &PublicKey,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        decrypt_package(&self.sk, sender_pk, ciphertext, nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Secp256k1;

    #[test]
    fn test_secure_package_lifecycle() {
        let secp = Secp256k1::new();

        // 1. Setup Identities (Alice and Bob)
        let (alice_sk, alice_pk) = secp.generate_keypair(&mut secp256k1::rand::rng());
        let (bob_sk, bob_pk) = secp.generate_keypair(&mut secp256k1::rand::rng());

        // 2. Prepare Data
        let message = b"Attack at dawn! But securely.";
        let timestamp = current_timestamp();

        // --- ALICE SENDS TO BOB ---

        // 3. Encrypt (Alice uses her SK and Bob's PK)
        // Note: encrypt_package returns (ciphertext, nonce)
        let (ciphertext, nonce) = encrypt_package(&alice_sk, &bob_pk, message);

        // 4. Sign (Alice signs the encrypted package)
        let signature = sign_package(&alice_sk, &ciphertext, &nonce, timestamp);

        // 5. Pack it up
        let package = SecurePackage {
            ciphertext: ciphertext.clone(),
            nonce: nonce.clone(),
            timestamp,
            signature,
        };

        // --- BOB RECEIVES ---

        // 6. Verify Origin & Freshness
        // Bob checks if this really came from Alice and isn't too old (e.g., 60s window)
        let is_valid = verify_package(&alice_pk, &package, 60);
        assert!(
            is_valid,
            "Package signature or timestamp verification failed"
        );

        // 7. Decrypt (Bob uses his SK and Alice's PK)
        let decrypted_bytes =
            decrypt_package(&bob_sk, &alice_pk, &package.ciphertext, &package.nonce)
                .expect("Decryption of a genuine package must succeed");

        // 8. Assert Success
        assert_eq!(
            message.to_vec(),
            decrypted_bytes,
            "Decrypted message does not match original!"
        );
        println!("Crypto Lifecycle Test: SUCCESS");
    }

    #[test]
    fn test_replay_attack_prevention() {
        let secp = Secp256k1::new();
        let (alice_sk, alice_pk) = secp.generate_keypair(&mut secp256k1::rand::rng());
        let (_bob_sk, bob_pk) = secp.generate_keypair(&mut secp256k1::rand::rng());

        let message = b"Old message";

        // Create an OLD timestamp (2 minutes ago)
        let old_timestamp = current_timestamp() - 120;

        let (ciphertext, nonce) = encrypt_package(&alice_sk, &bob_pk, message);
        let signature = sign_package(&alice_sk, &ciphertext, &nonce, old_timestamp);

        let expired_package = SecurePackage {
            ciphertext,
            nonce,
            timestamp: old_timestamp,
            signature,
        };

        // Verification should fail because max_age is 60s
        let is_valid = verify_package(&alice_pk, &expired_package, 60);
        assert!(!is_valid, "Expired package should have been rejected!");
    }

    #[test]
    fn test_tamper_detection() {
        let secp = Secp256k1::new();
        let (alice_sk, alice_pk) = secp.generate_keypair(&mut secp256k1::rand::rng());
        let (bob_sk, bob_pk) = secp.generate_keypair(&mut secp256k1::rand::rng());

        let message = b"Legit message";

        let (mut ciphertext, nonce) = encrypt_package(&alice_sk, &bob_pk, message);

        // ATTACK: Man-in-the-Middle flips a bit in the ciphertext
        ciphertext[0] ^= 0xFF;

        // Even if the signature was valid for the ORIGINAL ciphertext,
        // AES-GCM decryption handles integrity checks on the ciphertext itself.

        // Attempt to decrypt tampered ciphertext: must be a clean error, not a panic.
        let result = decrypt_package(&bob_sk, &alice_pk, &ciphertext, &nonce);

        assert_eq!(
            result,
            Err(DecryptError),
            "Decryption should fail on tampered ciphertext!"
        );
    }

    #[test]
    fn test_wrong_key_fails_without_panicking() {
        let secp = Secp256k1::new();
        let (alice_sk, alice_pk) = secp.generate_keypair(&mut secp256k1::rand::rng());
        let (_bob_sk, bob_pk) = secp.generate_keypair(&mut secp256k1::rand::rng());
        let (mallory_sk, _mallory_pk) = secp.generate_keypair(&mut secp256k1::rand::rng());

        let (ciphertext, nonce) = encrypt_package(&alice_sk, &bob_pk, b"for Bob only");

        // Mallory is not the intended recipient. This must be an error, never a
        // panic - otherwise anyone can crash a node by sending it a package.
        let result = decrypt_package(&mallory_sk, &alice_pk, &ciphertext, &nonce);
        assert_eq!(result, Err(DecryptError));
    }
}
