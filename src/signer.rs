use crate::authority::{ActorKeys, SignerPackage};
use crate::combiner;
use crate::crypto::*;
use crate::network::AuthorityAnchor;
use bincode;
use secp256k1::{Error, PublicKey};
use serde::{Deserialize, Serialize};
use taps_tt::protocol::taps_tt::*;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentPackage {
    pub commitment: Commitment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigmaPackage {
    pub z: Sign,
}

pub struct Signer {
    pub id: usize,

    pub identity_kp: IdentityKeyPair,
    pub transport_kp: TransportKeyPair,

    pub taps_kp: Option<KeyPair>,

    /// Combiner network keys, as issued by the Authority. The signer never takes
    /// them from the combiner's own (unauthenticated) handshake.
    pub combiner_keys: Option<ActorKeys>,

    current_commitment: Option<Commit>,
}

impl Signer {
    pub fn new(id: usize) -> Self {
        Signer {
            id,
            identity_kp: IdentityKeyPair::new(),
            transport_kp: TransportKeyPair::new(),
            taps_kp: None,
            combiner_keys: None,
            current_commitment: None,
        }
    }

    pub fn set_taps_key(&mut self, kp: KeyPair) {
        self.taps_kp = Some(kp);
    }

    fn secure_package<T: Serialize>(&self, package: &T, receiver_pk: &PublicKey) -> SecurePackage {
        let plain_bytes = bincode::serialize(package).expect("Serialization failed");
        let (ciphertext, nonce) = self.transport_kp.encrypt_to(receiver_pk, &plain_bytes);
        let timestamp = current_timestamp();
        let signature = self.identity_kp.sign_data(&ciphertext, &nonce, timestamp);

        SecurePackage {
            ciphertext,
            nonce,
            timestamp,
            signature,
        }
    }

    /// `anchor` must be the pinned Authority key material read from the trust
    /// anchor file - never keys taken from the incoming message.
    pub fn load_from_authority(
        &mut self,
        secure_pkg: &SecurePackage,
        anchor: &AuthorityAnchor,
    ) -> Result<(), Error> {
        let is_valid = IdentityKeyPair::verify_data(&anchor.identity_pk, secure_pkg);

        if !is_valid {
            eprintln!(
                "[Signer] Error: SecurePackage verification failed (Invalid Signature or Expired)."
            );
            return Err(Error::InvalidSignature);
        }

        let plaintext_bytes = self
            .transport_kp
            .decrypt_from(
                &anchor.transport_pk,
                &secure_pkg.ciphertext,
                &secure_pkg.nonce,
            )
            .map_err(|_| Error::InvalidMessage)?;

        let config: SignerPackage =
            bincode::deserialize(&plaintext_bytes).map_err(|_| Error::InvalidMessage)?;

        println!("[Signer] Bootstrap successful. Loading configuration...");

        self.taps_kp = Some(config.my_kp);
        self.combiner_keys = Some(config.combiner_keys);

        println!("[Signer] Configuration Loaded:");

        Ok(())
    }

    /// The Combiner's Authority-issued network keys.
    pub fn combiner_keys(&self) -> Result<ActorKeys, Error> {
        self.combiner_keys.ok_or(Error::InvalidMessage)
    }

    pub fn set_commitment(&mut self) -> Result<SecurePackage, Error> {
        let combiner_pk = self.combiner_keys()?.transport_pk;

        let commit = Commit::commit();
        let comm = Commitment::set(&commit);

        self.current_commitment = Some(commit);

        let pkg = CommitmentPackage { commitment: comm };

        Ok(self.secure_package(&pkg, &combiner_pk))
    }

    pub fn set_sigma(&mut self, signed_pkg: &BroadcastPackage) -> Result<SecurePackage, Error> {
        let keys = self.combiner_keys()?;

        let is_valid = IdentityKeyPair::verify_broadcast_data(&keys.identity_pk, signed_pkg);

        if !is_valid {
            eprintln!(
                "[Signer] Error: Challenge broadcast failed verification \
                 (Invalid Signature or Expired)."
            );
            return Err(Error::InvalidSignature);
        }

        let payload: combiner::SignerPackage = bincode::deserialize(&signed_pkg.text).expect("Serialization failed");

        let comm = self.current_commitment.as_ref()
            .expect("Protocol Error: No commitment found for this round!");

        let my_key = self.taps_kp.as_ref()
            .expect("Protocol Error: TAPS keys not initialized");

        let signature = Sign::sign(&comm, &my_key, &payload.c);

        let pkg = SigmaPackage { z: signature };

        Ok(self.secure_package(&pkg, &keys.transport_pk))
    }
}
