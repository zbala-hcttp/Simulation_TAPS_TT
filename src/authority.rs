use crate::crypto::*;
use crate::network::AuthorityAnchor;
use bincode;
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use taps_tt::protocol::taps_tt::*;

pub struct KeyPairs {
    pub signers_keys: Vec<KeyPair>,
    pub combiner_keys: KeyPair,
    pub tracer_keys: KeyPair,
    pub tracing_keys: Vec<KeyPair>,
}

impl KeyPairs {
    pub fn new(n: usize) -> Self {
        let mut signers = Vec::with_capacity(n);
        let mut tracing = Vec::with_capacity(n);

        for _ in 0..n {
            signers.push(KeyPair::create());
            tracing.push(KeyPair::create());
        }

        let combiner_kp = KeyPair::create();

        let tracer_kp = KeyPair::create();

        KeyPairs {
            signers_keys: signers,
            combiner_keys: combiner_kp,
            tracing_keys: tracing,
            tracer_keys: tracer_kp,
        }
    }

    pub fn set_pk(&self) -> PK {
        PK::set(&self.signers_keys, &self.combiner_keys, &self.tracer_keys)
    }

    pub fn set_quorum(&self, t: usize) -> Quorum {
        Quorum::choose(self.signers_keys.len(), t, &self.signers_keys)
    }

    pub fn set_tracing_keys(&self) -> TracingKeys {
        TracingKeys::set(&self.tracing_keys)
    }
}

/// Network keys of one actor, as registered with the Authority.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ActorKeys {
    pub identity_pk: PublicKey,
    pub transport_pk: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerPackage {
    pub my_kp: KeyPair,
    /// Authenticated network keys of the Combiner, so the signer never has to
    /// take them from an unverified handshake.
    pub combiner_keys: ActorKeys,
}

impl SignerPackage {
    pub fn new(auth_keys: &KeyPairs, index: usize, combiner_keys: ActorKeys) -> Self {
        let my_kp = auth_keys.signers_keys[index].clone();

        SignerPackage {
            my_kp,
            combiner_keys,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinerPackage {
    pub kp_cs: KeyPair,
    pub pk: PK,
    pub n: usize,
    pub(crate) t: usize,
    pub quo: Quorum,
    pub tks: TracingKeys,
    /// Network keys of every signer, indexed by signer id. This is what lets the
    /// Combiner tell a real share from signer #i apart from an impersonated one.
    pub signer_keys: Vec<ActorKeys>,
}

impl CombinerPackage {
    pub fn new(
        auth_keys: &KeyPairs,
        quo: Quorum,
        n: usize,
        t: usize,
        signer_keys: Vec<ActorKeys>,
    ) -> Self {
        CombinerPackage {
            kp_cs: auth_keys.combiner_keys.clone(),
            pk: auth_keys.set_pk(),
            n: n,
            t: t,
            quo,
            tks: TracingKeys::set(&auth_keys.tracing_keys),
            signer_keys,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerPackage {
    pub kp_t: KeyPair,
    pub pk: PK,
    pub tracing_keys: Vec<KeyPair>,
    /// Public system threshold. The tracer needs it to check that the quorum it
    /// recovers is actually large enough.
    pub t: usize,
    /// Authenticated network keys of the Combiner.
    pub combiner_keys: ActorKeys,
}

impl TracerPackage {
    pub fn new(auth_keys: &KeyPairs, t: usize, combiner_keys: ActorKeys) -> Self {
        TracerPackage {
            kp_t: auth_keys.tracer_keys.clone(),
            pk: auth_keys.set_pk(),
            tracing_keys: auth_keys.tracing_keys.clone(),
            t,
            combiner_keys,
        }
    }
}

pub struct Authority {
    pub keys: KeyPairs,
    pub identity_kp: IdentityKeyPair,
    pub transport_kp: TransportKeyPair,
}

impl Authority {
    pub fn new(n: usize) -> Self {
        Authority {
            keys: KeyPairs::new(n),
            identity_kp: IdentityKeyPair::new(),
            transport_kp: TransportKeyPair::new(),
        }
    }

    /// Helper: Serializes, Encrypts (Transport), and Signs (Identity).
    fn secure_package<T: Serialize>(&self, package: &T, receiver_pk: &PublicKey) -> SecurePackage {
        let plain_bytes = bincode::serialize(package).expect("Failed to serialize package");

        // Encrypt with Ephemeral Key
        let (ciphertext, nonce) = self.transport_kp.encrypt_to(receiver_pk, &plain_bytes);

        let timestamp = current_timestamp();

        // Sign with Identity Key
        let signature = self.identity_kp.sign_data(&ciphertext, &nonce, timestamp);

        SecurePackage {
            ciphertext,
            nonce,
            timestamp,
            signature,
        }
    }

    /// The Authority's own public keys, published as the trust anchor.
    pub fn anchor(&self) -> AuthorityAnchor {
        AuthorityAnchor {
            identity_pk: self.identity_kp.pk,
            transport_pk: self.transport_kp.pk,
        }
    }

    // --- 1. Prepare Signer Package ---
    pub fn prepare_signer_package(
        &self,
        index: usize,
        combiner_keys: ActorKeys,
        receiver_pk: &PublicKey,
    ) -> SecurePackage {
        let pkg = SignerPackage::new(&self.keys, index, combiner_keys);
        self.secure_package(&pkg, receiver_pk)
    }

    // --- 2. Prepare Combiner Package ---
    pub fn prepare_combiner_package(
        &self,
        quorum: Quorum,
        n: usize,
        t: usize,
        signer_keys: Vec<ActorKeys>,
        receiver_pk: &PublicKey,
    ) -> SecurePackage {
        // Pass the chosen quorum into the package
        let pkg = CombinerPackage::new(&self.keys, quorum, n, t, signer_keys);
        self.secure_package(&pkg, receiver_pk)
    }

    // --- 3. Prepare Tracer Package ---
    pub fn prepare_tracer_package(
        &self,
        t: usize,
        combiner_keys: ActorKeys,
        receiver_pk: &PublicKey,
    ) -> SecurePackage {
        let pkg = TracerPackage::new(&self.keys, t, combiner_keys);
        self.secure_package(&pkg, receiver_pk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authority_initialization() {
        let n = 5;
        let auth = KeyPairs::new(n);

        // Check key counts
        assert_eq!(auth.signers_keys.len(), n);
        assert_eq!(auth.tracing_keys.len(), n);

        // Check structural integrity (keys are valid)
        // (Just checking if they exist is enough, KeyPair::create guarantees validity)
        assert_eq!(auth.signers_keys.len(), n);
        assert_eq!(auth.tracing_keys.len(), n);
    }
}
