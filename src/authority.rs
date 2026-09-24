use crate::crypto::*;
use crate::network::AuthorityAnchor;
use bincode;
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use taps_tt::protocol::taps_tt::*;

/// Signer threshold `t = floor(n/2) + 1`.
pub fn signer_threshold(n: usize) -> usize {
    n / 2 + 1
}

/// Tracer reconstruction threshold `t_e = floor(2*n_3/3) + 1`.
pub fn tracer_threshold(n3: usize) -> usize {
    (2 * n3) / 3 + 1
}

/// Keys the Authority generates directly: signers and the combiner. The
/// tracer group key `pk_e` is no longer generated here - the `n_3` tracers
/// produce it themselves via distributed key generation (Figure
/// `dist-keygen`), and the Authority never learns any tracer secret.
pub struct KeyPairs {
    pub signers_keys: Vec<KeyPair>,
    pub combiner_keys: KeyPair,
}

impl KeyPairs {
    pub fn new(n: usize) -> Self {
        let mut signers = Vec::with_capacity(n);

        for _ in 0..n {
            signers.push(KeyPair::create());
        }

        let combiner_kp = KeyPair::create();

        KeyPairs {
            signers_keys: signers,
            combiner_keys: combiner_kp,
        }
    }

    pub fn signer_public_keys(&self) -> Vec<PublicKey> {
        self.signers_keys.iter().map(|kp| kp.public_key()).collect()
    }

    pub fn set_quorum(&self, t: usize) -> Quorum {
        Quorum::choose(self.signers_keys.len(), t, &self.signers_keys)
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
    pub pk_i: Vec<PublicKey>,
    pub n: usize,
    pub(crate) t: usize,
    /// Number of tracers and the reconstruction threshold they will use.
    pub n3: usize,
    pub te: usize,
    pub quo: Quorum,
    /// Network keys of every signer, indexed by signer id. This is what lets the
    /// Combiner tell a real share from signer #i apart from an impersonated one.
    pub signer_keys: Vec<ActorKeys>,
    /// Network keys of every tracer, indexed by tracer id (0-based; the DKG
    /// party index is `id + 1`).
    pub tracer_keys: Vec<ActorKeys>,
}

impl CombinerPackage {
    pub fn new(
        auth_keys: &KeyPairs,
        quo: Quorum,
        n: usize,
        t: usize,
        n3: usize,
        te: usize,
        signer_keys: Vec<ActorKeys>,
        tracer_keys: Vec<ActorKeys>,
    ) -> Self {
        CombinerPackage {
            kp_cs: auth_keys.combiner_keys.clone(),
            pk_i: auth_keys.signer_public_keys(),
            n,
            t,
            n3,
            te,
            quo,
            signer_keys,
            tracer_keys,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerPackage {
    /// 0-based tracer id; the DKG party index is `index + 1`.
    pub index: usize,
    pub n3: usize,
    pub te: usize,
    pub pk_i: Vec<PublicKey>,
    pub pk_cs: PublicKey,
    /// Public system threshold. The tracer needs it to check that the quorum it
    /// recovers is actually large enough.
    pub t: usize,
    /// Authenticated network keys of the Combiner.
    pub combiner_keys: ActorKeys,
    /// Authenticated network keys of every tracer (including itself), indexed
    /// by tracer id, so tracers can authenticate each other on their direct peer links.
    pub peer_tracers: Vec<ActorKeys>,
}

impl TracerPackage {
    pub fn new(
        auth_keys: &KeyPairs,
        index: usize,
        n3: usize,
        te: usize,
        t: usize,
        combiner_keys: ActorKeys,
        peer_tracers: Vec<ActorKeys>,
    ) -> Self {
        TracerPackage {
            index,
            n3,
            te,
            pk_i: auth_keys.signer_public_keys(),
            pk_cs: auth_keys.combiner_keys.public_key(),
            t,
            combiner_keys,
            peer_tracers,
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
        n3: usize,
        te: usize,
        signer_keys: Vec<ActorKeys>,
        tracer_keys: Vec<ActorKeys>,
        receiver_pk: &PublicKey,
    ) -> SecurePackage {
        let pkg = CombinerPackage::new(
            &self.keys,
            quorum,
            n,
            t,
            n3,
            te,
            signer_keys,
            tracer_keys,
        );
        self.secure_package(&pkg, receiver_pk)
    }

    // --- 3. Prepare Tracer Package ---
    pub fn prepare_tracer_package(
        &self,
        index: usize,
        n3: usize,
        te: usize,
        t: usize,
        combiner_keys: ActorKeys,
        peer_tracers: Vec<ActorKeys>,
        receiver_pk: &PublicKey,
    ) -> SecurePackage {
        let pkg = TracerPackage::new(&self.keys, index, n3, te, t, combiner_keys, peer_tracers);
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

        assert_eq!(auth.signers_keys.len(), n);
    }

    #[test]
    fn test_threshold_formulas() {
        assert_eq!(signer_threshold(100), 51);
        assert_eq!(signer_threshold(1), 1);
        assert_eq!(tracer_threshold(1), 1);
        assert_eq!(tracer_threshold(5), 4);
        assert_eq!(tracer_threshold(3), 3);
        assert_eq!(tracer_threshold(4), 3);
    }
}
