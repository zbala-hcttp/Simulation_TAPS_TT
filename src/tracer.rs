use crate::network::AuthorityAnchor;
use crate::{
    authority::{self, ActorKeys},
    combiner,
    crypto::*,
};
use secp256k1::{Error, PublicKey, Scalar};
use taps_tt::protocol::taps_tt::*;
use bincode;

pub struct Tracer {
    pub identity_kp: IdentityKeyPair,
    pub transport_kp: TransportKeyPair,

    pub taps_kp: Option<KeyPair>,
    /// Full tracing key pairs (tau_i). Secret - only the tracer holds these.
    pub tracing_kps: Option<Vec<KeyPair>>,
    /// The matching public tracing keys h_i. Part of the public parameters.
    pub tracing_keys: Option<TracingKeys>,
    /// Combiner network keys, as issued by the Authority.
    pub combiner_keys: Option<ActorKeys>,

    pub T: Option<ElGamalCiphertext>,
    pub v0: Option<PublicKey>,
    pub v_vec: Option<Vec<PublicKey>>,
    pub pk: Option<PK>,
    pub n: Option<usize>,
    /// Public threshold the recovered quorum must meet.
    pub t: Option<usize>,
    pub proof: Option<Proofs>,
    pub sigma: Option<Sigma>,

    pub message: Option<Vec<u8>>,
}

impl Tracer {
    pub fn new() -> Self {
        Tracer {
            identity_kp: IdentityKeyPair::new(),
            transport_kp: TransportKeyPair::new(),
            taps_kp: None,
            tracing_kps: None,
            tracing_keys: None,
            combiner_keys: None,
            pk: None,
            n: None,
            t: None,
            T: None,
            v0: None,
            v_vec: None,
            proof: None,
            sigma: None,
            message: None,
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
                "[Tracer] Error: SecurePackage verification failed (Invalid Signature or Expired)."
            );
            return Err(Error::InvalidSignature);
        }

        let plaintext_bytes = self
            .transport_kp
            .decrypt_from(
                &anchor.transport_pk, // Sender PK (Authority)
                &secure_pkg.ciphertext,
                &secure_pkg.nonce,
            )
            .map_err(|_| Error::InvalidMessage)?;

        let config: authority::TracerPackage =
            bincode::deserialize(&plaintext_bytes).map_err(|_| Error::InvalidMessage)?;

        self.taps_kp = Some(config.kp_t);
        self.pk = Some(config.pk);
        self.n = Some(config.tracing_keys.len());
        self.t = Some(config.t);
        self.combiner_keys = Some(config.combiner_keys);
        self.tracing_keys = Some(TracingKeys::set(&config.tracing_keys));
        self.tracing_kps = Some(config.tracing_keys);

        Ok(())
    }

    pub fn load_from_combiner(&mut self, broadcast_pkg: &BroadcastPackage) -> Result<(), Error> {
        // Verified against the combiner identity key the Authority issued, not
        // against anything carried alongside the message.
        let keys = self.combiner_keys.ok_or(Error::InvalidMessage)?;

        let is_valid = IdentityKeyPair::verify_broadcast_data(&keys.identity_pk, broadcast_pkg);
        if !is_valid {
            eprintln!("[Tracer] Error: BroadcastPackage verification failed.");
            return Err(Error::InvalidSignature);
        }

        let config: combiner::TracerPackage = match bincode::deserialize(&broadcast_pkg.text) {
            Ok(c) => c,
            Err(e) => {
                // PRINT THE ERROR
                eprintln!("[Tracer] Bincode Error: {:?}", e);
                return Err(Error::InvalidMessage);
            }
        };

        self.T = Some(config.T.clone());

        self.v0 = Some(config.v0.clone());
        self.v_vec = Some(config.v_vec.clone());

        self.proof = Some(config.proof);
        self.sigma = Some(config.sigma);
        self.message = Some(config.m.clone());

        Ok(())
    }

    /// Rebuilds the public statement from the received package.
    /// R and ct are taken from sigma so the transcript is unambiguous.
    fn statement<'a>(&'a self, sigma: &'a Sigma) -> Statement<'a> {
        Statement {
            pk: self.pk.as_ref().expect("PK not set in Tracer"),
            tks: self
                .tracing_keys
                .as_ref()
                .expect("Tracing keys not set in Tracer"),
            T: self.T.as_ref().expect("T not set in Tracer"),
            R: &sigma.R,
            m: self.message.as_ref().expect("Message not set in Tracer"),
            ct: &sigma.ct,
            v0: self.v0.as_ref().expect("v0 not set in Tracer"),
            v: self.v_vec.as_ref().expect("v_vec not set in Tracer"),
        }
    }

    /// The Schnorr challenge, re-derived locally - never taken from the combiner.
    pub fn challenge_c(&self) -> Scalar {
        let sigma = self.sigma.as_ref().expect("Sigma not set in Tracer");
        self.statement(sigma).c()
    }

    pub fn verify_sigma(&mut self) -> Result<bool, String> {
        let sigma = self.sigma.as_ref().expect("Sigma not set in Tracer");
        let m = self.message.as_ref().expect("Message not set in Tracer");
        let pk = self.pk.as_ref().expect("PK not set in Tracer");
        Sigma::verify(&pk, &m, &sigma).map_err(|e| format!("Sigma verification failed: {:?}", e))
    }

    /// Verifies the accountability NIZK. Uses public data only; the challenges
    /// are re-derived inside `Proofs::verify` from the statement.
    pub fn verify_proof(&mut self) -> Result<bool, String> {
        let proof = self.proof.as_ref().expect("Proof not set in Tracer");
        let sigma = self.sigma.as_ref().expect("Sigma not set in Tracer");

        Proofs::verify(proof, sigma, &self.statement(sigma))
            .map_err(|e| format!("Proof verification failed: {:?}", e))
    }

    /// Traces the signature: decrypts the quorum bits and checks that the
    /// decrypted Schnorr signature really is the one that quorum would produce.
    pub fn verify_sign(&mut self) -> Result<Vec<u8>, String> {
        let sigma = self.sigma.as_ref().expect("Sigma not set in Tracer");
        let kp = self
            .taps_kp
            .as_ref()
            .expect("TAPS keypair not set in Tracer");
        let g_z_prime = ElGamalCiphertext::decrypt(&sigma.ct, kp);

        let c = self.statement(sigma).c();
        let v0 = self.v0.as_ref().expect("v0 not set in Tracer");
        let v = self.v_vec.as_ref().expect("v_vec not set in Tracer");
        let tr_keys = self
            .tracing_kps
            .as_ref()
            .expect("Tracing keys not set in Tracer");
        let b_i = decrypt_bits(v0, v, tr_keys)?;

        let pk = self.pk.as_ref().expect("PK not set in Tracer");
        let quo = Quorum::set(pk, &b_i);
        let g_z: PublicKey = schnorr_signature(&sigma.R, &quo, &c);

        if g_z != g_z_prime {
            return Err(
                "Tracing failed: g^z from the decrypted quorum does not match the \
                 decrypted signature."
                    .to_string(),
            );
        }

        // The NIZK only proves that T commits to sum(b_i); it does not prove that
        // sum(b_i) >= t. The tracer can check it directly, having recovered the bits.
        let quorum_size = b_i.iter().filter(|&&b| b == 1).count();
        let t = self.t.expect("Threshold t not set in Tracer");
        if quorum_size < t {
            return Err(format!(
                "Tracing failed: quorum of {} signers is below the threshold t={}",
                quorum_size, t
            ));
        }

        Ok(b_i)
    }
}
