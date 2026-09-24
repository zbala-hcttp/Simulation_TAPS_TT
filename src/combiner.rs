use crate::crypto::*;
use bincode;
use secp256k1::{Error, PublicKey, Scalar};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use taps_tt::protocol::dkg::{DkgBroadcast, PartialDecryption};
use taps_tt::protocol::group::Gt;
use taps_tt::protocol::taps_tt::*;

use crate::authority::{ActorKeys, CombinerPackage};
use crate::network::AuthorityAnchor;
use crate::signer::{CommitmentPackage, SigmaPackage};

mod serde_scalar {
    use secp256k1::Scalar;
    use serde::{Deserialize, Deserializer, Serializer, Serialize}; // Added Serialize trait

    // Serialize a single Scalar
    pub fn serialize<S>(scalar: &Scalar, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = scalar.to_be_bytes();
        bytes.serialize(serializer)
    }

    // Deserialize a single Scalar
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        Scalar::from_be_bytes(bytes).map_err(serde::de::Error::custom)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignerPackage {
    pub R: PublicKey,
    #[serde(with = "serde_scalar")]
    pub c: Scalar,
}

/// Everything the tracers (or any public verifier) need.
///
/// Note that c, alpha and beta are deliberately *not* transported: the verifier
/// re-derives them from this statement. Accepting them from the prover would
/// void the Fiat-Shamir transform.
#[derive(Serialize, Deserialize, Debug)]
pub struct TracerPackage {
    pub T: ElGamalCiphertext,
    /// `v0[i]`, `v[i]` for every signer, under the tracer group key `pk_e`.
    pub v0: Vec<PublicKey>,
    pub v_vec: Vec<PublicKey>,
    pub proof: Proofs,
    pub sigma: Sigma,
    pub m: Vec<u8>,
}

// --- DKG relay payloads --------------------------------------------------

/// Round 1 (`DistributedKeyGen` steps 1-6): a tracer's own broadcast, sent to
/// the Combiner to be re-broadcast to every other tracer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgRound1Package {
    pub broadcast: DkgBroadcast,
}

/// The bundle of every tracer's round-1 broadcast, sent back by the Combiner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgRound1Bundle {
    /// `(tracer id, broadcast)`, 0-based tracer ids.
    pub broadcasts: Vec<(usize, DkgBroadcast)>,
}

/// Round 2 (step 8): the shares one tracer computed for every other tracer,
/// each individually encrypted and signed tracer-to-tracer. The Combiner
/// only routes these - it cannot decrypt them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgSharesPackage {
    /// `(recipient tracer id, package addressed to that recipient)`.
    pub shares: Vec<(usize, SecurePackage)>,
}

/// The inbox the Combiner reassembles for one recipient tracer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgShareInbox {
    /// `(sender tracer id, package from that sender)`.
    pub items: Vec<(usize, SecurePackage)>,
}

/// Step 10: a tracer reports its own `pk_k` once the DKG is complete, so the
/// Combiner can compute `pk_e = prod_{k in QUAL} pk_k`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgReportPackage {
    pub index: usize,
    pub pk: Gt,
}

/// A tracer's partial decryption, submitted to the Combiner to be relayed to
/// every other tracer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialDecryptionPackage {
    pub partial: PartialDecryption,
}

/// The bundle of every tracer's partial decryption, relayed back by the
/// Combiner so each tracer can locally recombine any `t_e` of them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialDecryptionBundle {
    pub partials: Vec<PartialDecryption>,
}

pub struct Combiner {
    // 1. Networking Keys (For secure communication)
    pub identity_kp: IdentityKeyPair,
    pub transport_kp: TransportKeyPair,

    /// Network keys of each signer, as issued by the Authority. Indexed by id.
    signer_keys: Option<Vec<ActorKeys>>,
    /// Network keys of each tracer, as issued by the Authority. Indexed by id.
    tracer_keys: Option<Vec<ActorKeys>>,

    // 2. TAPS Protocol State (Global info)
    pk_i: Option<Vec<PublicKey>>,
    pub quorum: Option<Quorum>,
    pub n: Option<usize>,
    pub t: Option<usize>,
    pub n3: Option<usize>,
    pub te: Option<usize>,
    pub taps_kp: Option<KeyPair>,

    // --- Tracer distributed key generation relay ---
    dkg_round1: BTreeMap<usize, DkgBroadcast>,
    dkg_inboxes: HashMap<usize, Vec<(usize, SecurePackage)>>,
    dkg_reports: BTreeMap<usize, Gt>,
    pub pk_e: Option<PublicKey>,
    pub pk: Option<PK>,

    // Round State (Signing)
    commitments: HashMap<usize, Commitment>,
    sigmas: HashMap<usize, Sign>,

    // ZKP State
    pub T: Option<ElGamalCiphertext>, // e.g. Encrypted Sum of Participants
    pub C: Option<ElGamalCiphertext>, // e.g. Encrypted Sign

    pub R: Option<PublicKey>,

    pub message: Option<Vec<u8>>, // The message being signed this round

    pub c: Option<Scalar>,     // The Challenge
    pub alpha: Option<Scalar>, // Fiat-Shamir param
    pub beta: Option<Scalar>,  // Fiat-Shamir param

    pub w_z: Option<Sign>,          // Aggregated signature (z)
    pub w_rho: Option<Secret>,      // Randomness for Encrypting t
    pub w_gamma: Option<Vec<Secret>>, // Per-signer randomness gamma_i
    pub w_psi: Option<Secret>,      // Randomness
    pub w_phi_i: Option<Phis>,

    pub v0: Option<Vec<PublicKey>>,
    pub v_vec: Option<Vec<PublicKey>>,

    // Zero-Knowledge Proof State (New)
    pub blinds: Option<Blinds>,
    pub hats: Option<Hats>,
    pub proofs: Option<Proofs>,

    // --- Tracer partial-decryption relay ---
    partials: BTreeMap<usize, PartialDecryption>,
}

impl Combiner {
    /// Creates a new Combiner with fresh network keys.
    /// Does not yet have the TAPS group public key or quorum.
    pub fn new() -> Self {
        Combiner {
            identity_kp: IdentityKeyPair::new(),
            transport_kp: TransportKeyPair::new(),
            signer_keys: None,
            tracer_keys: None,
            pk_i: None,
            quorum: None,
            n: None,
            t: None,
            n3: None,
            te: None,
            taps_kp: None,
            dkg_round1: BTreeMap::new(),
            dkg_inboxes: HashMap::new(),
            dkg_reports: BTreeMap::new(),
            pk_e: None,
            pk: None,
            commitments: HashMap::new(),
            sigmas: HashMap::new(),
            T: None,
            C: None,
            R: None,
            message: None,
            c: None,
            alpha: None,
            beta: None,
            w_z: None,
            w_rho: None,
            w_gamma: None,
            w_psi: None,
            w_phi_i: None,
            v0: None,
            v_vec: None,
            blinds: None,
            hats: None,
            proofs: None,
            partials: BTreeMap::new(),
        }
    }

    // --- Bootstrap: Load Configuration from Authority ---
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
                "[Combiner] Error: SecurePackage verification failed (Invalid Signature or Expired)."
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

        let config: CombinerPackage =
            bincode::deserialize(&plaintext_bytes).map_err(|_| Error::InvalidMessage)?;

        if config.signer_keys.len() != config.n {
            eprintln!("[Combiner] Error: signer key roster does not have n entries.");
            return Err(Error::InvalidMessage);
        }
        if config.tracer_keys.len() != config.n3 {
            eprintln!("[Combiner] Error: tracer key roster does not have n_3 entries.");
            return Err(Error::InvalidMessage);
        }

        println!("[Combiner] Bootstrap successful. Loading configuration...");

        self.signer_keys = Some(config.signer_keys);
        self.tracer_keys = Some(config.tracer_keys);
        self.pk_i = Some(config.pk_i);
        self.quorum = Some(config.quo);
        self.n = Some(config.n);
        self.t = Some(config.t);
        self.n3 = Some(config.n3);
        self.te = Some(config.te);
        self.taps_kp = Some(config.kp_cs);

        println!("[Combiner] Configuration Loaded:");
        println!("           - Signer threshold (t): {}", config.t);
        println!("           - Quorum Size:   {}", self.n.as_ref().unwrap());
        println!(
            "           - Tracers (n_3): {}, threshold (t_e): {}",
            config.n3, config.te
        );

        Ok(())
    }

    pub fn handle_commitment(&mut self, signer_id: usize, comm: Commitment) {
        if let Some(participant_count) = self.n {
            if signer_id < participant_count {
                println!("[Combiner] Stored Commitment from Signer #{}", signer_id);
                self.commitments.insert(signer_id, comm);
            } else {
                println!(
                    "[Combiner] Rejected Commitment: Signer #{} out of range (>= {})",
                    signer_id, participant_count
                );
            }
        } else {
            println!("[Combiner] Error: Participant count (n) not set, cannot accept Commitment.");
        }
    }

    /// Looks up signer `id`'s authenticated network keys from the Authority-issued
    /// roster. This is what binds an incoming package to a specific signer.
    fn keys_of_signer(&self, id: usize) -> Result<ActorKeys, Error> {
        self.signer_keys
            .as_ref()
            .ok_or(Error::InvalidMessage)?
            .get(id)
            .copied()
            .ok_or(Error::InvalidMessage)
    }

    /// Looks up tracer `id`'s authenticated network keys.
    fn keys_of_tracer(&self, id: usize) -> Result<ActorKeys, Error> {
        self.tracer_keys
            .as_ref()
            .ok_or(Error::InvalidMessage)?
            .get(id)
            .copied()
            .ok_or(Error::InvalidMessage)
    }

    pub fn load_commitment(
        &mut self,
        signer_id: &usize,
        secure_pkg: &SecurePackage,
    ) -> Result<(), Error> {
        let keys = self.keys_of_signer(*signer_id)?;

        let is_valid = IdentityKeyPair::verify_data(&keys.identity_pk, secure_pkg);

        if !is_valid {
            eprintln!(
                "[Combiner] Error: Commitment from Signer #{} failed verification \
                 (Invalid Signature or Expired).",
                signer_id
            );
            return Err(Error::InvalidSignature);
        }

        let plaintext_bytes = self
            .transport_kp
            .decrypt_from(
                &keys.transport_pk,
                &secure_pkg.ciphertext,
                &secure_pkg.nonce,
            )
            .map_err(|_| Error::InvalidMessage)?;

        let config: CommitmentPackage =
            bincode::deserialize(&plaintext_bytes).map_err(|_| Error::InvalidMessage)?;

        self.handle_commitment(*signer_id, config.commitment.clone());

        println!("[Combiner] Commitment Loaded:");
        println!("           - Signer ID: {}", *signer_id);

        Ok(())
    }

    // === Tracer distributed key generation relay ==========================

    /// Decrypts and authenticates a `SecurePackage` sent by tracer `id`.
    fn open_tracer_package<T: for<'de> Deserialize<'de>>(
        &self,
        id: usize,
        secure_pkg: &SecurePackage,
    ) -> Result<T, Error> {
        let keys = self.keys_of_tracer(id)?;

        if !IdentityKeyPair::verify_data(&keys.identity_pk, secure_pkg) {
            eprintln!(
                "[Combiner] Error: package from Tracer #{} failed verification.",
                id
            );
            return Err(Error::InvalidSignature);
        }

        let plaintext_bytes = self
            .transport_kp
            .decrypt_from(&keys.transport_pk, &secure_pkg.ciphertext, &secure_pkg.nonce)
            .map_err(|_| Error::InvalidMessage)?;

        bincode::deserialize(&plaintext_bytes).map_err(|_| Error::InvalidMessage)
    }

    /// Encrypts and signs a payload for tracer `id`, using the Combiner's own
    /// identity (used for the round-1 bundle and the attestation broadcast).
    pub fn seal_for_tracer<T: Serialize>(&self, id: usize, payload: &T) -> Result<SecurePackage, Error> {
        let keys = self.keys_of_tracer(id)?;
        let plain_bytes = bincode::serialize(payload).expect("Failed to serialize package");
        let (ciphertext, nonce) = self.transport_kp.encrypt_to(&keys.transport_pk, &plain_bytes);
        let timestamp = current_timestamp();
        let signature = self.identity_kp.sign_data(&ciphertext, &nonce, timestamp);
        Ok(SecurePackage {
            ciphertext,
            nonce,
            timestamp,
            signature,
        })
    }

    pub fn load_dkg_round1(&mut self, tracer_id: usize, secure_pkg: &SecurePackage) -> Result<(), Error> {
        let pkg: DkgRound1Package = self.open_tracer_package(tracer_id, secure_pkg)?;
        self.dkg_round1.insert(tracer_id, pkg.broadcast);
        println!("[Combiner] Received DKG round-1 broadcast from Tracer #{}", tracer_id);
        Ok(())
    }

    pub fn dkg_round1_complete(&self) -> bool {
        self.dkg_round1.len() == self.n3.unwrap_or(usize::MAX)
    }

    pub fn dkg_round1_bundle(&self) -> DkgRound1Bundle {
        DkgRound1Bundle {
            broadcasts: self.dkg_round1.iter().map(|(id, b)| (*id, b.clone())).collect(),
        }
    }

    /// Relays tracer `from`'s point-to-point shares into the per-recipient
    /// inboxes, without inspecting their (encrypted) contents.
    pub fn load_dkg_shares(&mut self, from: usize, secure_pkg: &SecurePackage) -> Result<(), Error> {
        let pkg: DkgSharesPackage = self.open_tracer_package(from, secure_pkg)?;
        for (to, package) in pkg.shares {
            self.dkg_inboxes.entry(to).or_default().push((from, package));
        }
        println!("[Combiner] Relayed DKG shares from Tracer #{}", from);
        Ok(())
    }

    pub fn dkg_inboxes_complete(&self) -> bool {
        let n3 = self.n3.unwrap_or(usize::MAX);
        (0..n3).all(|id| self.dkg_inboxes.get(&id).map(|v| v.len()).unwrap_or(0) == n3)
    }

    pub fn dkg_inbox_for(&self, id: usize) -> DkgShareInbox {
        DkgShareInbox {
            items: self.dkg_inboxes.get(&id).cloned().unwrap_or_default(),
        }
    }

    pub fn load_dkg_report(&mut self, tracer_id: usize, secure_pkg: &SecurePackage) -> Result<(), Error> {
        let pkg: DkgReportPackage = self.open_tracer_package(tracer_id, secure_pkg)?;
        self.dkg_reports.insert(tracer_id, pkg.pk);
        println!("[Combiner] Received DKG report from Tracer #{}", tracer_id);
        Ok(())
    }

    pub fn dkg_reports_complete(&self) -> bool {
        self.dkg_reports.len() == self.n3.unwrap_or(usize::MAX)
    }

    /// Step 2 of `S.KeyGen`: `pk_e = prod_{k in QUAL} pk_k`. Builds the full
    /// public registry `PK` now that the tracer group key is known.
    pub fn finalize_group_key(&mut self) -> Result<(), Error> {
        let mut pk_e_point = Gt::identity();
        for pk_k in self.dkg_reports.values() {
            pk_e_point = pk_e_point.add(pk_k);
        }
        let pk_e = pk_e_point.to_public_key().ok_or(Error::InvalidPublicKey)?;
        self.pk_e = Some(pk_e);

        let pk_i = self.pk_i.clone().ok_or(Error::InvalidMessage)?;
        let kp_cs = self.taps_kp.as_ref().ok_or(Error::InvalidMessage)?;
        self.pk = Some(PK::from_public_keys(pk_i, kp_cs.public_key(), pk_e));

        println!("[Combiner] Tracer group key pk_e established.");
        Ok(())
    }

    // --- Protocol Step: Aggregate Commitments (R) ---

    pub fn compute_aggregated_nonce(&mut self) -> Result<(), Error> {
        let quorum = self.quorum.as_ref().expect("Quorum not set in Combiner");
        let n = self.n.expect("Participant count (n) not set");

        let mut ordered_commitments = Vec::with_capacity(n);

        for i in 0..n {
            if let Some(c) = self.commitments.get(&i) {
                ordered_commitments.push(c.clone());
            } else {
                eprintln!("[Combiner] Error: Missing commitment from Signer #{}", i);
                return Err(Error::InvalidPublicKey);
            }
        }

        let R_val = Commitment::aggregate(&ordered_commitments, quorum)?;

        self.R = Some(R_val);
        println!("[Combiner] Aggregated Nonce R computed and stored.");

        Ok(())
    }

    // --- Protocol Step: Compute Challenge & Parameters (Phase 1) ---
    pub fn encrypt_threshold(&mut self) -> Result<(), Error> {
        let t_val = self.t.expect("Threshold t not set");

        let psi_secret = Secret::create();

        let t_scalar = {
            let mut bytes = [0u8; 32];
            let t_bytes = (t_val as u64).to_be_bytes();
            bytes[24..32].copy_from_slice(&t_bytes);
            Scalar::from_be_bytes(bytes).expect("Threshold scalar conversion failed")
        };

        let T_cipher = ElGamalCiphertext::encrypt_value(&psi_secret, &t_scalar);

        self.w_psi = Some(psi_secret);
        self.T = Some(T_cipher);

        Ok(())
    }

    /// Derives the Schnorr challenge c = H(params || T || R || m).
    pub fn compute_parameters(&mut self, message: &[u8]) -> Result<(), Error> {
        let pk = self.pk.as_ref().expect("PK not set");
        let T_cipher = self.T.as_ref().expect("Cipher not set");

        let R = self
            .R
            .as_ref()
            .expect("Aggregated Nonce R not computed yet");

        self.c = Some(compute_challenge_c(pk, T_cipher, R, message));
        self.message = Some(message.to_vec());

        println!("[Combiner] Computed challenge c.");

        Ok(())
    }

    /// Builds the public statement the accountability proof is about.
    fn statement(&self) -> Statement<'_> {
        Statement {
            pk: self.pk.as_ref().expect("PK not set"),
            T: self.T.as_ref().expect("T not set"),
            R: self.R.as_ref().expect("R not set"),
            m: self.message.as_ref().expect("Message not set"),
            ct: self.C.as_ref().expect("C not computed"),
            v0: self.v0.as_ref().expect("v0 not computed"),
            v: self.v_vec.as_ref().expect("v_vec not computed"),
        }
    }

    pub fn compute_alpha(&mut self) -> Result<(), Error> {
        let c = self.c.expect("Challenge c not computed yet");
        let alpha = self.statement().alpha(&c);

        self.alpha = Some(alpha);
        println!("[Combiner] Computed alpha (bound to C, v0, v_vec).");

        Ok(())
    }

    pub fn compute_beta(&mut self) -> Result<(), Error> {
        let alpha = self.alpha.expect("Alpha not computed yet");
        let proofs = self.proofs.as_ref().expect("Proofs not computed yet");
        let beta = self.statement().beta(&alpha, proofs);

        self.beta = Some(beta);
        println!("[Combiner] Computed beta (bound to the proof commitments).");

        Ok(())
    }

    pub fn handle_sigma(&mut self, signer_id: usize, signature_share: Sign) {
        if let Some(participant_count) = self.n {
            if signer_id < participant_count {
                println!("[Combiner] Stored Sign (z) from Signer #{}", signer_id);
                self.sigmas.insert(signer_id, signature_share);
            } else {
                println!(
                    "[Combiner] Rejected Sign: Signer #{} out of range (>= {})",
                    signer_id, participant_count
                );
            }
        } else {
            println!("[Combiner] Error: Participant count (t) not set.");
        }
    }

    pub fn load_sigma(&mut self, signer_id: &usize, secure_pkg: &SecurePackage) -> Result<(), Error> {
        let keys = self.keys_of_signer(*signer_id)?;

        let is_valid = IdentityKeyPair::verify_data(&keys.identity_pk, secure_pkg);

        if !is_valid {
            eprintln!(
                "[Combiner] Error: Share from Signer #{} failed verification \
                 (Invalid Signature or Expired).",
                signer_id
            );
            return Err(Error::InvalidSignature);
        }

        let plaintext_bytes = self
            .transport_kp
            .decrypt_from(
                &keys.transport_pk,
                &secure_pkg.ciphertext,
                &secure_pkg.nonce,
            )
            .map_err(|_| Error::InvalidMessage)?;

        let config: SigmaPackage =
            bincode::deserialize(&plaintext_bytes).map_err(|_| Error::InvalidMessage)?;

        self.handle_sigma(*signer_id, config.z.clone());

        println!("[Combiner] Share Loaded:");
        println!("           - Sign: {:?}", config.z.clone());

        Ok(())
    }

    pub fn compute_aggregated_sign(&mut self) -> Result<(), Error> {
        let quorum = self.quorum.as_ref().expect("Quorum not set in Combiner");
        let n = self.n.expect("Participant count (n) not set");

        let mut ordered_signs = Vec::with_capacity(n);

        for i in 0..n {
            if let Some(s) = self.sigmas.get(&i) {
                ordered_signs.push(s.clone());
            } else {
                eprintln!("[Combiner] Error: Missing signature from Signer #{}", i);
                return Err(Error::InvalidPublicKey);
            }
        }

        let aggregated_sign = Sign::aggregate(&ordered_signs, quorum);

        println!("[Combiner] Aggregation complete. Stored w_z.");
        self.w_z = Some(aggregated_sign);

        Ok(())
    }

    // --- Protocol Step: Encrypt Signature (C) ---

    pub fn compute_encrypted_signature(&mut self) -> Result<(), Error> {
        let z_struct = self.w_z.as_ref()
            .expect("w_z (Aggregated Signature) not computed yet");

        let pk = self.pk.as_ref().expect("PK not set in Combiner");

        let rho_secret = Secret::create();

        let c_cipher = ElGamalCiphertext::encrypt(&rho_secret, &z_struct, &pk);

        self.w_rho = Some(rho_secret);
        self.C = Some(c_cipher);

        println!("[Combiner] Encrypted z -> C. Stored w_rho (Secret) and C.");

        Ok(())
    }

    // --- Protocol Step: Compute Phi Vector ---

    /// Computes phi_i = alpha^(i+1) * gamma_i * (1 - b_i).
    pub fn compute_phis(&mut self) -> Result<(), Error> {
        let alpha = self.alpha.as_ref().expect("Alpha not set");
        let quorum = self.quorum.as_ref().expect("Quorum not set");
        let gammas = self
            .w_gamma
            .as_ref()
            .expect("w_gamma (per-signer randomness) not computed yet");

        let phis_struct = Phis::set(alpha, gammas, quorum);

        self.w_phi_i = Some(phis_struct);

        println!("[Combiner] Computed w_phi_i (via Phis::set).");

        Ok(())
    }

    // --- Protocol Step: Encrypt Bits (v0, v_vec) ---

    /// Draws a fresh gamma_i per signer and encrypts the quorum bits under
    /// the tracer group key pk_e.
    pub fn compute_encrypted_bits(&mut self) -> Result<(), Error> {
        let quorum = self.quorum.as_ref().expect("Quorum not set");
        let pk_e = self.pk_e.as_ref().expect("pk_e not set");

        let (gammas, ciphertexts) = encrypt_bits_threshold(quorum, pk_e);

        self.w_gamma = Some(gammas);
        self.v0 = Some(ciphertexts.iter().map(|c| c.c0).collect());
        self.v_vec = Some(ciphertexts.iter().map(|c| c.c1).collect());

        println!("[Combiner] Computed Encrypted Bits (v0, v_vec).");

        Ok(())
    }

    // --- Protocol Step: Generate Blinds (Random k values) ---

    pub fn compute_blinds(&mut self, n: usize) -> Result<(), Error> {
        let blinds_struct = Blinds::set(n);

        self.blinds = Some(blinds_struct);
        println!(
            "[Combiner] Computed Blinds (Randomness k) for n={} participants.",
            n
        );

        Ok(())
    }

    // --- Protocol Step: Compute Proofs (Commitments S) ---

    pub fn compute_proofs(&mut self) -> Result<(), Error> {
        let blinds = self.blinds.as_ref().expect("Blinds not computed");
        let pk = self.pk.as_ref().expect("PK not set");
        let pk_e = self.pk_e.as_ref().expect("pk_e not set");
        let v_vec = self.v_vec.as_ref().expect("Encrypted Bits (v_vec) not computed");
        let c = self.c.as_ref().expect("Challenge c not set");
        let alpha = self.alpha.as_ref().expect("Alpha not set");

        let proofs_struct = Proofs::compute_proofs(blinds, pk, pk_e, v_vec, c, alpha);

        self.proofs = Some(proofs_struct);
        println!("[Combiner] Computed Proofs (Commitments S).");

        Ok(())
    }

    // --- Protocol Step: Compute Hats (Responses) ---

    pub fn compute_hats(&mut self) -> Result<(), Error> {
        let z = self.w_z.as_ref().expect("w_z (Signature) not set").clone();
        let rho = self.w_rho.as_ref().expect("w_rho not set").clone();
        let gammas = self.w_gamma.as_ref().expect("w_gamma not set");
        let psi = self.w_psi.as_ref().expect("w_psi not set").clone();

        let quorum = self.quorum.as_ref().expect("Quorum not set");
        let phis = self.w_phi_i.as_ref().expect("w_phi_i not set");

        let witnesses_struct = Witnesses::set(z, rho, gammas, psi, quorum, phis);

        let beta = self.beta.as_ref().expect("Beta (Challenge) not set");
        let blinds = self.blinds.as_ref().expect("Blinds not computed");

        let hats_struct = Hats::set(beta, &witnesses_struct, blinds);

        self.hats = Some(hats_struct);
        println!("[Combiner] Computed Hats (Responses).");

        Ok(())
    }

    // --- Protocol Step: Construct Proof Package (Pi) ---

    pub fn construct_pi(&self) -> Result<Pi, Error> {
        let beta = self
            .beta
            .as_ref()
            .expect("Beta (Challenge) not set")
            .clone();
        let hats = self
            .hats
            .as_ref()
            .expect("Hats (Responses) not computed")
            .clone();

        let pi_struct = Pi { beta, hats };

        println!("[Combiner] Constructed Pi (Proof Package).");

        Ok(pi_struct)
    }

    // --- Protocol Step: Construct Final Signature (Sigma) ---

    pub fn construct_sigma(&self, message: &[u8]) -> Result<Sigma, Error> {
        let pi = self.construct_pi()?;

        let taps_kp = self.taps_kp.as_ref().expect("TAPS KeyPair not set");
        let R = self.R.as_ref().expect("Aggregated Nonce R not set");
        let C = self.C.as_ref().expect("Encrypted Signature C not computed");

        let sigma = Sigma::sign(taps_kp, message, R, C, pi);

        println!("[Combiner] Constructed Final Sigma.");

        Ok(sigma)
    }

    // --- Generic Signing Function ---
    pub fn sign_package<T: Serialize>(&self, payload: &T) -> BroadcastPackage {
        let text = bincode::serialize(payload).expect("Failed to serialize package");

        let mut nonce = vec![0u8; 12];
        let mut rng = rand::thread_rng();
        use rand::RngCore;
        rng.fill_bytes(&mut nonce);

        let timestamp = current_timestamp();

        let signature = self.identity_kp.sign_data(&text, &nonce, timestamp);

        BroadcastPackage {
            text,
            nonce,
            timestamp,
            signature,
        }
    }

    // --- Prepare Specific Packages ---

    pub fn prepare_signer_package(&self) -> BroadcastPackage {
        let R = self.R.as_ref().expect("R not set");
        let c = self.c.as_ref().expect("c not set");

        let payload = SignerPackage { R: *R, c: *c };

        self.sign_package(&payload)
    }

    /// For every tracer: the full public statement plus the proof and sigma.
    pub fn prepare_tracer_package(&self, sigma: &Sigma, m: &[u8]) -> BroadcastPackage {
        let T = self.T.as_ref().expect("T not set");
        let proof_struct = self.proofs.as_ref().expect("Proofs not computed");
        let v0 = self.v0.as_ref().expect("v0 not computed").clone();
        let v = self.v_vec.as_ref().expect("v_vec not computed").clone();

        let payload = TracerPackage {
            T: T.clone(),
            v0,
            v_vec: v,
            proof: proof_struct.clone(),
            sigma: sigma.clone(),
            m: m.to_vec(),
        };

        self.sign_package(&payload)
    }

    pub fn prepare_dkg_round1_bundle(&self) -> BroadcastPackage {
        self.sign_package(&self.dkg_round1_bundle())
    }

    // === Tracer partial-decryption relay ==================================

    pub fn load_partial_decryption(
        &mut self,
        tracer_id: usize,
        secure_pkg: &SecurePackage,
    ) -> Result<(), Error> {
        let pkg: PartialDecryptionPackage = self.open_tracer_package(tracer_id, secure_pkg)?;
        self.partials.insert(tracer_id, pkg.partial);
        println!("[Combiner] Received partial decryption from Tracer #{}", tracer_id);
        Ok(())
    }

    pub fn partial_decryptions_complete(&self) -> bool {
        self.partials.len() == self.n3.unwrap_or(usize::MAX)
    }

    pub fn prepare_partial_decryption_bundle(&self) -> BroadcastPackage {
        let payload = PartialDecryptionBundle {
            partials: self.partials.values().cloned().collect(),
        };
        self.sign_package(&payload)
    }
}
