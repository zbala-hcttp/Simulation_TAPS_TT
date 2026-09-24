use crate::network::AuthorityAnchor;
use crate::{
    authority::{self, ActorKeys},
    combiner,
    crypto::*,
};
use secp256k1::{Error, PublicKey, Scalar};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use taps_tt::protocol::dkg::{self, DecryptionInput, DkgBroadcast, DkgParticipant, PartialDecryption, TracerKeyShare};
use taps_tt::protocol::field::Fq;
use taps_tt::protocol::group::Gt;
use taps_tt::protocol::taps_tt::*;
use bincode;

/// A single Shamir share `s_{kw} = f_k(w)`, encrypted tracer-to-tracer
/// (Figure `dist-keygen`, step 8: "send `s_{kw}` to party `w` secretly").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgSharePayload {
    pub share: Fq,
}

pub struct Tracer {
    pub identity_kp: IdentityKeyPair,
    pub transport_kp: TransportKeyPair,

    /// 0-based tracer id; the DKG party index is `index + 1`.
    pub index: Option<usize>,
    pub n3: Option<usize>,
    pub te: Option<usize>,

    pub pk_i: Option<Vec<PublicKey>>,
    pub pk_cs: Option<PublicKey>,
    pub n: Option<usize>,
    /// Public threshold the recovered quorum must meet.
    pub t: Option<usize>,
    /// Combiner network keys, as issued by the Authority.
    pub combiner_keys: Option<ActorKeys>,
    /// Network keys of every tracer (including itself), indexed by id.
    pub peer_tracers: Option<Vec<ActorKeys>>,

    // --- Distributed key generation state ---
    dkg_participant: Option<DkgParticipant>,
    /// Keyed by DKG party index (1-based).
    dkg_broadcasts: BTreeMap<usize, DkgBroadcast>,
    /// Keyed by dealer's DKG party index (1-based).
    dkg_shares_received: BTreeMap<usize, Fq>,
    pub tracer_key_share: Option<TracerKeyShare>,
    pub pk_e: Option<PublicKey>,
    pub pk: Option<PK>,

    // --- The signed package from the Combiner ---
    pub T: Option<ElGamalCiphertext>,
    pub v0: Option<Vec<PublicKey>>,
    pub v_vec: Option<Vec<PublicKey>>,
    pub proof: Option<Proofs>,
    pub sigma: Option<Sigma>,

    pub message: Option<Vec<u8>>,
}

impl Tracer {
    pub fn new() -> Self {
        Tracer {
            identity_kp: IdentityKeyPair::new(),
            transport_kp: TransportKeyPair::new(),
            index: None,
            n3: None,
            te: None,
            pk_i: None,
            pk_cs: None,
            n: None,
            t: None,
            combiner_keys: None,
            peer_tracers: None,
            dkg_participant: None,
            dkg_broadcasts: BTreeMap::new(),
            dkg_shares_received: BTreeMap::new(),
            tracer_key_share: None,
            pk_e: None,
            pk: None,
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

        if config.peer_tracers.len() != config.n3 {
            eprintln!("[Tracer] Error: peer tracer roster does not have n_3 entries.");
            return Err(Error::InvalidMessage);
        }

        self.index = Some(config.index);
        self.n3 = Some(config.n3);
        self.te = Some(config.te);
        self.n = Some(config.pk_i.len());
        self.pk_i = Some(config.pk_i);
        self.pk_cs = Some(config.pk_cs);
        self.t = Some(config.t);
        self.combiner_keys = Some(config.combiner_keys);
        self.peer_tracers = Some(config.peer_tracers);

        Ok(())
    }

    /// 1-based DKG party index of this tracer.
    fn dkg_index(&self) -> usize {
        self.index.expect("Tracer not bootstrapped") + 1
    }

    /// Encrypts and signs a payload addressed to the Combiner.
    pub fn secure_package_for_combiner<T: Serialize>(
        &self,
        payload: &T,
    ) -> Result<SecurePackage, Error> {
        let keys = self.combiner_keys.ok_or(Error::InvalidMessage)?;
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

    // === Distributed key generation (Figure `dist-keygen`) =================

    /// Steps 1-6: samples this tracer's polynomial and proof of knowledge.
    /// Returns the broadcast to be sent to the Combiner for relay.
    pub fn start_dkg(&mut self) -> DkgBroadcast {
        let te = self.te.expect("t_e not set");
        let n3 = self.n3.expect("n_3 not set");
        let participant =
            DkgParticipant::new(self.dkg_index(), te, n3).expect("Invalid DKG parameters");
        let broadcast = participant.broadcast.clone();
        self.dkg_participant = Some(participant);
        broadcast
    }

    /// Step 7: verifies and records every tracer's round-1 broadcast.
    /// Broadcasts that fail their proof of knowledge are simply dropped -
    /// their dealer will not end up in `QUAL`.
    pub fn load_dkg_round1(&mut self, broadcasts: Vec<(usize, DkgBroadcast)>) {
        let te = self.te.expect("t_e not set");
        for (id, broadcast) in broadcasts {
            if dkg::verify_broadcast(&broadcast, te).is_ok() {
                self.dkg_broadcasts.insert(id + 1, broadcast);
            } else {
                eprintln!(
                    "[Tracer] Dropping tracer #{}: proof of knowledge does not verify",
                    id
                );
            }
        }
    }

    /// Step 8: computes the shares this tracer owes every other tracer,
    /// encrypted and signed tracer-to-tracer, so the Combiner can relay them
    /// without reading their contents.
    pub fn compute_shares_for_peers(&self) -> Vec<(usize, SecurePackage)> {
        let participant = self
            .dkg_participant
            .as_ref()
            .expect("DKG not started for this tracer");
        let n3 = self.n3.expect("n_3 not set");
        let peers = self.peer_tracers.as_ref().expect("peer tracers not set");

        (0..n3)
            .map(|recipient_id| {
                let share = participant.share_for(recipient_id + 1);
                let payload = DkgSharePayload { share };
                let plain = bincode::serialize(&payload).expect("serialize share");
                let recipient_keys = peers[recipient_id];
                let (ciphertext, nonce) = self
                    .transport_kp
                    .encrypt_to(&recipient_keys.transport_pk, &plain);
                let timestamp = current_timestamp();
                let signature = self.identity_kp.sign_data(&ciphertext, &nonce, timestamp);
                (
                    recipient_id,
                    SecurePackage {
                        ciphertext,
                        nonce,
                        timestamp,
                        signature,
                    },
                )
            })
            .collect()
    }

    /// Steps 7 and 9: decrypts, authenticates and verifies every share this
    /// tracer received, discarding any dealer whose share does not match its
    /// round-1 commitments.
    pub fn load_dkg_inbox(&mut self, items: Vec<(usize, SecurePackage)>) {
        let peers = self
            .peer_tracers
            .as_ref()
            .expect("peer tracers not set")
            .clone();
        let my_index = self.dkg_index();

        for (from_id, secure_pkg) in items {
            let Some(sender_keys) = peers.get(from_id) else {
                eprintln!("[Tracer] Share from unknown tracer id {}", from_id);
                continue;
            };

            if !IdentityKeyPair::verify_data(&sender_keys.identity_pk, &secure_pkg) {
                eprintln!("[Tracer] Share from tracer #{} failed authentication", from_id);
                continue;
            }

            let plaintext = match self.transport_kp.decrypt_from(
                &sender_keys.transport_pk,
                &secure_pkg.ciphertext,
                &secure_pkg.nonce,
            ) {
                Ok(p) => p,
                Err(_) => {
                    eprintln!("[Tracer] Share from tracer #{} failed to decrypt", from_id);
                    continue;
                }
            };

            let payload: DkgSharePayload = match bincode::deserialize(&plaintext) {
                Ok(p) => p,
                Err(_) => {
                    eprintln!("[Tracer] Malformed share from tracer #{}", from_id);
                    continue;
                }
            };

            let dealer_index = from_id + 1;
            let Some(dealer_broadcast) = self.dkg_broadcasts.get(&dealer_index) else {
                eprintln!("[Tracer] No valid broadcast on file for tracer #{}", from_id);
                continue;
            };

            if dkg::verify_share(dealer_broadcast, &payload.share, my_index).is_ok() {
                self.dkg_shares_received.insert(dealer_index, payload.share);
            } else {
                eprintln!(
                    "[Tracer] Share from tracer #{} is inconsistent with its commitments",
                    from_id
                );
            }
        }
    }

    /// Steps 10-11: combines the qualified broadcasts and shares into this
    /// tracer's long-lived key material, and builds the full public registry
    /// `PK` now that `pk_e` is known.
    pub fn finalize_dkg(&mut self) -> Result<(), String> {
        let qual: Vec<usize> = self.dkg_shares_received.keys().copied().collect();
        let participant = self
            .dkg_participant
            .as_ref()
            .ok_or("DKG not started for this tracer")?;

        let share = participant.finalize(&qual, &self.dkg_broadcasts, &self.dkg_shares_received)?;

        println!(
            "[Tracer] DKG complete: qualified set = {:?}, t_e = {}",
            share.qual, share.threshold
        );

        self.pk_e = Some(share.pk_e_as_public_key());
        self.tracer_key_share = Some(share);

        let pk_i = self.pk_i.clone().ok_or("pk_i not set")?;
        let pk_cs = self.pk_cs.ok_or("pk_cs not set")?;
        let pk_e = self.pk_e.ok_or("pk_e not set")?;
        self.pk = Some(PK::from_public_keys(pk_i, pk_cs, pk_e));

        Ok(())
    }

    /// This tracer's own `pk_k`, to be reported to the Combiner so it can
    /// compute `pk_e = prod_{k in QUAL} pk_k`.
    pub fn own_public_key(&self) -> Gt {
        self.tracer_key_share
            .as_ref()
            .expect("DKG not finalized")
            .pk
    }

    // === Combiner interaction ==============================================

    pub fn load_from_combiner(&mut self, broadcast_pkg: &BroadcastPackage) -> Result<(), Error> {
        let keys = self.combiner_keys.ok_or(Error::InvalidMessage)?;

        let is_valid = IdentityKeyPair::verify_broadcast_data(&keys.identity_pk, broadcast_pkg);
        if !is_valid {
            eprintln!("[Tracer] Error: BroadcastPackage verification failed.");
            return Err(Error::InvalidSignature);
        }

        let config: combiner::TracerPackage = match bincode::deserialize(&broadcast_pkg.text) {
            Ok(c) => c,
            Err(e) => {
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

    // === Threshold decryption / tracing (Figures `elgamal-decryption`, `trace`) ===

    /// Steps 2, 4-6: this tracer's own partial decryption of `ct` and every
    /// `v_i`, with Chaum-Pedersen proofs.
    pub fn partial_decrypt(&self) -> PartialDecryption {
        let sigma = self.sigma.as_ref().expect("Sigma not set in Tracer");
        let v0 = self.v0.as_ref().expect("v0 not set in Tracer");
        let v1 = self.v_vec.as_ref().expect("v_vec not set in Tracer");
        let share = self
            .tracer_key_share
            .as_ref()
            .expect("DKG not finalized for this tracer");

        let input = DecryptionInput::from_public_keys(&sigma.ct.c0, &sigma.ct.c1, v0, v1);
        dkg::partial_decrypt(share, &input)
    }

    /// Steps 9-13: verifies every collected partial decryption against the
    /// publicly recomputed verification keys, recombines any `t_e` valid
    /// ones, and runs `Trace` to recover the quorum.
    pub fn combine_and_trace(&self, partials: Vec<PartialDecryption>) -> Result<Vec<usize>, String> {
        let sigma = self.sigma.as_ref().ok_or("Sigma not set in Tracer")?;
        let v0 = self.v0.as_ref().ok_or("v0 not set in Tracer")?;
        let v1 = self.v_vec.as_ref().ok_or("v_vec not set in Tracer")?;
        let share = self
            .tracer_key_share
            .as_ref()
            .ok_or("DKG not finalized for this tracer")?;
        let te = self.te.ok_or("t_e not set")?;

        let input = DecryptionInput::from_public_keys(&sigma.ct.c0, &sigma.ct.c1, v0, v1);

        let mut valid: Vec<PartialDecryption> = Vec::with_capacity(partials.len());
        for partial in partials {
            let expected_vk = dkg::verification_key(&share.qual, &self.dkg_broadcasts, partial.tracer_index)?;
            if dkg::verify_partial_decryption(&partial, &input, &expected_vk).is_ok() {
                valid.push(partial);
            } else {
                eprintln!(
                    "[Tracer] Partial decryption from tracer index {} is invalid, ignoring it",
                    partial.tracer_index
                );
            }
        }

        let (g_z_prime, g_bits) = dkg::combine_partial_decryptions(&input, &valid, te)?;

        let mut bits: Vec<u8> = Vec::with_capacity(g_bits.len());
        for (i, g_bit) in g_bits.iter().enumerate() {
            bits.push(dkg::decode_bit(g_bit, i)?);
        }

        let pk = self.pk.as_ref().ok_or("PK not set in Tracer")?;
        let quo = Quorum::set(pk, &bits);
        let c = self.statement(sigma).c();
        let g_z_expected = schnorr_signature(&sigma.R, &quo, &c);

        if g_z_prime != Gt::from_public_key(&g_z_expected) {
            return Err(
                "Tracing failed: g^z from the decrypted quorum does not match the \
                 decrypted signature."
                    .to_string(),
            );
        }

        let quorum: Vec<usize> = bits
            .iter()
            .enumerate()
            .filter(|&(_, &b)| b == 1)
            .map(|(i, _)| i)
            .collect();

        let t = self.t.ok_or("Threshold t not set in Tracer")?;
        if quorum.len() < t {
            return Err(format!(
                "Tracing failed: quorum of {} signers is below the threshold t={}",
                quorum.len(),
                t
            ));
        }

        Ok(quorum)
    }
}
