use simulation_taps_tt::{
    combiner::{
        DkgReportPackage, DkgRound1Bundle, DkgRound1Package, DkgShareInbox, DkgSharesPackage,
        PartialDecryptionBundle, PartialDecryptionPackage,
    },
    network::{self, Message, Role},
    tracer::Tracer,
};
use std::env;
use std::error::Error;
use std::time::Instant;
use tokio::net::TcpStream;

// Network Constants
const AUTHORITY_ADDR: &str = "127.0.0.1:8080";
const COMBINER_ADDR: &str = "127.0.0.1:8081";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let index = args
        .get(1)
        .unwrap_or(&"0".to_string())
        .parse::<usize>()
        .map_err(|e| format!("Invalid tracer index: {}", e))?;

    println!("[Tracer #{}] Starting TAPS_TT Tracer Node...", index);

    // =========================================================================
    // Phase 1: Bootstrap from Authority
    // =========================================================================

    let start_keygen = Instant::now();
    let mut tracer = Tracer::new();
    let keygen_us = start_keygen.elapsed().as_micros();

    println!("[Tracer #{}] Connecting to Authority at {}...", index, AUTHORITY_ADDR);
    let mut auth_stream = TcpStream::connect(AUTHORITY_ADDR).await?;

    let anchor = network::load_authority_anchor()?;

    let hello = Message::Hello {
        id: index,
        role: Role::Tracer,
        pk: tracer.transport_kp.pk.serialize().to_vec(),
        identity_pk: tracer.identity_kp.pk.serialize().to_vec(),
    };
    network::send(&mut auth_stream, &hello).await?;

    let msg = network::receive(&mut auth_stream).await?;
    match msg {
        Message::Secure { package } => {
            println!("[Tracer #{}] Received SecurePackage from Authority. Bootstrapping...", index);
            let start_bootstrap = Instant::now();
            tracer.load_from_authority(&package, &anchor)?;
            println!(
                "BENCH,Setup,{}",
                keygen_us + start_bootstrap.elapsed().as_micros()
            );
        }
        _ => return Err("Unexpected message from Authority".into()),
    }

    let n3 = tracer.n3.unwrap();
    let te = tracer.te.unwrap();
    println!("[Tracer #{}] n_3={} t_e={}", index, n3, te);

    // =========================================================================
    // Phase 2: Combiner Interaction
    // =========================================================================

    println!("[Tracer #{}] Connecting to Combiner...", index);
    let mut combiner_stream = loop {
        match TcpStream::connect(COMBINER_ADDR).await {
            Ok(stream) => {
                println!("[Tracer #{}] Connected to Combiner!", index);
                break stream;
            }
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }
    };

    let hello_combiner = Message::Hello {
        id: index,
        role: Role::Tracer,
        pk: tracer.transport_kp.pk.serialize().to_vec(),
        identity_pk: tracer.identity_kp.pk.serialize().to_vec(),
    };
    network::send(&mut combiner_stream, &hello_combiner).await?;

    // =========================================================================
    // Phase 3: Distributed key generation among the n_3 tracers
    // =========================================================================

    let start_dkg = Instant::now();

    // Round 1: broadcast our own (pk_k, A_k, R_k, mu_k).
    let broadcast = tracer.start_dkg();
    let round1_pkg = tracer.secure_package_for_combiner(&DkgRound1Package { broadcast })?;
    network::send(&mut combiner_stream, &Message::Secure { package: round1_pkg }).await?;

    let msg = network::receive(&mut combiner_stream).await?;
    let bundle: DkgRound1Bundle = match msg {
        Message::Broadcast { package } => bincode::deserialize(&package.text)?,
        _ => return Err("Expected DKG round-1 bundle from Combiner".into()),
    };
    tracer.load_dkg_round1(bundle.broadcasts);

    // Round 2: compute and send the shares owed to every tracer.
    let shares = tracer.compute_shares_for_peers();
    let shares_pkg = tracer.secure_package_for_combiner(&DkgSharesPackage { shares })?;
    network::send(&mut combiner_stream, &Message::Secure { package: shares_pkg }).await?;

    let msg = network::receive(&mut combiner_stream).await?;
    let inbox: DkgShareInbox = match msg {
        Message::Secure { package } => {
            let plaintext = tracer
                .transport_kp
                .decrypt_from(
                    &tracer.combiner_keys.unwrap().transport_pk,
                    &package.ciphertext,
                    &package.nonce,
                )
                .map_err(|e| format!("Failed to decrypt DKG inbox: {:?}", e))?;
            bincode::deserialize(&plaintext)?
        }
        _ => return Err("Expected DKG share inbox from Combiner".into()),
    };
    tracer.load_dkg_inbox(inbox.items);

    tracer
        .finalize_dkg()
        .map_err(|e| format!("DKG finalization failed: {}", e))?;

    let report_pkg = tracer.secure_package_for_combiner(&DkgReportPackage {
        index,
        pk: tracer.own_public_key(),
    })?;
    network::send(&mut combiner_stream, &Message::Secure { package: report_pkg }).await?;

    let duration_dkg = start_dkg.elapsed();
    println!("BENCH,TracerDkg,{}", duration_dkg.as_micros());
    println!(
        "[Tracer #{}] DKG complete. pk_e = {:?}",
        index,
        tracer.pk_e.unwrap()
    );

    // =========================================================================
    // Phase 4: Receive and verify the combiner's attestation
    // =========================================================================

    let msg = network::receive(&mut combiner_stream).await?;

    match msg {
        Message::Broadcast {
            package: signed_pkg,
        } => {
            tracer.load_from_combiner(&signed_pkg)?;
        }
        _ => return Err("Expected TracerPackage from Combiner".into()),
    }

    let start_verify_sigma = Instant::now();
    let sigma_ok = tracer.verify_sigma()?;
    let duration = start_verify_sigma.elapsed();
    println!("BENCH,VerifySigma,{}", duration.as_micros());
    if !sigma_ok {
        return Err("Combiner signature (sigma) is invalid".into());
    }

    let start_verify_proof = Instant::now();
    let proof_ok = tracer.verify_proof()?;
    let duration_verify_proof = start_verify_proof.elapsed();
    println!("BENCH,VerifyProof,{}", duration_verify_proof.as_micros());
    if !proof_ok {
        return Err("Accountability proof is invalid".into());
    }

    // =========================================================================
    // Phase 5: Threshold decryption and tracing
    // =========================================================================

    let start_partial = Instant::now();
    let own_partial = tracer.partial_decrypt();
    let partial_pkg =
        tracer.secure_package_for_combiner(&PartialDecryptionPackage { partial: own_partial })?;
    network::send(&mut combiner_stream, &Message::Secure { package: partial_pkg }).await?;

    let msg = network::receive(&mut combiner_stream).await?;
    let bundle: PartialDecryptionBundle = match msg {
        Message::Broadcast { package } => bincode::deserialize(&package.text)?,
        _ => return Err("Expected partial decryption bundle from Combiner".into()),
    };

    let quorum = tracer
        .combine_and_trace(bundle.partials)
        .map_err(|e| format!("Tracing failed: {}", e))?;
    let duration_partial = start_partial.elapsed();
    println!("BENCH,VerifySign,{}", duration_partial.as_micros());

    println!(
        "[Tracer #{}] Traced quorum: {} of {} signers (threshold t={}) -> {:?}",
        index,
        quorum.len(),
        tracer.n.unwrap(),
        tracer.t.unwrap(),
        quorum
    );

    println!("[Tracer #{}] Protocol Finished Successfully.", index);

    Ok(())
}
