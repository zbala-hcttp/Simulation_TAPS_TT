use simulation_taps_tt::{
    combiner::TracerPublicKeyPackage,
    network::{self, Message, Role},
    tracer::Tracer,
    tracer_mesh::{TRACER_BASE_PORT, TracerMesh},
};
use std::collections::BTreeMap;
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
    //
    // Runs entirely over direct tracer-to-tracer links. The Combiner never
    // sees a broadcast or a share; it only receives our final pk_k.

    let mesh_start = Instant::now();
    let roster = tracer.peer_tracers.clone().ok_or("Peer tracer roster not set")?;
    let mut mesh = TracerMesh::establish(index, &roster, &hello_combiner, TRACER_BASE_PORT).await?;
    println!(
        "[Tracer #{}] Connected to {} peer tracer(s) in {} us.",
        index,
        mesh.peer_count(),
        mesh_start.elapsed().as_micros()
    );

    let start_dkg = Instant::now();

    // Round 1 (steps 1-7): broadcast our own signed (pk_k, A_k, R_k, mu_k)
    // and verify everyone else's proof of knowledge.
    let round1 = tracer.start_dkg();
    let received = mesh.broadcast(&Message::Broadcast { package: round1 }).await?;
    let mut peer_broadcasts = Vec::with_capacity(received.len());
    for (peer, msg) in received {
        match msg {
            Message::Broadcast { package } => peer_broadcasts.push((peer, package)),
            _ => eprintln!("[Tracer #{}] Unexpected round-1 message from tracer #{}", index, peer),
        }
    }
    tracer.load_dkg_round1_from_peers(peer_broadcasts);

    // Round 2 (steps 8-9): send each peer its secret share s_{kw}, encrypted
    // to that peer only, and verify the shares we receive.
    let mut outgoing = BTreeMap::new();
    for peer in mesh.peer_ids() {
        let package = tracer
            .dkg_share_for_peer(peer)
            .map_err(|e| format!("Cannot seal DKG share for tracer #{}: {:?}", peer, e))?;
        outgoing.insert(peer, Message::Secure { package });
    }
    let received = mesh.exchange(outgoing).await?;
    let mut inbox = Vec::with_capacity(received.len());
    for (peer, msg) in received {
        match msg {
            Message::Secure { package } => inbox.push((peer, package)),
            _ => eprintln!("[Tracer #{}] Unexpected share message from tracer #{}", index, peer),
        }
    }
    tracer.load_own_dkg_share();
    tracer.load_dkg_inbox(inbox);

    // Steps 10-11: QUAL, pk_e, sk_{e_k}, vk_k.
    tracer
        .finalize_dkg()
        .map_err(|e| format!("DKG finalization failed: {}", e))?;

    let duration_dkg = start_dkg.elapsed();
    println!("BENCH,TracerDkg,{}", duration_dkg.as_micros());
    println!(
        "[Tracer #{}] DKG complete. pk_e = {:?}",
        index,
        tracer.pk_e.unwrap()
    );

    // Report only pk_k to the Combiner, which computes pk_e = prod_k pk_k on
    // its own. If its pk_e ever differed from ours, the accountability proof
    // below - checked against our own pk_e - would fail.
    let report_pkg = tracer.secure_package_for_combiner(&TracerPublicKeyPackage {
        pk: tracer.own_public_key(),
    })?;
    network::send(&mut combiner_stream, &Message::Secure { package: report_pkg }).await?;

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
    // Phase 5: Threshold decryption and tracing, among the tracers only
    // =========================================================================

    let start_partial = Instant::now();
    let own_partial = tracer.partial_decrypt();

    // Step 7: send our partial decryption, with its Chaum-Pedersen proofs,
    // to every other tracer, encrypted to that tracer.
    let mut outgoing = BTreeMap::new();
    for peer in mesh.peer_ids() {
        let package = tracer
            .partial_for_peer(peer, &own_partial)
            .map_err(|e| format!("Cannot seal partial decryption for tracer #{}: {:?}", peer, e))?;
        outgoing.insert(peer, Message::Secure { package });
    }
    let received = mesh.exchange(outgoing).await?;
    let mut items = Vec::with_capacity(received.len());
    for (peer, msg) in received {
        match msg {
            Message::Secure { package } => items.push((peer, package)),
            _ => eprintln!("[Tracer #{}] Unexpected partial-decryption message from tracer #{}", index, peer),
        }
    }

    // Steps 8-13: verify every partial decryption and combine t_e of them.
    let mut partials = tracer.open_peer_partials(items);
    partials.push(own_partial);

    let quorum = tracer
        .combine_and_trace(partials)
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
