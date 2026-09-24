use simulation_taps_tt::crypto::BroadcastPackage;
use simulation_taps_tt::{
    combiner::Combiner,
    network::{self, Message, Role},
};
use std::error::Error;
use std::time::Instant;
use tokio::net::TcpStream;

const AUTHORITY_ADDR: &str = "127.0.0.1:8080";
const COMBINER_PORT: &str = "127.0.0.1:8081";

const MESSAGE_BYTES: &[u8] = b"Hello TAPS: Distributed Privacy-Preserving Blockchain Transaction";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("[Combiner] Starting TAPS_TT Combiner Node...");

    // =========================================================================
    // Phase 1: Bootstrap from Authority
    // =========================================================================

    let start_keygen = Instant::now();
    let mut combiner = Combiner::new();
    let keygen_us = start_keygen.elapsed().as_micros();

    let transport_pk_bytes = combiner.transport_kp.pk.serialize().to_vec();
    let identity_pk_bytes = combiner.identity_kp.pk.serialize().to_vec();

    println!(
        "[Combiner] Connecting to Authority at {}...",
        AUTHORITY_ADDR
    );
    let mut auth_stream = TcpStream::connect(AUTHORITY_ADDR).await?;

    let anchor = network::load_authority_anchor()?;

    let hello = Message::Hello {
        id: 0,
        role: Role::Combiner,
        pk: transport_pk_bytes,
        identity_pk: identity_pk_bytes,
    };
    network::send(&mut auth_stream, &hello).await?;

    let msg = network::receive(&mut auth_stream).await?;
    match msg {
        Message::Secure { package } => {
            println!("[Combiner] Received SecurePackage from Authority. Bootstrapping...");
            let start_bootstrap = Instant::now();
            combiner.load_from_authority(&package, &anchor)?;
            println!(
                "BENCH,Setup,{}",
                keygen_us + start_bootstrap.elapsed().as_micros()
            );
        }
        _ => return Err("Unexpected message from Authority".into()),
    }

    let n_signers = combiner.n.unwrap();
    let n3 = combiner.n3.unwrap();

    println!(
        "[Combiner] Bootstrap Complete. Quorum Size: {}, Tracers: {}",
        n_signers, n3
    );

    // =========================================================================
    // Phase 2: Network Setup (Server)
    // =========================================================================

    let listener = network::bind_with_retry(COMBINER_PORT).await?;
    println!("[Combiner] Listening on {}...", COMBINER_PORT);

    let expected_connections = n_signers + n3;

    let mut signer_streams: Vec<Option<TcpStream>> = (0..n_signers).map(|_| None).collect();
    let mut tracer_streams: Vec<Option<TcpStream>> = (0..n3).map(|_| None).collect();
    let mut connected_count = 0;

    println!(
        "[Combiner] Waiting for {} participants ({} signers, {} tracers)...",
        expected_connections, n_signers, n3
    );

    while connected_count < expected_connections {
        let (mut socket, addr) = listener.accept().await?;
        println!("[Combiner] Incoming connection from {}", addr);

        let msg = network::receive(&mut socket).await?;
        if let Message::Hello { id, role, .. } = msg {
            match role {
                Role::Signer => {
                    if id < n_signers && signer_streams[id].is_none() {
                        println!("[Combiner] Signer #{} connected.", id);
                        signer_streams[id] = Some(socket);
                        connected_count += 1;
                    } else {
                        println!("[Combiner] Rejected signer claim for id {}.", id);
                    }
                }
                Role::Tracer => {
                    if id < n3 && tracer_streams[id].is_none() {
                        println!("[Combiner] Tracer #{} connected.", id);
                        tracer_streams[id] = Some(socket);
                        connected_count += 1;
                    } else {
                        println!("[Combiner] Rejected tracer claim for id {}.", id);
                    }
                }
                _ => {}
            }
        }
    }
    println!("[Combiner] All participants connected. Starting Protocol.\n");

    // =========================================================================
    // Phase 3: Tracer distributed key generation relay
    // =========================================================================

    let start_dkg_relay = Instant::now();

    println!("[Combiner] >> DKG Round 1: Collecting tracer broadcasts...");
    for (id, stream_opt) in tracer_streams.iter_mut().enumerate() {
        if let Some(stream) = stream_opt {
            let msg = network::receive(stream).await?;
            if let Message::Secure { package } = msg {
                combiner.load_dkg_round1(id, &package)?;
            }
        }
    }

    let round1_bundle = combiner.prepare_dkg_round1_bundle();
    for stream_opt in tracer_streams.iter_mut() {
        if let Some(stream) = stream_opt {
            network::send(
                stream,
                &Message::Broadcast {
                    package: round1_bundle.clone(),
                },
            )
            .await?;
        }
    }

    println!("[Combiner] >> DKG Round 2: Relaying tracer shares...");
    for (id, stream_opt) in tracer_streams.iter_mut().enumerate() {
        if let Some(stream) = stream_opt {
            let msg = network::receive(stream).await?;
            if let Message::Secure { package } = msg {
                combiner.load_dkg_shares(id, &package)?;
            }
        }
    }

    for (id, stream_opt) in tracer_streams.iter_mut().enumerate() {
        if let Some(stream) = stream_opt {
            let inbox = combiner.dkg_inbox_for(id);
            let sealed = combiner.seal_for_tracer(id, &inbox)?;
            network::send(stream, &Message::Secure { package: sealed }).await?;
        }
    }

    println!("[Combiner] >> DKG Finalization: Collecting tracer public keys...");
    for (id, stream_opt) in tracer_streams.iter_mut().enumerate() {
        if let Some(stream) = stream_opt {
            let msg = network::receive(stream).await?;
            if let Message::Secure { package } = msg {
                combiner.load_dkg_report(id, &package)?;
            }
        }
    }

    combiner.finalize_group_key()?;
    let duration_dkg_relay = start_dkg_relay.elapsed();
    println!("BENCH,TracerDkgRelay,{}", duration_dkg_relay.as_micros());
    println!("[Combiner] Tracer group key pk_e established (n_3={}).", n3);

    // =========================================================================
    // Phase 4: Signing protocol
    // =========================================================================

    println!("[Combiner] >> Round 1: Collecting Commitments...");
    let mut commit_processing_us: u128 = 0;
    for (id, stream_opt) in signer_streams.iter_mut().enumerate() {
        if let Some(stream) = stream_opt {
            let msg = network::receive(stream).await?;

            if let Message::Secure { package } = msg {
                let start = Instant::now();
                combiner.load_commitment(&id, &package)?;
                commit_processing_us += start.elapsed().as_micros();
                println!("[Combiner] Verified Commitment from Signer #{}", id);
            }
        }
    }
    println!("Aggregation,{}", commit_processing_us);

    println!("[Combiner] >> Computing Parameters (R, c)...");
    let start_aggregate_nonce = Instant::now();
    combiner.compute_aggregated_nonce()?;
    let duration_aggregate_nonce = start_aggregate_nonce.elapsed();
    println!(
        "BENCH,Round_Aggregate_Nonce,{}",
        duration_aggregate_nonce.as_micros()
    );

    let start_encrypt_threshold = Instant::now();
    combiner.encrypt_threshold()?;
    let duration_encrypt_threshold = start_encrypt_threshold.elapsed();
    println!(
        "BENCH,EncryptionThreshold,{}",
        duration_encrypt_threshold.as_micros()
    );

    let start_compute_parameters = Instant::now();
    combiner.compute_parameters(MESSAGE_BYTES)?;
    let duration_compute_parameters = start_compute_parameters.elapsed();
    println!(
        "BENCH,Compute Parameters,{}",
        duration_compute_parameters.as_micros()
    );

    println!("[Combiner] >> Round 2: Broadcasting Challenge...");

    let signer_pkg: BroadcastPackage = combiner.prepare_signer_package();

    for stream_opt in signer_streams.iter_mut() {
        if let Some(stream) = stream_opt {
            network::send(
                stream,
                &Message::Broadcast {
                    package: signer_pkg.clone(),
                },
            )
            .await?;
        }
    }

    println!("[Combiner] >> Round 2: Collecting Signature Shares...");
    let mut share_processing_us: u128 = 0;
    for (id, stream_opt) in signer_streams.iter_mut().enumerate() {
        if let Some(stream) = stream_opt {
            let msg = network::receive(stream).await?;
            if let Message::Secure { package } = msg {
                let start = Instant::now();
                combiner.load_sigma(&id, &package)?;
                share_processing_us += start.elapsed().as_micros();
                println!("[Combiner] Received Share from Signer #{}", id);
            }
        }
    }
    println!("Collect Shares,{}", share_processing_us);

    println!("[Combiner] >> Finalization: Aggregating and Generating ZKP...");

    let start_aggregate_sign = Instant::now();
    combiner.compute_aggregated_sign()?;
    let duration_aggregate_sign = start_aggregate_sign.elapsed();
    println!(
        "BENCH,Aggregate Sign,{}",
        duration_aggregate_sign.as_micros()
    );

    let start_encrypted_signature = Instant::now();
    combiner.compute_encrypted_signature()?;
    let duration_encrypted_signature = start_encrypted_signature.elapsed();
    println!(
        "BENCH,Encrypted Signature,{}",
        duration_encrypted_signature.as_micros()
    );

    let start_compute_encrypted_bits = Instant::now();
    combiner.compute_encrypted_bits()?;
    let duration_compute_encrypted_bits = start_compute_encrypted_bits.elapsed();
    println!(
        "BENCH,Compute Encrypted Bits,{}",
        duration_compute_encrypted_bits.as_micros()
    );

    let start_compute_alpha = Instant::now();
    combiner.compute_alpha()?;
    let duration_compute_alpha = start_compute_alpha.elapsed();
    println!("BENCH,Compute Alpha,{}", duration_compute_alpha.as_micros());

    let start_compute_phis = Instant::now();
    combiner.compute_phis()?;
    let duration_compute_phis = start_compute_phis.elapsed();
    println!("BENCH,Compute Phis,{}", duration_compute_phis.as_micros());

    let start_compute_blinds = Instant::now();
    combiner.compute_blinds(n_signers)?;
    let duration_compute_blinds = start_compute_blinds.elapsed();
    println!("BENCH,Blinds,{}", duration_compute_blinds.as_micros());

    let start_compute_proofs = Instant::now();
    combiner.compute_proofs()?;
    let duration_compute_proofs = start_compute_proofs.elapsed();
    println!("BENCH,Proofs,{}", duration_compute_proofs.as_micros());

    let start_compute_beta = Instant::now();
    combiner.compute_beta()?;
    let duration_compute_beta = start_compute_beta.elapsed();
    println!("BENCH,Compute Beta,{}", duration_compute_beta.as_micros());

    let start_compute_compute_hats = Instant::now();
    combiner.compute_hats()?;
    let duration_compute_compute_hats = start_compute_compute_hats.elapsed();
    println!(
        "BENCH,Compute Hats,{}",
        duration_compute_compute_hats.as_micros()
    );

    let start_construct_sigma = Instant::now();
    let sigma = combiner.construct_sigma(MESSAGE_BYTES)?;
    let duration_construct_sigma = start_construct_sigma.elapsed();
    println!(
        "BENCH,Construct Sigma,{}",
        duration_construct_sigma.as_micros()
    );

    println!("[Combiner] >> Final Sigma Constructed!");

    // =========================================================================
    // Phase 5: Attestation broadcast to every tracer
    // =========================================================================

    println!("[Combiner] Sending Result to {} Tracer(s)...", n3);
    let tracer_pkg = combiner.prepare_tracer_package(&sigma, MESSAGE_BYTES);
    for stream_opt in tracer_streams.iter_mut() {
        if let Some(stream) = stream_opt {
            network::send(
                stream,
                &Message::Broadcast {
                    package: tracer_pkg.clone(),
                },
            )
            .await?;
        }
    }

    // =========================================================================
    // Phase 6: Relay tracers' partial decryptions to each other
    // =========================================================================

    println!("[Combiner] >> Collecting partial decryptions from tracers...");
    for (id, stream_opt) in tracer_streams.iter_mut().enumerate() {
        if let Some(stream) = stream_opt {
            let msg = network::receive(stream).await?;
            if let Message::Secure { package } = msg {
                combiner.load_partial_decryption(id, &package)?;
            }
        }
    }

    let partial_bundle = combiner.prepare_partial_decryption_bundle();
    for stream_opt in tracer_streams.iter_mut() {
        if let Some(stream) = stream_opt {
            network::send(
                stream,
                &Message::Broadcast {
                    package: partial_bundle.clone(),
                },
            )
            .await?;
        }
    }

    println!("\n[Combiner] Protocol Finished Successfully.");
    Ok(())
}
