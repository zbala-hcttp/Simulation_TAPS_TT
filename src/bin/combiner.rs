use simulation_taps_tt::crypto::BroadcastPackage;
use simulation_taps_tt::{
    combiner::Combiner,
    network::{self, Message, Role},
};
use std::error::Error;
use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};

const AUTHORITY_ADDR: &str = "127.0.0.1:8080";
const COMBINER_PORT: &str = "127.0.0.1:8081";

const MESSAGE_BYTES: &[u8] = b"Hello TAPS: Distributed Privacy-Preserving Blockchain Transaction";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("[Combiner] Starting TAPS Combiner Node...");

    // =========================================================================
    // Phase 1: Bootstrap from Authority
    // =========================================================================

    // 1. Generate Ephemeral Transport Keys. Timed: real setup work.
    let start_keygen = Instant::now();
    let mut combiner = Combiner::new();
    let keygen_us = start_keygen.elapsed().as_micros();

    let transport_pk_bytes = combiner.transport_kp.pk.serialize().to_vec();
    let identity_pk_bytes = combiner.identity_kp.pk.serialize().to_vec();

    // 2. Connect to Authority
    println!(
        "[Combiner] Connecting to Authority at {}...",
        AUTHORITY_ADDR
    );
    let mut auth_stream = TcpStream::connect(AUTHORITY_ADDR).await?;

    let anchor = network::load_authority_anchor()?;

    // 3. Send Hello
    let hello = Message::Hello {
        id: 0,
        role: Role::Combiner,
        pk: transport_pk_bytes,
        identity_pk: identity_pk_bytes,
    };
    network::send(&mut auth_stream, &hello).await?;

    // The wait for all other actors to register is not protocol cost, so the
    // benchmark timer starts only once the package is in hand.
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

    println!("[Combiner] Bootstrap Complete. Quorum Size: {}", n_signers);

    // =========================================================================
    // Phase 2: Network Setup (Server)
    // =========================================================================

    let listener = TcpListener::bind(COMBINER_PORT).await?;
    println!("[Combiner] Listening on {}...", COMBINER_PORT);

    let expected_connections = n_signers + 1;

    let mut signer_streams: Vec<Option<TcpStream>> = (0..n_signers).map(|_| None).collect();

    let mut tracer_stream: Option<TcpStream> = None;
    let mut connected_count = 0;

    println!(
        "[Combiner] Waiting for {} participants...",
        expected_connections
    );

    while connected_count < expected_connections {
        let (mut socket, addr) = listener.accept().await?;
        println!("[Combiner] Incoming connection from {}", addr);

        // Handshake. This only claims an id; the Authority-issued keys are what
        // authenticate the packages that follow.
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
                    if tracer_stream.is_none() {
                        println!("[Combiner] Tracer connected.");
                        tracer_stream = Some(socket);
                        connected_count += 1;
                    }
                }
                _ => {}
            }
        }
    }
    println!("[Combiner] All participants connected. Starting Protocol.\n");

    // =========================================================================
    // Phase 3: Protocol Execution
    // =========================================================================

    println!("[Combiner] >> Round 1: Collecting Commitments...");
    // Accumulate only the per-message verify/decrypt/deserialize cost; time spent
    // blocked on the socket is scheduling, not protocol work.
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

    // Encrypted bits (and gamma) must exist before alpha is drawn, and alpha
    // before phi_i, which depends on it.
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

    // beta is only well defined once the commitments S1..S4c above exist.
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

    if let Some(stream) = tracer_stream.as_mut() {
        println!("[Combiner] Sending Result to Tracer...");
        let tracer_pkg = combiner.prepare_tracer_package(&sigma, MESSAGE_BYTES);
        network::send(
            stream,
            &Message::Broadcast {
                package: tracer_pkg,
            },
        )
        .await?;
    }

    println!("\n[Combiner] Protocol Finished Successfully.");
    Ok(())
}
