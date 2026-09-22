use simulation_taps_tt::{
    network::{self, Message, Role},
    signer::Signer,
};
use std::env;
use std::error::Error;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

// Network Constants
const AUTHORITY_ADDR: &str = "127.0.0.1:8080";
const COMBINER_ADDR: &str = "127.0.0.1:8081";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: signer <id>");
        return Ok(());
    }
    let my_id: usize = args[1].parse()?;

    println!("[Signer #{}] Starting Node...", my_id);

    // =========================================================================
    // Phase 1: Bootstrap from Authority
    // =========================================================================

    // 1. Initialize our keys. Timed: this is real setup work.
    let start_keygen = Instant::now();
    let mut signer = Signer::new(my_id);
    let keygen_us = start_keygen.elapsed().as_micros();

    let my_transport_pk = signer.transport_kp.pk;
    let my_identity_pk = signer.identity_kp.pk;

    // 2. Connect to Authority
    println!("[Signer #{}] Connecting to Authority...", my_id);
    let mut auth_stream = TcpStream::connect(AUTHORITY_ADDR).await?;

    // The Authority publishes its anchor before it listens, so by now it exists.
    let anchor = network::load_authority_anchor()?;

    // 3. Handshake: Send our Hello (transport + identity keys)
    let hello_auth = Message::Hello {
        id: my_id,
        role: Role::Signer,
        pk: my_transport_pk.serialize().to_vec(),
        identity_pk: my_identity_pk.serialize().to_vec(),
    };
    network::send(&mut auth_stream, &hello_auth).await?;

    // 4. Receive Credentials (Encrypted SignerPackage)
    //    The blocking wait for every other actor to connect is deliberately
    //    outside the benchmark timer - it is scheduling, not protocol cost.
    let msg = network::receive(&mut auth_stream).await?;

    match msg {
        Message::Secure { package } => {
            println!("[Signer #{}] Received Credentials.", my_id);
            let start_bootstrap = Instant::now();
            signer.load_from_authority(&package, &anchor)?;
            println!(
                "BENCH,Setup,{}",
                keygen_us + start_bootstrap.elapsed().as_micros()
            );
            println!("[Signer #{}] TAPS Key Loaded.", my_id);
        }
        _ => return Err("Expected Welcome from Authority".into()),
    }
    drop(auth_stream);

    // =========================================================================
    // Phase 2: Combiner Interaction
    // =========================================================================

    println!(
        "[Signer #{}] Connecting to Combiner at {}...",
        my_id, COMBINER_ADDR
    );

    // FIX: Retry Loop. Keep trying until Combiner is ready.
    let mut combiner_stream = loop {
        match TcpStream::connect(COMBINER_ADDR).await {
            Ok(stream) => {
                println!("[Signer #{}] Connected to Combiner!", my_id);
                break stream;
            }
            Err(_) => {
                println!(
                    "[Signer #{}] Combiner not ready. Retrying in 2 seconds...",
                    my_id
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };

    // 1. Handshake: Announce ourselves. The Combiner already holds our keys
    //    from the Authority, so this only tells it which id we are; the packages
    //    that follow are what actually prove it.
    let hello_combiner = Message::Hello {
        id: my_id,
        role: Role::Signer,
        pk: my_transport_pk.serialize().to_vec(),
        identity_pk: my_identity_pk.serialize().to_vec(),
    };
    network::send(&mut combiner_stream, &hello_combiner).await?;
    println!("[Signer #{}] Handshake sent.", my_id);

    // --- Round 1: Send Commitment ---

    println!("[Signer #{}] >> Round 1: Sending Commitment...", my_id);

    let start_set_commitment = Instant::now();
    let comm_package = signer.set_commitment()?;
    let duration_set_commitment = start_set_commitment.elapsed();
    println!("BENCH,Commitment,{}", duration_set_commitment.as_micros());

    network::send(
        &mut combiner_stream,
        &Message::Secure {
            package: comm_package,
        },
    )
    .await?;

    println!(
        "[Signer #{}] >> Round 2: Waiting for Challenge (R, c)...",
        my_id
    );

    let msg = network::receive(&mut combiner_stream).await?;

    match msg {
        Message::Broadcast {
            package: signed_pkg,
        } => {
            println!("[Signer #{}] Received Challenge.", my_id);

            let start_set_sigma = Instant::now();
            let sigma_pkg = signer.set_sigma(&signed_pkg)?;
            let duration_set_sigma = start_set_sigma.elapsed();
            println!("BENCH,Sigma,{}", duration_set_sigma.as_micros());

            network::send(
                &mut combiner_stream,
                &Message::Secure { package: sigma_pkg },
            )
            .await?;
            println!("[Signer #{}] Sent Signature Share.", my_id);
        }
        _ => return Err("Expected SignerPackage from Combiner".into()),
    }

    println!("[Signer #{}] Protocol Finished Successfully.", my_id);
    Ok(())
}
