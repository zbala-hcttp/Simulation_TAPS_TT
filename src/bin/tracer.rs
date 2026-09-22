use simulation_taps_tt::{
    network::{self, Message, Role},
    tracer::Tracer,
};
use std::error::Error;
use std::time::Instant;
use tokio::net::TcpStream;

// Network Constants
const AUTHORITY_ADDR: &str = "127.0.0.1:8080";
const COMBINER_ADDR: &str = "127.0.0.1:8081";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("[Tracer] Starting TAPS Tracer Node...");

    // =========================================================================
    // Phase 1: Bootstrap from Authority
    // =========================================================================

    // Key generation is real setup work, so it is timed.
    let start_keygen = Instant::now();
    let mut tracer = Tracer::new();
    let keygen_us = start_keygen.elapsed().as_micros();

    println!("[Tracer] Connecting to Authority at {}...", AUTHORITY_ADDR);
    let mut auth_stream = TcpStream::connect(AUTHORITY_ADDR).await?;

    let anchor = network::load_authority_anchor()?;

    let hello = Message::Hello {
        id: 0,
        role: Role::Tracer,
        pk: tracer.transport_kp.pk.serialize().to_vec(),
        identity_pk: tracer.identity_kp.pk.serialize().to_vec(),
    };
    network::send(&mut auth_stream, &hello).await?;

    // Waiting for every other actor to register is not protocol cost, so the
    // benchmark timer starts only once the package is in hand.
    let msg = network::receive(&mut auth_stream).await?;
    match msg {
        Message::Secure { package } => {
            println!("[Tracer] Received SecurePackage from Authority. Bootstrapping...");
            let start_bootstrap = Instant::now();
            tracer.load_from_authority(&package, &anchor)?;
            println!(
                "BENCH,Setup,{}",
                keygen_us + start_bootstrap.elapsed().as_micros()
            );
        }
        _ => return Err("Unexpected message from Authority".into()),
    }

    // =========================================================================
    // Phase 2: Combiner Interaction
    // =========================================================================

    println!("[Tracer] Connecting to Combiner...");
    let mut combiner_stream = loop {
        match TcpStream::connect(COMBINER_ADDR).await {
            Ok(stream) => {
                println!("[Tracer] Connected to Combiner!");
                break stream;
            }
            Err(_) => {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }
    };

    let hello_combiner = Message::Hello {
        id: 0,
        role: Role::Tracer,
        pk: tracer.transport_kp.pk.serialize().to_vec(),
        identity_pk: tracer.identity_kp.pk.serialize().to_vec(),
    };
    network::send(&mut combiner_stream, &hello_combiner).await?;

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

    let start_verify_sign = Instant::now();
    let bits = tracer.verify_sign()?;
    let duration_verify_sign = start_verify_sign.elapsed();
    println!("BENCH,VerifySign,{}", duration_verify_sign.as_micros());

    let quorum_size: usize = bits.iter().filter(|&&b| b == 1).count();
    println!(
        "[Tracer] Traced quorum: {} of {} signers (threshold t={}) -> {:?}",
        quorum_size,
        bits.len(),
        tracer.t.unwrap(),
        bits
    );

    println!("[Tracer] Protocol Finished Successfully.");

    Ok(())
}
