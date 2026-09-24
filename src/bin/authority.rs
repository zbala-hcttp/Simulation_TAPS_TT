use secp256k1::PublicKey;
use simulation_taps_tt::{
    authority::{signer_threshold, tracer_threshold, ActorKeys, Authority},
    network::{self, Message, Role},
};
use std::env;
use std::error::Error;
use tokio::net::TcpStream;

const PORT: &str = "127.0.0.1:8080";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let n = args
        .get(1)
        .unwrap_or(&"6".to_string())
        .parse::<usize>()
        .map_err(|e| format!("Invalid N: {}", e))?;
    let n3 = args
        .get(2)
        .unwrap_or(&"1".to_string())
        .parse::<usize>()
        .map_err(|e| format!("Invalid N3: {}", e))?;

    // Reject impossible parameters here, with a clear message, rather than
    // letting an assert fire deep inside Quorum::choose or the tracer DKG.
    if n == 0 {
        return Err("N must be at least 1".into());
    }
    if n3 == 0 {
        return Err("N3 (tracer count) must be at least 1".into());
    }

    // Thresholds are fixed by the protocol's formulas, not chosen freely:
    // signer threshold t = floor(n/2) + 1, tracer threshold
    // t_e = floor(2*n_3/3) + 1.
    let t = signer_threshold(n);
    let te = tracer_threshold(n3);

    println!(
        "[Authority] Starting with N={} T={} N3={} Te={}...",
        n, t, n3, te
    );
    println!("[Authority] Starting TAPS_TT Setup Server on {}...", PORT);

    let auth = Authority::new(n);
    println!("[Authority] Generated Signer and Combiner Keys.");
    println!("[Authority] Tracer keys are NOT generated here - the {} tracers will run a distributed key generation among themselves.", n3);

    // Publish the trust anchor BEFORE listening, so anyone who manages to
    // connect is guaranteed to be able to read it.
    network::publish_authority_anchor(&auth.anchor())?;
    println!(
        "[Authority] Published trust anchor to '{}'.",
        network::AUTHORITY_ANCHOR_FILE
    );

    let listener = network::bind_with_retry(PORT).await?;

    let mut signers: Vec<Option<(TcpStream, ActorKeys)>> = (0..n).map(|_| None).collect();
    let mut combiner: Option<(TcpStream, ActorKeys)> = None;
    let mut tracers: Vec<Option<(TcpStream, ActorKeys)>> = (0..n3).map(|_| None).collect();

    let expected_connections = n + 1 + n3;
    let mut connected_count = 0;

    println!(
        "[Authority] Waiting for {} actors to connect ({} signers, 1 combiner, {} tracers)...",
        expected_connections, n, n3
    );

    // 3. Connection Loop (Handshake)
    while connected_count < expected_connections {
        let (mut socket, addr) = listener.accept().await?;
        println!("[Authority] Connection from {}", addr);

        let msg = network::receive(&mut socket).await?;

        match msg {
            Message::Hello {
                id,
                role,
                pk,
                identity_pk,
            } => {
                let keys = ActorKeys {
                    transport_pk: PublicKey::from_slice(&pk)?,
                    identity_pk: PublicKey::from_slice(&identity_pk)?,
                };

                match role {
                    Role::Signer => {
                        if id >= n {
                            println!("[Authority] Signer ID {} is out of bounds!", id);
                        } else if signers[id].is_some() {
                            println!("[Authority] Signer ID {} already registered!", id);
                        } else {
                            println!("[Authority] Signer #{} Handshake Verified.", id);
                            signers[id] = Some((socket, keys));
                            connected_count += 1;
                        }
                    }
                    Role::Combiner => {
                        if combiner.is_some() {
                            println!("[Authority] A Combiner is already registered!");
                        } else {
                            println!("[Authority] Combiner Handshake Verified.");
                            combiner = Some((socket, keys));
                            connected_count += 1;
                        }
                    }
                    Role::Tracer => {
                        if id >= n3 {
                            println!("[Authority] Tracer ID {} is out of bounds!", id);
                        } else if tracers[id].is_some() {
                            println!("[Authority] Tracer ID {} already registered!", id);
                        } else {
                            println!("[Authority] Tracer #{} Handshake Verified.", id);
                            tracers[id] = Some((socket, keys));
                            connected_count += 1;
                        }
                    }
                }
            }
            _ => println!("[Authority] Unexpected message during handshake."),
        }
    }

    println!("\n[Authority] All actors connected! Distributing keys...\n");

    // The Authority is the PKI: every actor learns its peers' network keys from
    // here, signed and encrypted, instead of trusting whatever a peer claims.
    let combiner_keys = combiner
        .as_ref()
        .map(|(_, keys)| *keys)
        .ok_or("Combiner never registered")?;

    let signer_keys: Vec<ActorKeys> = signers
        .iter()
        .map(|opt| opt.as_ref().map(|(_, keys)| *keys).ok_or("Missing signer"))
        .collect::<Result<_, _>>()?;

    let tracer_keys: Vec<ActorKeys> = tracers
        .iter()
        .map(|opt| opt.as_ref().map(|(_, keys)| *keys).ok_or("Missing tracer"))
        .collect::<Result<_, _>>()?;

    for (i, opt) in signers.iter_mut().enumerate() {
        if let Some((stream, keys)) = opt {
            let pkg = auth.prepare_signer_package(i, combiner_keys, &keys.transport_pk);

            network::send(stream, &Message::Secure { package: pkg }).await?;
            println!("[Authority] Sent SecurePackage to Signer #{}", i);
        }
    }

    if let Some((stream, keys)) = combiner.as_mut() {
        let quorum = auth.keys.set_quorum(t);
        let pkg = auth.prepare_combiner_package(
            quorum,
            n,
            t,
            n3,
            te,
            signer_keys.clone(),
            tracer_keys.clone(),
            &keys.transport_pk,
        );
        network::send(stream, &Message::Secure { package: pkg }).await?;
        println!("[Authority] Sent SecurePackage to Combiner");
    }

    for (i, opt) in tracers.iter_mut().enumerate() {
        if let Some((stream, keys)) = opt {
            let pkg = auth.prepare_tracer_package(
                i,
                n3,
                te,
                t,
                combiner_keys,
                tracer_keys.clone(),
                &keys.transport_pk,
            );
            network::send(stream, &Message::Secure { package: pkg }).await?;
            println!("[Authority] Sent SecurePackage to Tracer #{}", i);
        }
    }

    println!("[Authority] Setup Complete. Shutting down.");
    Ok(())
}
