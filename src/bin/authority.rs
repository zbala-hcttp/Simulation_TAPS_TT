use secp256k1::PublicKey;
use simulation_taps_tt::{
    authority::{ActorKeys, Authority},
    network::{self, Message, Role},
};
use std::env;
use std::error::Error;
use tokio::net::{TcpListener, TcpStream};

const PORT: &str = "127.0.0.1:8080";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let n = args
        .get(1)
        .unwrap_or(&"6".to_string())
        .parse::<usize>()
        .map_err(|e| format!("Invalid N: {}", e))?;
    let t = args
        .get(2)
        .unwrap_or(&"4".to_string())
        .parse::<usize>()
        .map_err(|e| format!("Invalid T: {}", e))?;

    // Reject impossible parameters here, with a clear message, rather than
    // letting an assert fire deep inside Quorum::choose.
    if n == 0 {
        return Err("N must be at least 1".into());
    }
    if t == 0 || t > n {
        return Err(format!("T must satisfy 1 <= T <= N (got T={}, N={})", t, n).into());
    }

    println!("[Authority] Starting with N={} T={}...", n, t);
    println!("[Authority] Starting TAPS Setup Server on {}...", PORT);

    let auth = Authority::new(n);
    println!("[Authority] Generated Master Keys.");

    // Publish the trust anchor BEFORE listening, so anyone who manages to
    // connect is guaranteed to be able to read it.
    network::publish_authority_anchor(&auth.anchor())?;
    println!(
        "[Authority] Published trust anchor to '{}'.",
        network::AUTHORITY_ANCHOR_FILE
    );

    let listener = TcpListener::bind(PORT).await?;

    let mut signers: Vec<Option<(TcpStream, ActorKeys)>> = (0..n).map(|_| None).collect();
    let mut combiner: Option<(TcpStream, ActorKeys)> = None;
    let mut tracer: Option<(TcpStream, ActorKeys)> = None;

    let expected_connections = n + 2;
    let mut connected_count = 0;

    println!(
        "[Authority] Waiting for {} actors to connect...",
        expected_connections
    );

    // 3. Connection Loop (Handshake)
    while connected_count < expected_connections {
        let (mut socket, addr) = listener.accept().await?;
        println!("[Authority] Connection from {}", addr);

        // Receive "Hello" Handshake
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
                        if tracer.is_some() {
                            println!("[Authority] A Tracer is already registered!");
                        } else {
                            println!("[Authority] Tracer Handshake Verified.");
                            tracer = Some((socket, keys));
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
            signer_keys.clone(),
            &keys.transport_pk,
        );
        network::send(stream, &Message::Secure { package: pkg }).await?;
        println!("[Authority] Sent SecurePackage to Combiner");
    }

    if let Some((stream, keys)) = tracer.as_mut() {
        let pkg = auth.prepare_tracer_package(t, combiner_keys, &keys.transport_pk);
        network::send(stream, &Message::Secure { package: pkg }).await?;
        println!("[Authority] Sent SecurePackage to Tracer");
    }

    println!("[Authority] Setup Complete. Shutting down.");
    Ok(())
}
