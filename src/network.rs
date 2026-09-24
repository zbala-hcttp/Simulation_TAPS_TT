use crate::crypto::{BroadcastPackage, SecurePackage};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

/// File the Authority publishes its public keys to, and the only piece of key
/// material any actor trusts a priori.
///
/// Verifying a package against a key taken from that same package proves nothing,
/// so the chain of trust has to start somewhere outside the wire. In a deployment
/// this anchor would be pinned in a config file or a CA; here every actor runs
/// from the same working directory, so a file stands in for that out-of-band
/// channel. Everything else - signer, combiner and tracer keys - is then
/// distributed by the Authority inside packages signed with this identity key.
pub const AUTHORITY_ANCHOR_FILE: &str = "taps_authority.pub";

/// The Authority's public keys, as pinned by every other actor.
#[derive(Debug, Clone, Copy)]
pub struct AuthorityAnchor {
    pub identity_pk: PublicKey,
    pub transport_pk: PublicKey,
}

/// Called by the Authority at startup, before it starts listening, so that any
/// actor able to connect is also able to read the anchor.
pub fn publish_authority_anchor(anchor: &AuthorityAnchor) -> Result<(), Box<dyn Error>> {
    let mut bytes = Vec::with_capacity(66);
    bytes.extend_from_slice(&anchor.identity_pk.serialize());
    bytes.extend_from_slice(&anchor.transport_pk.serialize());
    std::fs::write(AUTHORITY_ANCHOR_FILE, bytes)?;
    Ok(())
}

/// Called by every other actor once it has connected to the Authority.
pub fn load_authority_anchor() -> Result<AuthorityAnchor, Box<dyn Error>> {
    let bytes = std::fs::read(AUTHORITY_ANCHOR_FILE).map_err(|e| {
        format!(
            "Cannot read the Authority trust anchor '{}': {}. \
             Start the Authority first, from this working directory.",
            AUTHORITY_ANCHOR_FILE, e
        )
    })?;

    if bytes.len() != 66 {
        return Err(format!(
            "Malformed Authority trust anchor '{}': expected 66 bytes, found {}",
            AUTHORITY_ANCHOR_FILE,
            bytes.len()
        )
        .into());
    }

    Ok(AuthorityAnchor {
        identity_pk: PublicKey::from_slice(&bytes[..33])?,
        transport_pk: PublicKey::from_slice(&bytes[33..])?,
    })
}

/// The roles an actor can play in the system.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
pub enum Role {
    Signer,
    Combiner,
    Tracer,
}

/// The protocol messages exchanged over TCP.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message {
    /// Sent by Actor -> Authority / Combiner to join the network, and by a
    /// tracer to another tracer when it opens a peer-to-peer link.
    Hello {
        id: usize, // 0..n for Signers, 0 for others
        role: Role,
        pk: Vec<u8>,          // Transport Public Key (serialized)
        identity_pk: Vec<u8>, // Long-term Identity Public Key (serialized)
    },

    /// Point-to-point, encrypted and signed. The sender's keys are NOT carried
    /// here on purpose - the receiver already holds them, either pinned (the
    /// Authority) or distributed by the Authority (everyone else).
    Secure { package: SecurePackage },

    /// One-to-many, signed but not encrypted. Same reasoning for the keys.
    Broadcast { package: BroadcastPackage },
}

/// Binds a listener, retrying on `AddrInUse` for a while.
///
/// Back-to-back runs (the benchmark suite, or a manual run right after a
/// previous one) can start a new Authority/Combiner before the OS has
/// released the previous process' socket from `TIME_WAIT` - on Windows this
/// can take minutes, far longer than any reasonable inter-scenario
/// cooldown. Retrying here means that delay is absorbed automatically
/// instead of failing the whole run.
pub async fn bind_with_retry(addr: &str) -> Result<TcpListener, Box<dyn Error>> {
    let attempts = 60;
    let mut last_err = None;
    for attempt in 0..attempts {
        match TcpListener::bind(addr).await {
            Ok(listener) => return Ok(listener),
            Err(e) => {
                if attempt == 0 {
                    println!(
                        "[Network] Port {} is still in use, retrying (this is normal right after a previous run)...",
                        addr
                    );
                }
                last_err = Some(e);
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    Err(Box::new(last_err.unwrap()))
}

/// Helper: Send a message with a 4-byte length header.
///
/// Generic over the writer so it also works on one half of a split stream,
/// which the tracer mesh needs to send and receive on a link concurrently.
pub async fn send<W: AsyncWrite + Unpin>(stream: &mut W, msg: &Message) -> Result<(), Box<dyn Error>> {
    let bytes = bincode::serialize(msg)?;
    let len = bytes.len() as u32;

    stream.write_all(&len.to_be_bytes()).await?; // 1. Write Length
    stream.write_all(&bytes).await?; // 2. Write Payload
    stream.flush().await?;
    Ok(())
}

/// Helper: Receive a length-prefixed message.
pub async fn receive<R: AsyncRead + Unpin>(stream: &mut R) -> Result<Message, Box<dyn Error>> {
    // 1. Read Length (4 bytes)
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // 2. Read Payload
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;

    // 3. Deserialize
    let msg = bincode::deserialize(&buf)?;
    Ok(msg)
}
