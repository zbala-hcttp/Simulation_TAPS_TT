//! Direct tracer-to-tracer network.
//!
//! The distributed key generation (Figure `dist-keygen`) and the threshold
//! ElGamal decryption (Figure `elgamal-decryption`) run among the `n_3`
//! tracers only. The Combiner takes no part in either: it never sees a
//! round-1 broadcast, a Shamir share or a partial decryption. It only
//! receives each tracer's final `pk_k` and computes `pk_e = prod pk_k`.
//!
//! To that end every pair of tracers holds one TCP link. Tracer `k` listens on
//! `base_port + k`; it dials every lower-indexed tracer and accepts a
//! connection from every higher-indexed one, which yields exactly one link
//! per pair without any coordination.

use crate::authority::ActorKeys;
use crate::network::{self, Message, Role};
use futures::future::try_join_all;
use std::collections::BTreeMap;
use std::error::Error;
use std::time::Duration;
use tokio::net::TcpStream;

/// Tracer `k` listens on `127.0.0.1:(TRACER_BASE_PORT + k)`.
pub const TRACER_BASE_PORT: u16 = 8200;

/// Address tracer `index` listens on for its peers.
pub fn tracer_addr(base_port: u16, index: usize) -> String {
    format!("127.0.0.1:{}", base_port as usize + index)
}

/// The set of open links from one tracer to every other tracer.
pub struct TracerMesh {
    /// 0-based id of the tracer owning this mesh.
    pub index: usize,
    /// One stream per peer, keyed by the peer's 0-based id.
    peers: BTreeMap<usize, TcpStream>,
}

impl TracerMesh {
    /// Opens a link to every other tracer in `roster` (indexed by tracer id,
    /// this tracer included).
    ///
    /// The `Hello` exchanged here only routes the link to the right peer id;
    /// it is not what authenticates the peer. Everything sent over the mesh
    /// afterwards is signed with the sender's identity key and checked against
    /// the Authority-issued roster, so a connection claiming a wrong id cannot
    /// inject anything that will be accepted.
    pub async fn establish(
        index: usize,
        roster: &[ActorKeys],
        hello: &Message,
        base_port: u16,
    ) -> Result<Self, Box<dyn Error>> {
        let n3 = roster.len();
        if index >= n3 {
            return Err(format!("Tracer index {} out of range (n_3 = {})", index, n3).into());
        }

        let mut peers: BTreeMap<usize, TcpStream> = BTreeMap::new();
        if n3 == 1 {
            return Ok(TracerMesh { index, peers });
        }

        // Bind before dialing anyone, so higher-indexed tracers dialing us
        // are queued in the backlog instead of being refused.
        let expected_inbound = n3 - 1 - index;
        let listener = if expected_inbound > 0 {
            Some(network::bind_with_retry(&tracer_addr(base_port, index)).await?)
        } else {
            None
        };

        // Dial every lower-indexed tracer.
        for peer in 0..index {
            let addr = tracer_addr(base_port, peer);
            let mut stream = loop {
                match TcpStream::connect(&addr).await {
                    Ok(stream) => break stream,
                    Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
                }
            };
            network::send(&mut stream, hello).await?;
            peers.insert(peer, stream);
        }

        // Accept every higher-indexed tracer.
        if let Some(listener) = listener {
            while peers.len() < n3 - 1 {
                let (mut stream, addr) = listener.accept().await?;
                let msg = match network::receive(&mut stream).await {
                    Ok(msg) => msg,
                    Err(e) => {
                        eprintln!("[Tracer #{}] Dropping peer link from {}: {}", index, addr, e);
                        continue;
                    }
                };

                match msg {
                    Message::Hello {
                        id,
                        role: Role::Tracer,
                        identity_pk,
                        ..
                    } if id > index
                        && id < n3
                        && !peers.contains_key(&id)
                        && identity_pk == roster[id].identity_pk.serialize().to_vec() =>
                    {
                        peers.insert(id, stream);
                    }
                    _ => {
                        eprintln!(
                            "[Tracer #{}] Rejected peer link from {}: unexpected or duplicate Hello",
                            index, addr
                        );
                    }
                }
            }
        }

        Ok(TracerMesh { index, peers })
    }

    /// Number of peers (i.e. `n_3 - 1`).
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Ids of the connected peers, in ascending order.
    pub fn peer_ids(&self) -> Vec<usize> {
        self.peers.keys().copied().collect()
    }

    /// One communication round: sends `outgoing[w]` to every peer `w` and
    /// receives exactly one message from every peer, all concurrently.
    ///
    /// Sending and receiving happen at the same time on every link: if every
    /// tracer first sent everything and only then started reading, large
    /// payloads (the partial decryptions grow with `n_1`) could fill the TCP
    /// buffers on both ends and deadlock.
    pub async fn exchange(
        &mut self,
        mut outgoing: BTreeMap<usize, Message>,
    ) -> Result<BTreeMap<usize, Message>, Box<dyn Error>> {
        let mut jobs = Vec::with_capacity(self.peers.len());
        for (&peer, stream) in self.peers.iter_mut() {
            let msg = outgoing
                .remove(&peer)
                .ok_or_else(|| format!("No outgoing message for tracer #{}", peer))?;
            jobs.push(async move {
                let (mut reader, mut writer) = stream.split();
                let (_, received) = tokio::try_join!(
                    network::send(&mut writer, &msg),
                    network::receive(&mut reader)
                )?;
                Ok::<_, Box<dyn Error>>((peer, received))
            });
        }

        Ok(try_join_all(jobs).await?.into_iter().collect())
    }

    /// Sends the same message to every peer and receives one from each.
    pub async fn broadcast(&mut self, msg: &Message) -> Result<BTreeMap<usize, Message>, Box<dyn Error>> {
        let outgoing = self.peer_ids().into_iter().map(|w| (w, msg.clone())).collect();
        self.exchange(outgoing).await
    }
}
