//! The tracers' distributed key generation and threshold decryption run over
//! direct tracer-to-tracer links; the Combiner only ever receives each
//! tracer's `pk_k` and computes `pk_e = prod_k pk_k` from them.

use futures::future::join_all;
use simulation_taps_tt::authority::{self, ActorKeys, Authority};
use simulation_taps_tt::combiner::{Combiner, TracerPublicKeyPackage};
use simulation_taps_tt::crypto::{IdentityKeyPair, TransportKeyPair};
use simulation_taps_tt::network::{Message, Role};
use simulation_taps_tt::tracer::{DkgSharePayload, Tracer};
use simulation_taps_tt::tracer_mesh::TracerMesh;
use std::collections::BTreeMap;
use std::error::Error;
use taps_tt::protocol::group::Gt;

fn fresh_actor_keys() -> ActorKeys {
    ActorKeys {
        identity_pk: IdentityKeyPair::new().pk,
        transport_pk: TransportKeyPair::new().pk,
    }
}

fn keys_of_tracer(tracer: &Tracer) -> ActorKeys {
    ActorKeys {
        identity_pk: tracer.identity_kp.pk,
        transport_pk: tracer.transport_kp.pk,
    }
}

fn hello_of(tracer: &Tracer, index: usize) -> Message {
    Message::Hello {
        id: index,
        role: Role::Tracer,
        pk: tracer.transport_kp.pk.serialize().to_vec(),
        identity_pk: tracer.identity_kp.pk.serialize().to_vec(),
    }
}

/// Bootstraps a Combiner and `n3` tracers in-process, exactly as the
/// Authority binary would.
fn bootstrap(n: usize, n3: usize) -> (Combiner, Vec<Tracer>) {
    let auth = Authority::new(n);
    let anchor = auth.anchor();
    let t = authority::signer_threshold(n);
    let te = authority::tracer_threshold(n3);

    let mut combiner = Combiner::new();
    let combiner_keys = ActorKeys {
        identity_pk: combiner.identity_kp.pk,
        transport_pk: combiner.transport_kp.pk,
    };

    let mut tracers: Vec<Tracer> = (0..n3).map(|_| Tracer::new()).collect();
    let tracer_keys: Vec<ActorKeys> = tracers.iter().map(keys_of_tracer).collect();
    let signer_keys: Vec<ActorKeys> = (0..n).map(|_| fresh_actor_keys()).collect();

    let pkg = auth.prepare_combiner_package(
        auth.keys.set_quorum(t),
        n,
        t,
        n3,
        te,
        signer_keys,
        tracer_keys.clone(),
        &combiner.transport_kp.pk,
    );
    combiner.load_from_authority(&pkg, &anchor).expect("combiner bootstrap");

    for (i, tracer) in tracers.iter_mut().enumerate() {
        let pkg = auth.prepare_tracer_package(
            i,
            n3,
            te,
            t,
            combiner_keys,
            tracer_keys.clone(),
            &tracer.transport_kp.pk,
        );
        tracer.load_from_authority(&pkg, &anchor).expect("tracer bootstrap");
    }

    (combiner, tracers)
}

/// Runs one tracer's side of the DKG over the mesh, as `bin/tracer.rs` does.
async fn run_dkg(
    mut tracer: Tracer,
    index: usize,
    base_port: u16,
) -> Result<(Tracer, TracerMesh), Box<dyn Error>> {
    let roster = tracer.peer_tracers.clone().ok_or("roster not set")?;
    let hello = hello_of(&tracer, index);
    let mut mesh = TracerMesh::establish(index, &roster, &hello, base_port).await?;

    let round1 = tracer.start_dkg();
    let received = mesh.broadcast(&Message::Broadcast { package: round1 }).await?;
    let peer_broadcasts = received
        .into_iter()
        .filter_map(|(peer, msg)| match msg {
            Message::Broadcast { package } => Some((peer, package)),
            _ => None,
        })
        .collect();
    tracer.load_dkg_round1_from_peers(peer_broadcasts);

    let mut outgoing = BTreeMap::new();
    for peer in mesh.peer_ids() {
        let package = tracer.dkg_share_for_peer(peer).map_err(|e| format!("{:?}", e))?;
        outgoing.insert(peer, Message::Secure { package });
    }
    let received = mesh.exchange(outgoing).await?;
    let inbox = received
        .into_iter()
        .filter_map(|(peer, msg)| match msg {
            Message::Secure { package } => Some((peer, package)),
            _ => None,
        })
        .collect();
    tracer.load_own_dkg_share();
    tracer.load_dkg_inbox(inbox);
    tracer.finalize_dkg()?;

    Ok((tracer, mesh))
}

async fn run_all_dkgs(tracers: Vec<Tracer>, base_port: u16) -> Vec<(Tracer, TracerMesh)> {
    let jobs = tracers
        .into_iter()
        .enumerate()
        .map(|(i, tracer)| run_dkg(tracer, i, base_port));
    join_all(jobs)
        .await
        .into_iter()
        .map(|r| r.expect("tracer DKG failed"))
        .collect()
}

#[tokio::test]
async fn combiner_derives_pk_e_from_tracer_public_keys_only() {
    let (n, n3) = (4, 4);
    let (mut combiner, tracers) = bootstrap(n, n3);

    let finished = run_all_dkgs(tracers, 8400).await;

    // Every tracer reached the same group key on its own.
    let pk_e = finished[0].0.pk_e.expect("pk_e");
    for (tracer, _) in &finished {
        assert_eq!(tracer.pk_e, Some(pk_e));
    }

    // The Combiner only gets pk_k from each tracer ...
    for (i, (tracer, _)) in finished.iter().enumerate() {
        let pkg = tracer
            .secure_package_for_combiner(&TracerPublicKeyPackage {
                pk: tracer.own_public_key(),
            })
            .expect("seal pk_k");
        combiner.load_tracer_public_key(i, &pkg).expect("pk_k accepted");
    }
    assert!(combiner.tracer_public_keys_complete());

    // ... and computes the very same pk_e = prod_k pk_k.
    combiner.finalize_group_key().expect("group key");
    assert_eq!(combiner.pk_e, Some(pk_e));
}

#[tokio::test]
async fn product_of_pk_k_equals_group_key() {
    let (_, tracers) = bootstrap(3, 3);
    let finished = run_all_dkgs(tracers, 8410).await;

    let mut product = Gt::identity();
    for (tracer, _) in &finished {
        product = product.add(&tracer.own_public_key());
    }
    assert_eq!(product.to_public_key(), finished[0].0.pk_e);
}

#[tokio::test]
async fn single_tracer_needs_no_peers() {
    let (mut combiner, tracers) = bootstrap(3, 1);
    let finished = run_all_dkgs(tracers, 8420).await;
    let (tracer, mesh) = &finished[0];

    assert_eq!(mesh.peer_count(), 0);

    let pkg = tracer
        .secure_package_for_combiner(&TracerPublicKeyPackage {
            pk: tracer.own_public_key(),
        })
        .expect("seal pk_k");
    combiner.load_tracer_public_key(0, &pkg).expect("pk_k accepted");
    combiner.finalize_group_key().expect("group key");
    assert_eq!(combiner.pk_e, tracer.pk_e);
}

#[tokio::test]
async fn mesh_routes_each_message_to_its_recipient() {
    let (_, tracers) = bootstrap(3, 3);
    let base_port = 8430;

    let jobs = tracers.iter().enumerate().map(|(i, tracer)| {
        let roster = tracer.peer_tracers.clone().expect("roster");
        let hello = hello_of(tracer, i);
        async move {
            let mut mesh = TracerMesh::establish(i, &roster, &hello, base_port).await?;
            let outgoing = mesh
                .peer_ids()
                .into_iter()
                .map(|w| {
                    let tag = Message::Hello {
                        id: i * 10 + w,
                        role: Role::Tracer,
                        pk: vec![],
                        identity_pk: vec![],
                    };
                    (w, tag)
                })
                .collect();
            let received = mesh.exchange(outgoing).await?;
            Ok::<_, Box<dyn Error>>((i, received))
        }
    });

    for result in join_all(jobs).await {
        let (me, received) = result.expect("exchange failed");
        assert_eq!(received.len(), 2);
        for (from, msg) in received {
            match msg {
                Message::Hello { id, .. } => assert_eq!(id, from * 10 + me),
                other => panic!("unexpected message {:?}", other),
            }
        }
    }
}

#[test]
fn share_sealed_for_one_tracer_cannot_be_opened_by_another() {
    let (_, mut tracers) = bootstrap(3, 3);
    for tracer in tracers.iter_mut() {
        tracer.start_dkg();
    }

    // Tracer 0 seals a share for tracer 1; tracer 2 must not be able to read it.
    let pkg = tracers[0].dkg_share_for_peer(1).expect("seal");
    assert!(tracers[1].open_from_peer::<DkgSharePayload>(0, &pkg).is_ok());
    assert!(tracers[2].open_from_peer::<DkgSharePayload>(0, &pkg).is_err());

    // And tracer 1 must reject it if it is attributed to the wrong sender.
    assert!(tracers[1].open_from_peer::<DkgSharePayload>(2, &pkg).is_err());
}

#[test]
fn combiner_rejects_pk_k_attributed_to_the_wrong_tracer() {
    let (mut combiner, mut tracers) = bootstrap(3, 2);
    for tracer in tracers.iter_mut() {
        tracer.start_dkg();
        tracer.load_own_dkg_share();
    }

    let pkg = tracers[0]
        .secure_package_for_combiner(&TracerPublicKeyPackage {
            pk: Gt::generator(),
        })
        .expect("seal");
    assert!(combiner.load_tracer_public_key(1, &pkg).is_err());
    assert!(combiner.load_tracer_public_key(0, &pkg).is_ok());
    assert!(!combiner.tracer_public_keys_complete());
}
