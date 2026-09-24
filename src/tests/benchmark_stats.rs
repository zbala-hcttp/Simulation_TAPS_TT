use simulation_taps_tt::bench_stats::{
    Actor, BenchRecord, Role, Summarizer, collect_records, parse_bench_line,
};

fn record(actor: Actor, phase: &str, micros: u128) -> BenchRecord {
    BenchRecord {
        actor,
        phase: phase.to_string(),
        micros,
    }
}

#[test]
fn parses_only_well_formed_bench_lines() {
    assert_eq!(parse_bench_line("BENCH,Setup,123"), Some(("Setup".to_string(), 123)));
    assert_eq!(
        parse_bench_line("BENCH,Compute Parameters,42\r"),
        Some(("Compute Parameters".to_string(), 42))
    );
    assert_eq!(parse_bench_line("Aggregation,17"), None);
    assert_eq!(parse_bench_line("[Signer] BENCH,Setup,1"), None);
    assert_eq!(parse_bench_line("BENCH,Setup,abc"), None);
    assert_eq!(parse_bench_line("BENCH,Setup"), None);
}

#[test]
fn collects_records_from_actor_stdout() {
    let stdout = "[Signer #3] starting\nBENCH,Setup,10\nBENCH,Commitment,20\nsome log\nBENCH,Sign,30\n";
    let records = collect_records(Actor::Signer(3), stdout);
    assert_eq!(
        records,
        vec![
            record(Actor::Signer(3), "Setup", 10),
            record(Actor::Signer(3), "Commitment", 20),
            record(Actor::Signer(3), "Sign", 30),
        ]
    );
}

#[test]
fn pools_every_actor_of_a_role_over_every_run() {
    let mut summarizer = Summarizer::new();
    // Two runs of N=2, N3=1: two signers, one combiner, one tracer.
    summarizer.add_run(
        2,
        1,
        &[
            record(Actor::Combiner, "GroupKey", 100),
            record(Actor::Signer(0), "Setup", 10),
            record(Actor::Signer(1), "Setup", 30),
            record(Actor::Tracer(0), "TracerDkg", 5),
        ],
    );
    summarizer.add_run(
        2,
        1,
        &[
            record(Actor::Combiner, "GroupKey", 200),
            record(Actor::Signer(0), "Setup", 20),
            record(Actor::Signer(1), "Setup", 40),
            record(Actor::Tracer(0), "TracerDkg", 15),
        ],
    );

    let rows = summarizer.summaries();
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|r| r.n == 2 && r.n3 == 1 && r.runs == 2));

    // Signer "Setup": 2 signers x 2 runs = 4 samples {10, 30, 20, 40}.
    let setup = rows
        .iter()
        .find(|r| r.role == Role::Signer && r.operation == "Setup")
        .expect("signer setup");
    assert_eq!(setup.samples, 4);
    assert_eq!(setup.mean, 25.0);
    assert_eq!(setup.min, 10);
    assert_eq!(setup.max, 40);
    // Sample std dev: sqrt(((15^2 + 5^2 + 5^2 + 15^2)) / 3) = sqrt(500/3).
    assert!((setup.std_dev - (500.0f64 / 3.0).sqrt()).abs() < 1e-9);

    let group_key = rows
        .iter()
        .find(|r| r.role == Role::Combiner)
        .expect("combiner");
    assert_eq!((group_key.samples, group_key.mean), (2, 150.0));
    assert_eq!((group_key.min, group_key.max), (100, 200));

    let dkg = rows.iter().find(|r| r.role == Role::Tracer).expect("tracer");
    assert_eq!((dkg.samples, dkg.mean), (2, 10.0));
}

#[test]
fn single_sample_has_zero_std_dev() {
    let mut summarizer = Summarizer::new();
    summarizer.add_run(1, 1, &[record(Actor::Signer(0), "Setup", 7)]);
    let row = &summarizer.summaries()[0];
    assert_eq!((row.samples, row.runs), (1, 1));
    assert_eq!((row.mean, row.std_dev, row.min, row.max), (7.0, 0.0, 7, 7));
}

#[test]
fn orders_scenarios_then_roles_then_protocol_order() {
    let mut summarizer = Summarizer::new();
    summarizer.add_run(
        10,
        5,
        &[
            record(Actor::Tracer(0), "TracerDkg", 1),
            record(Actor::Combiner, "Setup", 1),
            record(Actor::Signer(1), "Setup", 1),
            record(Actor::Signer(0), "Commitment", 1),
            record(Actor::Signer(0), "Sigma", 1),
        ],
    );
    summarizer.add_run(10, 1, &[record(Actor::Signer(0), "Setup", 7)]);

    let rows: Vec<(usize, usize, Role, String)> = summarizer
        .summaries()
        .into_iter()
        .map(|r| (r.n, r.n3, r.role, r.operation))
        .collect();

    assert_eq!(
        rows,
        vec![
            (10, 1, Role::Signer, "Setup".to_string()),
            (10, 5, Role::Signer, "Setup".to_string()),
            (10, 5, Role::Signer, "Commitment".to_string()),
            (10, 5, Role::Signer, "Sigma".to_string()),
            (10, 5, Role::Combiner, "Setup".to_string()),
            (10, 5, Role::Tracer, "TracerDkg".to_string()),
        ]
    );
}
