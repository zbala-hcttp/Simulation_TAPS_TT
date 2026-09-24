# Simulation_TAPS_TT

A networked benchmark/simulation of the `TAPS_TT` protocol, with each role
(Authority, Combiner, Signer, Tracer) as its own OS process communicating
over TCP on localhost.

## Actors

- **Authority** (`bin/authority.rs`, port 8080) - a one-shot setup server.
  It generates key pairs for the signers and the combiner, computes the
  thresholds `t = floor(n/2) + 1` and `t_e = floor(2*n_3/3) + 1`, waits for
  every signer, the combiner and every tracer to connect, distributes signed
  and encrypted credentials to each of them, then exits. It never generates
  or sees any tracer secret.
- **Combiner** (`bin/combiner.rs`, port 8081) - the long-lived hub for
  the signing protocol. It runs the usual commit/challenge/respond rounds
  with the signers. On the tracer side it is deliberately agnostic of how
  the tracer keys come about: each tracer sends it only its public key
  `pk_k`, and it computes the group key `pk_e = prod_k pk_k` from those.
  It never sees a tracer's DKG broadcast, Shamir share or partial
  decryption, and it takes no part in tracing.
- **Signer** (`bin/signer.rs <id>`) - one signing participant; unaffected by
  the tracer side of the protocol.
- **Tracer** (`bin/tracer.rs <id>`, peer port `8200 + id`) - one of the
  `n_3` tracers. The tracers form their own peer-to-peer mesh
  (`src/tracer_mesh.rs`): tracer `k` listens on `127.0.0.1:(8200 + k)`,
  dials every lower-indexed tracer and accepts every higher-indexed one.
  Over that mesh, and only there, they run the distributed key generation
  (signed round-1 broadcasts, then Shamir shares each encrypted to their
  recipient) and later exchange their partial decryptions with
  Chaum-Pedersen proofs, each encrypted to its recipient. Each tracer then
  reports its `pk_k` to the Combiner, verifies the combiner's signature and
  accountability proof against its *own* `pk_e`, and combines any `t_e`
  valid partial decryptions (its own included) to recover the signing
  quorum.

Message flow between tracers and the Combiner:

```
tracer k  <--- DKG round 1 / shares / partial decryptions --->  tracer w   (mesh only)
tracer k  ---- pk_k ---------------------------------------->  Combiner   (pk_e = prod pk_k)
tracer k  <--- (T, v_i, proofs, sigma, m) --------------------  Combiner
```

`n_3 = 1` is fully supported: the tracer DKG degenerates to a single
qualified party with `t_e = 1` and an empty tracer mesh; the rest of the
flow runs unchanged.

## Running a scenario by hand

From this directory, in separate terminals (or backgrounded), with `N`
signers and `N3` tracers:

```
cargo run --release --bin authority -- <N> <N3>
cargo run --release --bin combiner
cargo run --release --bin tracer -- 0        # repeat for tracer ids 0..N3-1
cargo run --release --bin signer -- 0        # repeat for signer ids 0..N-1
```

The Authority must be started first (it publishes the trust anchor file
`taps_authority.pub` that every other actor reads), and the Combiner should
be up before the tracers and signers try to connect - they retry the
connection every 500ms until it is. Tracers likewise retry dialing their
lower-indexed peers until those are listening, so tracers can be started in
any order. Ports `8200 .. 8200 + N3 - 1` must be free.

## Benchmark suite

```
cargo run --release --bin benchmark -- <N> <N3> <REPEATS>
```

Builds every binary in release mode and runs the scenario with `N` signers
and `N3` tracers `REPEATS` times back to back (e.g. `-- 100 5 20` runs
`N=100, N3=5` twenty times), spawning the Authority, Combiner, `N3` tracers
and `N` signers as child processes for each run and checking that every
actor exits successfully. `REPEATS` is optional and defaults to 1. With no
arguments at all, a fixed default suite is run once per scenario (`N` in
`{10, 25, 50, 100}` crossed with `N3` in `{1, 5}`).

Per-phase timings (parsed from each actor's `BENCH,<phase>,<microseconds>`
stdout lines) are written to `benchmark_results_signers.csv`,
`benchmark_results_combiner.csv` and `benchmark_results_tracer.csv`, each
with a `Run` column (1..`REPEATS`) so the runs can be averaged. The files are
overwritten at the start of every invocation and flushed after each run, so
an interrupted series keeps the runs completed so far. A 5-second cool-down
separates consecutive runs so the OS can release the ports.

Summary statistics over the repeated runs go to a single file,
`benchmark_results_summary.csv`, with one row per scenario, role and
operation:

| Column | Meaning |
| --- | --- |
| `N`, `N3` | number of signers `n_1` and tracers `n_3` |
| `Runs` | number of successful runs of the scenario |
| `Role` | `signer`, `combiner` or `tracer` |
| `Operation` | the `BENCH` phase, e.g. `Setup`, `Commitment`, `Sigma` for a signer |
| `Samples` | number of measurements pooled: every actor of the role in every run, e.g. 10 signers x 20 runs = 200 |
| `Mean_Microseconds` | mean |
| `Std_Dev_Microseconds` | sample standard deviation (`n - 1` denominator; 0 for a single sample) |
| `Min_Microseconds`, `Max_Microseconds` | fastest and slowest measurement |

Only runs in which every actor exited successfully enter the summary
(failed runs remain in the raw files). The summary is rewritten after every
successful run, so it is also up to date if a long series is interrupted.

## Unit tests

```
cargo test
```

`tests/tracer_dkg_isolation.rs` runs the tracer DKG over a real in-process
tracer mesh and checks that the Combiner reaches the same `pk_e` from the
reported `pk_k` values alone, that the mesh routes each message to its
recipient, and that shares and `pk_k` reports are bound to their sender.
`tests/benchmark_args.rs` and `tests/benchmark_stats.rs` cover the benchmark
command-line parsing and the summary statistics.
