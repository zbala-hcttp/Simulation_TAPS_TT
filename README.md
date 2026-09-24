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
- **Combiner** (`bin/combiner.rs`, port 8081) - the long-lived hub. Besides
  running the usual commit/challenge/respond signing rounds with the
  signers, it also relays the tracers' distributed key generation (their
  round-1 broadcasts and round-2 point-to-point Shamir shares), collects
  their public shares to compute the group tracer key `pk_e`, and later
  relays their partial decryptions to each other so they can jointly trace
  the quorum. It only ever routes tracer-to-tracer material it cannot
  itself decrypt - it never learns a tracer secret either.
- **Signer** (`bin/signer.rs <id>`) - one signing participant; unaffected by
  the tracer side of the protocol.
- **Tracer** (`bin/tracer.rs <id>`) - one of the `n_3` tracers. Runs its
  share of the distributed key generation, verifies the combiner's
  signature and accountability proof, computes its own partial decryption
  with a Chaum-Pedersen proof, and combines any `t_e` valid partial
  decryptions (its own included) to recover the signing quorum.

`n_3 = 1` is fully supported: the tracer DKG degenerates to a single
qualified party with `t_e = 1`, and the rest of the flow - including the
partial-decryption relay - runs unchanged.

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
connection every 500ms until it is.

## Benchmark suite

```
cargo run --release --bin benchmark
```

Builds every binary in release mode and runs a fixed set of `(N, N3)`
scenarios (currently `N` in `{10, 25, 50, 100}` crossed with `N3` in
`{1, 5}`), spawning the Authority, Combiner, `N3` tracers and `N` signers as
child processes for each one and checking that every actor exits
successfully. Per-phase timings (parsed from each actor's `BENCH,<phase>,
<microseconds>` stdout lines) are written to `benchmark_results_signers.csv`,
`benchmark_results_combiner.csv` and `benchmark_results_tracer.csv`.

## Unit tests

```
cargo test
```

