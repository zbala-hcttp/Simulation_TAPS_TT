//! Per-operation timing records of the benchmark suite, and their averages
//! over repeated runs of a scenario.

use std::collections::HashMap;

/// Which process a timing came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Actor {
    Combiner,
    Signer(usize),
    Tracer(usize),
}

/// One `BENCH,<phase>,<microseconds>` line printed by an actor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchRecord {
    pub actor: Actor,
    pub phase: String,
    pub micros: u128,
}

/// Parses a `BENCH,<phase>,<microseconds>` stdout line into
/// `(phase, microseconds)`. Any other line yields `None`.
pub fn parse_bench_line(line: &str) -> Option<(String, u128)> {
    let mut parts = line.trim().splitn(3, ',');
    if parts.next()? != "BENCH" {
        return None;
    }
    let phase = parts.next()?.to_string();
    let micros = parts.next()?.trim().parse::<u128>().ok()?;
    Some((phase, micros))
}

/// Collects every `BENCH` record from one actor's stdout.
pub fn collect_records(actor: Actor, stdout: &str) -> Vec<BenchRecord> {
    stdout
        .lines()
        .filter_map(parse_bench_line)
        .map(|(phase, micros)| BenchRecord {
            actor,
            phase,
            micros,
        })
        .collect()
}

/// The kind of actor, ignoring its id. Summary statistics pool every actor
/// of the same role together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    Signer,
    Combiner,
    Tracer,
}

impl Role {
    pub fn of(actor: Actor) -> Role {
        match actor {
            Actor::Signer(_) => Role::Signer,
            Actor::Combiner => Role::Combiner,
            Actor::Tracer(_) => Role::Tracer,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Role::Signer => "signer",
            Role::Combiner => "combiner",
            Role::Tracer => "tracer",
        }
    }
}

/// Statistics of one operation of one role in one `(n, n_3)` scenario, over
/// every actor of that role and every successful run.
#[derive(Debug, Clone, PartialEq)]
pub struct OperationSummary {
    pub n: usize,
    pub n3: usize,
    /// Number of successful runs of the scenario.
    pub runs: usize,
    pub role: Role,
    pub operation: String,
    /// Number of measurements, e.g. `n * runs` for a signer operation.
    pub samples: usize,
    pub mean: f64,
    /// Sample standard deviation (`n - 1` denominator); 0 for one sample.
    pub std_dev: f64,
    pub min: u128,
    pub max: u128,
}

type Key = (usize, usize, Role, String);

/// Collects every measurement of every successful run.
#[derive(Debug, Default)]
pub struct Summarizer {
    /// Keys in first-seen order, so operations keep their protocol order.
    order: Vec<Key>,
    samples: HashMap<Key, Vec<u128>>,
    runs: HashMap<(usize, usize), usize>,
}

impl Summarizer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds every record of one successful run of scenario `(n, n3)`.
    pub fn add_run(&mut self, n: usize, n3: usize, records: &[BenchRecord]) {
        *self.runs.entry((n, n3)).or_insert(0) += 1;
        for record in records {
            let key: Key = (n, n3, Role::of(record.actor), record.phase.clone());
            self.samples
                .entry(key.clone())
                .or_insert_with(|| {
                    self.order.push(key);
                    Vec::new()
                })
                .push(record.micros);
        }
    }

    /// One summary per scenario, role (signer, combiner, tracer) and
    /// operation, with each role's operations in protocol order.
    pub fn summaries(&self) -> Vec<OperationSummary> {
        let mut keys = self.order.clone();
        // Stable sort: operations of one role keep their first-seen order.
        keys.sort_by_key(|(n, n3, role, _)| (*n, *n3, *role));
        keys.into_iter()
            .map(|key| {
                let values = &self.samples[&key];
                let (n, n3, role, operation) = key;
                let count = values.len();
                let mean = values.iter().map(|&v| v as f64).sum::<f64>() / count as f64;
                let std_dev = if count > 1 {
                    let squares: f64 = values.iter().map(|&v| (v as f64 - mean).powi(2)).sum();
                    (squares / (count - 1) as f64).sqrt()
                } else {
                    0.0
                };
                OperationSummary {
                    n,
                    n3,
                    runs: self.runs[&(n, n3)],
                    role,
                    operation,
                    samples: count,
                    mean,
                    std_dev,
                    min: *values.iter().min().expect("non-empty"),
                    max: *values.iter().max().expect("non-empty"),
                }
            })
            .collect()
    }
}
