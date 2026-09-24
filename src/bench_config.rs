//! Command-line configuration of the benchmark suite (`bin/benchmark.rs`).

/// One `(n_1, n_3)` scenario and how many times to run it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scenario {
    /// Number of signers `n_1`.
    pub n: usize,
    /// Number of tracers `n_3`.
    pub n3: usize,
    /// How many times the scenario is run back to back.
    pub repeats: usize,
}

pub const USAGE: &str = "Usage: benchmark [<n> <n3> [<repeats>]]\n\
     \n  <n>        number of signers (n_1), at least 1\
     \n  <n3>       number of tracers (n_3), at least 1\
     \n  <repeats>  how many times to run the scenario (default 1)\
     \n\nWith no arguments, runs the default suite once per scenario.";

/// The suite run when no arguments are given, each scenario once.
pub fn default_scenarios() -> Vec<Scenario> {
    [
        (10, 1),
        (10, 5),
        (25, 1),
        (25, 5),
        (50, 1),
        (50, 5),
        (100, 1),
        (100, 5),
    ]
    .into_iter()
    .map(|(n, n3)| Scenario { n, n3, repeats: 1 })
    .collect()
}

fn parse_positive(value: &str, name: &str) -> Result<usize, String> {
    match value.parse::<usize>() {
        Ok(v) if v >= 1 => Ok(v),
        _ => Err(format!("Invalid {}: '{}' (expected an integer >= 1)", name, value)),
    }
}

/// Parses the arguments after the program name.
///
/// - no arguments: the default suite;
/// - `<n> <n3>`: that scenario, once;
/// - `<n> <n3> <repeats>`: that scenario, `repeats` times.
pub fn parse_args(args: &[String]) -> Result<Vec<Scenario>, String> {
    match args {
        [] => Ok(default_scenarios()),
        [n, n3] => Ok(vec![Scenario {
            n: parse_positive(n, "n")?,
            n3: parse_positive(n3, "n3")?,
            repeats: 1,
        }]),
        [n, n3, repeats] => Ok(vec![Scenario {
            n: parse_positive(n, "n")?,
            n3: parse_positive(n3, "n3")?,
            repeats: parse_positive(repeats, "repeats")?,
        }]),
        _ => Err(format!("Expected 0, 2 or 3 arguments, got {}", args.len())),
    }
}
