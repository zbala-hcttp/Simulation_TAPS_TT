use simulation_taps_tt::bench_config::{Scenario, default_scenarios, parse_args};

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| s.to_string()).collect()
}

#[test]
fn no_arguments_runs_default_suite_once() {
    let scenarios = parse_args(&[]).expect("valid");
    assert_eq!(scenarios, default_scenarios());
    assert!(scenarios.iter().all(|s| s.repeats == 1));
}

#[test]
fn n_and_n3_run_once() {
    assert_eq!(
        parse_args(&args(&["50", "5"])).expect("valid"),
        vec![Scenario { n: 50, n3: 5, repeats: 1 }]
    );
}

#[test]
fn repeats_is_taken_from_third_argument() {
    assert_eq!(
        parse_args(&args(&["100", "7", "20"])).expect("valid"),
        vec![Scenario { n: 100, n3: 7, repeats: 20 }]
    );
}

#[test]
fn rejects_zero_negative_and_non_numeric_values() {
    assert!(parse_args(&args(&["0", "5", "20"])).is_err());
    assert!(parse_args(&args(&["10", "0"])).is_err());
    assert!(parse_args(&args(&["10", "5", "0"])).is_err());
    assert!(parse_args(&args(&["-3", "5"])).is_err());
    assert!(parse_args(&args(&["ten", "5"])).is_err());
}

#[test]
fn rejects_wrong_argument_count() {
    assert!(parse_args(&args(&["10"])).is_err());
    assert!(parse_args(&args(&["10", "5", "20", "1"])).is_err());
}
