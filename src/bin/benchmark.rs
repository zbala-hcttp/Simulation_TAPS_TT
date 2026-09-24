use simulation_taps_tt::bench_config::{self, Scenario};
use simulation_taps_tt::bench_stats::{Actor, BenchRecord, Summarizer, collect_records};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

/// Raw per-run timings, one row per `BENCH` line.
const RAW_SIGNERS: &str = "benchmark_results_signers.csv";
const RAW_COMBINER: &str = "benchmark_results_combiner.csv";
const RAW_TRACER: &str = "benchmark_results_tracer.csv";

/// Per-operation statistics over every actor of a role and every
/// successful run of each scenario.
const SUMMARY: &str = "benchmark_results_summary.csv";

fn create_csv(path: &str, header: &str) -> File {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap_or_else(|e| panic!("Cannot open {}: {}", path, e));
    writeln!(file, "{}", header).unwrap();
    file
}

/// Appends one run's records to the raw CSV files.
fn write_raw(
    n: usize,
    n3: usize,
    run: usize,
    records: &[BenchRecord],
    file_s: &mut File,
    file_c: &mut File,
    file_t: &mut File,
) {
    for r in records {
        match r.actor {
            Actor::Combiner => {
                writeln!(file_c, "{},{},{},{},{}", n, n3, run, r.phase, r.micros).unwrap()
            }
            Actor::Signer(i) => {
                writeln!(file_s, "{},{},{},{},{},{}", n, n3, run, i, r.phase, r.micros).unwrap()
            }
            Actor::Tracer(k) => {
                writeln!(file_t, "{},{},{},{},{},{}", n, n3, run, k, r.phase, r.micros).unwrap()
            }
        }
    }
    file_s.flush().unwrap();
    file_c.flush().unwrap();
    file_t.flush().unwrap();
}

/// (Re)writes the summary CSV from everything collected so far.
fn write_summary(summarizer: &Summarizer) {
    let mut file = create_csv(
        SUMMARY,
        concat!(
            "N,N3,Runs,Role,Operation,Samples,",
            "Mean_Microseconds,Std_Dev_Microseconds,Min_Microseconds,Max_Microseconds"
        ),
    );
    for row in summarizer.summaries() {
        writeln!(
            file,
            "{},{},{},{},{},{},{:.2},{:.2},{},{}",
            row.n,
            row.n3,
            row.runs,
            row.role.name(),
            row.operation,
            row.samples,
            row.mean,
            row.std_dev,
            row.min,
            row.max
        )
        .unwrap();
    }
}

fn main() {
    // `benchmark [<n> <n3> [<repeats>]]`. The signer threshold
    // t = floor(n/2)+1 and the tracer threshold t_e = floor(2*n_3/3)+1 are
    // derived by the Authority itself.
    let cli_args: Vec<String> = std::env::args().skip(1).collect();
    let scenarios: Vec<Scenario> = match bench_config::parse_args(&cli_args) {
        Ok(scenarios) => scenarios,
        Err(e) => {
            eprintln!("{}\n\n{}", e, bench_config::USAGE);
            std::process::exit(2);
        }
    };

    let mut file_s = create_csv(RAW_SIGNERS, "N,N3,Run,Signer_ID,Phase,Time_Microseconds");
    let mut file_c = create_csv(RAW_COMBINER, "N,N3,Run,Phase,Time_Microseconds");
    let mut file_t = create_csv(RAW_TRACER, "N,N3,Run,Tracer_ID,Phase,Time_Microseconds");

    let mut summarizer = Summarizer::new();
    write_summary(&summarizer);

    println!("==================================================");
    println!("   STARTING TAPS_TT BENCHMARK SUITE");
    println!("==================================================");

    let status = Command::new("cargo")
        .args(&["build", "--release", "--bins"])
        .status()
        .expect("Build failed");
    assert!(status.success(), "cargo build --release --bins failed");

    let mut failures = 0usize;
    let total_runs: usize = scenarios.iter().map(|s| s.repeats).sum();
    let mut completed_runs = 0usize;

    for scenario in &scenarios {
        let mut scenario_failures = 0usize;
        for run in 1..=scenario.repeats {
            completed_runs += 1;
            let (ok, records) = run_scenario(scenario.n, scenario.n3, run, scenario.repeats);

            // Every run is kept in the raw files, failed ones included, so a
            // failure can be investigated. Only successful runs enter the
            // summary: a run that died partway would skew or leave gaps in it.
            write_raw(
                scenario.n,
                scenario.n3,
                run,
                &records,
                &mut file_s,
                &mut file_c,
                &mut file_t,
            );
            if ok {
                summarizer.add_run(scenario.n, scenario.n3, &records);
                // Rewritten after every run, so an interrupted series still
                // leaves the statistics of the runs completed so far.
                write_summary(&summarizer);
            } else {
                scenario_failures += 1;
            }

            // Cool-down period to let OS reclaim ports (TIME_WAIT state)
            if completed_runs < total_runs {
                thread::sleep(Duration::from_secs(5));
            }
        }

        println!(
            "\n>>> Scenario N={} N3={}: {}/{} run(s) succeeded <<<",
            scenario.n,
            scenario.n3,
            scenario.repeats - scenario_failures,
            scenario.repeats
        );
        failures += scenario_failures;
    }

    println!("\n==================================================");
    if failures == 0 {
        println!("   ALL {} RUN(S) COMPLETED SUCCESSFULLY", total_runs);
    } else {
        // A scenario that dies partway through still produces a partially filled
        // CSV, so silence here would look just like success. Say it plainly.
        println!(
            "   {} RUN(S) FAILED - excluded from the summary, raw results are incomplete",
            failures
        );
    }
    println!(
        "   Raw timings:  {}, {}, {}",
        RAW_SIGNERS, RAW_COMBINER, RAW_TRACER
    );
    println!("   Summary:      {}", SUMMARY);
    println!("==================================================");

    if failures > 0 {
        std::process::exit(1);
    }
}

/// Runs one (n_1, n_3) scenario once, as run number `run` of `repeats`.
/// Returns whether every actor succeeded, and every `BENCH` record printed.
fn run_scenario(n: usize, n3: usize, run: usize, repeats: usize) -> (bool, Vec<BenchRecord>) {
    println!(
        "\n>>> Running Scenario: N={} N3={} (run {}/{}) <<<",
        n, n3, run, repeats
    );

    let release_path = "target/release";
    let ext = if cfg!(target_os = "windows") { ".exe" } else { "" };

    let mut ok = true;
    let mut records: Vec<BenchRecord> = Vec::new();

    let mut authority = Command::new(format!("{}/authority{}", release_path, ext))
        .arg(n.to_string())
        .arg(n3.to_string())
        .stdout(Stdio::null()) // We don't need Authority logs
        .spawn()
        .expect("Failed to start Authority");
    thread::sleep(Duration::from_secs(2));

    let combiner = Command::new(format!("{}/combiner{}", release_path, ext))
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start Combiner");

    thread::sleep(Duration::from_secs(2));

    let mut tracer_handles: Vec<Child> = Vec::new();
    for k in 0..n3 {
        let t = Command::new(format!("{}/tracer{}", release_path, ext))
            .arg(k.to_string())
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to start tracer");
        tracer_handles.push(t);
        thread::sleep(Duration::from_millis(50));
    }

    let mut signer_handles: Vec<Child> = Vec::new();
    for i in 0..n {
        let s = Command::new(format!("{}/signer{}", release_path, ext))
            .arg(i.to_string())
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to start signer");
        signer_handles.push(s);
        thread::sleep(Duration::from_millis(10)); // Slight stagger
    }

    let output_c = combiner.wait_with_output().expect("Combiner failed");
    if !output_c.status.success() {
        eprintln!(
            "   [Combiner] EXITED WITH FAILURE ({:?}) for N={} N3={} run {}",
            output_c.status.code(),
            n,
            n3,
            run
        );
        ok = false;
    }
    records.extend(collect_records(
        Actor::Combiner,
        &String::from_utf8_lossy(&output_c.stdout),
    ));

    for (i, s) in signer_handles.into_iter().enumerate() {
        let output_s = s.wait_with_output().expect("Failed to wait on signer");
        if !output_s.status.success() {
            eprintln!(
                "   [Signer #{}] EXITED WITH FAILURE ({:?})",
                i,
                output_s.status.code()
            );
            ok = false;
        }
        records.extend(collect_records(
            Actor::Signer(i),
            &String::from_utf8_lossy(&output_s.stdout),
        ));
    }

    for (k, t) in tracer_handles.into_iter().enumerate() {
        let output_t = t.wait_with_output().expect("Tracer failed");
        if !output_t.status.success() {
            eprintln!(
                "   [Tracer #{}] EXITED WITH FAILURE ({:?}) - verification did not pass",
                k,
                output_t.status.code()
            );
            ok = false;
        }
        records.extend(collect_records(
            Actor::Tracer(k),
            &String::from_utf8_lossy(&output_t.stdout),
        ));
    }

    // The Authority exits on its own once setup is done; kill it only if it is
    // somehow still alive, so a stray process cannot hold port 8080.
    match authority.try_wait() {
        Ok(Some(status)) if !status.success() => {
            eprintln!("   [Authority] EXITED WITH FAILURE ({:?})", status.code());
            ok = false;
        }
        Ok(None) => {
            let _ = authority.kill();
            let _ = authority.wait();
        }
        _ => {}
    }

    (ok, records)
}
