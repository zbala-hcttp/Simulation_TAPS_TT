use std::fs::OpenOptions;
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

fn main() {
    let scenarios = vec![
        (10, 6),
        (25, 13),
        (50, 26),
        (100, 51),
        (250, 126),
        (500, 251),
    ];

    let mut file_s = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("benchmark_results_signers.csv")
        .expect("Cannot open file");

    let mut file_c = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("benchmark_results_combiner.csv")
        .expect("Cannot open file");

    let mut file_t = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("benchmark_results_tracer.csv")
        .expect("Cannot open file");

    writeln!(file_s, "N,T,Signer_ID,Phase,Time_Microseconds").unwrap();
    writeln!(file_c, "N,T,Phase,Time_Microseconds").unwrap();
    writeln!(file_t, "N,T,Phase,Time_Microseconds").unwrap();

    println!("==================================================");
    println!("   STARTING TAPS BENCHMARK SUITE");
    println!("==================================================");

    let status = Command::new("cargo")
        .args(&["build", "--release", "--bins"])
        .status()
        .expect("Build failed");
    assert!(status.success(), "cargo build --release --bins failed");

    let mut failures = 0usize;

    for (n, t) in scenarios {
        if !run_scenario(n, t, &mut file_s, &mut file_c, &mut file_t) {
            failures += 1;
        }

        // Cool-down period to let OS reclaim ports (TIME_WAIT state)
        thread::sleep(Duration::from_secs(5));
    }

    println!("\n==================================================");
    if failures == 0 {
        println!("   ALL SCENARIOS COMPLETED SUCCESSFULLY");
    } else {
        // A scenario that dies partway through still produces a partially filled
        // CSV, so silence here would look just like success. Say it plainly.
        println!("   {} SCENARIO(S) FAILED - results are incomplete", failures);
    }
    println!("==================================================");

    if failures > 0 {
        std::process::exit(1);
    }
}

/// Runs one (n, t) scenario. Returns false if any actor failed.
fn run_scenario(
    n: usize,
    t: usize,
    file_s: &mut std::fs::File,
    file_c: &mut std::fs::File,
    file_t: &mut std::fs::File,
) -> bool {
    println!("\n>>> Running Scenario: N={} T={} <<<", n, t);

    let release_path = "target/release";
    let ext = if cfg!(target_os = "windows") { ".exe" } else { "" };

    let mut ok = true;

    let mut authority = Command::new(format!("{}/authority{}", release_path, ext))
        .arg(n.to_string())
        .arg(t.to_string())
        .stdout(Stdio::null()) // We don't need Authority logs
        .spawn()
        .expect("Failed to start Authority");
    thread::sleep(Duration::from_secs(2));

    let combiner = Command::new(format!("{}/combiner{}", release_path, ext))
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start Combiner");

    thread::sleep(Duration::from_secs(2));

    let tracer = Command::new(format!("{}/tracer{}", release_path, ext))
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start Tracer");

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
            "   [Combiner] EXITED WITH FAILURE ({:?}) for N={} T={}",
            output_c.status.code(),
            n,
            t
        );
        ok = false;
    }

    let stdout_str_c = String::from_utf8_lossy(&output_c.stdout);
    for line in stdout_str_c.lines() {
        if line.starts_with("BENCH") {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 3 {
                let phase = parts[1];
                let time = parts[2];
                writeln!(file_c, "{},{},{},{}", n, t, phase, time).unwrap();
                //println!("   [Combiner] {}: {} us", phase, time);
            }
        }
    }

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
        let stdout_str_s = String::from_utf8_lossy(&output_s.stdout);
        for line in stdout_str_s.lines() {
            if line.starts_with("BENCH") {
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 3 {
                    writeln!(file_s, "{},{},{},{},{}", n, t, i, parts[1], parts[2]).unwrap();
                    //println!("   [Signer] {}: {} us", parts[1], parts[2]);
                }
            }
        }
    }

    let output_t = tracer.wait_with_output().expect("Tracer failed");
    if !output_t.status.success() {
        eprintln!(
            "   [Tracer] EXITED WITH FAILURE ({:?}) - verification did not pass",
            output_t.status.code()
        );
        ok = false;
    }

    let stdout_str_t = String::from_utf8_lossy(&output_t.stdout);
    for line in stdout_str_t.lines() {
        if line.starts_with("BENCH") {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 3 {
                let phase = parts[1];
                let time = parts[2];
                writeln!(file_t, "{},{},{},{}", n, t, phase, time).unwrap();
                //println!("   [Tracer] {}: {} us", phase, time);
            }
        }
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

    ok
}
