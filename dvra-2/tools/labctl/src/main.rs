use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, ExitCode, Stdio},
    thread,
    time::{Duration, Instant},
};

const SCENARIOS: &[(&str, &str)] = &[
    ("DVRA-001", "IDOR between tenant projects"),
    (
        "DVRA-004",
        "tenant-controlled shell post-processing command",
    ),
    ("DVRA-006", "validator/normalizer parser offset mismatch"),
    ("DVRA-008", "panic-unsound unsafe collection"),
    ("DVRA-009", "invalid Send/Sync implementation"),
    (
        "DVRA-013",
        "real unsafe decoder defect in an unregistered route",
    ),
    ("DVRA-014", "safe fixed-program Command::new false positive"),
];

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("dvra-labctl: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = env::args().collect::<Vec<_>>();
    match args.get(1).map(String::as_str) {
        None | Some("help") | Some("--help") | Some("-h") => {
            print_help();
            Ok(())
        }
        Some("list") => {
            list_scenarios();
            Ok(())
        }
        Some("audit") => audit(),
        Some("doctor") => doctor(),
        Some("reproduce") if args.len() == 3 => reproduce(&args[2]),
        Some("reproduce") => Err("usage: dvra-labctl reproduce <DVRA-ID>".into()),
        Some(other) => Err(format!("unknown command: {other}").into()),
    }
}

fn print_help() {
    println!("usage: dvra-labctl <list|audit|doctor|reproduce>");
}

fn list_scenarios() {
    for (id, title) in SCENARIOS {
        println!("{id}: {title}");
    }
}

fn doctor() -> Result<(), Box<dyn Error>> {
    check_command("cargo", "cargo", &["--version"], Duration::from_secs(5))?;
    check_command("docker", "docker", &["--version"], Duration::from_secs(5))?;
    check_command("docker info", "docker", &["info"], Duration::from_secs(10))?;
    check_command(
        "docker compose config",
        "docker",
        &[
            "compose",
            "-f",
            workspace_root()
                .join("infrastructure/compose.yaml")
                .to_str()
                .ok_or("compose path is not valid utf-8")?,
            "--profile",
            "labs",
            "config",
        ],
        Duration::from_secs(15),
    )?;
    check_command(
        "docker buildx",
        "docker",
        &["buildx", "ls"],
        Duration::from_secs(10),
    )?;
    check_command(
        "cargo-fuzz",
        "cargo",
        &["fuzz", "--help"],
        Duration::from_secs(5),
    )?;
    check_command(
        "cargo-miri",
        "cargo",
        &["miri", "--version"],
        Duration::from_secs(5),
    )?;
    Ok(())
}

fn audit() -> Result<(), Box<dyn Error>> {
    let root = workspace_root();
    let mut failures = Vec::new();

    for path in required_paths() {
        require_path(&root, path, &mut failures);
    }

    for (id, _title) in SCENARIOS {
        let manifest = format!("scenarios/public/{id}.yaml");
        require_path(&root, &manifest, &mut failures);
        require_manifest_field(
            &root,
            &manifest,
            "benchmark_oracle: instructor-oracle/scenarios.yaml",
            &mut failures,
        );
        require_manifest_field(&root, &manifest, "reproducer:", &mut failures);
        require_manifest_field(&root, &manifest, "expected_signal:", &mut failures);
    }

    let public_dir = root.join("scenarios/public");
    let public_count = fs::read_dir(&public_dir)?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "yaml")
        })
        .count();
    if public_count != SCENARIOS.len() {
        failures.push(format!(
            "scenario registry has {} ids but {public_count} public manifests exist",
            SCENARIOS.len()
        ));
    }

    if failures.is_empty() {
        println!("ok: repository completeness audit");
        Ok(())
    } else {
        for failure in &failures {
            eprintln!("audit failure: {failure}");
        }
        Err(format!("{} audit failure(s)", failures.len()).into())
    }
}

fn required_paths() -> &'static [&'static str] {
    &[
        "README.md",
        "docs/completeness.md",
        "docs/instructor-guide.md",
        "docs/qa.md",
        "docs/threat-models.md",
        "docs/verification.md",
        "docs/benchmark-oracle.md",
        "docs/private-oracle.schema.example.yaml",
        "instructor-oracle/scenarios.yaml",
        "apps/api/src/lib.rs",
        "apps/mock-metadata-service/src/main.rs",
        "apps/worker/src/main.rs",
        "configs/operator-safe.yaml",
        "configs/tenant-vulnerable.yaml",
        "crates/auth/src/lib.rs",
        "crates/binary-parser/src/lib.rs",
        "crates/unsafe-cache/src/lib.rs",
        "crates/worker-engine/src/lib.rs",
        "fuzz/fuzz_targets/dvra_006_differential.rs",
        "fuzz/seeds/dvra-006/escaped-delimiter.dvra",
        "infrastructure/compose.yaml",
        "infrastructure/containers/Dockerfile",
        "infrastructure/containers/miri.Dockerfile",
        "infrastructure/seccomp/README.md",
        "labs/compiler-soundness/README.md",
        "labs/rudra-patterns/README.md",
        "labs/stdlib-archaeology/README.md",
        "labs/vulnerable-dependencies/README.md",
        "scenarios/fixtures/parser/basic.dvra",
        "scenarios/fixtures/parser/dvra-006.dvra",
        "tools/miri-reproduce.sh",
    ]
}

fn require_path(root: &Path, relative_path: &str, failures: &mut Vec<String>) {
    if !root.join(relative_path).exists() {
        failures.push(format!("missing required path: {relative_path}"));
    }
}

fn require_manifest_field(
    root: &Path,
    relative_path: &str,
    expected: &str,
    failures: &mut Vec<String>,
) {
    match fs::read_to_string(root.join(relative_path)) {
        Ok(contents) if contents.contains(expected) => {}
        Ok(_) => failures.push(format!("{relative_path} missing `{expected}`")),
        Err(error) => failures.push(format!("cannot read {relative_path}: {error}")),
    }
}

fn check_command(
    label: &str,
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<(), Box<dyn Error>> {
    let mut child = match Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            println!("missing or not ready: {label} ({error})");
            return Ok(());
        }
    };

    match wait_with_timeout(&mut child, timeout)? {
        Ok(status) if status.success() => {
            println!("ok: {label}");
        }
        Ok(status) => {
            println!("missing or not ready: {label} ({status})");
        }
        Err(()) => {
            let _ = child.kill();
            let _ = child.wait();
            println!("missing or not ready: {label} (timed out)");
        }
    }
    Ok(())
}

fn wait_with_timeout(
    child: &mut Child,
    timeout: Duration,
) -> Result<Result<std::process::ExitStatus, ()>, Box<dyn Error>> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            return Ok(Ok(status));
        }
        thread::sleep(Duration::from_millis(100));
    }
    Ok(Err(()))
}

fn reproduce(id: &str) -> Result<(), Box<dyn Error>> {
    let normalized = id.to_ascii_uppercase();
    match normalized.as_str() {
        "DVRA-001" | "001" => {
            run_cargo(&["test", "-p", "dvra-api", "dvra_001", "--", "--nocapture"])
        }
        "DVRA-004" | "004" => run_cargo(&[
            "test",
            "-p",
            "dvra-worker-engine",
            "dvra_004",
            "--",
            "--nocapture",
        ]),
        "DVRA-006" | "006" => run_cargo(&[
            "test",
            "-p",
            "dvra-binary-parser",
            "dvra_006",
            "--",
            "--nocapture",
        ]),
        "DVRA-008" | "008" => run_compose_service("dvra-miri-008"),
        "DVRA-009" | "009" => run_cargo(&[
            "test",
            "-p",
            "dvra-unsafe-cache",
            "--features",
            "loom-model",
            "dvra_009",
            "--",
            "--nocapture",
        ]),
        "DVRA-013" | "013" => run_compose_service("dvra-miri-013"),
        "DVRA-014" | "014" => run_cargo(&[
            "test",
            "-p",
            "dvra-worker-engine",
            "dvra_014",
            "--",
            "--nocapture",
        ]),
        _ => Err(format!("unknown scenario id: {id}").into()),
    }
}

fn run_cargo(args: &[&str]) -> Result<(), Box<dyn Error>> {
    run_command(Command::new("cargo").args(args))
}

fn run_compose_service(service: &str) -> Result<(), Box<dyn Error>> {
    let compose_path = workspace_root().join("infrastructure/compose.yaml");
    run_command(
        Command::new("docker")
            .arg("compose")
            .arg("-f")
            .arg(compose_path)
            .arg("--profile")
            .arg("labs")
            .arg("run")
            .arg("--rm")
            .arg(service),
    )
}

fn run_command(command: &mut Command) -> Result<(), Box<dyn Error>> {
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("command exited with {status}").into())
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}
