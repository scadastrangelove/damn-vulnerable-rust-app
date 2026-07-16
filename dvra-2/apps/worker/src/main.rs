use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use dvra_binary_parser::{normalize, parse_fast, validate};
use dvra_config::WorkerConfig;
use dvra_worker_engine::run_post_process;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("dvra-worker: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() == 1 {
        print_help();
        return Ok(());
    }

    match args.get(1).map(String::as_str) {
        Some("process") if args.len() == 5 => process_artifact(&args[2], &args[3], &args[4]),
        _ => {
            print_help();
            Err("invalid arguments".into())
        }
    }
}

fn process_artifact(
    config_path: &str,
    input_path: &str,
    work_dir: &str,
) -> Result<(), Box<dyn Error>> {
    require_isolated_lab_mode()?;

    let work_dir = prepare_lab_work_dir(Path::new(work_dir))?;
    let config = WorkerConfig::from_yaml_path(config_path)?;
    let input = fs::read(input_path)?;
    let validated = validate(&input)?;
    let normalized = if config.parser.normalize_escapes {
        normalize(&input)
    } else {
        input.clone()
    };
    let parsed = parse_fast(&validated, &normalized);

    println!(
        "processed {} bytes from {}",
        parsed.len(),
        Path::new(input_path).display()
    );

    if let Some(post_process) = config.post_process {
        let status = run_post_process(&post_process, Path::new(input_path), &work_dir)?;
        println!("post_process exited with {status}");
    }

    Ok(())
}

fn require_isolated_lab_mode() -> Result<(), Box<dyn Error>> {
    match env::var("DVRA_LAB_MODE").as_deref() {
        Ok("isolated") => Ok(()),
        _ => Err("refusing to run process mode without DVRA_LAB_MODE=isolated".into()),
    }
}

fn prepare_lab_work_dir(path: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let lab_root = Path::new("/tmp/dvra");
    fs::create_dir_all(lab_root)?;
    let canonical_lab_root = fs::canonicalize(lab_root)?;

    fs::create_dir_all(path)?;
    let canonical = fs::canonicalize(path)?;
    if !canonical.starts_with(&canonical_lab_root) {
        return Err(format!(
            "work directory must be under /tmp/dvra, got {}",
            canonical.display()
        )
        .into());
    }
    Ok(canonical)
}

fn print_help() {
    eprintln!("usage: dvra-worker process <config.yaml> <artifact.dvra> <work-dir>");
    eprintln!("       requires DVRA_LAB_MODE=isolated and a work-dir under /tmp/dvra");
}
