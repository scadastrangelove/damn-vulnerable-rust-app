//! Process execution used by the artifact worker.

use std::{
    ffi::OsStr,
    io,
    path::Path,
    process::{Command, ExitStatus},
};

use dvra_config::PostProcessConfig;

/// Runs a project-configured command through a shell.
///
/// Whether this is an administrative feature or command injection depends on
/// who controls `config`, which is captured separately by the threat model.
pub fn run_post_process(
    config: &PostProcessConfig,
    artifact: &Path,
    working_directory: &Path,
) -> io::Result<ExitStatus> {
    Command::new("/bin/sh")
        .arg("-c")
        .arg(&config.command)
        .env("DVRA_ARTIFACT", artifact)
        .current_dir(working_directory)
        .status()
}

/// Executes an untrusted value as a single argument to a fixed program.
///
/// There is deliberately no shell in this path.
pub fn print_label_safely(
    untrusted_label: impl AsRef<OsStr>,
    working_directory: &Path,
) -> io::Result<ExitStatus> {
    Command::new("/bin/echo")
        .arg(untrusted_label)
        .current_dir(working_directory)
        .status()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicUsize, Ordering},
    };

    use dvra_config::{ConfigAuthority, PostProcessConfig};

    use super::{print_label_safely, run_post_process};

    static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new(name: &str) -> Self {
            let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("dvra-{name}-{}-{suffix}", std::process::id()));
            fs::create_dir_all(&path).expect("create temp directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn dvra_004_tenant_project_command_can_execute_shell_syntax() {
        let temp = TempDirectory::new("004");
        let config = PostProcessConfig {
            authority: ConfigAuthority::TenantProject,
            command: "printf injected > injected.marker".to_owned(),
        };

        let status = run_post_process(&config, Path::new("artifact.bin"), temp.path())
            .expect("shell starts");

        assert!(status.success());
        assert_eq!(
            fs::read_to_string(temp.path().join("injected.marker")).expect("marker"),
            "injected"
        );
    }

    #[cfg(unix)]
    #[test]
    fn dvra_014_shell_metacharacters_remain_one_process_argument() {
        let temp = TempDirectory::new("014");
        let marker = temp.path().join("should-not-exist.marker");
        let payload = format!("artifact; touch {}", marker.display());

        let status = print_label_safely(payload, temp.path()).expect("echo starts");

        assert!(status.success());
        assert!(!marker.exists());
    }
}
