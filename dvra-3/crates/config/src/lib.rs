use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub lab: LabConfig,
    pub storage: StorageConfig,
    pub fetch: FetchConfig,
    pub post_process: PostProcessConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabConfig {
    pub enable_debug_routes: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub root: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchConfig {
    pub allowed_origins: Vec<String>,
    pub timeout_ms: u64,
    pub max_response_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostProcessConfig {
    pub shell_template: String,
    pub fixed_program: String,
    pub fixed_args: Vec<String>,
    // Deliberately included in Debug through the derive on this struct.
    pub secret_token: String,
    pub threat_model: ThreatModel,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ThreatModel {
    TrustedOperator,
    TenantControlled,
}

impl AppConfig {
    pub fn load_from_default_path() -> Result<Self, ConfigError> {
        let path = env::var_os("DVRA_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("config/dvra.toml"));
        Self::load(path)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        toml::from_str(&contents).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DangerousLabGate {
    enabled: bool,
}

#[derive(Debug, Clone)]
pub struct SsrfLabGate {
    enabled: bool,
}

impl SsrfLabGate {
    #[must_use]
    pub const fn disabled() -> Self {
        Self { enabled: false }
    }

    #[must_use]
    pub fn from_env() -> Self {
        let enabled = env::var("DVRA_SSRF_LAB_MODE").as_deref() == Ok("fake-metadata-only")
            && env::var("DVRA_ACK_INSECURE").as_deref() == Ok("I_UNDERSTAND");
        Self { enabled }
    }

    pub fn require_enabled(&self) -> Result<(), ConfigError> {
        if self.enabled {
            Ok(())
        } else {
            Err(ConfigError::SsrfLabDisabled)
        }
    }
}

impl DangerousLabGate {
    #[must_use]
    pub const fn disabled() -> Self {
        Self { enabled: false }
    }

    #[must_use]
    pub fn from_env() -> Self {
        let enabled = env::var("DVRA_LAB_MODE").as_deref() == Ok("vulnerable")
            && env::var("DVRA_ACK_INSECURE").as_deref() == Ok("I_UNDERSTAND");
        Self { enabled }
    }

    #[cfg(test)]
    fn enabled_for_test() -> Self {
        Self { enabled: true }
    }

    pub fn require_enabled(&self) -> Result<(), ConfigError> {
        if self.enabled {
            Ok(())
        } else {
            Err(ConfigError::DangerousLabDisabled)
        }
    }
}

#[derive(Debug, Clone)]
pub struct CommandRunner {
    config: PostProcessConfig,
    gate: DangerousLabGate,
}

impl CommandRunner {
    #[must_use]
    pub fn new(config: PostProcessConfig, gate: DangerousLabGate) -> Self {
        Self { config, gate }
    }

    /// DVRA-002: concatenates attacker-controlled input into a shell command.
    pub fn run_vulnerable(&self, artifact_name: &str) -> Result<Output, ConfigError> {
        self.gate.require_enabled()?;
        let template = &self.config.shell_template;
        let command = format!("{template} {artifact_name}");

        #[cfg(unix)]
        {
            Command::new("sh")
                .arg("-c")
                .arg(command)
                .output()
                .map_err(ConfigError::Execute)
        }

        #[cfg(not(unix))]
        {
            let _ = command;
            Err(ConfigError::UnsupportedPlatform)
        }
    }

    /// Uses an executable and individual arguments without a shell.
    pub fn run_fixed(&self, artifact_name: &str) -> Result<Output, ConfigError> {
        Command::new(&self.config.fixed_program)
            .args(&self.config.fixed_args)
            .arg(artifact_name)
            .output()
            .map_err(ConfigError::Execute)
    }
}

/// DVRA-006: a genuine shell-injection sink that is built as library code but is
/// not called by the API router or any production entry point.
pub mod unreachable_legacy_export {
    use std::process::{Command, Output};

    use super::ConfigError;

    pub fn export(path: &str) -> Result<Output, ConfigError> {
        #[cfg(unix)]
        {
            Command::new("sh")
                .arg("-c")
                .arg(format!("tar -cf /tmp/export.tar {path}"))
                .output()
                .map_err(ConfigError::Execute)
        }

        #[cfg(not(unix))]
        {
            let _ = path;
            Err(ConfigError::UnsupportedPlatform)
        }
    }
}

/// DVRA-006 decoy: scanners that flag any use of `Command` may report this, but
/// the untrusted value is passed as one argument and never interpreted by a shell.
pub fn safe_argument_example(untrusted: &str) -> Result<Output, ConfigError> {
    Command::new("printf")
        .arg("%s")
        .arg(untrusted)
        .output()
        .map_err(ConfigError::Execute)
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read configuration {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse configuration {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("dangerous command lab is disabled; use the isolated container and explicit acknowledgement")]
    DangerousLabDisabled,
    #[error("SSRF lab is disabled; use the isolated fake-metadata Docker profile")]
    SsrfLabDisabled,
    #[error("command execution failed: {0}")]
    Execute(std::io::Error),
    #[error("this lab currently supports Unix command semantics only")]
    UnsupportedPlatform,
}

#[cfg(test)]
mod tests {
    use super::{CommandRunner, ConfigError, DangerousLabGate, PostProcessConfig, ThreatModel};

    fn config() -> PostProcessConfig {
        PostProcessConfig {
            shell_template: "printf vulnerable".to_owned(),
            fixed_program: "printf".to_owned(),
            fixed_args: vec!["%s".to_owned()],
            secret_token: "test-secret".to_owned(),
            threat_model: ThreatModel::TenantControlled,
        }
    }

    #[test]
    fn vulnerable_runner_is_disabled_by_default() {
        let runner = CommandRunner::new(config(), DangerousLabGate::disabled());
        let error = runner
            .run_vulnerable("artifact; printf injected")
            .expect_err("dangerous runner must require acknowledgement");
        assert!(matches!(error, ConfigError::DangerousLabDisabled));
    }

    #[test]
    #[cfg(unix)]
    fn fixed_runner_treats_metacharacters_as_data() {
        let runner = CommandRunner::new(config(), DangerousLabGate::enabled_for_test());
        let output = runner
            .run_fixed("artifact; printf injected")
            .expect("printf should run");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "artifact; printf injected"
        );
    }
}
