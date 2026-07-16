//! YAML and environment-backed configuration for the worker lab.

use std::{env, error::Error, fmt, fs, path::Path};

use serde::Deserialize;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ConfigAuthority {
    OperatorOnly,
    TenantProject,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ParserConfig {
    #[serde(default = "default_true")]
    pub normalize_escapes: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct PostProcessConfig {
    pub authority: ConfigAuthority,
    pub command: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct WorkerConfig {
    #[serde(default)]
    pub parser: ParserConfig,
    pub post_process: Option<PostProcessConfig>,
}

impl Default for ParserConfig {
    fn default() -> Self {
        Self {
            normalize_escapes: true,
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Yaml(serde_yaml::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "failed to read configuration: {error}"),
            Self::Yaml(error) => write!(formatter, "invalid YAML configuration: {error}"),
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Yaml(error) => Some(error),
        }
    }
}

impl From<std::io::Error> for ConfigError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_yaml::Error> for ConfigError {
    fn from(error: serde_yaml::Error) -> Self {
        Self::Yaml(error)
    }
}

impl WorkerConfig {
    pub fn from_yaml_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let source = fs::read_to_string(path)?;
        let mut config: Self = serde_yaml::from_str(&source)?;
        config.apply_environment();
        Ok(config)
    }

    /// Environment values intentionally override YAML to model layered config.
    pub fn apply_environment(&mut self) {
        if let Ok(command) = env::var("DVRA_POST_PROCESS_COMMAND") {
            match &mut self.post_process {
                Some(post_process) => post_process.command = command,
                None => {
                    self.post_process = Some(PostProcessConfig {
                        authority: ConfigAuthority::OperatorOnly,
                        command,
                    });
                }
            }
        }
    }
}

const fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::{ConfigAuthority, WorkerConfig};

    #[test]
    fn parses_tenant_controlled_post_processing() {
        let config: WorkerConfig = serde_yaml::from_str(
            r#"
parser:
  normalize_escapes: true
post_process:
  authority: tenant-project
  command: "printf owned"
"#,
        )
        .expect("valid fixture");

        let post_process = config.post_process.expect("post process");
        assert_eq!(post_process.authority, ConfigAuthority::TenantProject);
        assert_eq!(post_process.command, "printf owned");
    }
}
