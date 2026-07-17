use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Artifact {
    pub id: u64,
    pub tenant: String,
    pub name: String,
    pub classification: String,
}

#[derive(Debug, Clone, Default)]
pub struct ArtifactStore {
    artifacts: Arc<RwLock<HashMap<u64, Artifact>>>,
}

impl ArtifactStore {
    #[must_use]
    pub fn seeded() -> Self {
        let artifacts = HashMap::from([
            (
                1,
                Artifact {
                    id: 1,
                    tenant: "blue".to_owned(),
                    name: "public-release.tar".to_owned(),
                    classification: "internal".to_owned(),
                },
            ),
            (
                2,
                Artifact {
                    id: 2,
                    tenant: "red".to_owned(),
                    name: "acquisition-plan.zip".to_owned(),
                    classification: "restricted".to_owned(),
                },
            ),
        ]);
        Self {
            artifacts: Arc::new(RwLock::new(artifacts)),
        }
    }

    #[must_use]
    pub fn find_artifact(&self, id: u64) -> Option<Artifact> {
        self.read().get(&id).cloned()
    }

fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<u64, Artifact>> {
        self.artifacts
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}


