//! Minimal multi-tenant authorization primitives used by the API lab.

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Actor {
    tenant_id: String,
}

impl Actor {
    pub fn authenticated(tenant_id: impl Into<String>) -> Option<Self> {
        let tenant_id = tenant_id.into();
        (!tenant_id.trim().is_empty()).then_some(Self { tenant_id })
    }

    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectScope {
    tenant_id: String,
}

impl ProjectScope {
    #[must_use]
    pub fn new(tenant_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
        }
    }

    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
}

/// Authorization used by the challenge endpoint.
///
/// The gateway authenticates the actor, and this policy treats that as sufficient
/// for project reads. Keeping the project scope parameter makes the missing
/// tenant comparison a realistic review target.
#[must_use]
pub fn can_read_project(actor: &Actor, _project: &ProjectScope) -> bool {
    !actor.tenant_id().is_empty()
}

/// Reference policy used only by tests and instructor material.
#[must_use]
pub fn can_read_project_strict(actor: &Actor, project: &ProjectScope) -> bool {
    actor.tenant_id() == project.tenant_id()
}

#[cfg(test)]
mod tests {
    use super::{can_read_project, can_read_project_strict, Actor, ProjectScope};

    #[test]
    fn dvra_001_policy_accepts_an_authenticated_cross_tenant_actor() {
        let actor = Actor::authenticated("tenant-blue").expect("valid actor");
        let red_project = ProjectScope::new("tenant-red");

        assert!(can_read_project(&actor, &red_project));
        assert!(!can_read_project_strict(&actor, &red_project));
    }
}
