//! HTTP surface for the artifact service lab.

use std::{collections::HashMap, sync::Arc};

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use dvra_auth::{can_read_project, Actor, ProjectScope};
use dvra_binary_parser::legacy_decode;
use serde::Serialize;

#[derive(Clone, Debug)]
struct Project {
    tenant_id: String,
    artifacts: HashMap<String, Artifact>,
}

#[derive(Clone, Debug, Serialize)]
struct Artifact {
    id: String,
    project_id: String,
    label: String,
    body: String,
}

#[derive(Clone, Debug, Default)]
pub struct AppState {
    projects: HashMap<String, Project>,
}

#[derive(Clone, Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
}

pub fn app() -> Router {
    Router::new()
        .route("/health", get(health))
        .route(
            "/api/projects/{project_id}/artifacts/{artifact_id}",
            get(get_artifact),
        )
        .with_state(Arc::new(AppState::seeded()))
}

async fn health() -> &'static str {
    "ok"
}

async fn get_artifact(
    State(state): State<Arc<AppState>>,
    Path((project_id, artifact_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(actor) = actor_from_headers(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "missing tenant identity",
            }),
        )
            .into_response();
    };

    let Some(project) = state.projects.get(&project_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "project not found",
            }),
        )
            .into_response();
    };

    let project_scope = ProjectScope::new(project.tenant_id.clone());
    if !can_read_project(&actor, &project_scope) {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorBody { error: "forbidden" }),
        )
            .into_response();
    }

    match project.artifacts.get(&artifact_id) {
        Some(artifact) => (StatusCode::OK, Json(artifact)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "artifact not found",
            }),
        )
            .into_response(),
    }
}

fn actor_from_headers(headers: &HeaderMap) -> Option<Actor> {
    headers
        .get("x-tenant-id")
        .and_then(|value| value.to_str().ok())
        .and_then(Actor::authenticated)
}

/// Legacy decoder endpoint kept as a realistic dead route for DVRA-013.
///
/// The function is built and callable from tests, but it is intentionally not
/// registered in `app()`.
pub async fn unregistered_legacy_decode(body: Bytes) -> Json<serde_json::Value> {
    let record = legacy_decode(&body);
    Json(serde_json::json!({
        "tag": record.tag,
        "payload_len": record.payload.len(),
    }))
}

impl AppState {
    fn seeded() -> Self {
        let mut projects = HashMap::new();
        projects.insert(
            "red-proj".to_owned(),
            Project {
                tenant_id: "tenant-red".to_owned(),
                artifacts: HashMap::from([(
                    "release-plan".to_owned(),
                    Artifact {
                        id: "release-plan".to_owned(),
                        project_id: "red-proj".to_owned(),
                        label: "red team release plan".to_owned(),
                        body: "internal artifact visible through DVRA-001".to_owned(),
                    },
                )]),
            },
        );
        projects.insert(
            "blue-proj".to_owned(),
            Project {
                tenant_id: "tenant-blue".to_owned(),
                artifacts: HashMap::from([(
                    "sample".to_owned(),
                    Artifact {
                        id: "sample".to_owned(),
                        project_id: "blue-proj".to_owned(),
                        label: "blue sample".to_owned(),
                        body: "ordinary tenant-owned artifact".to_owned(),
                    },
                )]),
            },
        );
        Self { projects }
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    use super::app;

    #[tokio::test]
    async fn dvra_001_cross_tenant_actor_can_read_foreign_artifact() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/projects/red-proj/artifacts/release-plan")
                    .header("x-tenant-id", "tenant-blue")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let body = String::from_utf8(bytes.to_vec()).expect("utf8");
        assert!(body.contains("red team release plan"));
    }

    #[tokio::test]
    async fn artifact_reads_require_an_authenticated_actor() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/projects/red-proj/artifacts/release-plan")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn dvra_013_legacy_decoder_route_is_not_registered() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/legacy/decode")
                    .header("x-tenant-id", "tenant-red")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
