use std::{sync::Arc, time::Duration};

use anyhow::Context;
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json,
};
use dvra_config::{AppConfig, CommandRunner, DangerousLabGate, SsrfLabGate};
use dvra_core::{Artifact, ArtifactStore};
use dvra_fetch::{FetchResponse, Fetcher};
use serde::{Deserialize, Serialize};
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
struct ApiState {
    store: ArtifactStore,
    config: Arc<AppConfig>,
    command_runner: CommandRunner,
    fetcher: Fetcher,
    lab_gate: DangerousLabGate,
    ssrf_lab_gate: SsrfLabGate,
}

#[derive(Debug, Serialize)]
struct Health {
    status: &'static str,
    service: &'static str,
}

#[derive(Debug, Deserialize)]
struct PostProcessRequest {
    artifact_name: String,
}

#[derive(Debug, Deserialize)]
struct FetchRequest {
    url: String,
}

#[derive(Debug, Serialize)]
struct ExtractionResult {
    files: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CommandResult {
    status: i32,
    stdout: String,
    stderr: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }

    fn bad_gateway(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(serde_json::json!({ "error": self.message }))).into_response()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("dvra=info")),
        )
        .init();

    let config = Arc::new(AppConfig::load_from_default_path()?);
    let gate = DangerousLabGate::from_env();
    let ssrf_lab_gate = SsrfLabGate::from_env();
    let command_runner = CommandRunner::new(config.post_process.clone(), gate.clone());
    let fetcher = Fetcher::new(
        &config.fetch.allowed_origins,
        Duration::from_millis(config.fetch.timeout_ms),
        config.fetch.max_response_bytes,
    )
    .context("building HTTP fetch clients")?;
    let state = ApiState {
        store: ArtifactStore::seeded(),
        config: Arc::clone(&config),
        command_runner,
        fetcher,
        lab_gate: gate,
        ssrf_lab_gate,
    };

    let mut app = Router::new()
        .route("/health", get(health))
        .route("/v1/artifacts/{id}", get(get_artifact_vulnerable))
        .route("/v1/fixed/artifacts/{id}", get(get_artifact_fixed))
        .route(
            "/v1/parse",
            post(parse_vulnerable).layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/v1/fixed/parse",
            post(parse_fixed).layer(DefaultBodyLimit::max(64 * 1024)),
        )
        .route(
            "/v1/bundles/{job_id}",
            post(extract_bundle_vulnerable).layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/v1/fixed/bundles/{job_id}",
            post(extract_bundle_fixed).layer(DefaultBodyLimit::max(1024 * 1024)),
        )
        .route("/v1/post-process", post(post_process_vulnerable))
        .route("/v1/fixed/post-process", post(post_process_fixed))
        .route(
            "/v1/fetch",
            post(fetch_vulnerable).layer(DefaultBodyLimit::max(8 * 1024)),
        )
        .route(
            "/v1/fixed/fetch",
            post(fetch_fixed).layer(DefaultBodyLimit::max(8 * 1024)),
        );

    if config.lab.enable_debug_routes {
        app = app.route("/v1/debug/config", get(debug_config));
    }

    let app = app.with_state(state);
    let listener = tokio::net::TcpListener::bind(&config.server.bind)
        .await
        .with_context(|| {
            let bind = &config.server.bind;
            format!("binding {bind}")
        })?;

    tracing::info!(bind = %config.server.bind, "DVRA API listening");
    axum::serve(listener, app).await.context("serving DVRA API")?;
    Ok(())
}

async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        service: "dvra-api",
    })
}

async fn get_artifact_vulnerable(
    State(state): State<ApiState>,
    Path(id): Path<u64>,
    headers: HeaderMap,
) -> Result<Json<Artifact>, ApiError> {
    let claimed_tenant = tenant_from_headers(&headers)?;

    // DVRA-001: the caller is authenticated to a tenant, but the lookup is not
    // scoped to that tenant. The value is used only for logging.
    let artifact = state
        .store
        .get_unscoped(id)
        .ok_or_else(|| ApiError::not_found("artifact not found"))?;
    tracing::info!(%claimed_tenant, artifact_id = id, "artifact read");
    Ok(Json(artifact))
}

async fn get_artifact_fixed(
    State(state): State<ApiState>,
    Path(id): Path<u64>,
    headers: HeaderMap,
) -> Result<Json<Artifact>, ApiError> {
    let tenant = tenant_from_headers(&headers)?;
    let artifact = state
        .store
        .get_scoped(&tenant, id)
        .ok_or_else(|| ApiError::not_found("artifact not found"))?;
    Ok(Json(artifact))
}

async fn parse_vulnerable(body: Bytes) -> Result<Json<dvra_parser::Document>, ApiError> {
    // DVRA-003: validation offsets are calculated before normalization and then
    // used against the shorter normalized buffer. A fuzz seed triggers a panic.
    let document = dvra_parser::parse_vulnerable(&body)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    Ok(Json(document))
}

async fn parse_fixed(body: Bytes) -> Result<Json<dvra_parser::Document>, ApiError> {
    let document = dvra_parser::parse_reference(&body)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    Ok(Json(document))
}

async fn extract_bundle_vulnerable(
    State(state): State<ApiState>,
    Path(job_id): Path<u64>,
    body: Bytes,
) -> Result<Json<ExtractionResult>, ApiError> {
    state
        .lab_gate
        .require_enabled()
        .map_err(|error| ApiError::forbidden(error.to_string()))?;
    let destination = state.config.storage.root.join(format!("job-{job_id}"));
    let files = dvra_bundle::extract_vulnerable(&body, &destination)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    Ok(Json(extraction_result(files)))
}

async fn extract_bundle_fixed(
    State(state): State<ApiState>,
    Path(job_id): Path<u64>,
    body: Bytes,
) -> Result<Json<ExtractionResult>, ApiError> {
    let destination = state.config.storage.root.join(format!("job-{job_id}"));
    let files = dvra_bundle::extract_fixed(&body, &destination)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    Ok(Json(extraction_result(files)))
}

async fn post_process_vulnerable(
    State(state): State<ApiState>,
    Json(request): Json<PostProcessRequest>,
) -> Result<Json<CommandResult>, ApiError> {
    let output = state
        .command_runner
        .run_vulnerable(&request.artifact_name)
        .map_err(|error| ApiError::forbidden(error.to_string()))?;
    Ok(Json(command_result(output)))
}

async fn post_process_fixed(
    State(state): State<ApiState>,
    Json(request): Json<PostProcessRequest>,
) -> Result<Json<CommandResult>, ApiError> {
    let output = state
        .command_runner
        .run_fixed(&request.artifact_name)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    Ok(Json(command_result(output)))
}

async fn fetch_vulnerable(
    State(state): State<ApiState>,
    Json(request): Json<FetchRequest>,
) -> Result<Json<FetchResponse>, ApiError> {
    state
        .ssrf_lab_gate
        .require_enabled()
        .map_err(|error| ApiError::forbidden(error.to_string()))?;

    let response = state
        .fetcher
        .fetch_vulnerable(&request.url)
        .await
        .map_err(|error| ApiError::bad_gateway(error.to_string()))?;
    Ok(Json(response))
}

async fn fetch_fixed(
    State(state): State<ApiState>,
    Json(request): Json<FetchRequest>,
) -> Result<Json<FetchResponse>, ApiError> {
    let response = state
        .fetcher
        .fetch_fixed(&request.url)
        .await
        .map_err(|error| ApiError::forbidden(error.to_string()))?;
    Ok(Json(response))
}

async fn debug_config(State(state): State<ApiState>) -> StatusCode {
    // DVRA-007: AppConfig derives Debug, including secret_token. Whether this is
    // exploitable depends on route exposure and log-reader trust.
    tracing::warn!(config = ?state.config, "runtime configuration requested");
    StatusCode::NO_CONTENT
}

fn tenant_from_headers(headers: &HeaderMap) -> Result<String, ApiError> {
    headers
        .get("x-tenant")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| ApiError::bad_request("missing x-tenant header"))
}

fn extraction_result(paths: Vec<std::path::PathBuf>) -> ExtractionResult {
    ExtractionResult {
        files: paths
            .into_iter()
            .map(|path| path.display().to_string())
            .collect(),
    }
}

fn command_result(output: std::process::Output) -> CommandResult {
    CommandResult {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc, time::Duration};

    use axum::{
        body::Bytes,
        extract::{Path, State},
        http::{HeaderMap, HeaderValue, StatusCode},
    };
    use dvra_config::{
        AppConfig, CommandRunner, DangerousLabGate, FetchConfig, LabConfig, PostProcessConfig,
        ServerConfig, SsrfLabGate, StorageConfig, ThreatModel,
    };
    use dvra_fetch::Fetcher;

    use super::{
        ApiState, FetchRequest, extract_bundle_fixed, extract_bundle_vulnerable, fetch_fixed,
        fetch_vulnerable, get_artifact_fixed, get_artifact_vulnerable,
    };

    fn state() -> ApiState {
        let gate = DangerousLabGate::disabled();
        let post_process = PostProcessConfig {
            shell_template: "printf processed".to_owned(),
            fixed_program: "printf".to_owned(),
            fixed_args: vec!["%s".to_owned()],
            secret_token: "test-secret".to_owned(),
            threat_model: ThreatModel::TenantControlled,
        };
        let config = Arc::new(AppConfig {
            server: ServerConfig {
                bind: "127.0.0.1:0".to_owned(),
            },
            lab: LabConfig {
                enable_debug_routes: false,
            },
            storage: StorageConfig {
                root: PathBuf::from("/tmp/dvra-test-storage"),
            },
            fetch: FetchConfig {
                allowed_origins: vec!["https://updates.example.invalid".to_owned()],
                timeout_ms: 100,
                max_response_bytes: 4096,
            },
            post_process: post_process.clone(),
        });

        let fetcher = Fetcher::new(
            &config.fetch.allowed_origins,
            Duration::from_millis(config.fetch.timeout_ms),
            config.fetch.max_response_bytes,
        )
        .expect("valid test fetch configuration");

        ApiState {
            store: dvra_core::ArtifactStore::seeded(),
            config,
            command_runner: CommandRunner::new(post_process, gate.clone()),
            fetcher,
            lab_gate: gate,
            ssrf_lab_gate: SsrfLabGate::disabled(),
        }
    }

    fn blue_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-tenant", HeaderValue::from_static("blue"));
        headers
    }

    #[tokio::test]
    async fn vulnerable_handler_returns_another_tenants_artifact() {
        let response = get_artifact_vulnerable(State(state()), Path(2), blue_headers())
            .await
            .expect("vulnerable route returns artifact");
        assert_eq!(response.0.tenant, "red");
    }

    #[tokio::test]
    async fn fixed_handler_enforces_tenant_scope() {
        let error = get_artifact_fixed(State(state()), Path(2), blue_headers())
            .await
            .expect_err("fixed route must reject cross-tenant access");
        assert_eq!(error.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn vulnerable_bundle_handler_is_gated_by_default() {
        let error = extract_bundle_vulnerable(State(state()), Path(8), Bytes::new())
            .await
            .expect_err("dangerous filesystem route must require acknowledgement");
        assert_eq!(error.status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn fixed_bundle_handler_rejects_parent_traversal() {
        let path = "../other-job.txt";
        let mut body = b"DVB1\x01".to_vec();
        body.push(u8::try_from(path.len()).expect("test path fits"));
        body.extend_from_slice(path.as_bytes());
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(b"test");

        let error = extract_bundle_fixed(State(state()), Path(8), Bytes::from(body))
            .await
            .expect_err("fixed extractor should reject traversal");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn vulnerable_fetch_handler_is_gated_by_default() {
        let error = fetch_vulnerable(
            State(state()),
            axum::Json(FetchRequest {
                url: "http://metadata:8081/latest/meta-data/iam/security-credentials/dvra"
                    .to_owned(),
            }),
        )
        .await
        .expect_err("dangerous fetch route must require acknowledgement");
        assert_eq!(error.status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn fixed_fetch_handler_denies_metadata_origin_before_connecting() {
        let error = fetch_fixed(
            State(state()),
            axum::Json(FetchRequest {
                url: "http://metadata:8081/latest/meta-data/iam/security-credentials/dvra"
                    .to_owned(),
            }),
        )
        .await
        .expect_err("metadata origin must not be allowlisted");
        assert_eq!(error.status, StatusCode::FORBIDDEN);
    }
}
