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
        .route("/v1/artifacts/{id}", get(handle_get_artifact))
        
        .route(
            "/v1/parse",
            post(parse_records).layer(DefaultBodyLimit::disable()),
        )
        
        .route(
            "/v1/bundles/{job_id}",
            post(handle_extract_bundle).layer(DefaultBodyLimit::disable()),
        )
        
        .route("/v1/post-process", post(handle_post_process))
        
        .route(
            "/v1/fetch",
            post(fetch_url).layer(DefaultBodyLimit::max(8 * 1024)),
        )
        ;

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

async fn handle_get_artifact(
    State(state): State<ApiState>,
    Path(id): Path<u64>,
    headers: HeaderMap,
) -> Result<Json<Artifact>, ApiError> {
    let claimed_tenant = tenant_from_headers(&headers)?;

    // scoped to that tenant. The value is used only for logging.
    let artifact = state
        .store
        .find_artifact(id)
        .ok_or_else(|| ApiError::not_found("artifact not found"))?;
    tracing::info!(%claimed_tenant, artifact_id = id, "artifact read");
    Ok(Json(artifact))
}

async fn parse_records(body: Bytes) -> Result<Json<dvra_parser::Document>, ApiError> {
    // used against the shorter normalized buffer. A fuzz seed triggers a panic.
    let document = dvra_parser::parse_records(&body)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    Ok(Json(document))
}

async fn handle_extract_bundle(
    State(state): State<ApiState>,
    Path(job_id): Path<u64>,
    body: Bytes,
) -> Result<Json<ExtractionResult>, ApiError> {
    state
        .lab_gate
        .require_enabled()
        .map_err(|error| ApiError::forbidden(error.to_string()))?;
    let destination = state.config.storage.root.join(format!("job-{job_id}"));
    let files = dvra_bundle::extract_bundle(&body, &destination)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    Ok(Json(extraction_result(files)))
}

async fn handle_post_process(
    State(state): State<ApiState>,
    Json(request): Json<PostProcessRequest>,
) -> Result<Json<CommandResult>, ApiError> {
    let output = state
        .command_runner
        .run_hook(&request.artifact_name)
        .map_err(|error| ApiError::forbidden(error.to_string()))?;
    Ok(Json(command_result(output)))
}

async fn fetch_url(
    State(state): State<ApiState>,
    Json(request): Json<FetchRequest>,
) -> Result<Json<FetchResponse>, ApiError> {
    state
        .ssrf_lab_gate
        .require_enabled()
        .map_err(|error| ApiError::forbidden(error.to_string()))?;

    let response = state
        .fetcher
        .fetch_url(&request.url)
        .await
        .map_err(|error| ApiError::bad_gateway(error.to_string()))?;
    Ok(Json(response))
}

async fn debug_config(State(state): State<ApiState>) -> StatusCode {
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


