use std::env;

use anyhow::Context;
use axum::{
    Json, Router,
    response::Redirect,
    routing::get,
};
use serde::Serialize;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Serialize)]
struct Health {
    status: &'static str,
    service: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct FakeCredentials {
    code: &'static str,
    access_key_id: &'static str,
    secret_access_key: &'static str,
    token: &'static str,
    expiration: &'static str,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("dvra_metadata_service=info")),
        )
        .init();

    let bind = env::var("DVRA_METADATA_BIND").unwrap_or_else(|_| "0.0.0.0:8081".to_owned());
    let app = Router::new()
        .route("/health", get(health))
        .route(
            "/latest/meta-data/iam/security-credentials/dvra",
            get(credentials),
        )
        .route("/redirect-to-credentials", get(redirect_to_credentials));
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .with_context(|| format!("binding fake metadata service to {bind}"))?;

    tracing::info!(%bind, "fake metadata service listening");
    axum::serve(listener, app)
        .await
        .context("serving fake metadata service")?;
    Ok(())
}

async fn health() -> Json<Health> {
    Json(Health {
        status: "ok",
        service: "dvra-metadata-service",
    })
}

async fn credentials() -> Json<FakeCredentials> {
    Json(FakeCredentials {
        code: "Success",
        access_key_id: "DVRAFAKEACCESSKEY",
        secret_access_key: "dvra-fake-secret-not-a-real-credential",
        token: "DVRA_FAKE_METADATA_TOKEN",
        expiration: "2099-01-01T00:00:00Z",
    })
}

async fn redirect_to_credentials() -> Redirect {
    Redirect::temporary("/latest/meta-data/iam/security-credentials/dvra")
}
