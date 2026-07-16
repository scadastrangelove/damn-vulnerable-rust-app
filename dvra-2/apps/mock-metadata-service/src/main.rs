use std::{env, net::SocketAddr};

use axum::{routing::get, Json, Router};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr =
        env::var("DVRA_METADATA_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:3100".to_owned());
    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route(
            "/latest/meta-data/iam/security-credentials/dvra",
            get(fake_credentials),
        );

    let listener = tokio::net::TcpListener::bind(bind_addr.parse::<SocketAddr>()?).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn fake_credentials() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "AccessKeyId": "DVRA_FAKE_ACCESS_KEY",
        "SecretAccessKey": "DVRA_FAKE_SECRET_KEY",
        "Token": "DVRA_FAKE_SESSION_TOKEN",
        "Expiration": "2099-01-01T00:00:00Z"
    }))
}
