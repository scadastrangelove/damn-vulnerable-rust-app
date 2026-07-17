use std::time::Duration;

use reqwest::Client;
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Fetcher {
    http_client: Client,
}


#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FetchResponse {
    pub status: u16,
    pub final_url: String,
    pub body: String,
}

impl Fetcher {
    pub fn new(
        _allowed_origins: &[String],
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<Self, FetchError> {
        if max_response_bytes == 0 {
            return Err(FetchError::InvalidResponseLimit);
        }

        let http_client = Client::builder().timeout(timeout).build()?;

        Ok(Self { http_client })
    }

    /// Fetches a URL and returns the final status, URL, and body.
    pub async fn fetch_url(&self, raw_url: &str) -> Result<FetchResponse, FetchError> {
        let response = self.http_client.get(raw_url).send().await?;
        let status = response.status().as_u16();
        let final_url = response.url().to_string();
        let body = response.bytes().await?;

        Ok(FetchResponse {
            status,
            final_url,
            body: String::from_utf8_lossy(&body).into_owned(),
        })
    }

}

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("invalid allowed origin {origin}: {reason}")]
    InvalidAllowedOrigin { origin: String, reason: String },
    #[error("URL scheme is denied: {0}")]
    SchemeDenied(String),
    #[error("URL credentials are denied")]
    CredentialsDenied,
    #[error("URL fragments are denied")]
    FragmentDenied,
    #[error("origin is not in the egress allowlist: {0}")]
    OriginDenied(String),
    #[error("upstream redirect denied with status {0}")]
    RedirectDenied(u16),
    #[error("upstream response exceeds {limit} bytes")]
    ResponseTooLarge { limit: usize },
    #[error("response limit must be greater than zero")]
    InvalidResponseLimit,
}


