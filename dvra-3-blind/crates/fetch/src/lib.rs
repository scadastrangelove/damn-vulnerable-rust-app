use std::{collections::HashSet, time::Duration};

use reqwest::{Client, redirect::Policy};
use serde::Serialize;
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone)]
pub struct Fetcher {
    vulnerable_client: Client,
    fixed_client: Client,
    policy: EgressPolicy,
    max_response_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct EgressPolicy {
    allowed_origins: HashSet<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FetchResponse {
    pub status: u16,
    pub final_url: String,
    pub body: String,
}

impl Fetcher {
    pub fn new(
        allowed_origins: &[String],
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<Self, FetchError> {
        if max_response_bytes == 0 {
            return Err(FetchError::InvalidResponseLimit);
        }

        let vulnerable_client = Client::builder().timeout(timeout).build()?;
        let fixed_client = Client::builder()
            .timeout(timeout)
            .redirect(Policy::none())
            .build()?;

        Ok(Self {
            vulnerable_client,
            fixed_client,
            policy: EgressPolicy::new(allowed_origins)?,
            max_response_bytes,
        })
    }

    /// policy, follows redirects, and buffers the complete response.
    pub async fn fetch_url(&self, raw_url: &str) -> Result<FetchResponse, FetchError> {
        let response = self.vulnerable_client.get(raw_url).send().await?;
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

impl EgressPolicy {
    pub fn new(allowed_origins: &[String]) -> Result<Self, FetchError> {
        let allowed_origins = allowed_origins
            .iter()
            .map(|origin| canonical_configured_origin(origin))
            .collect::<Result<HashSet<_>, _>>()?;
        Ok(Self { allowed_origins })
    }

    pub fn validate(&self, url: &Url) -> Result<(), FetchError> {
        if !matches!(url.scheme(), "http" | "https") {
            return Err(FetchError::SchemeDenied(url.scheme().to_owned()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(FetchError::CredentialsDenied);
        }
        if url.fragment().is_some() {
            return Err(FetchError::FragmentDenied);
        }

        let origin = url.origin().ascii_serialization();
        if !self.allowed_origins.contains(&origin) {
            return Err(FetchError::OriginDenied(origin));
        }
        Ok(())
    }
}

fn canonical_configured_origin(raw: &str) -> Result<String, FetchError> {
    let url = Url::parse(raw).map_err(|error| FetchError::InvalidAllowedOrigin {
        origin: raw.to_owned(),
        reason: error.to_string(),
    })?;

    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(FetchError::InvalidAllowedOrigin {
            origin: raw.to_owned(),
            reason: "expected a bare http(s) origin without credentials, path, query, or fragment"
                .to_owned(),
        });
    }

    Ok(url.origin().ascii_serialization())
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


