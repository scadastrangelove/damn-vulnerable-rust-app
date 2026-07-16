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

    /// DVRA-009: accepts an attacker-controlled URL, applies no destination
    /// policy, follows redirects, and buffers the complete response.
    pub async fn fetch_vulnerable(&self, raw_url: &str) -> Result<FetchResponse, FetchError> {
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

    /// Comparison implementation: validates the exact origin before connecting,
    /// refuses redirects, and enforces a response-size ceiling while reading.
    pub async fn fetch_fixed(&self, raw_url: &str) -> Result<FetchResponse, FetchError> {
        let url = Url::parse(raw_url)?;
        self.policy.validate(&url)?;

        let mut response = self.fixed_client.get(url).send().await?;
        if response.status().is_redirection() {
            return Err(FetchError::RedirectDenied(response.status().as_u16()));
        }

        if response
            .content_length()
            .is_some_and(|length| length > self.max_response_bytes as u64)
        {
            return Err(FetchError::ResponseTooLarge {
                limit: self.max_response_bytes,
            });
        }

        let status = response.status().as_u16();
        let final_url = response.url().to_string();
        let mut body = Vec::new();

        while let Some(chunk) = response.chunk().await? {
            let next_length = body
                .len()
                .checked_add(chunk.len())
                .ok_or(FetchError::ResponseTooLarge {
                    limit: self.max_response_bytes,
                })?;
            if next_length > self.max_response_bytes {
                return Err(FetchError::ResponseTooLarge {
                    limit: self.max_response_bytes,
                });
            }
            body.extend_from_slice(&chunk);
        }

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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use url::Url;

    use super::{EgressPolicy, FetchError, Fetcher};

    fn policy() -> EgressPolicy {
        EgressPolicy::new(&["https://updates.example.invalid".to_owned()])
            .expect("valid test policy")
    }

    #[test]
    fn exact_allowed_origin_accepts_arbitrary_paths() {
        let url = Url::parse("https://updates.example.invalid/releases/latest?arch=x86_64")
            .expect("valid URL");
        policy().validate(&url).expect("origin should be allowed");
    }

    #[test]
    fn metadata_service_origin_is_denied() {
        let url = Url::parse(
            "http://metadata:8081/latest/meta-data/iam/security-credentials/dvra",
        )
        .expect("valid URL");
        let error = policy().validate(&url).expect_err("metadata must be denied");
        assert!(matches!(error, FetchError::OriginDenied(_)));
    }

    #[test]
    fn configured_origin_must_not_include_a_path() {
        let error = EgressPolicy::new(&["https://updates.example.invalid/releases".to_owned()])
            .expect_err("path-bearing origin must be rejected");
        assert!(matches!(error, FetchError::InvalidAllowedOrigin { .. }));
    }

    #[tokio::test]
    async fn vulnerable_client_follows_redirect_to_second_resource() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind redirect test server");
        let address = listener.local_addr().expect("test server address");
        let server = tokio::spawn(async move {
            respond_once(
                &listener,
                b"HTTP/1.1 302 Found\r\nLocation: /secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await;
            respond_once(
                &listener,
                b"HTTP/1.1 200 OK\r\nContent-Length: 24\r\nConnection: close\r\n\r\nDVRA_FAKE_METADATA_TOKEN",
            )
            .await;
        });

        let origin = format!("http://{address}");
        let fetcher = Fetcher::new(&[origin.clone()], Duration::from_secs(2), 4096)
            .expect("test fetcher");
        let response = fetcher
            .fetch_vulnerable(&format!("{origin}/redirect"))
            .await
            .expect("vulnerable client follows redirect");

        assert_eq!(response.body, "DVRA_FAKE_METADATA_TOKEN");
        assert!(response.final_url.ends_with("/secret"));
        server.await.expect("redirect test server");
    }

    #[tokio::test]
    async fn fixed_client_does_not_follow_redirect() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind redirect test server");
        let address = listener.local_addr().expect("test server address");
        let server = tokio::spawn(async move {
            respond_once(
                &listener,
                b"HTTP/1.1 302 Found\r\nLocation: /secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await;
        });

        let origin = format!("http://{address}");
        let fetcher = Fetcher::new(&[origin.clone()], Duration::from_secs(2), 4096)
            .expect("test fetcher");
        let error = fetcher
            .fetch_fixed(&format!("{origin}/redirect"))
            .await
            .expect_err("fixed client must refuse redirects");

        assert!(matches!(error, FetchError::RedirectDenied(302)));
        server.await.expect("redirect test server");
    }

    async fn respond_once(listener: &TcpListener, response: &[u8]) {
        let (mut stream, _) = listener.accept().await.expect("accept test request");
        let mut request = [0u8; 2048];
        let bytes_read = stream.read(&mut request).await.expect("read test request");
        assert!(bytes_read > 0, "test client sent an empty request");
        stream
            .write_all(response)
            .await
            .expect("write test response");
    }
}
