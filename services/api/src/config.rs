use anyhow::{Context, Result};

/// Output format for structured log lines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogFormat {
    /// Human-readable text (default; suitable for local development).
    Text,
    /// Newline-delimited JSON (suitable for log aggregators like Loki, Splunk,
    /// Datadog). Enable with `LOG_FORMAT=json`.
    Json,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub session_duration_days: i64,
    /// Maximum number of `GET /users/{username}/keys` calls allowed per
    /// authenticated user per second. Protects against bulk one-time prekey
    /// exhaustion (key-bundle scraping). Default: 2 req/s per user.
    /// Set via the `KEY_BUNDLE_RATE_LIMIT_RPS` environment variable.
    pub key_bundle_rate_limit_rps: u32,
    /// Maximum login/signup/recovery attempts per username per second.
    /// Limits password brute-forcing and recovery-code guessing.
    /// Default: 1 req/s. Set via `AUTH_RATE_LIMIT_RPS`.
    #[allow(unused)] // read in state.rs; rust-analyzer misses cross-file refs
    pub auth_rate_limit_rps: u32,
    /// When `true`, the server adds an HSTS header to every response and logs
    /// a reminder at startup that TLS must be terminated at the edge.
    /// MUST be `true` in all non-local deployments.
    /// Default: `false` (to avoid blocking local dev). Set `REQUIRE_HTTPS=true`
    /// in production.
    pub require_https: bool,
    /// Log output format. Set `LOG_FORMAT=json` in production for structured
    /// log aggregation. Default: text.
    pub log_format: LogFormat,
}

impl Config {
    /// Load configuration from environment variables. All variables must be
    /// present unless a default is documented.
    pub fn from_env() -> Result<Self> {
        let require_https = std::env::var("REQUIRE_HTTPS")
            .unwrap_or_else(|_| "false".into())
            .to_lowercase();
        let log_format_str = std::env::var("LOG_FORMAT")
            .unwrap_or_else(|_| "text".into())
            .to_lowercase();

        Ok(Self {
            database_url: std::env::var("DATABASE_URL")
                .context("DATABASE_URL must be set")?,
            session_duration_days: std::env::var("SESSION_DURATION_DAYS")
                .unwrap_or_else(|_| "30".into())
                .parse()
                .context("SESSION_DURATION_DAYS must be a positive integer")?,
            key_bundle_rate_limit_rps: std::env::var("KEY_BUNDLE_RATE_LIMIT_RPS")
                .unwrap_or_else(|_| "2".into())
                .parse()
                .context("KEY_BUNDLE_RATE_LIMIT_RPS must be a positive integer")?,
            auth_rate_limit_rps: std::env::var("AUTH_RATE_LIMIT_RPS")
                .unwrap_or_else(|_| "1".into())
                .parse()
                .context("AUTH_RATE_LIMIT_RPS must be a positive integer")?,
            require_https: require_https == "true" || require_https == "1",
            log_format: if log_format_str == "json" {
                LogFormat::Json
            } else {
                LogFormat::Text
            },
        })
    }
}
