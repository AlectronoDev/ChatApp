use anyhow::{Context, Result};

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
    #[allow(dead_code)] // read in state.rs; rust-analyzer misses cross-file refs
    pub auth_rate_limit_rps: u32,
}

impl Config {
    /// Load configuration from environment variables. All variables must be
    /// present unless a default is documented.
    pub fn from_env() -> Result<Self> {
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
        })
    }
}
