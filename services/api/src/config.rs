use anyhow::{Context, Result};

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub session_duration_days: i64,
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
        })
    }
}
