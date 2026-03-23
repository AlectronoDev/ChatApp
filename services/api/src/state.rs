use std::num::NonZeroU32;
use std::sync::Arc;

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::Config;

// axum provides a blanket `impl<T: Clone> FromRef<T> for T`, so AppState
// automatically satisfies FromRef<AppState> without an explicit impl.
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Config,
    /// Per-user rate limiter for sensitive post-auth endpoints (key-bundle fetch).
    /// Keyed by `user_id` (UUID). Each authenticated user gets its own GCRA bucket.
    ///
    /// NOTE: the DashMap backing this limiter grows monotonically with distinct
    /// callers. Bounded by registered-user count; fine for a single-process
    /// deployment. Use Redis for multi-instance deployments.
    pub rate_limiter: Arc<DefaultKeyedRateLimiter<Uuid>>,
    /// Per-username rate limiter for unauthenticated auth endpoints (login,
    /// signup, recover). Keyed by the submitted username string so that attacks
    /// against a specific account are limited independently of others.
    pub auth_rate_limiter: Arc<DefaultKeyedRateLimiter<String>>,
}

impl AppState {
    pub fn new(db: PgPool, config: Config) -> Self {
        let key_bundle_quota = Quota::per_second(
            NonZeroU32::new(config.key_bundle_rate_limit_rps.max(1))
                .expect("key_bundle_rate_limit_rps must be >= 1"),
        );
        let rate_limiter = Arc::new(RateLimiter::keyed(key_bundle_quota));

        let auth_quota = Quota::per_second(
            NonZeroU32::new(config.auth_rate_limit_rps.max(1))
                .expect("auth_rate_limit_rps must be >= 1"),
        );
        let auth_rate_limiter = Arc::new(RateLimiter::keyed(auth_quota));

        Self { db, config, rate_limiter, auth_rate_limiter }
    }
}
