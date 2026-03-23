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
    /// Per-user rate limiter for sensitive endpoints (e.g. key-bundle fetch).
    ///
    /// Keyed by `user_id`. Each key gets its own independent GCRA bucket;
    /// one user's quota does not affect others. `Arc` makes `AppState` `Clone`
    /// without cloning the underlying map.
    ///
    /// NOTE: the DashMap backing this limiter grows monotonically as new users
    /// make requests. For a long-running deployment this is bounded by the
    /// total number of registered users — acceptable for a single-process
    /// deployment. A Redis-backed solution would be needed for multi-instance.
    pub rate_limiter: Arc<DefaultKeyedRateLimiter<Uuid>>,
}

impl AppState {
    pub fn new(db: PgPool, config: Config) -> Self {
        let quota = Quota::per_second(
            NonZeroU32::new(config.key_bundle_rate_limit_rps.max(1))
                .expect("rate limit rps must be >= 1"),
        );
        let rate_limiter = Arc::new(RateLimiter::keyed(quota));

        Self { db, config, rate_limiter }
    }
}
