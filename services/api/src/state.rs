use sqlx::PgPool;

use crate::config::Config;

// axum provides a blanket `impl<T: Clone> FromRef<T> for T`, so AppState
// automatically satisfies FromRef<AppState> without an explicit impl.
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: Config,
}

impl AppState {
    pub fn new(db: PgPool, config: Config) -> Self {
        Self { db, config }
    }
}
