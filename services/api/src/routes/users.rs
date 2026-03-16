use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;

use crate::{error::AppError, extract::AuthUser, state::AppState};
use protocol::UserSearchResult;

// ─── Exact user lookup ────────────────────────────────────────────────────────

pub async fn get_user(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(username): Path<String>,
) -> Result<Json<UserSearchResult>, AppError> {
    let row = sqlx::query!(
        "SELECT id, username FROM users WHERE username = $1",
        username,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("User '{username}' not found.")))?;

    Ok(Json(UserSearchResult {
        user_id: row.id,
        username: row.username,
    }))
}

// ─── Prefix search ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SearchQuery {
    q: String,
}

pub async fn search_users(
    State(state): State<AppState>,
    _auth: AuthUser,
    Query(params): Query<SearchQuery>,
) -> Result<Json<Vec<UserSearchResult>>, AppError> {
    if params.q.len() < 2 {
        return Err(AppError::BadRequest(
            "Search query must be at least 2 characters.".into(),
        ));
    }
    if params.q.len() > 32 {
        return Err(AppError::BadRequest(
            "Search query must not exceed 32 characters.".into(),
        ));
    }

    // Prefix match — append '%' server-side to prevent arbitrary LIKE patterns.
    let pattern = format!("{}%", params.q.to_lowercase());

    let rows = sqlx::query!(
        "SELECT id, username FROM users WHERE username LIKE $1 ORDER BY username LIMIT 20",
        pattern,
    )
    .fetch_all(&state.db)
    .await?;

    let results = rows
        .into_iter()
        .map(|r| UserSearchResult {
            user_id: r.id,
            username: r.username,
        })
        .collect();

    Ok(Json(results))
}
