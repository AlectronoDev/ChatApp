use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use uuid::Uuid;

use crate::{error::AppError, extract::AuthUser, state::AppState};
use protocol::{
    ChannelSummary, CreateChannelRequest, CreateChannelResponse, CreateServerRequest,
    CreateServerResponse, InviteToServerRequest, ServerDetails, ServerMember, ServerSummary,
};

// ─── Create a server ──────────────────────────────────────────────────────────

pub async fn create_server(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateServerRequest>,
) -> Result<(StatusCode, Json<CreateServerResponse>), AppError> {
    let name = req.name.trim().to_owned();
    if name.is_empty() || name.len() > 100 {
        return Err(AppError::BadRequest("Server name must be 1–100 characters.".into()));
    }

    let mut tx = state.db.begin().await?;

    let server_id = sqlx::query_scalar!(
        "INSERT INTO servers (name, created_by) VALUES ($1, $2) RETURNING id",
        name,
        auth.user_id,
    )
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query!(
        "INSERT INTO server_members (server_id, user_id, role) VALUES ($1, $2, 'owner')",
        server_id,
        auth.user_id,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    tracing::info!(server_id = %server_id, owner = %auth.user_id, name = %name, "server created");

    Ok((StatusCode::CREATED, Json(CreateServerResponse { server_id })))
}

// ─── List servers for the authenticated user ──────────────────────────────────

pub async fn list_servers(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<ServerSummary>>, AppError> {
    let rows = sqlx::query!(
        r#"
        SELECT s.id AS server_id, s.name, sm.role, s.created_at
        FROM servers s
        JOIN server_members sm ON sm.server_id = s.id AND sm.user_id = $1
        ORDER BY s.created_at DESC
        "#,
        auth.user_id,
    )
    .fetch_all(&state.db)
    .await?;

    let servers = rows
        .into_iter()
        .map(|r| ServerSummary {
            server_id: r.server_id,
            name: r.name,
            role: r.role,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(servers))
}

// ─── Get server details + member list ────────────────────────────────────────

pub async fn get_server(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(server_id): Path<Uuid>,
) -> Result<Json<ServerDetails>, AppError> {
    let is_member = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM server_members WHERE server_id = $1 AND user_id = $2)",
        server_id,
        auth.user_id,
    )
    .fetch_one(&state.db)
    .await?
    .unwrap_or(false);

    if !is_member {
        return Err(AppError::Forbidden);
    }

    let server = sqlx::query!(
        "SELECT id, name, created_at FROM servers WHERE id = $1",
        server_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| AppError::NotFound("Server not found.".into()))?;

    let member_rows = sqlx::query!(
        r#"
        SELECT u.id AS user_id, u.username, sm.role, sm.joined_at
        FROM server_members sm
        JOIN users u ON u.id = sm.user_id
        WHERE sm.server_id = $1
        ORDER BY sm.joined_at ASC
        "#,
        server_id,
    )
    .fetch_all(&state.db)
    .await?;

    let members = member_rows
        .into_iter()
        .map(|r| ServerMember {
            user_id: r.user_id,
            username: r.username,
            role: r.role,
            joined_at: r.joined_at,
        })
        .collect();

    Ok(Json(ServerDetails {
        server_id: server.id,
        name: server.name,
        members,
        created_at: server.created_at,
    }))
}

// ─── Invite a user to a server ────────────────────────────────────────────────

pub async fn invite_to_server(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(server_id): Path<Uuid>,
    Json(req): Json<InviteToServerRequest>,
) -> Result<StatusCode, AppError> {
    // Only the owner may invite others.
    let role = sqlx::query_scalar!(
        "SELECT role FROM server_members WHERE server_id = $1 AND user_id = $2",
        server_id,
        auth.user_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::Forbidden)?;

    if role != "owner" {
        return Err(AppError::Forbidden);
    }

    let user_exists = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)",
        req.user_id,
    )
    .fetch_one(&state.db)
    .await?
    .unwrap_or(false);

    if !user_exists {
        return Err(AppError::NotFound("User not found.".into()));
    }

    let result = sqlx::query!(
        r#"
        INSERT INTO server_members (server_id, user_id, role)
        VALUES ($1, $2, 'member')
        ON CONFLICT (server_id, user_id) DO NOTHING
        "#,
        server_id,
        req.user_id,
    )
    .execute(&state.db)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::Conflict("User is already a member of this server.".into()));
    }

    tracing::info!(
        server_id = %server_id,
        invited_user = %req.user_id,
        by = %auth.user_id,
        "user invited to server"
    );

    Ok(StatusCode::NO_CONTENT)
}

// ─── Leave or kick a member ───────────────────────────────────────────────────

pub async fn remove_member(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((server_id, target_user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let caller_role = sqlx::query_scalar!(
        "SELECT role FROM server_members WHERE server_id = $1 AND user_id = $2",
        server_id,
        auth.user_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::Forbidden)?;

    // Any member may remove themselves; only the owner may remove others.
    if auth.user_id != target_user_id && caller_role != "owner" {
        return Err(AppError::Forbidden);
    }

    // The owner cannot leave — they must delete the server instead.
    if auth.user_id == target_user_id && caller_role == "owner" {
        return Err(AppError::BadRequest(
            "The server owner cannot leave. Delete the server instead.".into(),
        ));
    }

    sqlx::query!(
        "DELETE FROM server_members WHERE server_id = $1 AND user_id = $2",
        server_id,
        target_user_id,
    )
    .execute(&state.db)
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

// ─── Delete a server ──────────────────────────────────────────────────────────

pub async fn delete_server(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(server_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let role = sqlx::query_scalar!(
        "SELECT role FROM server_members WHERE server_id = $1 AND user_id = $2",
        server_id,
        auth.user_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::Forbidden)?;

    if role != "owner" {
        return Err(AppError::Forbidden);
    }

    // ON DELETE CASCADE handles server_members, channels, and channel_envelopes.
    sqlx::query!("DELETE FROM servers WHERE id = $1", server_id)
        .execute(&state.db)
        .await?;

    tracing::info!(server_id = %server_id, deleted_by = %auth.user_id, "server deleted");

    Ok(StatusCode::NO_CONTENT)
}

// ─── Create a channel ─────────────────────────────────────────────────────────

pub async fn create_channel(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(server_id): Path<Uuid>,
    Json(req): Json<CreateChannelRequest>,
) -> Result<(StatusCode, Json<CreateChannelResponse>), AppError> {
    let name = req.name.trim().to_owned();
    if name.is_empty() || name.len() > 100 {
        return Err(AppError::BadRequest("Channel name must be 1–100 characters.".into()));
    }

    let role = sqlx::query_scalar!(
        "SELECT role FROM server_members WHERE server_id = $1 AND user_id = $2",
        server_id,
        auth.user_id,
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::Forbidden)?;

    if role != "owner" {
        return Err(AppError::Forbidden);
    }

    let channel_id = sqlx::query_scalar!(
        "INSERT INTO channels (server_id, name) VALUES ($1, $2) RETURNING id",
        server_id,
        name,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(db)
            if db.constraint() == Some("channels_server_id_name_key") =>
        {
            AppError::Conflict(format!(
                "A channel named '{name}' already exists in this server."
            ))
        }
        _ => AppError::Internal(e.into()),
    })?;

    tracing::info!(
        channel_id = %channel_id,
        server_id = %server_id,
        name = %name,
        "channel created"
    );

    Ok((StatusCode::CREATED, Json(CreateChannelResponse { channel_id })))
}

// ─── List channels in a server ────────────────────────────────────────────────

pub async fn list_channels(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(server_id): Path<Uuid>,
) -> Result<Json<Vec<ChannelSummary>>, AppError> {
    let is_member = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM server_members WHERE server_id = $1 AND user_id = $2)",
        server_id,
        auth.user_id,
    )
    .fetch_one(&state.db)
    .await?
    .unwrap_or(false);

    if !is_member {
        return Err(AppError::Forbidden);
    }

    let rows = sqlx::query!(
        "SELECT id, name, created_at FROM channels WHERE server_id = $1 ORDER BY created_at ASC",
        server_id,
    )
    .fetch_all(&state.db)
    .await?;

    let channels = rows
        .into_iter()
        .map(|r| ChannelSummary { channel_id: r.id, name: r.name, created_at: r.created_at })
        .collect();

    Ok(Json(channels))
}
