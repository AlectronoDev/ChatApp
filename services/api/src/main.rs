use axum::{
    routing::{delete, get, post},
    Json, Router,
};
use sqlx::postgres::PgPoolOptions;

mod config;
mod error;
mod extract;
mod routes;
mod state;

use config::Config;
use protocol::HealthResponse;
use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = Config::from_env()?;

    let db = PgPoolOptions::new()
        .max_connections(20)
        .connect(&config.database_url)
        .await?;

    sqlx::migrate!("../../infra/migrations").run(&db).await?;
    tracing::info!("database migrations applied");

    let state = AppState::new(db, config);

    let app = Router::new()
        .route("/health", get(health_handler))
        // Auth
        .route("/auth/signup", post(routes::auth::signup))
        .route("/auth/login", post(routes::auth::login))
        .route("/auth/logout", post(routes::auth::logout))
        .route("/auth/recover", post(routes::auth::recover))
        .route("/users/me", get(routes::auth::me))
        // Devices
        .route("/devices", post(routes::devices::register_device))
        .route("/devices", get(routes::devices::list_devices))
        .route("/devices/{id}", delete(routes::devices::delete_device))
        // Key bundles for E2EE session establishment
        .route(
            "/users/{username}/keys",
            get(routes::devices::get_user_key_bundles),
        )
        // Public identity keys for a single device (no prekey consumption)
        .route("/devices/{id}/info", get(routes::devices::get_device_public_info))
        // User search and lookup — static segments registered before /:username
        .route("/users/search", get(routes::users::search_users))
        .route("/users/{username}", get(routes::users::get_user))
        // DM threads
        .route("/dms", post(routes::messages::create_or_get_dm))
        .route("/dms", get(routes::messages::list_dms))
        // Messages within a DM thread
        .route("/dms/{thread_id}/messages", post(routes::messages::send_message))
        .route("/dms/{thread_id}/messages", get(routes::messages::fetch_messages))
        .route("/dms/{thread_id}/messages/ack", post(routes::messages::ack_messages))
        // Servers
        .route("/servers", post(routes::servers::create_server))
        .route("/servers", get(routes::servers::list_servers))
        .route("/servers/{id}", get(routes::servers::get_server))
        .route("/servers/{id}", delete(routes::servers::delete_server))
        .route("/servers/{id}/invites", post(routes::servers::invite_to_server))
        .route("/servers/{id}/members/{user_id}", delete(routes::servers::remove_member))
        // Channels (management scoped to a server)
        .route("/servers/{id}/channels", post(routes::servers::create_channel))
        .route("/servers/{id}/channels", get(routes::servers::list_channels))
        // Channel messages
        .route("/channels/{id}/messages", post(routes::channels::send_channel_message))
        .route("/channels/{id}/messages", get(routes::channels::fetch_channel_messages))
        .route("/channels/{id}/messages/ack", post(routes::channels::ack_channel_messages))
        .with_state(state);

    let addr = "0.0.0.0:3000";
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("API server listening on {addr}");

    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok".into() })
}
