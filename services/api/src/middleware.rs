//! Request-level middleware for observability and HTTP security hardening.
//!
//! Two layers are wired into the global router in `main.rs`:
//!
//! 1. `trace_requests` — logs every request/response pair with method, path
//!    (no query string), status code, and latency. Never logs headers,
//!    request bodies, or response bodies.
//!
//! 2. `security_headers` — adds security-relevant HTTP response headers to
//!    every response. Optionally adds HSTS if `config.require_https` is set.

use std::time::Instant;

use axum::{
    extract::{Request, State},
    http::{header::HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

use crate::state::AppState;

// ─── Request tracing ──────────────────────────────────────────────────────────

/// Log every HTTP request/response pair.
///
/// Logged fields:
/// - `request_id` — UUID v7, unique per request; correlates log lines.
/// - `method` — HTTP verb (GET, POST, …).
/// - `path` — URL path only. Query strings are intentionally excluded because
///   they may contain cursor values or filter terms that could leak structure.
/// - `status` — HTTP status code of the response.
/// - `latency_ms` — wall-clock milliseconds from request received to response
///   sent (does not include TLS/TCP overhead at the proxy layer).
///
/// NOT logged: `Authorization`, `Cookie`, or any other request/response header;
/// request bodies; response bodies.
pub async fn trace_requests(request: Request, next: Next) -> Response {
    let request_id = Uuid::now_v7();
    let method = request.method().clone();
    // Path only — strip the query string to avoid leaking filter/cursor values.
    let path = request.uri().path().to_owned();
    let start = Instant::now();

    let response = next.run(request).await;

    let status = response.status().as_u16();
    let latency_ms = start.elapsed().as_millis();

    tracing::info!(
        request_id = %request_id,
        method     = %method,
        path       = path,
        status,
        latency_ms,
        "request"
    );

    response
}

// ─── Security headers ─────────────────────────────────────────────────────────

/// Add security-relevant HTTP response headers to every response.
///
/// Headers always set:
/// - `X-Content-Type-Options: nosniff` — prevents MIME-type sniffing.
/// - `X-Frame-Options: DENY` — prevents clickjacking in browser contexts.
/// - `Cache-Control: no-store` — API responses must not be stored in caches
///   (tokens, message ciphertext, key bundles are all in API responses).
/// - `Referrer-Policy: strict-origin` — limits cross-origin referrer leakage.
///
/// Set only when `config.require_https = true`:
/// - `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
///   (2-year HSTS pin, suitable for HSTS preload list submission).
pub async fn security_headers(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // Safe to unwrap: these are compile-time-known valid header values.
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin"),
    );

    if state.config.require_https {
        headers.insert(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
        );
    }

    response
}
