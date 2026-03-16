# Encrypted Chat App

A Discord-like chat application with end-to-end encryption. The server only
ever stores ciphertext and public key material — message content is never
readable by the server operator.

## Architecture

```
apps/
  web/          React + TypeScript web client (coming later)
  desktop/      Tauri desktop shell wrapping the web UI (coming later)
services/
  api/          Rust HTTP + WebSocket API (axum + tokio)
crates/
  crypto_core/  All cryptographic operations — isolated here
  protocol/     Shared request/response/event schema types
infra/
  docker-compose.yml   Local dev infrastructure (PostgreSQL)
docs/           Threat model, protocol notes, architecture decisions
```

## Prerequisites

- [Rust](https://rustup.rs/) (stable)
- [Docker](https://docs.docker.com/get-docker/) for the local database

## Local development

```sh
# Start the database
docker compose -f infra/docker-compose.yml up -d

# Copy and edit env
cp .env.example .env

# Run the API
cargo run -p api
```

The health endpoint will be available at `http://localhost:3000/health`.

## Workspace crates

| Crate          | Description                                          |
|----------------|------------------------------------------------------|
| `api`          | HTTP/WebSocket API service                           |
| `protocol`     | Shared typed API schemas (request/response/events)   |
| `crypto_core`  | Cryptographic primitives — the only place for crypto |
