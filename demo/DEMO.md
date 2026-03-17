# ChatApp — Demo Setup Guide

This guide walks you through everything needed to get the ChatApp running locally from
scratch — database, API server, and two CLI clients — on **Linux/macOS** or **Windows**.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Clone and open the project](#2-clone-and-open-the-project)
3. [Start the database](#3-start-the-database)
4. [Configure environment variables](#4-configure-environment-variables)
5. [Apply database migrations](#5-apply-database-migrations)
6. [Build the project](#6-build-the-project)
7. [Run the API server](#7-run-the-api-server)
8. [Run the CLI demo](#8-run-the-cli-demo)
9. [Two-user demo walkthrough](#9-two-user-demo-walkthrough)
10. [Stopping everything](#10-stopping-everything)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Prerequisites

You need the following tools installed before you start. Each heading links to its
official install page.

### Rust + Cargo

Rust's toolchain manager `rustup` installs both `rustc` (the compiler) and `cargo`
(the build tool / package manager).

**Linux / macOS — run in a terminal:**

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Follow the on-screen prompts (the default "standard installation" is fine), then reload
your shell:

```bash
source "$HOME/.cargo/env"
```

**Windows — download and run:**  
[https://rustup.rs](https://rustup.rs) — click **"DOWNLOAD RUSTUP-INIT.EXE"** and follow the installer.

Verify the install worked:

```bash
cargo --version   # should print e.g. "cargo 1.78.0"
```

---

### Docker Desktop

Docker runs the PostgreSQL database inside a container so you do not need to install
Postgres directly on your machine.

- **Windows / macOS:** [https://www.docker.com/products/docker-desktop/](https://www.docker.com/products/docker-desktop/)
- **Linux:** install Docker Engine + the Compose plugin via your package manager, e.g.
on Fedora:

```bash
sudo dnf install docker docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER   # lets you run docker without sudo (re-login after)
```

Verify Docker is running:

```bash
docker --version
docker compose version
```

---

### sqlx-cli

`sqlx-cli` is a command-line tool that applies database migrations. Install it once
with cargo:

```bash
cargo install sqlx-cli --no-default-features --features postgres,rustls
```

This may take a few minutes the first time.

---

## 2. Clone and open the project

If you have not already cloned the repository:

```bash
git clone "https://github.com/AlectronoDev/ChatApp" ChatApp
cd ChatApp
```

All commands in this guide are run from the **project root** (the folder containing
`Cargo.toml`) unless stated otherwise.

---

## 3. Start the database

The database runs in a Docker container defined in `infra/docker-compose.yml`.

```bash
cd infra
docker compose up -d --wait
cd ..
```

- `-d` runs the container in the background.
- `--wait` waits until Postgres reports healthy before returning.

You should see output ending with something like:

```
Container infra-db-1  Healthy
```

The database is now running on **localhost port 5432** with:


| Setting  | Value     |
| -------- | --------- |
| Host     | localhost |
| Port     | 5432      |
| Database | chatapp   |
| Username | chatapp   |
| Password | chatapp   |


> The container restarts automatically when Docker starts, so you only need to do this
> once per machine reboot.

---

## 4. Configure environment variables

The API server reads its configuration from a `.env` file in the project root.

Copy the provided example:

```bash
# Linux / macOS
cp .env.example .env

# Windows (PowerShell)
Copy-Item .env.example .env
```

The default values in `.env` already match the Docker container, so you do not need to
change anything for a local demo:

```
DATABASE_URL=postgres://chatapp:chatapp@localhost:5432/chatapp
RUST_LOG=info
```

> `.env` is git-ignored and should never be committed — it may contain secrets.

---

## 5. Apply database migrations

`sqlx` checks SQL queries at **compile time** against a live database. This means the
database tables must exist before you can build the project.

Run the migrations once (with the Docker container already running from step 3):

```bash
DATABASE_URL=postgres://chatapp:chatapp@localhost:5432/chatapp \
  sqlx migrate run --source infra/migrations
```

**Windows (PowerShell):**

```powershell
$env:DATABASE_URL = "postgres://chatapp:chatapp@localhost:5432/chatapp"
sqlx migrate run --source infra/migrations
```

You should see output like:

```
Applied 0001_create_users.sql
Applied 0002_create_sessions.sql
...
Applied 0008_create_channel_envelopes.sql
```

> You only need to run this **once**. The API server checks for new migrations and
> applies them automatically on every startup after this initial run.

---

## 6. Build the project

From the project root, build everything with:

```bash
cargo build
```

This compiles the API server and both the CLI client. It will take a few minutes the
first time as Cargo downloads and compiles all dependencies. Subsequent builds are much
faster.

When complete, the binaries are placed in `target/debug/`:


| Binary              | Description         |
| ------------------- | ------------------- |
| `target/debug/api`  | The HTTP API server |
| `target/debug/chat` | The CLI chat client |


> On Windows the binaries have a `.exe` extension:
> `target\debug\api.exe` and `target\debug\chat.exe`.

---

## 7. Run the API server

Open a dedicated terminal for the API server and keep it running while you use the CLI.

```bash
# Linux / macOS
cargo run -p api

# Windows (PowerShell)
cargo run -p api
```

On first run you will see the migrations being confirmed, then:

```
INFO api: database migrations applied
INFO api: API server listening on 0.0.0.0:3000
```

The server is now accepting connections on **[http://localhost:3000](http://localhost:3000)**.

> Keep this terminal open. The CLI clients connect to it for every action.

---

## 8. Run the CLI demo

The `demo/` folder contains two isolated user environments:

```
demo/
├── user1/
│   ├── run.sh      ← Linux / macOS
│   └── run.ps1     ← Windows
└── user2/
    ├── run.sh
    └── run.ps1
```

Each `run` script launches the `chat` binary with its working directory set to that
user's folder. This means each user's login session (`chat_session.json`) is saved
separately so they do not interfere with each other.

**Linux / macOS:**

```bash
# Open two separate terminal windows/tabs, then:

# Terminal A
./demo/user1/run.sh

# Terminal B
./demo/user2/run.sh
```

**Windows (PowerShell):**

```powershell
# Terminal A
.\demo\user1\run.ps1

# Terminal B
.\demo\user2\run.ps1
```

---

## 9. Two-user demo walkthrough

Follow these steps to see two users sign up and exchange an end-to-end encrypted
message.

### Step 1 — Sign up as user1 (Terminal A)

```
╔═══════════════════════════════╗
║       ChatApp CLI v0.1        ║
╚═══════════════════════════════╝

[1] Sign up
[2] Log in
Choice: 1

Username: alice
Password: (type a password — it will not be echoed)
```

After signup the app displays a **recovery code** — note it down somewhere safe, it is  
shown only once. Press Enter to continue. (**RECOVERY CODES ARE NOT YET IMPLEMENTED IN THIS VERSION**)

The app generates encryption keys for your device and logs you in automatically.

### Step 2 — Sign up as user2 (Terminal B)

Repeat the same signup process in Terminal B, choosing a different username (e.g.
`bob`).

### Step 3 — Start a direct message from user1

In Terminal A you will see the main menu:

```
═══ Logged in as 'alice' ═══
[1] Direct messages
[2] Message someone new
[3] Servers
[4] Quit
Choice: 2

Username to message: bob
```

Type a message and press Enter. The message is encrypted on your device before being
sent to the server — the server only ever stores ciphertext.

### Step 4 — Read the message as user2

In Terminal B, select:

```
[1] Direct messages
```

You will see the conversation with alice. Select it to open the thread and read the
message. You can reply from here.

### Step 5 — Logging in again later

Each user's session is saved in `demo/user1/chat_session.json` and
`demo/user2/chat_session.json`. Running the script again will resume the session
automatically without needing to log in:

```
Resuming session as 'alice'.
```

To start fresh (e.g. to test with a different account), delete the session file:

```bash
rm demo/user1/chat_session.json
```

---

## 10. Stopping everything

**Stop the CLI:** press `4` then Enter in the main menu, or `Ctrl+C`.

**Stop the API server:** press `Ctrl+C` in the API terminal.

**Stop the database container:**

```bash
cd infra
docker compose stop    # stops the container, keeps data
docker compose down    # stops and removes the container (data volume is kept)
docker compose down -v # stops, removes container AND wipes all data
```

---

## 11. Troubleshooting

### `Binary not found` when running `run.sh` / `run.ps1`

You need to build first:

```bash
cargo build --bin chat
```

---

### `error: relation "users" does not exist` (compile error)

The database migrations have not been applied yet. Run step 5 again:

```bash
DATABASE_URL=postgres://chatapp:chatapp@localhost:5432/chatapp \
  sqlx migrate run --source infra/migrations
```

---

### `Connection refused` when starting the API

The Docker container is not running. Start it:

```bash
cd infra && docker compose up -d --wait
```

---

### `DATABASE_URL must be set` when starting the API

The `.env` file is missing from the project root. Copy it from the example:

```bash
cp .env.example .env
```

---

### The API starts but the CLI shows a connection error

Make sure the API server is running and listening on port 3000 before starting the CLI.  
Check the API terminal for any error output.