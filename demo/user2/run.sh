#!/usr/bin/env bash
# Run the chat client from this directory.
# chat_session.json is stored here and holds your login session.
set -euo pipefail
cd "$(dirname "$0")"

BINARY="../../target/debug/chat"

if [[ ! -f "$BINARY" ]]; then
    echo "Binary not found at $BINARY — build it first with: cargo build --bin chat"
    exit 1
fi

exec "$BINARY"
