# Run the chat client from this directory.
# chat_session.json is stored here and holds your login session.
Set-Location $PSScriptRoot

$binary = "..\..\target\debug\chat.exe"

if (-not (Test-Path $binary)) {
    Write-Error "Binary not found at $binary — build it first with: cargo build --bin chat"
    exit 1
}

& $binary
