//! Interactive command-line chat client.
//!
//! ## Two-terminal demo setup
//!
//!   Terminal 1 (alice):
//!     mkdir alice && cd alice
//!     cargo run --bin chat
//!
//!   Terminal 2 (bob):
//!     mkdir bob && cd bob
//!     cargo run --bin chat
//!
//! Each terminal stores its session in a local `chat_session.json` file.
//! The API server must be running: `cargo run --bin api`

mod api;

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::Local;
use std::{
    collections::HashMap,
    io::{self, Write},
};
use uuid::Uuid;

use api::ApiClient;
use crypto_core::{decrypt_from_device, dh_public_key_b64, encrypt_for_device, generate_device_keys};
use protocol::{InboundMessage, OutboundEnvelope, SignedPrekey};

const SESSION_FILE: &str = "chat_session.json";

// ─── Local session storage ────────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
struct Session {
    username: String,
    user_id: Uuid,
    token: String,
    device_id: Uuid,
    /// base64-encoded 32-byte Ed25519 signing seed.
    signing_seed_b64: String,
    /// base64-encoded 32-byte X25519 DH secret.
    dh_secret_b64: String,
    /// base64-encoded 32-byte X25519 signed prekey secret.
    signed_prekey_secret_b64: String,
    signed_prekey_id: i32,
    /// Cache: peer device_id (string) → their DH public key (base64).
    #[serde(default)]
    peer_dh_cache: HashMap<String, String>,
    /// Cache: peer user_id (string) → their username.
    #[serde(default)]
    peer_usernames: HashMap<String, String>,
    /// Cache: peer user_id (string) → (device_id, identity_dh_key_b64).
    /// Populated the first time we fetch a user's key bundle so group sends
    /// don't need to re-fetch on every message.
    #[serde(default)]
    user_device_cache: HashMap<String, (Uuid, String)>,
}

impl Session {
    fn dh_secret_bytes(&self) -> Result<[u8; 32]> {
        B64.decode(&self.dh_secret_b64)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("stored DH secret has wrong length"))
    }

    fn save(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(SESSION_FILE, json)?;
        Ok(())
    }

    fn load() -> Option<Self> {
        let text = std::fs::read_to_string(SESSION_FILE).ok()?;
        serde_json::from_str(&text).ok()
    }
}

// ─── Entry point ─────────────────────────────────────────────────────────────

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let api = ApiClient::new();

    println!();
    println!("╔═══════════════════════════════╗");
    println!("║       ChatApp CLI v0.1        ║");
    println!("╚═══════════════════════════════╝");
    println!();

    let mut session = match Session::load() {
        Some(s) => {
            println!("Resuming session as '{}'.", s.username);
            s
        }
        None => setup_session(&api)?,
    };

    main_menu(&api, &mut session)
}

// ─── Session setup (signup / login) ──────────────────────────────────────────

fn setup_session(api: &ApiClient) -> Result<Session> {
    println!("[1] Sign up");
    println!("[2] Log in");
    let choice = prompt("Choice")?;

    match choice.as_str() {
        "1" => signup_flow(api),
        "2" => login_flow(api),
        _ => {
            println!("Invalid choice.");
            setup_session(api)
        }
    }
}

fn signup_flow(api: &ApiClient) -> Result<Session> {
    let username = prompt("Username")?;
    let password = rpassword::prompt_password("Password: ")?;

    let resp = api
        .signup(&username, &password)
        .context("Signup failed")?;

    println!();
    println!("✓ Account created.");
    println!();
    println!("  ┌─────────────────────────────────────────────────┐");
    println!("  │  RECOVERY CODE — save this somewhere safe!       │");
    println!("  │  It is shown exactly once and cannot be          │");
    println!("  │  recovered if lost.                              │");
    println!("  │                                                  │");
    println!("  │  {}  │", resp.recovery_code);
    println!("  └─────────────────────────────────────────────────┘");
    println!();
    prompt("Press Enter to continue...")?;

    register_device_and_save(api, resp.user_id, &resp.username, &resp.token)
}

fn login_flow(api: &ApiClient) -> Result<Session> {
    let username = prompt("Username")?;
    let password = rpassword::prompt_password("Password: ")?;

    let resp = api.login(&username, &password).context("Login failed")?;
    println!("✓ Logged in as '{}'.", resp.username);

    register_device_and_save(api, resp.user_id, &resp.username, &resp.token)
}

fn register_device_and_save(
    api: &ApiClient,
    user_id: Uuid,
    username: &str,
    token: &str,
) -> Result<Session> {
    print!("Generating device keys... ");
    io::stdout().flush()?;

    let (material, public_keys) = generate_device_keys();

    println!("done.");
    print!("Registering device... ");
    io::stdout().flush()?;

    let dev_resp = api
        .register_device(
            token,
            &format!("{}'s CLI", username),
            public_keys.identity_key,
            public_keys.identity_dh_key,
            SignedPrekey {
                key_id: public_keys.signed_prekey_id,
                public_key: public_keys.signed_prekey_pub,
                signature: public_keys.signed_prekey_sig,
            },
        )
        .context("Device registration failed")?;

    println!("done.");

    let session = Session {
        username: username.to_owned(),
        user_id,
        token: token.to_owned(),
        device_id: dev_resp.device_id,
        signing_seed_b64: B64.encode(material.signing_seed),
        dh_secret_b64: B64.encode(material.dh_secret),
        signed_prekey_secret_b64: B64.encode(material.signed_prekey_secret),
        signed_prekey_id: material.signed_prekey_id,
        peer_dh_cache: HashMap::new(),
        peer_usernames: HashMap::new(),
        user_device_cache: HashMap::new(),
    };

    session.save()?;
    println!("Session saved to '{SESSION_FILE}'.");
    println!();

    Ok(session)
}

// ─── Main menu ────────────────────────────────────────────────────────────────

fn main_menu(api: &ApiClient, session: &mut Session) -> Result<()> {
    loop {
        println!("═══ Logged in as '{}' ═══", session.username);
        println!("[1] Direct messages");
        println!("[2] Message someone new");
        println!("[3] Servers");
        println!("[4] Quit");

        match prompt("Choice")?.as_str() {
            "1" => list_and_open_dm(api, session)?,
            "2" => open_new_dm(api, session)?,
            "3" => server_hub(api, session)?,
            "4" | "q" => {
                println!("Goodbye.");
                break;
            }
            _ => println!("Unknown choice.\n"),
        }
    }
    Ok(())
}

// ─── DM thread selection ──────────────────────────────────────────────────────

fn list_and_open_dm(api: &ApiClient, session: &mut Session) -> Result<()> {
    let threads = api.list_dms(&session.token)?;

    if threads.is_empty() {
        println!("No conversations yet. Start one with option [2].\n");
        return Ok(());
    }

    // Cache every peer's username so display_messages can show real names.
    let mut dirty = false;
    for t in &threads {
        let key = t.other_user.user_id.to_string();
        if !session.peer_usernames.contains_key(&key) {
            session.peer_usernames.insert(key, t.other_user.username.clone());
            dirty = true;
        }
    }
    if dirty {
        session.save()?;
    }

    println!();
    for (i, t) in threads.iter().enumerate() {
        println!("[{}] DM with {}", i + 1, t.other_user.username);
    }
    println!("[0] Back");

    let choice = prompt("Open conversation")?;
    if choice == "0" || choice.is_empty() {
        return Ok(());
    }

    let idx: usize = choice.parse::<usize>().context("invalid choice")? - 1;
    let thread = threads.get(idx).context("invalid choice")?;

    chat_loop(api, session, thread.thread_id, &thread.other_user.username)
}

fn open_new_dm(api: &ApiClient, session: &mut Session) -> Result<()> {
    let target_username = prompt("Username to message")?;

    if target_username == session.username {
        println!("You can't message yourself.\n");
        return Ok(());
    }

    // Fetch the target's device info so we can cache their DH key.
    let (other_user_id, other_device_id, other_dh_key) =
        api.get_user_dh_key(&session.token, &target_username)?;

    // Cache the DH key, username, and user→device mapping.
    session.peer_dh_cache.insert(other_device_id.to_string(), other_dh_key.clone());
    session.peer_usernames.insert(other_user_id.to_string(), target_username.clone());
    session.user_device_cache.insert(other_user_id.to_string(), (other_device_id, other_dh_key));
    session.save()?;

    let dm = api.create_or_get_dm(&session.token, other_user_id)?;

    if dm.created {
        println!("✓ New conversation started with '{target_username}'.");
    } else {
        println!("✓ Resumed existing conversation with '{target_username}'.");
    }

    chat_loop(api, session, dm.thread_id, &target_username)
}

// ─── Chat loop ────────────────────────────────────────────────────────────────

fn chat_loop(
    api: &ApiClient,
    session: &mut Session,
    thread_id: Uuid,
    peer_username: &str,
) -> Result<()> {
    println!();
    println!("═══ DM with {} (thread {}) ═══", peer_username, &thread_id.to_string()[..8]);
    println!("  Press Enter to refresh | type a message and Enter to send | 'q' to go back");
    println!();

    let mut last_batch_id: Option<Uuid> = None;

    // Load recent history on entry.
    last_batch_id = display_messages(api, session, thread_id, last_batch_id)?;

    loop {
        print!(">> ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim().to_owned();

        if input == "q" || input == "quit" {
            println!();
            break;
        }

        if !input.is_empty() {
            // Encrypt and send the message.
            match send_encrypted(api, session, thread_id, peer_username, &input) {
                Ok(batch_id) => {
                    let time = Local::now().format("%H:%M:%S");
                    println!("[{time}] {}: {input}", session.username);
                    // Advance cursor past the message we just sent.
                    last_batch_id = Some(batch_id);
                }
                Err(e) => println!("  [send failed: {e}]"),
            }
        }

        // Refresh — show any new incoming messages.
        match display_messages(api, session, thread_id, last_batch_id) {
            Ok(new_cursor) => {
                if new_cursor != last_batch_id {
                    last_batch_id = new_cursor;
                }
            }
            Err(e) => println!("  [fetch failed: {e}]"),
        }
    }

    Ok(())
}

// ─── Send a message ───────────────────────────────────────────────────────────

fn send_encrypted(
    api: &ApiClient,
    session: &mut Session,
    thread_id: Uuid,
    peer_username: &str,
    plaintext: &str,
) -> Result<Uuid> {
    // Find all recipient devices. For now we fetch the peer's key bundle (which
    // may consume a one-time prekey) if we don't have their DH key cached.
    let our_dh = session.dh_secret_bytes()?;
    let mut envelopes: Vec<OutboundEnvelope> = Vec::new();

    // Build the list of (device_id, dh_pub_b64) to encrypt for.
    let mut recipients: Vec<(Uuid, String)> = Vec::new();

    // Collect known peer devices from cache.
    let cached: Vec<(Uuid, String)> = session
        .peer_dh_cache
        .iter()
        .map(|(id, key)| (id.parse::<Uuid>().unwrap(), key.clone()))
        .collect();

    if cached.is_empty() {
        // No cache — fetch key bundles (this may consume a one-time prekey).
        let (user_id, device_id, dh_key) = api.get_user_dh_key(&session.token, peer_username)?;
        session.peer_dh_cache.insert(device_id.to_string(), dh_key.clone());
        session.user_device_cache.insert(user_id.to_string(), (device_id, dh_key.clone()));
        session.save()?;
        recipients.push((device_id, dh_key));
    } else {
        recipients = cached;
    }

    // Encrypt one envelope per recipient device.
    let aad = thread_id.as_bytes().as_slice();
    for (device_id, dh_pub_b64) in recipients {
        let ciphertext = encrypt_for_device(&our_dh, &dh_pub_b64, plaintext, aad)
            .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;
        envelopes.push(OutboundEnvelope { recipient_device_id: device_id, ciphertext });
    }

    if envelopes.is_empty() {
        anyhow::bail!("no recipient devices found");
    }

    // Add a self-envelope so our own device receives a copy. This lets us
    // display sent messages in chat history using self-ECDH decryption.
    let own_dh_pub_b64 = dh_public_key_b64(&our_dh);
    let self_ciphertext = encrypt_for_device(&our_dh, &own_dh_pub_b64, plaintext, aad)
        .map_err(|e| anyhow::anyhow!("self-encryption failed: {e}"))?;
    envelopes.push(OutboundEnvelope {
        recipient_device_id: session.device_id,
        ciphertext: self_ciphertext,
    });

    let resp = api.send_message(&session.token, thread_id, session.device_id, envelopes)?;
    Ok(resp.batch_id)
}

// ─── Shared decrypt-and-display helper ───────────────────────────────────────

/// Decrypts `messages` using `aad`, prints each one, and returns
/// `(new_cursor, batch_ids_to_ack)`.  The caller is responsible for ACKing.
fn render_messages(
    api: &ApiClient,
    session: &mut Session,
    messages: &[InboundMessage],
    aad: &[u8],
    cursor: Option<Uuid>,
) -> Result<(Option<Uuid>, Vec<Uuid>)> {
    let our_dh = session.dh_secret_bytes()?;
    let mut new_cursor = cursor;
    let mut batch_ids_to_ack = Vec::new();

    for msg in messages {
        let time = msg.created_at.with_timezone(&Local).format("%H:%M:%S");
        let sender_device_key = msg.sender_device_id.to_string();

        // For self-envelopes use self-ECDH; for peers look up or fetch their key.
        let sender_dh_pub = if msg.sender_user_id == session.user_id {
            dh_public_key_b64(&our_dh)
        } else {
            match session.peer_dh_cache.get(&sender_device_key) {
                Some(k) => k.clone(),
                None => {
                    let info =
                        api.get_device_public_info(&session.token, msg.sender_device_id)?;
                    let key = info.identity_dh_key.clone();
                    session.peer_dh_cache.insert(sender_device_key, key.clone());
                    session.save()?;
                    key
                }
            }
        };

        let plaintext =
            match decrypt_from_device(&our_dh, &sender_dh_pub, &msg.ciphertext, aad) {
                Ok(p) => p,
                Err(e) => format!("[decryption failed: {e}]"),
            };

        let sender_display = if msg.sender_user_id == session.user_id {
            session.username.clone()
        } else {
            session
                .peer_usernames
                .get(&msg.sender_user_id.to_string())
                .cloned()
                .unwrap_or_else(|| format!("user:{}", &msg.sender_user_id.to_string()[..8]))
        };

        println!("[{time}] {sender_display}: {plaintext}");

        new_cursor = Some(msg.batch_id);
        batch_ids_to_ack.push(msg.batch_id);
    }

    Ok((new_cursor, batch_ids_to_ack))
}

// ─── Fetch and display new DM messages ───────────────────────────────────────

fn display_messages(
    api: &ApiClient,
    session: &mut Session,
    thread_id: Uuid,
    cursor: Option<Uuid>,
) -> Result<Option<Uuid>> {
    let messages =
        api.fetch_messages(&session.token, thread_id, session.device_id, cursor)?;

    if messages.is_empty() {
        return Ok(cursor);
    }

    let (new_cursor, acks) =
        render_messages(api, session, &messages, thread_id.as_bytes(), cursor)?;

    if !acks.is_empty() {
        let _ = api.ack_messages(&session.token, thread_id, session.device_id, acks);
    }

    Ok(new_cursor)
}

// ─── Fetch and display new channel messages ───────────────────────────────────

fn display_channel_messages(
    api: &ApiClient,
    session: &mut Session,
    channel_id: Uuid,
    cursor: Option<Uuid>,
) -> Result<Option<Uuid>> {
    let messages =
        api.fetch_channel_messages(&session.token, channel_id, session.device_id, cursor)?;

    if messages.is_empty() {
        return Ok(cursor);
    }

    let (new_cursor, acks) =
        render_messages(api, session, &messages, channel_id.as_bytes(), cursor)?;

    if !acks.is_empty() {
        let _ =
            api.ack_channel_messages(&session.token, channel_id, session.device_id, acks);
    }

    Ok(new_cursor)
}

// ─── Server / channel UI ──────────────────────────────────────────────────────

fn server_hub(api: &ApiClient, session: &mut Session) -> Result<()> {
    loop {
        println!("═══ Servers ═══");
        println!("[1] My servers");
        println!("[2] Create a server");
        println!("[0] Back");

        match prompt("Choice")?.as_str() {
            "1" => list_and_open_server(api, session)?,
            "2" => create_server_flow(api, session)?,
            "0" | "" => break,
            _ => println!("Unknown choice.\n"),
        }
    }
    Ok(())
}

fn create_server_flow(api: &ApiClient, session: &mut Session) -> Result<()> {
    let name = prompt("Server name")?;
    if name.is_empty() {
        println!("Name cannot be empty.\n");
        return Ok(());
    }
    let resp = api.create_server(&session.token, &name).context("Failed to create server")?;
    println!("✓ Server '{}' created (id: {}).\n", name, &resp.server_id.to_string()[..8]);
    Ok(())
}

fn list_and_open_server(api: &ApiClient, session: &mut Session) -> Result<()> {
    let servers = api.list_servers(&session.token)?;

    if servers.is_empty() {
        println!("You are not in any servers yet.\n");
        return Ok(());
    }

    println!();
    for (i, s) in servers.iter().enumerate() {
        println!("[{}] {} ({})", i + 1, s.name, s.role);
    }
    println!("[0] Back");

    let choice = prompt("Open server")?;
    if choice == "0" || choice.is_empty() {
        return Ok(());
    }

    let idx: usize = choice.parse::<usize>().context("invalid choice")? - 1;
    let server = servers.get(idx).context("invalid choice")?;

    server_menu(api, session, server.server_id, &server.name, &server.role)
}

fn server_menu(
    api: &ApiClient,
    session: &mut Session,
    server_id: Uuid,
    server_name: &str,
    role: &str,
) -> Result<()> {
    loop {
        println!();
        println!("═══ {} ═══", server_name);
        println!("[1] Channels");
        if role == "owner" {
            println!("[2] Create channel");
            println!("[3] Invite a user");
        }
        println!("[0] Back");

        match prompt("Choice")?.as_str() {
            "1" => list_and_open_channel(api, session, server_id, server_name)?,
            "2" if role == "owner" => create_channel_flow(api, session, server_id)?,
            "3" if role == "owner" => invite_user_flow(api, session, server_id)?,
            "0" | "" => break,
            _ => println!("Unknown choice.\n"),
        }
    }
    Ok(())
}

fn create_channel_flow(api: &ApiClient, session: &mut Session, server_id: Uuid) -> Result<()> {
    let name = prompt("Channel name")?;
    if name.is_empty() {
        println!("Name cannot be empty.\n");
        return Ok(());
    }
    let resp = api
        .create_channel(&session.token, server_id, &name)
        .context("Failed to create channel")?;
    println!("✓ Channel '{}' created (id: {}).\n", name, &resp.channel_id.to_string()[..8]);
    Ok(())
}

fn invite_user_flow(api: &ApiClient, session: &mut Session, server_id: Uuid) -> Result<()> {
    let username = prompt("Username to invite")?;
    if username.is_empty() {
        return Ok(());
    }

    // Resolve username → user_id.
    let user_info: protocol::UserSearchResult = {
        let resp = api
            .client_get_user(&session.token, &username)
            .context("User lookup failed")?;
        resp
    };

    api.invite_to_server(&session.token, server_id, user_info.user_id)
        .context("Invite failed")?;

    // Cache their info for future sends.
    session.peer_usernames.insert(user_info.user_id.to_string(), username.clone());
    session.save()?;

    println!("✓ Invited '{}' to the server.\n", username);
    Ok(())
}

fn list_and_open_channel(
    api: &ApiClient,
    session: &mut Session,
    server_id: Uuid,
    server_name: &str,
) -> Result<()> {
    let channels = api.list_channels(&session.token, server_id)?;

    if channels.is_empty() {
        println!("No channels yet. Create one with option [2].\n");
        return Ok(());
    }

    println!();
    for (i, c) in channels.iter().enumerate() {
        println!("[{}] #{}", i + 1, c.name);
    }
    println!("[0] Back");

    let choice = prompt("Open channel")?;
    if choice == "0" || choice.is_empty() {
        return Ok(());
    }

    let idx: usize = choice.parse::<usize>().context("invalid choice")? - 1;
    let channel = channels.get(idx).context("invalid choice")?;

    // Pre-populate peer info from the member list so the first send is fast.
    let server = api.get_server(&session.token, server_id)?;
    let mut dirty = false;
    for member in &server.members {
        let uid_key = member.user_id.to_string();
        if member.user_id != session.user_id
            && !session.user_device_cache.contains_key(&uid_key)
        {
            session.peer_usernames.insert(uid_key.clone(), member.username.clone());
            // Fetch and cache their device key eagerly.
            match api.get_user_dh_key(&session.token, &member.username) {
                Ok((uid, dev_id, dh_pub)) => {
                    session.peer_dh_cache.insert(dev_id.to_string(), dh_pub.clone());
                    session.user_device_cache.insert(uid.to_string(), (dev_id, dh_pub));
                }
                Err(e) => println!("  [warn: could not fetch keys for {}: {e}]", member.username),
            }
            dirty = true;
        } else if !session.peer_usernames.contains_key(&uid_key) {
            session.peer_usernames.insert(uid_key, member.username.clone());
            dirty = true;
        }
    }
    if dirty {
        session.save()?;
    }

    channel_chat_loop(api, session, server_id, channel.channel_id, &channel.name, server_name)
}

fn channel_chat_loop(
    api: &ApiClient,
    session: &mut Session,
    server_id: Uuid,
    channel_id: Uuid,
    channel_name: &str,
    server_name: &str,
) -> Result<()> {
    println!();
    println!(
        "═══ #{} in {} ═══",
        channel_name, server_name
    );
    println!("  Press Enter to refresh | type a message and Enter to send | 'q' to go back");
    println!();

    let mut last_batch_id: Option<Uuid> = None;
    last_batch_id = display_channel_messages(api, session, channel_id, last_batch_id)?;

    loop {
        print!(">> ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim().to_owned();

        if input == "q" || input == "quit" {
            println!();
            break;
        }

        if !input.is_empty() {
            match send_channel_encrypted(api, session, server_id, channel_id, &input) {
                Ok(batch_id) => {
                    let time = Local::now().format("%H:%M:%S");
                    println!("[{time}] {}: {input}", session.username);
                    last_batch_id = Some(batch_id);
                }
                Err(e) => println!("  [send failed: {e}]"),
            }
        }

        match display_channel_messages(api, session, channel_id, last_batch_id) {
            Ok(new_cursor) => {
                if new_cursor != last_batch_id {
                    last_batch_id = new_cursor;
                }
            }
            Err(e) => println!("  [fetch failed: {e}]"),
        }
    }

    Ok(())
}

// ─── Encrypt and send a channel message ──────────────────────────────────────

fn send_channel_encrypted(
    api: &ApiClient,
    session: &mut Session,
    server_id: Uuid,
    channel_id: Uuid,
    plaintext: &str,
) -> Result<Uuid> {
    let our_dh = session.dh_secret_bytes()?;
    let aad = channel_id.as_bytes().as_slice();
    let mut envelopes: Vec<OutboundEnvelope> = Vec::new();

    // Get the current member list so we encrypt for every member device.
    let server = api.get_server(&session.token, server_id)?;

    for member in &server.members {
        if member.user_id == session.user_id {
            continue; // Self-envelope is added separately below.
        }

        let uid_key = member.user_id.to_string();

        let (device_id, dh_pub) =
            if let Some(cached) = session.user_device_cache.get(&uid_key) {
                cached.clone()
            } else {
                // Not yet cached — fetch now and store in all three caches.
                let (uid, dev_id, dh) =
                    api.get_user_dh_key(&session.token, &member.username)?;
                session.peer_dh_cache.insert(dev_id.to_string(), dh.clone());
                session.peer_usernames.insert(uid.to_string(), member.username.clone());
                session.user_device_cache.insert(uid.to_string(), (dev_id, dh.clone()));
                session.save()?;
                (dev_id, dh)
            };

        let ciphertext = encrypt_for_device(&our_dh, &dh_pub, plaintext, aad)
            .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;
        envelopes.push(OutboundEnvelope { recipient_device_id: device_id, ciphertext });
    }

    // Self-envelope so we can see sent messages in history.
    let own_dh_pub = dh_public_key_b64(&our_dh);
    let self_ciphertext = encrypt_for_device(&our_dh, &own_dh_pub, plaintext, aad)
        .map_err(|e| anyhow::anyhow!("self-encryption failed: {e}"))?;
    envelopes.push(OutboundEnvelope {
        recipient_device_id: session.device_id,
        ciphertext: self_ciphertext,
    });

    if envelopes.len() < 2 {
        // Only the self-envelope exists — no other members have devices yet.
        // Send anyway so the sender can see their own message.
    }

    let resp =
        api.send_channel_message(&session.token, channel_id, session.device_id, envelopes)?;
    Ok(resp.batch_id)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn prompt(label: &str) -> Result<String> {
    print!("{label}: ");
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_owned())
}
