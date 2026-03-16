//! Thin wrapper around the chat API using reqwest blocking.

use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use uuid::Uuid;

use protocol::{
    AckMessagesRequest, ChannelSummary, CreateChannelRequest, CreateChannelResponse,
    CreateDmRequest, CreateDmResponse, CreateServerRequest, CreateServerResponse, DevicePublicInfo,
    DmThreadSummary, FetchMessagesResponse, InboundMessage, InviteToServerRequest, LoginRequest,
    LoginResponse, OutboundEnvelope, RegisterDeviceRequest, RegisterDeviceResponse,
    SendMessageRequest, SendMessageResponse, ServerDetails, ServerSummary, SignedPrekey,
    SignupRequest, SignupResponse,
};

pub struct ApiClient {
    client: Client,
    base_url: String,
}

impl ApiClient {
    pub fn new() -> Self {
        let base_url = std::env::var("CHAT_API_URL")
            .unwrap_or_else(|_| "http://localhost:3000".into());
        Self {
            client: Client::new(),
            base_url,
        }
    }

    // ─── Auth ──────────────────────────────────────────────────────────────

    pub fn signup(&self, username: &str, password: &str) -> Result<SignupResponse> {
        let resp = self
            .client
            .post(format!("{}/auth/signup", self.base_url))
            .json(&SignupRequest {
                username: username.into(),
                password: password.into(),
            })
            .send()?;
        self.parse(resp)
    }

    pub fn login(&self, username: &str, password: &str) -> Result<LoginResponse> {
        let resp = self
            .client
            .post(format!("{}/auth/login", self.base_url))
            .json(&LoginRequest {
                username: username.into(),
                password: password.into(),
            })
            .send()?;
        self.parse(resp)
    }

    // ─── Devices ───────────────────────────────────────────────────────────

    pub fn register_device(
        &self,
        token: &str,
        display_name: &str,
        identity_key: String,
        identity_dh_key: String,
        signed_prekey: SignedPrekey,
    ) -> Result<RegisterDeviceResponse> {
        let resp = self
            .client
            .post(format!("{}/devices", self.base_url))
            .bearer_auth(token)
            .json(&RegisterDeviceRequest {
                display_name: display_name.into(),
                identity_key,
                identity_dh_key,
                signed_prekey,
                one_time_prekeys: vec![],
            })
            .send()?;
        self.parse(resp)
    }

    pub fn get_device_public_info(&self, token: &str, device_id: Uuid) -> Result<DevicePublicInfo> {
        let resp = self
            .client
            .get(format!("{}/devices/{}/info", self.base_url, device_id))
            .bearer_auth(token)
            .send()?;
        self.parse(resp)
    }

    // ─── Users / DMs ───────────────────────────────────────────────────────

    pub fn list_dms(&self, token: &str) -> Result<Vec<DmThreadSummary>> {
        let resp = self
            .client
            .get(format!("{}/dms", self.base_url))
            .bearer_auth(token)
            .send()?;
        self.parse(resp)
    }

    pub fn create_or_get_dm(&self, token: &str, with_user_id: Uuid) -> Result<CreateDmResponse> {
        let resp = self
            .client
            .post(format!("{}/dms", self.base_url))
            .bearer_auth(token)
            .json(&CreateDmRequest { with_user_id })
            .send()?;
        self.parse(resp)
    }

    pub fn client_get_user(
        &self,
        token: &str,
        username: &str,
    ) -> Result<protocol::UserSearchResult> {
        let resp = self
            .client
            .get(format!("{}/users/{}", self.base_url, username))
            .bearer_auth(token)
            .send()?;
        self.parse(resp)
    }

    pub fn get_user_dh_key(&self, token: &str, username: &str) -> Result<(Uuid, Uuid, String)> {
        // Returns (user_id, device_id, identity_dh_key_b64) for the first device.
        let bundles: Vec<protocol::DeviceKeyBundle> = {
            let resp = self
                .client
                .get(format!("{}/users/{}/keys", self.base_url, username))
                .bearer_auth(token)
                .send()?;
            self.parse(resp)?
        };

        let first = bundles
            .into_iter()
            .next()
            .context("target user has no registered devices")?;

        // We need the user_id — fetch it from the profile endpoint.
        let user_info: protocol::UserSearchResult = {
            let resp = self
                .client
                .get(format!("{}/users/{}", self.base_url, username))
                .bearer_auth(token)
                .send()?;
            self.parse(resp)?
        };

        Ok((user_info.user_id, first.device_id, first.identity_dh_key))
    }

    // ─── Messages ──────────────────────────────────────────────────────────

    pub fn send_message(
        &self,
        token: &str,
        thread_id: Uuid,
        sender_device_id: Uuid,
        envelopes: Vec<OutboundEnvelope>,
    ) -> Result<SendMessageResponse> {
        let resp = self
            .client
            .post(format!("{}/dms/{}/messages", self.base_url, thread_id))
            .bearer_auth(token)
            .json(&SendMessageRequest {
                sender_device_id,
                envelopes,
            })
            .send()?;
        self.parse(resp)
    }

    pub fn fetch_messages(
        &self,
        token: &str,
        thread_id: Uuid,
        device_id: Uuid,
        after: Option<Uuid>,
    ) -> Result<Vec<InboundMessage>> {
        let mut url = format!(
            "{}/dms/{}/messages?device_id={}",
            self.base_url, thread_id, device_id
        );
        if let Some(cursor) = after {
            url.push_str(&format!("&after={}", cursor));
        }
        let resp = self.client.get(&url).bearer_auth(token).send()?;
        let body: FetchMessagesResponse = self.parse(resp)?;
        Ok(body.messages)
    }

    pub fn ack_messages(
        &self,
        token: &str,
        thread_id: Uuid,
        device_id: Uuid,
        batch_ids: Vec<Uuid>,
    ) -> Result<()> {
        self.client
            .post(format!("{}/dms/{}/messages/ack", self.base_url, thread_id))
            .bearer_auth(token)
            .json(&AckMessagesRequest { device_id, batch_ids })
            .send()?;
        Ok(())
    }

    // ─── Servers ───────────────────────────────────────────────────────────

    pub fn create_server(&self, token: &str, name: &str) -> Result<CreateServerResponse> {
        let resp = self
            .client
            .post(format!("{}/servers", self.base_url))
            .bearer_auth(token)
            .json(&CreateServerRequest { name: name.into() })
            .send()?;
        self.parse(resp)
    }

    pub fn list_servers(&self, token: &str) -> Result<Vec<ServerSummary>> {
        let resp = self
            .client
            .get(format!("{}/servers", self.base_url))
            .bearer_auth(token)
            .send()?;
        self.parse(resp)
    }

    pub fn get_server(&self, token: &str, server_id: Uuid) -> Result<ServerDetails> {
        let resp = self
            .client
            .get(format!("{}/servers/{}", self.base_url, server_id))
            .bearer_auth(token)
            .send()?;
        self.parse(resp)
    }

    pub fn invite_to_server(&self, token: &str, server_id: Uuid, user_id: Uuid) -> Result<()> {
        self.client
            .post(format!("{}/servers/{}/invites", self.base_url, server_id))
            .bearer_auth(token)
            .json(&InviteToServerRequest { user_id })
            .send()?;
        Ok(())
    }

    pub fn leave_server(&self, token: &str, server_id: Uuid, user_id: Uuid) -> Result<()> {
        self.client
            .delete(format!(
                "{}/servers/{}/members/{}",
                self.base_url, server_id, user_id
            ))
            .bearer_auth(token)
            .send()?;
        Ok(())
    }

    // ─── Channels ──────────────────────────────────────────────────────────

    pub fn create_channel(
        &self,
        token: &str,
        server_id: Uuid,
        name: &str,
    ) -> Result<CreateChannelResponse> {
        let resp = self
            .client
            .post(format!("{}/servers/{}/channels", self.base_url, server_id))
            .bearer_auth(token)
            .json(&CreateChannelRequest { name: name.into() })
            .send()?;
        self.parse(resp)
    }

    pub fn list_channels(&self, token: &str, server_id: Uuid) -> Result<Vec<ChannelSummary>> {
        let resp = self
            .client
            .get(format!("{}/servers/{}/channels", self.base_url, server_id))
            .bearer_auth(token)
            .send()?;
        self.parse(resp)
    }

    pub fn send_channel_message(
        &self,
        token: &str,
        channel_id: Uuid,
        sender_device_id: Uuid,
        envelopes: Vec<OutboundEnvelope>,
    ) -> Result<SendMessageResponse> {
        let resp = self
            .client
            .post(format!("{}/channels/{}/messages", self.base_url, channel_id))
            .bearer_auth(token)
            .json(&SendMessageRequest { sender_device_id, envelopes })
            .send()?;
        self.parse(resp)
    }

    pub fn fetch_channel_messages(
        &self,
        token: &str,
        channel_id: Uuid,
        device_id: Uuid,
        after: Option<Uuid>,
    ) -> Result<Vec<InboundMessage>> {
        let mut url = format!(
            "{}/channels/{}/messages?device_id={}",
            self.base_url, channel_id, device_id
        );
        if let Some(cursor) = after {
            url.push_str(&format!("&after={}", cursor));
        }
        let resp = self.client.get(&url).bearer_auth(token).send()?;
        let body: FetchMessagesResponse = self.parse(resp)?;
        Ok(body.messages)
    }

    pub fn ack_channel_messages(
        &self,
        token: &str,
        channel_id: Uuid,
        device_id: Uuid,
        batch_ids: Vec<Uuid>,
    ) -> Result<()> {
        self.client
            .post(format!("{}/channels/{}/messages/ack", self.base_url, channel_id))
            .bearer_auth(token)
            .json(&AckMessagesRequest { device_id, batch_ids })
            .send()?;
        Ok(())
    }

    // ─── Internal ──────────────────────────────────────────────────────────

    fn parse<T: serde::de::DeserializeOwned>(
        &self,
        resp: reqwest::blocking::Response,
    ) -> Result<T> {
        let status = resp.status();
        let text = resp.text()?;
        if status.is_success() {
            serde_json::from_str(&text).with_context(|| format!("failed to parse response: {text}"))
        } else {
            // Try to extract the server's error message.
            let msg = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v["message"].as_str().map(str::to_owned))
                .unwrap_or(text);
            bail!("{} — {}", status, msg)
        }
    }
}
