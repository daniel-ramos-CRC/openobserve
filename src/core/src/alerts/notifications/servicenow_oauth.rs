// Copyright 2026 OpenObserve Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Opt-in OAuth authentication for ServiceNow alert destinations.
//!
//! The existing Basic authentication path is deliberately unchanged.
//! Credentials are referenced by environment-variable name, never stored in
//! destination metadata or emitted in errors/logs.

use std::{collections::HashMap, sync::LazyLock, time::{Duration, Instant}};
use tokio::sync::Mutex;
use config::meta::destinations::Endpoint;
use config::utils::ssrf_guard::SsrfGuard;
use serde_json::Value;

struct Token {
    access_token: String,
    expires_at: Instant,
}
static TOKENS: LazyLock<Mutex<HashMap<String, Token>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn field<'a>(endpoint: &'a Endpoint, name: &str) -> &'a str {
    endpoint.metadata.get(name).map(String::as_str).unwrap_or("")
}

pub fn enabled(endpoint: &Endpoint) -> bool {
    endpoint.destination_type.as_deref() == Some("servicenow")
        && field(endpoint, "credential_authMethod") == "oauth2"
}

/// Acquire an access token only for explicitly opted-in ServiceNow destinations.
/// A missing or invalid OAuth configuration fails closed (no Basic fallback).
pub async fn bearer(endpoint: &Endpoint) -> anyhow::Result<Option<String>> {
    if !enabled(endpoint) {
        return Ok(None);
    }

    let grant = field(endpoint, "credential_oauthGrantType");
    if grant != "client_credentials" && grant != "password" {
        anyhow::bail!("Unsupported ServiceNow OAuth grant type");
    }
    let token_url = field(endpoint, "credential_oauthTokenUrl");
    let client_id = field(endpoint, "credential_oauthClientId");
    let secret_env = field(endpoint, "credential_oauthClientSecretEnv");
    let scope = field(endpoint, "credential_oauthScope");
    if token_url.is_empty() || client_id.is_empty() {
        anyhow::bail!("Incomplete ServiceNow OAuth configuration");
    }
    let read_secret = |name: &str| -> anyhow::Result<String> {
        if !name.starts_with("ZO_OAUTH_")
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            anyhow::bail!("OAuth secret must reference a ZO_OAUTH_* environment variable");
        }
        std::env::var(name).map_err(|_| anyhow::anyhow!("Required OAuth environment variable is not configured"))
    };

    let secret = read_secret(secret_env)?;
    let username_env = field(endpoint, "credential_oauthUsernameEnv");
    let password_env = field(endpoint, "credential_oauthPasswordEnv");
    let username = if grant == "password" { Some(read_secret(username_env)?) } else { None };
    let password = if grant == "password" { Some(read_secret(password_env)?) } else { None };

    let cache_key = format!("{token_url}|{client_id}|{secret_env}|{scope}|{grant}|{username_env}|{password_env}");
    let mut cache = TOKENS.lock().await;
    if let Some(token) = cache.get(&cache_key) {
        if Instant::now() < token.expires_at {
            return Ok(Some(token.access_token.clone()));
        }
    }

    // Token endpoints use the same DNS/redirect SSRF protection as alert destinations.
    SsrfGuard::validate_destination_url_with_config_async(token_url)
        .await
        .map_err(|_| anyhow::anyhow!("OAuth token URL blocked by SSRF policy"))?;
    if url::Url::parse(token_url)?.scheme() != "https" {
        anyhow::bail!("OAuth token endpoint must use HTTPS");
    }
    let client = common::utils::ssrf_guard::build_safe_destination_client(
        reqwest::Client::builder().timeout(Duration::from_secs(15)),
    )?;
    let mut params = vec![
        ("grant_type", grant),
        ("client_id", client_id),
        ("client_secret", secret.as_str()),
    ];
    if !scope.is_empty() {
        params.push(("scope", scope));
    }
    if let (Some(username), Some(password)) = (&username, &password) {
        params.push(("username", username.as_str()));
        params.push(("password", password.as_str()));
    }
    let response = client.post(token_url).form(&params).send().await
        .map_err(|_| anyhow::anyhow!("ServiceNow OAuth token request failed"))?;
    if !response.status().is_success() {
        anyhow::bail!("ServiceNow OAuth token endpoint rejected the request (HTTP {})", response.status());
    }
    let response: Value = response.json().await
        .map_err(|_| anyhow::anyhow!("Invalid ServiceNow OAuth token response"))?;
    let access_token = response["access_token"].as_str()
        .filter(|token| !token.is_empty())
        .ok_or_else(|| anyhow::anyhow!("ServiceNow OAuth response omitted access_token"))?
        .to_string();
    let ttl = response["expires_in"].as_u64()
        .or_else(|| response["expires_in"].as_str().and_then(|v| v.parse().ok()))
        .ok_or_else(|| anyhow::anyhow!("ServiceNow OAuth response omitted expires_in"))?;
    if ttl == 0 {
        anyhow::bail!("ServiceNow OAuth token has zero lifetime");
    }
    // Refresh early; never use a token after its advertised expiry.
    let margin = std::cmp::min(60, std::cmp::max(1, ttl / 10));
    let lifespan = ttl.saturating_sub(margin);
    cache.insert(cache_key, Token {
        access_token: access_token.clone(),
        expires_at: Instant::now() + Duration::from_secs(lifespan),
    });
    Ok(Some(access_token))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn basic_destinations_remain_opted_out() {
        assert!(!enabled(&Endpoint::default()));
        let endpoint = Endpoint {
            destination_type: Some("servicenow".to_string()),
            ..Default::default()
        };
        assert!(!enabled(&endpoint));
    }
}
