// Copyright 2026 OpenObserve Inc.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Opt-in OAuth authentication for ServiceNow alert destinations.
//!
//! The existing Basic authentication path is deliberately unchanged.
//! Secrets are encrypted in persisted destination metadata and are never
//! returned to the UI or emitted in errors/logs.

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
    // Derive the token endpoint from the configured ServiceNow instance URL.
    // The UI never asks the user to type a separate token URL.
    let mut parsed_url = url::Url::parse(&endpoint.url)
        .map_err(|_| anyhow::anyhow!("Invalid ServiceNow instance URL"))?;
    if parsed_url.scheme() != "https" || parsed_url.host_str().is_none() {
        anyhow::bail!("ServiceNow OAuth requires an HTTPS instance URL");
    }
    parsed_url.set_path("/oauth_token.do");
    parsed_url.set_query(None);
    parsed_url.set_fragment(None);
    let token_url = parsed_url.as_str();

    let client_id = field(endpoint, "credential_oauthClientId");
    let scope = field(endpoint, "credential_oauthScope");
    if client_id.trim().is_empty() {
        anyhow::bail!("Incomplete ServiceNow OAuth configuration");
    }
    let key = std::env::var("ZO_OAUTH_ENCRYPTION_KEY")
        .map_err(|_| anyhow::anyhow!("OAuth encryption key is not configured"))?;
    let dek = config::utils::encryption::decode_encryption_key(&key)
        .map_err(|_| anyhow::anyhow!("Invalid OAuth encryption key"))?;
    let decrypt = |name: &str| -> anyhow::Result<String> {
        let encrypted = field(endpoint, name);
        if encrypted.is_empty() {
            anyhow::bail!("Required OAuth secret is missing");
        }
        config::utils::encryption::decrypt_secret_value(&dek, encrypted)
            .map_err(|_| anyhow::anyhow!("Unable to decrypt stored OAuth secret"))
    };
    let secret = decrypt("oauth_client_secret_enc")?;
    let username = if grant == "password" {
        let value = field(endpoint, "credential_oauthUsername");
        if value.is_empty() {
            anyhow::bail!("Password grant username is missing");
        }
        Some(value.to_string())
    } else {
        None
    };
    let password = if grant == "password" {
        Some(decrypt("oauth_password_enc")?)
    } else {
        None
    };
    // Cache by destination identity/configuration; tokens stay in process memory.
    let cache_key = format!("{token_url}|{client_id}|{scope}|{grant}|{username:?}|{secret}");
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

    #[test]
    fn oauth_is_only_enabled_for_explicit_servicenow_opt_in() {
        let mut endpoint = Endpoint {
            destination_type: Some("servicenow".to_string()),
            ..Default::default()
        };
        endpoint.metadata.insert("credential_authMethod".to_string(), "oauth2".to_string());
        assert!(enabled(&endpoint));
        endpoint.destination_type = Some("custom".to_string());
        assert!(!enabled(&endpoint));
        endpoint.destination_type = Some("servicenow".to_string());
        endpoint.metadata.insert("credential_authMethod".to_string(), "basic".to_string());
        assert!(!enabled(&endpoint));
    }

    #[tokio::test]
    async fn incomplete_oauth_config_fails_closed() {
        let mut endpoint = Endpoint {
            destination_type: Some("servicenow".to_string()),
            ..Default::default()
        };
        endpoint.metadata.insert("credential_authMethod".to_string(), "oauth2".to_string());
        assert!(bearer(&endpoint).await.is_err());
    }
}
