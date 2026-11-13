# ServiceNow OAuth 2.0 destination — experimental implementation

This branch adds **opt-in OAuth 2.0** to the built-in ServiceNow destination. Existing Basic destinations stay on their current authentication path unless the user explicitly selects OAuth 2.0.

## Grant types

- `client_credentials` (recommended for service-to-service integrations)
- `password` (legacy resource-owner-password grant; use only where explicitly authorized)

Authorization Code is intentionally **not** offered: it requires a login/redirect, authorization callback, durable refresh-token storage, and a separate user-consent workflow. Selecting an unsupported flow must never quietly fall back to Basic.

## Configuration

In the ServiceNow destination form, choose **OAuth 2.0** and provide:

- OAuth token endpoint (HTTPS, commonly `https://<instance>.service-now.com/oauth_token.do`)
- Grant type, client ID and **the name** of the environment variable containing the client secret
- Optional scope
- For legacy password grant, the names of environment variables containing username and password

Example ECS task **environment variable names** (values should be sourced securely from Secrets Manager/Vault):

```text
ZO_OAUTH_SERVICENOW_CLIENT_SECRET
ZO_OAUTH_SERVICENOW_USERNAME   # only for password grant
ZO_OAUTH_SERVICENOW_PASSWORD   # only for password grant
```

Never commit client secrets, real tokens, or vault values to GitHub. The destination stores only variable *names* in metadata; token material remains server-side. Task restarts pick up rotated ECS secrets; an already-running process will reuse a cached token until its TTL elapses.

## Execution

The Rust sender obtains a token with form-encoded OAuth parameters, caches it within each process based on `expires_in`, renews before expiry, and applies a Bearer header to outgoing ServiceNow alert requests and incident-resolution requests. A missing OAuth configuration or failed token request **fails closed** rather than sending Basic credentials. Other destinations are unchanged.

The same shared notification code handles alert-triggered sends, but the generic editor's **Test** request currently uses a different API path and does not resolve OAuth references. Validate end-to-end using a disposable saved destination and a controlled test alert.

## Local validation

```bash
git fetch origin
git switch -c test-servicenow-oauth origin/feature/servicenow-oauth2-auth
cargo fmt --all -- --check
cargo check -p openobserve-core
cargo test -p openobserve-core servicenow_oauth
cd web
npm run type-check
```

Check `src/core/Cargo.toml` for the exact Rust package name if necessary. Run `cargo fmt --all` locally before committing formatting fixes.

## Limitations and follow-up

- Experimental: **not yet compiled/tested** against a local environment. Do not deploy to production.
- The OAuth form's pre-save **Test** button is not yet wired to the backend token resolver.
- Cache is per-process/per-ECS-task; separate Fargate tasks acquire their own tokens.
- A failed API call with HTTP 401 does not yet force refresh/retry.
- Token requests are serialized by a process-wide mutex during refresh.
- Credential replacement/revocation should be re-tested when switching existing Basic destinations to OAuth.
- Password grant is a legacy compatibility mode; new deployments should prefer client credentials.
- OAuth configuration currently uses environment-variable references, not native Vault secret storage.
- Only the two supported grant types are offered; Authorization Code is out of scope until a secure callback/refresh-token architecture exists.
