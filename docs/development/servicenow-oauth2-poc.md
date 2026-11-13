# ServiceNow OAuth 2.0 — UI-managed prototype

Branch: `feature/servicenow-oauth2-auth`. This is an uncompiled proof of concept, **not production-ready**.

## Existing functionality

The ServiceNow destination keeps **Basic Authentication as the default**. Previously saved Basic destinations are unaffected unless an editor explicitly selects OAuth 2.0.

## New ServiceNow form

- **Instance URL** remains the main ServiceNow incident-table URL. The backend derives `/oauth_token.do` from its origin. There is **no separate Token URL field**.
- **Authentication method**: Basic or OAuth 2.0.
- **OAuth grant type**: Client Credentials (preferred) or Password (legacy).
- **Client Credentials**: client ID, client secret, optional scope.
- **Password grant**: all of the above, plus service-account username and password.
- Assignment group, resolution code, and the existing message-template selection remain available.

## UI-only per-destination setup

The client secret and password are submitted through write-only API fields, encrypted with OpenObserve's existing AES-256-SIV helper *before* persisting destination metadata, and removed from destination GET/list responses. A GET response can expose non-secret configuration plus `credential_oauthClientSecretSaved`/`credential_oauthPasswordSaved` status flags, never the ciphertext or secret. Updating a destination with secret inputs left blank preserves the previous encrypted values.

No environment variables or ECS restarts are required **per ServiceNow destination**.

**One-time deployment requirement:** configure a random, 64-byte base64-encoded AES-SIV key as `ZO_OAUTH_ENCRYPTION_KEY` through ECS Secrets Manager injection on every OpenObserve task. Keep it stable across restarts; loss of the key makes stored credentials unrecoverable. This is a new global secret and therefore needs a **one-time** task-definition change. Do not commit the key or OAuth credentials to GitHub.

## Backend flow

1. User saves ServiceNow OAuth settings through the UI.
2. API validates HTTPS, grant, and secret completeness; encrypts write-only secret fields.
3. Destination persistence stores ciphertext with existing destination records.
4. On a real alert, the token manager derives `https://<instance>/oauth_token.do`, decrypts stored credentials server-side and requests an access token.
5. Token is cached in the sending process until just before `expires_in`; the API send adds `Authorization: Bearer …`.
6. Existing Basic destinations continue using their existing Authorization header.

The code reuses the shared safe outbound HTTP client and SSRF guard.

## Security/feature gaps before production

- **Not compiled/tested yet**. Run Rust and frontend checks locally.
- The ServiceNow prebuilt **Test** button now submits OAuth configuration to the server, obtains a token, and makes a test HTTP request. It may create a real ServiceNow incident and must be validated end-to-end. Editing a saved destination may reuse its encrypted secret only when the URL is unchanged and the caller can update that destination.
- No forced refresh/retry on 401 from ServiceNow.
- Process-local token cache, not shared across Fargate tasks.
- Encryption key must be shared, backed up, restricted, and rotated carefully.
- Changing from OAuth to Basic drops OAuth ciphertext on the next save, but that behavior still needs regression testing.
- Verify authorization controls and that logs/debug traces do not expose credentials.
- Confirm that changing a destination type cannot expose ciphertext through alternate API endpoints.
- Password grant is a legacy choice; prefer `client_credentials` for new applications.

## Pull/test

```bash
cd ~/openobserve
git fetch origin
git switch -c test-servicenow-oauth-ui origin/feature/servicenow-oauth2-auth
cargo fmt --all
cargo check -p openobserve-core
cargo check -p openobserve-api-management
cargo test -p openobserve-core servicenow_oauth
cd web && NODE_OPTIONS=--max-old-space-size=8192 npm run type-check:app
```

Do not deploy to production until the remaining items are addressed and end-to-end test coverage is complete.
