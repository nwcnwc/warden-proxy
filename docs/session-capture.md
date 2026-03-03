# Session Capture Architecture

## Overview

Warden can capture authenticated web sessions so jailed apps can access user accounts (email, calendars, dashboards, etc.) without ever seeing passwords or tokens.

The user logs into a website once through a Warden-managed browser window. Warden captures ALL auth state — cookies, localStorage, and sessionStorage. From then on, any jailed app accessing that domain gets the captured auth state injected transparently.

## Auth State Capture

We capture three types of auth state from the WebView:

1. **Cookies** — Traditional session cookies (most websites)
2. **localStorage** — JWTs, API tokens, SPA auth state (modern apps)
3. **sessionStorage** — Temporary session tokens (some SPAs)

All three are extracted via the `wry` WebView API after the user closes the login window.

## Cross-Platform Browser Engine

Uses `wry` crate (same engine as Tauri):
- **Linux:** webkit2gtk
- **macOS:** WKWebView (built-in)
- **Windows:** WebView2/Edge (built-in)

No external browser dependency. Native look and feel on each platform.

## Flow

1. User clicks "Add Website Access" in Warden's Office
2. Enters domain (e.g., "yahoo.com") or clicks a quick-login icon
3. Warden opens a `wry` WebView window navigated to `https://<domain>`
4. User logs in normally (supports 2FA, CAPTCHAs, biometrics, etc.)
5. User clicks "Done" button (injected into WebView) or closes window
6. Warden extracts from the WebView:
   - All cookies for the domain and subdomains
   - All localStorage key/value pairs for the origin
   - All sessionStorage key/value pairs for the origin
7. Auth state encrypted and stored in `~/.warden/sessions/<domain>.json`
8. Proxy begins injecting auth state for matching requests

## Storage Format

```json
{
  "domain": "yahoo.com",
  "captured_at": "2026-03-03T20:00:00Z",
  "last_used": "2026-03-03T21:30:00Z",
  "status": "active",
  "cookies": [
    {
      "name": "session_id",
      "value": "abc123...",
      "domain": ".yahoo.com",
      "path": "/",
      "expires": 1772600000,
      "secure": true,
      "http_only": true,
      "same_site": "Lax"
    }
  ],
  "local_storage": {
    "https://mail.yahoo.com": {
      "auth_token": "eyJhbG...",
      "user_prefs": "{...}"
    }
  },
  "session_storage": {
    "https://mail.yahoo.com": {
      "csrf_token": "xyz789"
    }
  }
}
```

## Proxy Injection

### Cookie Injection
When a jailed app fetches any URL matching the captured domain:
1. Strip all cookies from the app's request (defense in depth)
2. Inject stored cookies that match the request domain/path/secure flags
3. Standard cookie domain matching (`.yahoo.com` matches `mail.yahoo.com`)

### localStorage/sessionStorage Injection
This is trickier — localStorage lives in the browser, not in HTTP headers.
Approach: The Service Worker intercepts the page load and injects a script that populates localStorage/sessionStorage with the captured values before the app's own scripts run.

The SW fetches the stored values from: `GET /admin/api/sessions/<domain>/storage`
Then injects them via `postMessage` to the app iframe or directly if same-origin.

## Session Keepalive

Background task (configurable interval, default 15 minutes):
- For each active session, makes a lightweight request with stored cookies
- Checks response for auth failure indicators:
  - HTTP 401/403
  - Redirect to login page (302 to `/login`, `/signin`, etc.)
  - Response body containing "sign in", "log in" patterns
- If session appears expired:
  - Mark status as "expired" in storage
  - Show warning in admin UI
  - Optionally notify user to re-authenticate

## API Endpoints

### `POST /admin/api/sessions/capture`
Start a session capture.
```json
{"domain": "yahoo.com", "start_url": "https://mail.yahoo.com"}
```
Opens WebView window. Returns immediately:
```json
{"status": "capturing", "domain": "yahoo.com"}
```

### `GET /admin/api/sessions`
List all captured sessions.
```json
[
  {"domain": "yahoo.com", "status": "active", "captured_at": "...", "cookie_count": 12, "storage_keys": 5},
  {"domain": "github.com", "status": "expired", "captured_at": "...", "cookie_count": 8, "storage_keys": 0}
]
```

### `GET /admin/api/sessions/<domain>`
Get details for a specific session (without exposing actual values).

### `GET /admin/api/sessions/<domain>/storage`
Get localStorage/sessionStorage values for injection by the Service Worker.

### `DELETE /admin/api/sessions/<domain>`
Revoke a captured session. Deletes all stored auth state.

### `POST /admin/api/sessions/<domain>/refresh`
Trigger a manual keepalive check.

## Admin UI (public/admin/sessions/index.html)

- Amber admin theme
- "Warden Admin Panel" banner
- Quick Login icons: Google, Yahoo, Microsoft, GitHub, Facebook, Twitter
- Domain input field for any website
- Active sessions list:
  - Domain, capture date, last used, status indicator
  - Cookie count, storage key count
  - Refresh button (trigger keepalive)
  - Revoke button (delete session)
  - Re-login button (re-open WebView for expired sessions)
- Add to Warden's Office section on launchpad

## Security Considerations

- Session files encrypted at rest (`~/.warden/sessions/` using vault encryption)
- WebView profile isolated per domain (no cross-domain cookie leakage)
- Captured auth state never sent to jailed apps directly — only injected by proxy
- Traffic monitor logs all session-injected requests
- User can revoke any session instantly
- No passwords are ever stored — only session tokens/cookies

## Dependencies

- `wry` crate — WebView abstraction
- `webkit2gtk` (Linux) — usually pre-installed on desktop Linux
- Feature-flagged: `cargo build --features session-capture`

## Regression Tests

All core functionality must have regression tests that protect against breakage as new features are added.

### Proxy Core (tests/proxy_tests.rs)
- Auth header stripping (Authorization, x-api-key, Cookie) — verify nothing leaks through
- Destination-based key injection — correct key for correct service
- Unknown destination gets no injection
- Malicious app sending auth to evil.com — verify no key injected
- CORS headers added correctly
- Request ID generation and propagation
- Streaming response passthrough (SSE chunks arrive in order)

### Cookie/Session Injection (tests/session_tests.rs)
- Domain matching: `.yahoo.com` matches `mail.yahoo.com`, `calendar.yahoo.com`
- Domain matching: `yahoo.com` does NOT match `notyahoo.com`
- Subdomain specificity: `mail.yahoo.com` cookies don't apply to `finance.yahoo.com`
- Secure cookie only injected on HTTPS requests
- Path matching for cookies
- App cookies stripped before injection (defense in depth)
- Expired cookies not injected
- Session revocation removes all auth state immediately

### localStorage/sessionStorage Injection (tests/storage_tests.rs)
- Storage values returned only for matching origin
- Cross-origin requests get no storage data
- Revoked sessions return empty storage

### Traffic Monitor (tests/traffic_tests.rs)
- Ring buffer doesn't exceed max size (1000 entries)
- Oldest entries evicted when buffer full
- SSE stream delivers new entries in real-time
- Filter by service, method, status works correctly
- Timestamp ordering preserved

### Rate Limiter (tests/limiter_tests.rs)
- RPM limit enforced — 61st request in a minute gets 429
- RPD limit enforced
- Limits are per-service, not global
- Counter reset after time window

### Access Control (tests/access_tests.rs)
- Wildcard origin matching (`http://localhost:*`)
- Specific origin matching
- Denied origin gets 403
- Service-level access control (origin allowed for service A but not B)

### Key Vault (tests/vault_tests.rs)
- Env var source resolves correctly
- Missing env var handled gracefully (service unavailable, not crash)
- Multiple sources (env, inline, encrypted) can coexist
- Key values never appear in logs or error messages

### WebSocket (tests/websocket_tests.rs)
- Bidirectional message passing
- Auth injection on upgrade request
- Connection cleanup on client disconnect
- Connection cleanup on upstream disconnect

## Launchpad Integration

Add to Warden's Office section:
- Icon: 🌐
- Name: "Website Access"
- Description: "Log into websites once. Jailed apps get access without passwords."
- Links to /admin/sessions/
