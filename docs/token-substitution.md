# Token Substitution Architecture

## Principle

The proxy maintains a complete illusion for jailed apps. Apps see fake credentials that look real. Real credentials never cross the jail boundary. The proxy swaps fakes↔reals on every request/response.

## Service Worker Role

The SW is a dumb bridge for INBOUND requests (app → proxy). It only reroutes URLs.

For OUTBOUND responses (proxy → app), the SW CAN do work:
- Populate localStorage/sessionStorage with fake tokens
- The SW never sees real secrets — only fakes provided by the proxy

**Rule: The SW never holds or handles real secrets. Fakes only.**

## Cookie Strategy (Merge, Not Replace)

### Outbound requests (app → internet via proxy):
1. Start with the app's cookies (may include CSRF tokens, tracking, etc.)
2. Remove any cookies that match our captured AUTH cookies by name
3. Inject the REAL auth cookies from our session store
4. Result: real auth + app's operational cookies merged

### Inbound responses (internet → app via proxy):
1. Pass through all Set-Cookie headers (CSRF, tracking, etc.)
2. If a Set-Cookie updates one of our known auth cookies:
   - Store the new real value in our session store
   - Replace the Set-Cookie value with the corresponding fake
3. App receives fake auth cookies + real operational cookies

### Auth vs Operational cookies:
- AUTH cookies: captured during login flow, tracked by name
- OPERATIONAL cookies: everything else (CSRF, tracking, preferences)
- Determined at capture time — cookies present after successful login = auth cookies

## Token Substitution in Response Bodies

For SPAs that return auth tokens in JSON response bodies:

### Outbound requests:
1. App sends fake token in Authorization header (read from its localStorage/IndexedDB)
2. Proxy looks up fake→real mapping
3. Proxy replaces fake with real in the header
4. Request goes upstream with real credentials

### Inbound responses:
1. Response body contains real tokens (e.g., {"access_token": "real-jwt"})
2. Proxy scans response body for known token patterns
3. Proxy replaces real tokens with fake equivalents
4. Proxy stores/updates the real↔fake mapping
5. App receives response with fake tokens
6. App stores fake token in IndexedDB/localStorage — thinks it's real

### Token detection:
- During captured login flow, record which response fields contained tokens
- Store field paths: e.g., "body.access_token", "body.data.refresh_token"
- On subsequent requests to same endpoint, apply substitution to those fields
- Also: regex pattern matching for JWT-shaped strings (eyJ...) as fallback

## Fake Token Generation

- Fakes must be stable — same fake for same real token
- Use HMAC-SHA256(real_token, warden_secret) truncated, prefixed with "wdn_"
- Format mimics the real token type (JWT-shaped fake for JWT, cookie-shaped for cookie)
- Mapping stored in ~/.warden/sessions/<domain>_tokens.json

## wcurl — CLI Proxy Client

A lightweight tool for VMs, scripts, and local network clients to access the proxy.

### Usage:
```bash
# Simple — just like curl but through Warden
wcurl https://api.openai.com/v1/chat/completions \
  -d '{"model":"gpt-4","messages":[...]}'

# Equivalent to:
curl http://<warden-host>:7400/proxy/openai/v1/chat/completions \
  -d '{"model":"gpt-4","messages":[...]}'

# With a captured session domain:
wcurl https://mail.yahoo.com/api/v1/mailboxes
# Routes through proxy, gets auth cookies injected
```

### Implementation:
- Shell script wrapper around curl
- Rewrites URLs: matches registered service base URLs → proxy paths
- Configurable proxy host (default: localhost:7400, env: WARDEN_HOST)
- Fetches routes from /routes endpoint to know which URLs to rewrite
- Passes all other curl flags through unchanged
- Ships in bin/wcurl, installed to ~/.local/bin/wcurl

### For VMs:
- Copy wcurl into the VM image or download from proxy: GET /tools/wcurl
- The proxy serves wcurl at /tools/wcurl so any VM can bootstrap itself
- Inside the VM: `curl -o wcurl http://<host-ip>:7400/tools/wcurl && chmod +x wcurl`

## Two Authenticated Paths

1. **Browser apps** → SW reroutes fetch() → proxy handles auth
2. **CLI/VM/network** → wcurl → proxy handles auth

Both converge at the same proxy. Same security, same traffic monitor, same rate limits.

## Network Access

The proxy currently binds to 127.0.0.1 (localhost only).
For LAN access (VMs, other machines), add config option:
```json
{"bind": "0.0.0.0"}
```
With appropriate access control — only allow configured origins/IPs.
