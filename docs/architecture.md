# Architecture

## Overview

Warden is a localhost HTTP proxy with a companion Service Worker. Together, they provide transparent, secure API access for browser-sandboxed applications.

```
┌─────────────────────────────────────────────────────────┐
│  Browser                                                │
│                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │   App Tab   │  │   App Tab   │  │   App Tab   │     │
│  │             │  │             │  │             │     │
│  │ fetch() with│  │ fetch() with│  │ fetch() via │     │
│  │ fake keys   │  │ fake keys   │  │ direct mode │     │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘     │
│         │                │                │             │
│  ┌──────▼────────────────▼────────────────▼──────┐      │
│  │          Warden Service Worker                │      │
│  │                                               │      │
│  │  1. Match URL against registered services     │      │
│  │  2. Strip auth headers from request           │      │
│  │  3. Rewrite URL: api.openai.com → localhost   │      │
│  │  4. Forward to Warden proxy                   │      │
│  │                                               │      │
│  │  Non-matching URLs pass through untouched     │      │
│  └───────────────────────┬───────────────────────┘      │
└──────────────────────────┼──────────────────────────────┘
                           │
                  HTTP to 127.0.0.1:7400
                           │
              ┌────────────▼────────────┐
              │     Warden Proxy        │
              │                         │
              │  ┌───────────────────┐  │
              │  │   CORS Handler    │  │  Handle preflight, add headers
              │  └────────┬──────────┘  │
              │  ┌────────▼──────────┐  │
              │  │  Access Control   │  │  Check origin allowlist
              │  └────────┬──────────┘  │
              │  ┌────────▼──────────┐  │
              │  │  Auth Stripper    │  │  Remove ALL auth headers
              │  └────────┬──────────┘  │
              │  ┌────────▼──────────┐  │
              │  │   Rate Limiter    │  │  Check rpm/rpd limits
              │  └────────┬──────────┘  │
              │  ┌────────▼──────────┐  │
              │  │    Key Vault      │  │  Match destination → inject real key
              │  └────────┬──────────┘  │
              │  ┌────────▼──────────┐  │
              │  │  Request Logger   │  │  Audit trail
              │  └────────┬──────────┘  │
              │  ┌────────▼──────────┐  │
              │  │    Forwarder      │  │  Send to real API
              │  └────────┬──────────┘  │
              └───────────┼─────────────┘
                          │
              ┌───────────▼───────────┐
              │   External Services   │
              │                       │
              │  api.openai.com       │
              │  api.anthropic.com    │
              │  (any registered)     │
              └───────────────────────┘
```

## Request Flow

### Transparent Mode (Service Worker)

1. App calls `fetch("https://api.openai.com/v1/chat/completions", { headers: { Authorization: "Bearer sk-fake" } })`
2. Service Worker intercepts the request
3. SW checks: is `api.openai.com` a registered service? → Yes, it maps to `openai`
4. SW strips auth headers (`Authorization`, `x-api-key`, `api-key`, `cookie`)
5. SW rewrites URL: `http://127.0.0.1:7400/proxy/openai/v1/chat/completions`
6. Proxy receives request at `/proxy/openai/v1/chat/completions`
7. Proxy strips auth headers again (defense in depth)
8. Proxy checks origin allowlist → allowed
9. Proxy checks rate limit → under limit
10. Proxy looks up `openai` in vault → gets real key
11. Proxy injects real key into `Authorization` header
12. Proxy forwards to `https://api.openai.com/v1/chat/completions`
13. Response flows back through proxy → SW → app
14. App receives response as if it talked to OpenAI directly

### Direct Mode

Same as above, starting at step 6. The app calls `localhost:7400/proxy/openai/...` directly.

## Modules

### Service Worker (`src/client/warden-sw.js`)

- Runs in the browser's Service Worker context
- On activation, fetches route table from `GET /routes`
- Intercepts `fetch()` events matching registered service URLs
- Strips auth headers and reroutes to Warden proxy
- Non-matching requests pass through untouched
- Falls back to hardcoded common routes if proxy unreachable at activation time

### Loader (`src/client/warden-loader.js`)

- Standalone script that registers the Service Worker
- Single `<script>` tag to add to any page
- Handles registration, activation, and error logging

### Proxy Server (`src/index.js`)

- Node.js HTTP server bound to `127.0.0.1:7400`
- Routes: `/proxy/*` (proxy), `/health`, `/status`, `/routes`, `/client/*`
- Coordinates all modules in the request pipeline

### Key Vault (`src/vault.js`)

- Stores service configurations (name, auth header, key value, base URL)
- Supports environment variable interpolation (`${VAR}`)
- Lookup by service name only — never by request content

### Access Controller (`src/access.js`)

- Origin-based allowlisting
- Wildcard support (`http://localhost:*`)
- No rules = open mode (development only)

### Rate Limiter (`src/limiter.js`)

- Sliding window counters per service
- Configurable requests-per-minute and requests-per-day
- Returns 429 when exceeded

### CORS Handler (`src/cors.js`)

- Handles OPTIONS preflight requests
- Adds `Access-Control-Allow-*` headers to all responses
- Origin validation against allowlist

### Logger (`src/logger.js`)

- Structured console logging
- Configurable log levels (error, warn, info, debug)
- Request timing

## Configuration

Config is loaded from `~/.warden/config.yaml` (JSON format in v0.1).

Environment variables are interpolated at startup: `${VAR}` is replaced with `process.env.VAR`.

See README.md for full config reference.

## Design Decisions

1. **No external dependencies** — v0.1 uses only Node.js built-in modules. Zero `node_modules`. This minimizes attack surface and keeps the install simple.

2. **JSON config with YAML extension** — We want to support YAML eventually but ship without a parser dependency for now.

3. **Localhost-only binding** — Warden binds to `127.0.0.1`, not `0.0.0.0`. It's a local service for local apps.

4. **Two-layer auth stripping** — Both SW and proxy strip auth headers. Neither trusts the other to do it.

5. **Destination-based key injection** — The most important security decision. See SECURITY.md.
