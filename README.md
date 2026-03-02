# 🔒 Warden Proxy

**A localhost proxy that gives browser-sandboxed applications safe, controlled access to the outside world.**

Every browser tab is a virtual machine — sandboxed, isolated, secure. But that sandbox also means browser apps can't hold API keys safely, can't talk to local devices, and can't access external services without exposing credentials in client-side code.

Warden is the solution. It runs on localhost and acts as a **supervised gateway** between your browser applications and the outside world. API keys never touch the browser. External access is explicitly configured and controlled. Your AI agents, web apps, and browser-based tools get the capabilities they need without breaking the sandbox.

## The Problem

Browser applications today face an impossible choice:

1. **Stay in the sandbox** — safe but limited. No API keys, no device access, no external services.
2. **Use a remote server** — capable but complex. Now you need infrastructure, deployment, and your API keys transit someone else's servers.
3. **Embed keys in client code** — convenient but catastrophic. Anyone can view source and steal your credentials.

## The Solution

Warden runs locally on your machine and provides:

- **🔑 Secure API key management** — Keys stay on your machine, never enter browser JavaScript
- **🌐 CORS resolution** — Proxy handles cross-origin requests transparently
- **🔒 Allowlist-based access control** — Explicitly configure which origins can access which services
- **🤖 AI agent supervision** — Control what browser-based AI agents can and cannot do
- **📱 Device bridging** — Unified interface to local devices (cameras, IoT, hardware)
- **⚡ Zero latency** — It's localhost. No network hop.

## How It Works

```
┌─────────────────────────────────────────────┐
│  Browser (The Virtual Machine)              │
│                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │  Tab 1   │  │  Tab 2   │  │  Tab 3   │  │
│  │  AI App  │  │  Web App │  │  GIFOS   │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  │
│       │              │              │        │
│       └──────────────┼──────────────┘        │
│                      │                       │
│              fetch("localhost:7400")          │
└──────────────────────┬───────────────────────┘
                       │
            ┌──────────▼──────────┐
            │   Warden Proxy      │
            │   localhost:7400    │
            │                     │
            │  • Auth & API keys  │
            │  • Access control   │
            │  • Request logging  │
            │  • Rate limiting    │
            └──┬────┬────┬───┬───┘
               │    │    │   │
            ┌──▼┐ ┌─▼─┐ ▼  ┌▼──────┐
            │LLM│ │API│ DB │Devices │
            └───┘ └───┘    └───────┘
```

## Quick Start

```bash
# Install
npm install -g warden-proxy

# Initialize config
warden init

# Add an API key
warden add-key openai sk-your-key-here

# Allow a browser origin to use it
warden allow http://localhost:3000 openai

# Start the proxy
warden start
```

Then from your browser app:

```javascript
// Instead of calling OpenAI directly (exposing your key):
// fetch("https://api.openai.com/v1/chat/completions", { headers: { Authorization: "Bearer sk-..." } })

// Call Warden (key injected server-side):
const response = await fetch("http://localhost:7400/proxy/openai/v1/chat/completions", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    model: "gpt-4",
    messages: [{ role: "user", content: "Hello" }]
  })
});
```

Warden injects the API key, forwards the request, and returns the response. Your browser code never sees the key.

## Configuration

```yaml
# ~/.warden/config.yaml
port: 7400
log_level: info

# API keys (or use environment variables)
keys:
  openai:
    header: "Authorization"
    value: "Bearer ${OPENAI_API_KEY}"
    base_url: "https://api.openai.com"
  anthropic:
    header: "x-api-key"
    value: "${ANTHROPIC_API_KEY}"
    base_url: "https://api.anthropic.com"

# Access control - which origins can use which keys
access:
  - origin: "http://localhost:*"
    allow: ["openai", "anthropic"]
  - origin: "https://myapp.com"
    allow: ["openai"]

# Rate limiting
limits:
  openai:
    rpm: 60      # requests per minute
    rpd: 1000    # requests per day
  anthropic:
    rpm: 30

# Device bridges (future)
devices: {}
```

## Architecture

Warden is built with a modular architecture:

- **Core proxy** — HTTP server on localhost, handles routing and CORS
- **Key vault** — Secure storage for API keys (encrypted at rest)
- **Access controller** — Origin-based allowlisting with wildcard support
- **Rate limiter** — Per-service rate limiting to prevent runaway costs
- **Request logger** — Full audit trail of what went where
- **Device bridge** — Pluggable adapters for local device access (planned)

## Use Cases

### 🤖 AI Agents in the Browser
Build AI agents that run entirely in browser tabs. Warden gives them access to LLM APIs, search, tools — all without exposing credentials.

### 🎨 Browser-as-VM Applications
Any application using the browser as a computing platform can use Warden for safe external access.

### 🔧 Local Development
Replace scattered `.env` files and hardcoded keys with a single, secure proxy. All your local dev servers share one key store.

### 📱 IoT / Device Control
Build browser dashboards that control local hardware through Warden's device bridge.

## Philosophy

The browser is the most widely deployed, most secure application runtime in history. Warden doesn't fight the sandbox — it complements it. The browser provides isolation and security. Warden provides supervised access to the outside world.

Think of it as the **orderly at the asylum door** — the browser keeps everything safely contained, and Warden is the trusted assistant who carries things in and out.

## Roadmap

- [x] Project setup and architecture
- [ ] Core HTTP proxy with CORS handling
- [ ] API key vault (encrypted storage)
- [ ] Origin-based access control
- [ ] CLI (`warden init`, `warden start`, `warden add-key`, `warden allow`)
- [ ] Rate limiting
- [ ] Request logging and audit trail
- [ ] WebSocket proxy support
- [ ] Device bridge plugin system
- [ ] Browser extension (optional — auto-configure origins)
- [ ] WASI integration (for Wasm apps outside the browser)

## Contributing

This project is in early development. Issues and PRs welcome.

## License

MIT
