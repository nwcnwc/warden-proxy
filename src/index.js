/**
 * Warden Proxy - Core Server
 * 
 * A localhost HTTP proxy that provides browser-sandboxed applications
 * with safe, controlled access to external services.
 * 
 * Architecture:
 * 
 *   Browser Tab (sandboxed VM)
 *        │
 *        │  fetch("http://localhost:7400/proxy/openai/v1/chat/completions")
 *        │
 *   ┌────▼────────────────────┐
 *   │  Warden Proxy           │
 *   │                         │
 *   │  1. CORS handling       │  ← Allow browser origins
 *   │  2. Origin validation   │  ← Check allowlist
 *   │  3. Key injection       │  ← Add API key from vault
 *   │  4. Rate limiting       │  ← Prevent runaway costs
 *   │  5. Request logging     │  ← Audit trail
 *   │  6. Forward request     │  ← Proxy to real API
 *   │                         │
 *   └────┬────────────────────┘
 *        │
 *   External API (OpenAI, Anthropic, etc.)
 */

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { loadConfig } = require('./config');
const { createProxyHandler } = require('./proxy');
const { createCorsHandler } = require('./cors');
const { createAccessController } = require('./access');
const { createKeyVault } = require('./vault');
const { createRateLimiter } = require('./limiter');
const { createLogger } = require('./logger');

const DEFAULT_PORT = 7400;

async function start(options = {}) {
  const config = await loadConfig(options.configPath);
  const port = options.port || config.port || DEFAULT_PORT;

  // Initialize modules
  const logger = createLogger(config);
  const vault = await createKeyVault(config);
  const access = createAccessController(config);
  const limiter = createRateLimiter(config);
  const cors = createCorsHandler(config);
  const proxy = createProxyHandler({ vault, access, limiter, logger, config });

  const server = http.createServer(async (req, res) => {
    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
      cors.handlePreflight(req, res);
      return;
    }

    // Add CORS headers to all responses
    cors.addHeaders(req, res);

    // Health check
    if (req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', version: require('../package.json').version }));
      return;
    }

    // Routes endpoint — used by Service Worker to learn which APIs to intercept
    if (req.url === '/routes') {
      const routes = {};
      const services = vault.listServices();
      for (const name of services) {
        const svc = vault.getService(name);
        if (svc && svc.base_url) {
          routes[svc.base_url.replace(/\/$/, '')] = name;
        }
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(routes));
      return;
    }

    // Serve client files (Service Worker, loader)
    if (req.url.startsWith('/client/')) {
      const filename = req.url.replace('/client/', '');
      const filePath = path.join(__dirname, 'client', filename);
      if (fs.existsSync(filePath)) {
        const content = fs.readFileSync(filePath, 'utf-8');
        const ext = path.extname(filename);
        const contentType = ext === '.js' ? 'application/javascript' : 'text/plain';
        // Service Worker requires same-origin OR the Service-Worker-Allowed header
        res.writeHead(200, {
          'Content-Type': contentType,
          'Service-Worker-Allowed': '/',
        });
        res.end(content);
        return;
      }
    }

    // Status endpoint
    if (req.url === '/status') {
      const status = {
        uptime: process.uptime(),
        services: vault.listServices(),
        access: access.listRules(),
        limits: limiter.getStatus(),
      };
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(status, null, 2));
      return;
    }

    // Proxy requests: /proxy/<service>/...
    if (req.url.startsWith('/proxy/')) {
      await proxy.handle(req, res);
      return;
    }

    // 404
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found. Use /proxy/<service>/<path>' }));
  });

  server.listen(port, '127.0.0.1', () => {
    logger.info(`🔒 Warden Proxy running on http://127.0.0.1:${port}`);
    logger.info(`   Services: ${vault.listServices().join(', ') || 'none configured'}`);
    logger.info(`   Config: ${config._path || '~/.warden/config.yaml'}`);
  });

  return server;
}

module.exports = { start };

// Run directly
if (require.main === module) {
  start().catch(err => {
    console.error('Failed to start:', err.message);
    process.exit(1);
  });
}
