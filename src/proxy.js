/**
 * Core Proxy Handler
 * 
 * Routes: /proxy/<service>/<path>
 * 
 * 1. Parse service name from URL
 * 2. Check origin access
 * 3. Check rate limits
 * 4. Inject API key
 * 5. Forward request to target service
 * 6. Return response
 */

const https = require('node:https');
const http = require('node:http');
const { URL } = require('node:url');

function createProxyHandler({ vault, access, limiter, logger, config }) {

  async function handle(req, res) {
    const startTime = Date.now();

    // Parse: /proxy/<service>/<remaining-path>
    const match = req.url.match(/^\/proxy\/([^/]+)(\/.*)?$/);
    if (!match) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid proxy URL. Use /proxy/<service>/<path>' }));
      return;
    }

    const serviceName = match[1];
    const targetPath = match[2] || '/';
    const origin = req.headers.origin || req.headers.referer || 'unknown';

    // Check access
    if (!access.isAllowed(origin, serviceName)) {
      logger.warn(`Access denied: ${origin} -> ${serviceName}`);
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `Origin not allowed to access ${serviceName}` }));
      return;
    }

    // Check rate limit
    if (!limiter.check(serviceName)) {
      logger.warn(`Rate limited: ${serviceName}`);
      res.writeHead(429, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `Rate limit exceeded for ${serviceName}` }));
      return;
    }

    // Get service config from vault
    const service = vault.getService(serviceName);
    if (!service) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `Unknown service: ${serviceName}` }));
      return;
    }

    // Build target URL
    const targetUrl = new URL(targetPath, service.base_url);

    // Build headers - copy from original request
    const headers = { ...req.headers };
    delete headers.host;
    delete headers.origin;
    delete headers.referer;

    // SECURITY: Strip ALL auth from the VM's request.
    // The app may send fake keys, real keys, garbage — doesn't matter.
    // We throw away everything auth-related and inject based SOLELY
    // on the matched destination service. Never text replacement.
    // Never based on what the app sent. Only based on where it's going.
    delete headers.authorization;
    delete headers['x-api-key'];
    delete headers['api-key'];
    delete headers.cookie;

    // Inject the REAL key based on destination service identity
    if (service.header && service.value) {
      headers[service.header.toLowerCase()] = service.value;
    }

    // Read request body
    const body = await readBody(req);

    // Forward request
    const protocol = targetUrl.protocol === 'https:' ? https : http;

    const proxyReq = protocol.request(targetUrl, {
      method: req.method,
      headers,
    }, (proxyRes) => {
      // Copy response headers
      const responseHeaders = { ...proxyRes.headers };
      delete responseHeaders['transfer-encoding']; // We'll handle this

      res.writeHead(proxyRes.statusCode, responseHeaders);
      proxyRes.pipe(res);

      proxyRes.on('end', () => {
        const duration = Date.now() - startTime;
        logger.info(`${req.method} ${serviceName}${targetPath} -> ${proxyRes.statusCode} (${duration}ms)`);
      });
    });

    proxyReq.on('error', (err) => {
      logger.error(`Proxy error: ${serviceName} - ${err.message}`);
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Failed to reach ${serviceName}: ${err.message}` }));
      }
    });

    if (body) {
      proxyReq.write(body);
    }
    proxyReq.end();
  }

  return { handle };
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    if (req.method === 'GET' || req.method === 'HEAD') {
      resolve(null);
      return;
    }
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

module.exports = { createProxyHandler };
