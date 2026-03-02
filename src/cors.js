/**
 * CORS Handler
 * 
 * Handles preflight requests and adds CORS headers
 * so browser tabs can talk to localhost without issues.
 */

function createCorsHandler(config) {
  const allowedOrigins = new Set();
  
  // Build allowed origins from access rules
  if (config.access) {
    for (const rule of config.access) {
      allowedOrigins.add(rule.origin);
    }
  }

  function isOriginAllowed(origin) {
    if (!origin) return true; // Non-browser requests
    
    for (const pattern of allowedOrigins) {
      if (pattern === '*') return true;
      if (pattern.includes('*')) {
        const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
        if (regex.test(origin)) return true;
      }
      if (pattern === origin) return true;
    }

    // Default: allow localhost origins
    if (origin.startsWith('http://localhost') || origin.startsWith('http://127.0.0.1')) {
      return true;
    }

    return false;
  }

  function addHeaders(req, res) {
    const origin = req.headers.origin;
    
    if (isOriginAllowed(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin || '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
      res.setHeader('Access-Control-Max-Age', '86400');
    }
  }

  function handlePreflight(req, res) {
    addHeaders(req, res);
    res.writeHead(204);
    res.end();
  }

  return { addHeaders, handlePreflight, isOriginAllowed };
}

module.exports = { createCorsHandler };
