/**
 * Warden Service Worker
 *
 * Installed inside the browser "VM". Transparently intercepts fetch requests
 * to registered API endpoints and reroutes them through the Warden proxy.
 *
 * The app thinks it's talking to api.openai.com with its own key.
 * It's actually talking to the Warden proxy, which handles auth.
 *
 * SECURITY MODEL:
 * - This SW only rewrites the DESTINATION (URL routing)
 * - It does NOT touch, read, or forward any auth headers from the app
 * - The app's fake/real/garbage keys are irrelevant — Warden strips them
 * - Real key injection happens server-side in the proxy, based on destination
 * - The SW is "dumb routing" — the proxy is "smart auth"
 */

// Use same origin — Warden serves both the app and acts as the proxy
const WARDEN_ORIGIN = self.location.origin;

// Service routing table: API base URL → Warden service name
// Loaded from Warden's /routes endpoint on activation
let serviceRoutes = {};

// Fetch route config from Warden on activation
self.addEventListener('activate', (event) => {
  event.waitUntil(
    fetch(`${WARDEN_ORIGIN}/routes`)
      .then(res => res.json())
      .then(routes => {
        serviceRoutes = routes;
        console.log('[Warden SW] Routes loaded:', Object.keys(routes));
      })
      .catch(err => {
        console.warn('[Warden SW] Could not load routes from proxy:', err.message);
        // Fallback: common defaults
        serviceRoutes = {
          'https://api.openai.com': 'openai',
          'https://api.anthropic.com': 'anthropic',
          'https://generativelanguage.googleapis.com': 'google',
        };
      })
  );
  // Take control of all pages immediately
  self.clients.claim();
});

self.addEventListener('install', () => {
  // Activate immediately, don't wait for old SW
  self.skipWaiting();
});

// Session storage cache: domain -> { local_storage, session_storage }
let sessionStorageCache = {};

// Check for session storage that needs injection into pages
async function checkSessionStorage(domain) {
  if (sessionStorageCache[domain] !== undefined) return sessionStorageCache[domain];
  try {
    const resp = await fetch(`${WARDEN_ORIGIN}/admin/api/sessions/${encodeURIComponent(domain)}/storage`);
    if (!resp.ok) { sessionStorageCache[domain] = null; return null; }
    const data = await resp.json();
    const hasData = (Object.keys(data.local_storage || {}).length > 0 ||
                     Object.keys(data.session_storage || {}).length > 0);
    sessionStorageCache[domain] = hasData ? data : null;
    return sessionStorageCache[domain];
  } catch (e) {
    sessionStorageCache[domain] = null;
    return null;
  }
}

// Listen for messages from pages requesting session storage
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'GET_SESSION_STORAGE') {
    const domain = event.data.domain;
    checkSessionStorage(domain).then(data => {
      if (event.source) {
        event.source.postMessage({
          type: 'SESSION_STORAGE_DATA',
          domain: domain,
          data: data
        });
      }
    });
  }
  // Invalidate cache when sessions change
  if (event.data && event.data.type === 'INVALIDATE_SESSION_CACHE') {
    sessionStorageCache = {};
  }
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  const requestOrigin = url.origin;

  // Check if this request targets a registered API service
  const serviceName = serviceRoutes[requestOrigin];
  if (!serviceName) {
    // Not a registered API — let it pass through untouched
    return;
  }

  // Reroute through Warden proxy
  // Original: https://api.openai.com/v1/chat/completions
  // Becomes:  /proxy/openai/v1/chat/completions (same origin)
  const wardenUrl = `${WARDEN_ORIGIN}/proxy/${serviceName}${url.pathname}${url.search}`;

  // Clone the request but strip auth headers
  // (Warden will strip them again server-side — defense in depth)
  const cleanHeaders = new Headers();
  for (const [key, value] of event.request.headers) {
    const lower = key.toLowerCase();
    // Skip auth headers — Warden handles auth based on destination
    if (lower === 'authorization' || lower === 'x-api-key' ||
        lower === 'api-key' || lower === 'cookie') {
      continue;
    }
    cleanHeaders.set(key, value);
  }

  const proxyRequest = new Request(wardenUrl, {
    method: event.request.method,
    headers: cleanHeaders,
    body: event.request.body,
    mode: 'cors',
    credentials: 'omit',
    duplex: 'half',
  });

  event.respondWith(
    fetch(proxyRequest).catch(err => {
      console.error(`[Warden SW] Proxy error for ${serviceName}:`, err);
      return new Response(JSON.stringify({
        error: {
          message: `Warden proxy unavailable. Is it running on ${WARDEN_ORIGIN}?`,
          type: 'warden_proxy_error',
        }
      }), {
        status: 502,
        headers: { 'Content-Type': 'application/json' },
      });
    })
  );
});
