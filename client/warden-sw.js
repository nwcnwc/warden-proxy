/**
 * Warden Service Worker
 *
 * A dumb bridge. Nothing more.
 *
 * Intercepts fetch requests to registered API endpoints and reroutes them
 * to the Warden proxy on the same origin. Passes everything through
 * untouched — headers, body, all of it.
 *
 * The proxy handles ALL security: auth, access control, everything.
 * This SW makes zero security decisions.
 */

const WARDEN_ORIGIN = self.location.origin;

let serviceRoutes = {};

self.addEventListener('activate', (event) => {
  event.waitUntil(
    fetch(`${WARDEN_ORIGIN}/routes`)
      .then(res => res.json())
      .then(routes => {
        serviceRoutes = routes;
      })
      .catch(() => {
        serviceRoutes = {
          'https://api.openai.com': 'openai',
          'https://api.anthropic.com': 'anthropic',
          'https://generativelanguage.googleapis.com': 'google',
        };
      })
  );
  self.clients.claim();
});

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  const serviceName = serviceRoutes[url.origin];

  if (!serviceName) return;

  // Reroute URL, pass everything else through unchanged
  const wardenUrl = `${WARDEN_ORIGIN}/proxy/${serviceName}${url.pathname}${url.search}`;

  const proxyRequest = new Request(wardenUrl, {
    method: event.request.method,
    headers: event.request.headers,
    body: event.request.body,
    duplex: 'half',
  });

  event.respondWith(
    fetch(proxyRequest).catch(() => {
      return new Response(JSON.stringify({
        error: { message: 'Proxy unavailable', type: 'proxy_error' }
      }), { status: 502, headers: { 'Content-Type': 'application/json' } });
    })
  );
});
