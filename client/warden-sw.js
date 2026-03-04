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
 *
 * On outbound responses, the SW can populate the app's storage with
 * values provided by the proxy via a custom header. These are always
 * fake values — the SW never sees real secrets.
 */

const WARDEN_ORIGIN = self.location.origin;
const STORAGE_HEADER = 'x-warden-storage';

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

/**
 * Deliver storage values to the app's window context.
 * The proxy provides fake values via a response header.
 * We decode them and send to the matching client for population.
 */
async function deliverStorage(clientId, data) {
  const client = await self.clients.get(clientId);
  if (client) {
    client.postMessage({
      type: 'warden-storage',
      localStorage: data.local_storage || {},
      sessionStorage: data.session_storage || {},
    });
  }
}

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
    fetch(proxyRequest)
      .then(response => {
        // Check for storage data from the proxy
        const storageValue = response.headers.get(STORAGE_HEADER);
        if (storageValue) {
          try {
            const decoded = atob(storageValue);
            const data = JSON.parse(decoded);
            // Send to the requesting client for population
            if (event.clientId) {
              deliverStorage(event.clientId, data);
            }
          } catch (e) {
            // Ignore decode errors
          }

          // Build a clean response without the storage header
          const cleanHeaders = new Headers();
          for (const [key, value] of response.headers) {
            if (key.toLowerCase() !== STORAGE_HEADER) {
              cleanHeaders.set(key, value);
            }
          }
          return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: cleanHeaders,
          });
        }
        return response;
      })
      .catch(() => {
        return new Response(JSON.stringify({
          error: { message: 'Proxy unavailable', type: 'proxy_error' }
        }), { status: 502, headers: { 'Content-Type': 'application/json' } });
      })
  );
});
