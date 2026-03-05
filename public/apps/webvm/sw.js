/**
 * WebVM Service Worker — Cross-Origin Isolation
 * 
 * Adds COEP/COOP/CORP headers to ALL responses so CheerpX can use
 * SharedArrayBuffer. Based on webvm.io's approach.
 */

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('fetch', (event) => {
  event.respondWith(
    (async () => {
      let r;
      try {
        r = await fetch(event.request);
      } catch (e) {
        console.error(e);
        return new Response('Network error', { status: 502 });
      }

      if (r.status === 0) return r;

      const newHeaders = new Headers(r.headers);
      newHeaders.set('Cross-Origin-Embedder-Policy', 'require-corp');
      newHeaders.set('Cross-Origin-Opener-Policy', 'same-origin');
      newHeaders.set('Cross-Origin-Resource-Policy', 'cross-origin');

      // Handle redirects (CheerpOS needs resolved URL)
      if (r.redirected) {
        newHeaders.set('location', r.url);
      }

      return new Response(r.redirected ? null : r.body, {
        headers: newHeaders,
        status: r.redirected ? 301 : r.status,
        statusText: r.statusText,
      });
    })()
  );
});
