/**
 * Warden Loader
 * 
 * Drop this script into any web page to activate Warden's Service Worker.
 * Once loaded, all fetch() calls to registered APIs are transparently
 * rerouted through the Warden proxy.
 * 
 * Usage:
 *   <script src="http://127.0.0.1:7400/client/warden-loader.js"></script>
 * 
 * Or dynamically:
 *   const script = document.createElement('script');
 *   script.src = 'http://127.0.0.1:7400/client/warden-loader.js';
 *   document.head.appendChild(script);
 * 
 * That's it. No other changes needed. The app's existing API calls
 * (with fake or no keys) will work transparently.
 */

(async function wardenInit() {
  if (!('serviceWorker' in navigator)) {
    console.warn('[Warden] Service Workers not supported in this browser');
    return;
  }

  try {
    const registration = await navigator.serviceWorker.register(
      'http://127.0.0.1:7400/client/warden-sw.js',
      { scope: '/' }
    );

    console.log('[Warden] Service Worker registered');

    // Wait for it to activate
    if (registration.installing) {
      await new Promise(resolve => {
        registration.installing.addEventListener('statechange', function() {
          if (this.state === 'activated') resolve();
        });
      });
    }

    console.log('[Warden] ✅ Active — API calls are now proxied through Warden');
  } catch (err) {
    console.error('[Warden] Failed to register Service Worker:', err);
    console.info('[Warden] Falling back to direct API calls (no proxy protection)');
  }
})();
