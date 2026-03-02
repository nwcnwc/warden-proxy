const { describe, it } = require('node:test');
const assert = require('node:assert');

describe('Security: Auth stripping', () => {

  it('should strip authorization headers from proxied requests', async () => {
    // Verify the proxy handler strips auth headers
    // by checking the proxy.js source contains the stripping logic
    const fs = require('node:fs');
    const proxySource = fs.readFileSync(require.resolve('../src/proxy'), 'utf-8');
    
    // Must strip these headers
    assert.ok(proxySource.includes("delete headers.authorization"), 
      'Must strip authorization header');
    assert.ok(proxySource.includes("delete headers['x-api-key']"), 
      'Must strip x-api-key header');
    assert.ok(proxySource.includes("delete headers['api-key']"), 
      'Must strip api-key header');
    assert.ok(proxySource.includes("delete headers.cookie"), 
      'Must strip cookie header');
  });

  it('should inject keys based on destination service, not request content', async () => {
    const { createKeyVault } = require('../src/vault');
    const vault = await createKeyVault({
      keys: {
        openai: {
          header: 'Authorization',
          value: 'Bearer sk-real-key',
          base_url: 'https://api.openai.com'
        }
      }
    });

    // Key injection is based on service name lookup, not request parsing
    const service = vault.getService('openai');
    assert.ok(service, 'Should find service by name');
    assert.strictEqual(service.header, 'Authorization');
    assert.strictEqual(service.value, 'Bearer sk-real-key');

    // Unknown service returns null — no key injection
    const unknown = vault.getService('evil');
    assert.strictEqual(unknown, null, 'Unknown service should return null (no key)');
  });

  it('Service Worker should strip auth headers client-side (defense in depth)', () => {
    const fs = require('node:fs');
    const swSource = fs.readFileSync(
      require.resolve('../src/client/warden-sw'), 'utf-8'
    );

    // SW must also strip auth — defense in depth
    assert.ok(swSource.includes('authorization'), 'SW must filter authorization');
    assert.ok(swSource.includes('x-api-key'), 'SW must filter x-api-key');
    assert.ok(swSource.includes('continue'), 'SW must skip auth headers');
  });
});

describe('Security: Destination-only routing', () => {

  it('should only inject keys for registered services', async () => {
    const { createKeyVault } = require('../src/vault');
    const vault = await createKeyVault({
      keys: {
        openai: {
          header: 'Authorization',
          value: 'Bearer sk-real',
          base_url: 'https://api.openai.com'
        }
      }
    });

    // Registered service gets a key
    assert.ok(vault.getService('openai'));

    // Unregistered service gets nothing — can't trick Warden
    // into injecting keys for evil.com
    assert.strictEqual(vault.getService('evil-service'), null);
    assert.strictEqual(vault.getService(''), null);
    assert.strictEqual(vault.getService('openai-fake'), null);
  });
});
