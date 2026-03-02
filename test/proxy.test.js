const { describe, it } = require('node:test');
const assert = require('node:assert');

describe('Warden Proxy', () => {
  it('should be importable', () => {
    const { start } = require('../src/index');
    assert.ok(typeof start === 'function');
  });
});

describe('Access Controller', () => {
  it('should allow all when no rules configured', () => {
    const { createAccessController } = require('../src/access');
    const ac = createAccessController({ access: [] });
    assert.ok(ac.isAllowed('http://evil.com', 'openai'));
  });

  it('should enforce rules when configured', () => {
    const { createAccessController } = require('../src/access');
    const ac = createAccessController({
      access: [{ origin: 'http://localhost:3000', allow: ['openai'] }]
    });
    assert.ok(ac.isAllowed('http://localhost:3000', 'openai'));
    assert.ok(!ac.isAllowed('http://evil.com', 'openai'));
  });

  it('should support wildcard origins', () => {
    const { createAccessController } = require('../src/access');
    const ac = createAccessController({
      access: [{ origin: 'http://localhost:*', allow: ['openai'] }]
    });
    assert.ok(ac.isAllowed('http://localhost:3000', 'openai'));
    assert.ok(ac.isAllowed('http://localhost:8080', 'openai'));
  });
});

describe('Rate Limiter', () => {
  it('should allow requests under limit', () => {
    const { createRateLimiter } = require('../src/limiter');
    const limiter = createRateLimiter({ limits: { openai: { rpm: 5 } } });
    assert.ok(limiter.check('openai'));
    assert.ok(limiter.check('openai'));
  });

  it('should block requests over limit', () => {
    const { createRateLimiter } = require('../src/limiter');
    const limiter = createRateLimiter({ limits: { test: { rpm: 2 } } });
    assert.ok(limiter.check('test'));
    assert.ok(limiter.check('test'));
    assert.ok(!limiter.check('test'));
  });
});
