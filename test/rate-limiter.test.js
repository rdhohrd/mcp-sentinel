'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { RateLimiter } = require('../src/guards/rate-limiter');

test('RateLimiter - enforces global rate limit', () => {
  const limiter = new RateLimiter({ maxCallsPerMinute: 3 });

  assert.strictEqual(limiter.consume().allowed, true);
  assert.strictEqual(limiter.consume().allowed, true);
  assert.strictEqual(limiter.consume().allowed, true);

  const blocked = limiter.consume();
  assert.strictEqual(blocked.allowed, false);
  assert.match(blocked.reason, /Global rate limit exceeded/i);
});

test('RateLimiter - supports per-tool rate limit overrides', () => {
  const limiter = new RateLimiter({
    maxCallsPerMinute: 50,
    toolOverrides: {
      heavy_action: 2
    }
  });

  // Heavy action has limit 2
  assert.strictEqual(limiter.consume('heavy_action').allowed, true);
  assert.strictEqual(limiter.consume('heavy_action').allowed, true);

  const blocked = limiter.consume('heavy_action');
  assert.strictEqual(blocked.allowed, false);
  assert.match(blocked.reason, /heavy_action/i);

  // Normal action can still proceed
  assert.strictEqual(limiter.consume('light_action').allowed, true);
});
