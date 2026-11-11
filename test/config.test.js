'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { ConfigLoader, PRESETS } = require('../src/config');

test('ConfigLoader - loads standard, strict, and read-only presets', () => {
  const standard = ConfigLoader.load({ preset: 'standard' });
  assert.strictEqual(standard.name, 'standard');
  assert.strictEqual(standard.execGuard.allowSudo, false);

  const strict = ConfigLoader.load({ preset: 'strict' });
  assert.strictEqual(strict.name, 'strict');
  assert.strictEqual(strict.rateLimiter.maxCallsPerMinute, 30);

  const readOnly = ConfigLoader.load({ preset: 'read-only' });
  assert.strictEqual(readOnly.name, 'read-only');
  assert.ok(readOnly.toolFilter.allowlist.includes('read_*'));
});

test('ConfigLoader - merges custom JSON configuration file and CLI flags', () => {
  const tmpConfig = path.join(os.tmpdir(), `sentinel-config-${Date.now()}.json`);

  try {
    fs.writeFileSync(tmpConfig, JSON.stringify({
      rateLimiter: { maxCallsPerMinute: 42 },
      execGuard: { blockedCommands: ['telnet'] }
    }), 'utf8');

    const loaded = ConfigLoader.load({
      configFile: tmpConfig,
      timeout: 12345
    });

    assert.strictEqual(loaded.rateLimiter.maxCallsPerMinute, 42);
    assert.strictEqual(loaded.circuitBreaker.defaultTimeoutMs, 12345);
    assert.deepStrictEqual(loaded.execGuard.blockedCommands, ['telnet']);
  } finally {
    if (fs.existsSync(tmpConfig)) fs.unlinkSync(tmpConfig);
  }
});
