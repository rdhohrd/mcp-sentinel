'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const os = require('node:os');
const { PathGuard } = require('../src/guards/path-guard');

test('PathGuard - blocks directory traversal attacks', () => {
  const guard = new PathGuard();

  const attacks = [
    '../../etc/passwd',
    '..\\..\\windows\\system32',
    'folder/../../../secret.txt',
    'safe/..%2f..%2fetc/shadow',
    'folder/%2e%2e/%2e%2e/data'
  ];

  for (const attack of attacks) {
    const res = guard.inspectPath(attack);
    assert.strictEqual(res.allowed, false, `Expected attack to be blocked: ${attack}`);
    assert.match(res.reason, /traversal/i);
  }
});

test('PathGuard - blocks poison null byte injection', () => {
  const guard = new PathGuard();
  const res = guard.inspectPath('valid.txt\0.jpg');
  assert.strictEqual(res.allowed, false);
  assert.match(res.reason, /null byte/i);
});

test('PathGuard - blocks access to sensitive credential files', () => {
  const guard = new PathGuard();

  const sensitive = [
    '/etc/passwd',
    '/etc/shadow',
    '~/.ssh/id_rsa',
    '.ssh/id_ed25519',
    '.aws/credentials',
    '.env',
    '.env.production',
    'service_account.json',
    '~/.gnupg/secring.gpg'
  ];

  for (const file of sensitive) {
    const res = guard.inspectPath(file);
    assert.strictEqual(res.allowed, false, `Expected sensitive file to be blocked: ${file}`);
    assert.match(res.reason, /sensitive/i);
  }
});

test('PathGuard - enforces allowedRoots jail', () => {
  const sandbox = path.join(os.tmpdir(), 'sentinel-test-sandbox');
  const guard = new PathGuard({ allowedRoots: [sandbox] });

  // Inside sandbox: allowed
  const inside = path.join(sandbox, 'src', 'app.js');
  assert.strictEqual(guard.inspectPath(inside).allowed, true);

  // Outside sandbox: blocked
  const outside = path.join(os.tmpdir(), 'other-folder', 'leak.txt');
  const res = guard.inspectPath(outside);
  assert.strictEqual(res.allowed, false);
  assert.match(res.reason, /outside configured sandbox roots/i);
});

test('PathGuard - recursively inspects complex tool arguments', () => {
  const guard = new PathGuard();

  const safeArgs = {
    action: 'read',
    options: {
      filePath: 'src/components/Header.jsx'
    }
  };
  assert.strictEqual(guard.inspectToolArguments(safeArgs).allowed, true);

  const maliciousArgs = {
    action: 'read',
    metadata: {
      nested: {
        file: '../../../etc/passwd'
      }
    }
  };
  const res = guard.inspectToolArguments(maliciousArgs);
  assert.strictEqual(res.allowed, false);
  assert.match(res.reason, /traversal/i);
});
