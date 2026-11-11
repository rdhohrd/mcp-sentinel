'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { AuditLogger, GENESIS_HASH } = require('../src/audit/audit-logger');

test('AuditLogger - generates cryptographically linked hash chain', () => {
  const tmpLog = path.join(os.tmpdir(), `sentinel-audit-test-${Date.now()}.jsonl`);

  try {
    const logger = new AuditLogger({ logPath: tmpLog });

    const e1 = logger.logEvent({ action: 'ALLOW', tool: 'read_file' });
    const e2 = logger.logEvent({ action: 'BLOCK', tool: 'rm_rf' });
    const e3 = logger.logEvent({ action: 'REDACT', tool: 'get_env' });

    logger.close();

    assert.strictEqual(e1.prev_hash, GENESIS_HASH);
    assert.strictEqual(e2.prev_hash, e1.hash);
    assert.strictEqual(e3.prev_hash, e2.hash);

    // Verify valid file
    const verifyRes = AuditLogger.verifyFile(tmpLog);
    assert.strictEqual(verifyRes.valid, true);
    assert.strictEqual(verifyRes.count, 3);
  } finally {
    if (fs.existsSync(tmpLog)) fs.unlinkSync(tmpLog);
  }
});

test('AuditLogger - detects tampered log entries', () => {
  const tmpLog = path.join(os.tmpdir(), `sentinel-audit-tamper-${Date.now()}.jsonl`);

  try {
    const logger = new AuditLogger({ logPath: tmpLog });
    logger.logEvent({ user: 'alice', action: 'ALLOW' });
    logger.logEvent({ user: 'bob', action: 'BLOCK' });
    logger.logEvent({ user: 'charlie', action: 'ALLOW' });
    logger.close();

    // Tamper with middle line
    const lines = fs.readFileSync(tmpLog, 'utf8').trim().split('\n');
    const middle = JSON.parse(lines[1]);
    middle.payload.action = 'ALLOW_TAMPERED'; // Attacker alters blocked record to allowed
    lines[1] = JSON.stringify(middle);
    fs.writeFileSync(tmpLog, lines.join('\n') + '\n', 'utf8');

    // Verification must fail!
    const verifyRes = AuditLogger.verifyFile(tmpLog);
    assert.strictEqual(verifyRes.valid, false);
    assert.strictEqual(verifyRes.brokenAtLine, 2);
    assert.match(verifyRes.error, /Tampering detected/i);
  } finally {
    if (fs.existsSync(tmpLog)) fs.unlinkSync(tmpLog);
  }
});
