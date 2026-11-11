'use strict';

const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');

const GENESIS_HASH = '0'.repeat(64);

class AuditLogger {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.logPath = options.logPath ? path.resolve(options.logPath) : path.resolve(process.cwd(), 'sentinel-audit.jsonl');
    this.secretKey = options.secretKey || null; // Optional HMAC secret key
    this.lastHash = GENESIS_HASH;
    this.sequence = 0;

    if (this.enabled) {
      this._initChain();
    }
  }

  _initChain() {
    try {
      if (fs.existsSync(this.logPath)) {
        const content = fs.readFileSync(this.logPath, 'utf8').trim();
        if (content) {
          const lines = content.split('\n');
          const lastLine = lines[lines.length - 1];
          if (lastLine) {
            const parsed = JSON.parse(lastLine);
            if (parsed && parsed.hash && typeof parsed.seq === 'number') {
              this.lastHash = parsed.hash;
              this.sequence = parsed.seq;
            }
          }
        }
      }
    } catch {
      // Fallback in-memory
    }
  }

  _computeHash(prevHash, payloadStr) {
    const data = `${prevHash}:${payloadStr}`;
    if (this.secretKey) {
      return crypto.createHmac('sha256', this.secretKey).update(data).digest('hex');
    }
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Appends an audit event to the hash chain
   */
  logEvent(event) {
    if (!this.enabled) return null;

    this.sequence += 1;
    const timestamp = new Date().toISOString();
    const payload = {
      ...event,
      timestamp
    };

    const payloadStr = JSON.stringify(payload);
    const hash = this._computeHash(this.lastHash, payloadStr);

    const record = {
      seq: this.sequence,
      timestamp,
      prev_hash: this.lastHash,
      payload,
      hash
    };

    this.lastHash = hash;

    try {
      fs.appendFileSync(this.logPath, JSON.stringify(record) + '\n', 'utf8');
    } catch {
      // In-memory fallback
    }

    return record;
  }

  close() {
    // Synchronous writes require no stream draining
  }

  /**
   * Cryptographically verifies the integrity of an audit log file
   */
  static verifyFile(filePath, secretKey = null) {
    const fullPath = path.resolve(filePath);
    if (!fs.existsSync(fullPath)) {
      return { valid: false, error: `File not found: ${fullPath}` };
    }

    const content = fs.readFileSync(fullPath, 'utf8').trim();
    if (!content) {
      return { valid: true, count: 0, message: 'Log file is empty.' };
    }

    const lines = content.split('\n');
    let expectedPrevHash = GENESIS_HASH;
    let expectedSeq = 1;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;

      let record;
      try {
        record = JSON.parse(line);
      } catch (err) {
        return {
          valid: false,
          brokenAtLine: i + 1,
          error: `Malformed JSON at line ${i + 1}: ${err.message}`
        };
      }

      if (record.seq !== expectedSeq) {
        return {
          valid: false,
          brokenAtLine: i + 1,
          error: `Sequence mismatch at line ${i + 1}. Expected seq ${expectedSeq}, got ${record.seq}`
        };
      }

      if (record.prev_hash !== expectedPrevHash) {
        return {
          valid: false,
          brokenAtLine: i + 1,
          error: `Tampering detected at line ${i + 1}! prev_hash mismatch. Expected "${expectedPrevHash}", found "${record.prev_hash}"`
        };
      }

      const payloadStr = JSON.stringify(record.payload);
      const computedHash = secretKey
        ? crypto.createHmac('sha256', secretKey).update(`${record.prev_hash}:${payloadStr}`).digest('hex')
        : crypto.createHash('sha256').update(`${record.prev_hash}:${payloadStr}`).digest('hex');

      if (computedHash !== record.hash) {
        return {
          valid: false,
          brokenAtLine: i + 1,
          error: `Tampering detected at line ${i + 1}! Content was modified. Computed hash "${computedHash}" does not match recorded hash "${record.hash}"`
        };
      }

      expectedPrevHash = record.hash;
      expectedSeq += 1;
    }

    return {
      valid: true,
      count: lines.length,
      lastHash: expectedPrevHash,
      message: `Verification successful: ${lines.length} records verified with intact cryptographic hash chain.`
    };
  }
}

module.exports = {
  AuditLogger,
  GENESIS_HASH
};
