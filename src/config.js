'use strict';

const fs = require('node:fs');
const path = require('node:path');

const PRESETS = {
  standard: {
    name: 'standard',
    description: 'Balanced security: blocks directory traversal, dangerous commands, secret leakage, and enforces rate limits.',
    pathGuard: {
      enabled: true,
      blockSensitiveFiles: true
    },
    execGuard: {
      enabled: true,
      allowSudo: false
    },
    secretGuard: {
      enabled: true,
      mode: 'redact'
    },
    rateLimiter: {
      enabled: true,
      maxCallsPerMinute: 60
    },
    circuitBreaker: {
      enabled: true,
      defaultTimeoutMs: 30000
    },
    audit: {
      enabled: true,
      logPath: 'sentinel-audit.jsonl'
    }
  },

  strict: {
    name: 'strict',
    description: 'Zero-trust sandbox: locks filesystem to current directory, whitelists commands, and limits rates aggressively.',
    pathGuard: {
      enabled: true,
      allowedRoots: ['.'],
      blockSensitiveFiles: true
    },
    execGuard: {
      enabled: true,
      allowSudo: false,
      blockedCommands: ['sudo', 'su', 'curl', 'wget', 'nc', 'ncat', 'python', 'perl', 'ruby', 'bash', 'sh']
    },
    secretGuard: {
      enabled: true,
      mode: 'redact'
    },
    rateLimiter: {
      enabled: true,
      maxCallsPerMinute: 30
    },
    circuitBreaker: {
      enabled: true,
      defaultTimeoutMs: 15000
    },
    audit: {
      enabled: true,
      logPath: 'sentinel-audit.jsonl'
    }
  },

  'read-only': {
    name: 'read-only',
    description: 'Read-only audit mode: permits only non-destructive reading and listing operations.',
    toolFilter: {
      enabled: true,
      allowlist: ['read_*', 'get_*', 'list_*', 'search_*', 'fetch_*', 'view_*', 'query_*'],
      denylist: ['write_*', 'delete_*', 'drop_*', 'execute_*', 'create_*', 'update_*', 'modify_*', 'exec_*']
    },
    pathGuard: {
      enabled: true,
      blockSensitiveFiles: true
    },
    execGuard: {
      enabled: true,
      blockedCommands: ['*']
    },
    secretGuard: {
      enabled: true,
      mode: 'redact'
    },
    rateLimiter: {
      enabled: true,
      maxCallsPerMinute: 60
    },
    circuitBreaker: {
      enabled: true,
      defaultTimeoutMs: 20000
    },
    audit: {
      enabled: true,
      logPath: 'sentinel-audit.jsonl'
    }
  }
};

class ConfigLoader {
  /**
   * Loads config from a file, preset, or options object
   */
  static load(options = {}) {
    let base = JSON.parse(JSON.stringify(PRESETS[options.preset || 'standard'] || PRESETS.standard));

    if (options.configFile) {
      const fullPath = path.resolve(options.configFile);
      if (fs.existsSync(fullPath)) {
        const raw = fs.readFileSync(fullPath, 'utf8');
        try {
          const parsed = JSON.parse(raw);
          base = this._deepMerge(base, parsed);
        } catch (e) {
          throw new Error(`Failed to parse configuration file "${fullPath}": ${e.message}`);
        }
      } else {
        throw new Error(`Configuration file not found: ${fullPath}`);
      }
    }

    // Merge direct command-line overrides
    if (options.allowedRoots) {
      base.pathGuard = base.pathGuard || {};
      base.pathGuard.allowedRoots = options.allowedRoots;
    }

    if (options.rateLimit) {
      base.rateLimiter = base.rateLimiter || {};
      base.rateLimiter.maxCallsPerMinute = options.rateLimit;
    }

    if (options.timeout) {
      base.circuitBreaker = base.circuitBreaker || {};
      base.circuitBreaker.defaultTimeoutMs = options.timeout;
    }

    if (options.auditLog) {
      base.audit = base.audit || {};
      base.audit.logPath = options.auditLog;
    }

    return base;
  }

  static _deepMerge(target, source) {
    const output = { ...target };
    for (const key of Object.keys(source)) {
      if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
        output[key] = this._deepMerge(target[key] || {}, source[key]);
      } else {
        output[key] = source[key];
      }
    }
    return output;
  }
}

module.exports = {
  PRESETS,
  ConfigLoader
};
