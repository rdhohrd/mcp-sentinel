'use strict';

const path = require('node:path');
const os = require('node:os');

// Known sensitive paths and system targets that must never be accessed by default
const SENSITIVE_PATH_PATTERNS = [
  /(\/|\\|^)\.ssh(\/|\\|$)/i,
  /(\/|\\|^)\.aws(\/|\\|$)/i,
  /(\/|\\|^)\.gnupg(\/|\\|$)/i,
  /(\/|\\|^)\.docker(\/|\\|$)/i,
  /(\/|\\|^)\.env(\.[a-z0-9_-]+)?$/i,
  /(\/|\\|^)etc\/(passwd|shadow|sudoers|master\.passwd)$/i,
  /(\/|\\|^)proc\/(self|[0-9]+)\/(environ|mem|maps|cmdline)$/i,
  /(\/|\\|^)id_rsa(\.pub)?$/i,
  /(\/|\\|^)id_ed25519(\.pub)?$/i,
  /(\/|\\|^)id_ecdsa(\.pub)?$/i,
  /(\/|\\|^)credentials(\.json|\.xml)?$/i,
  /(\/|\\|^)service[_-]?account.*\.json$/i,
  /(\/|\\|^)authorized_keys$/i,
  /(\/|\\|^)known_hosts$/i,
  /windows[\\\/]system32[\\\/]config/i
];

class PathGuard {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.allowedRoots = (options.allowedRoots || []).map(r => path.resolve(this._expandHome(r)));
    this.blockedPaths = (options.blockedPaths || []).map(p => this._expandHome(p));
    this.allowSymlinks = options.allowSymlinks === true;
    this.blockSensitiveFiles = options.blockSensitiveFiles !== false;
  }

  _expandHome(filepath) {
    if (typeof filepath !== 'string') return filepath;
    if (filepath.startsWith('~/') || filepath === '~') {
      return path.join(os.homedir(), filepath.slice(1));
    }
    return filepath;
  }

  /**
   * Decodes URL encoding and normalizes dangerous character sequences
   */
  _normalizePathString(input) {
    if (typeof input !== 'string') return input;
    let decoded = input;

    // Decode URL encodings up to 3 times to catch double/triple encoding attacks
    for (let i = 0; i < 3; i++) {
      try {
        const next = decodeURIComponent(decoded);
        if (next === decoded) break;
        decoded = next;
      } catch {
        break;
      }
    }

    return decoded;
  }

  /**
   * Scans a single path string for traversal, null bytes, and sensitive patterns
   */
  inspectPath(rawPath) {
    if (!this.enabled) return { allowed: true };
    if (typeof rawPath !== 'string') return { allowed: true };

    // Check null bytes (poison null byte attack)
    if (rawPath.includes('\0') || rawPath.includes('%00')) {
      return {
        allowed: false,
        reason: 'Path contains poison null byte (CWE-626)'
      };
    }

    const decoded = this._normalizePathString(rawPath);

    // Explicit check for directory traversal sequences
    if (/(^|[/\\])\.\.([/\\]|$)/.test(decoded) || decoded.includes('..') && (decoded.includes('/') || decoded.includes('\\'))) {
      const normalized = path.normalize(decoded);
      // If normalizing still attempts to climb above relative root or has multiple '..'
      if (normalized.startsWith('..') || decoded.includes('../') || decoded.includes('..\\')) {
        return {
          allowed: false,
          reason: `Directory traversal sequence detected in path: "${rawPath}" (CWE-22)`
        };
      }
    }

    // Check sensitive file/directory patterns
    if (this.blockSensitiveFiles) {
      for (const pattern of SENSITIVE_PATH_PATTERNS) {
        if (pattern.test(decoded)) {
          return {
            allowed: false,
            reason: `Access to sensitive system or credential file blocked: "${rawPath}" (CWE-200)`
          };
        }
      }
    }

    // Check custom blocked paths
    for (const blocked of this.blockedPaths) {
      const normBlocked = path.resolve(blocked);
      const normTarget = path.resolve(this._expandHome(decoded));
      if (normTarget === normBlocked || normTarget.startsWith(normBlocked + path.sep)) {
        return {
          allowed: false,
          reason: `Target path is explicitly blocked by policy: "${rawPath}"`
        };
      }
    }

    // Check allowed roots jail if configured
    if (this.allowedRoots.length > 0) {
      const resolved = path.resolve(this._expandHome(decoded));
      const isInsideAllowedRoot = this.allowedRoots.some(root => {
        const rel = path.relative(root, resolved);
        return !rel.startsWith('..') && !path.isAbsolute(rel);
      });

      if (!isInsideAllowedRoot) {
        return {
          allowed: false,
          reason: `Path "${rawPath}" resolves outside configured sandbox roots: [${this.allowedRoots.join(', ')}]`
        };
      }
    }

    return { allowed: true };
  }

  /**
   * Recursively inspects all path-like strings in tool call arguments
   */
  inspectToolArguments(args) {
    if (!this.enabled || !args || typeof args !== 'object') {
      return { allowed: true };
    }

    const pathKeyRegex = /(path|file|dir|folder|source|destination|dest|target|cwd|root)/i;

    const traverse = (obj) => {
      if (!obj) return { allowed: true };

      if (typeof obj === 'string') {
        // If string contains slashes or file extension, inspect it
        if (obj.includes('/') || obj.includes('\\') || obj.startsWith('.')) {
          const res = this.inspectPath(obj);
          if (!res.allowed) return res;
        }
        return { allowed: true };
      }

      if (Array.isArray(obj)) {
        for (const item of obj) {
          const res = traverse(item);
          if (!res.allowed) return res;
        }
        return { allowed: true };
      }

      if (typeof obj === 'object') {
        for (const [key, val] of Object.entries(obj)) {
          if (typeof val === 'string') {
            if (pathKeyRegex.test(key) || val.includes('/') || val.includes('\\') || val.startsWith('.')) {
              const res = this.inspectPath(val);
              if (!res.allowed) return res;
            }
          } else {
            const res = traverse(val);
            if (!res.allowed) return res;
          }
        }
      }

      return { allowed: true };
    };

    return traverse(args);
  }
}

module.exports = {
  PathGuard,
  SENSITIVE_PATH_PATTERNS
};
