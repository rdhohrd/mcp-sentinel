'use strict';

// Precision credential patterns (DLP)
const SECRET_DETECTORS = [
  {
    type: 'AWS_ACCESS_KEY',
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    placeholder: '[REDACTED:AWS_ACCESS_KEY]'
  },
  {
    type: 'ANTHROPIC_API_KEY',
    regex: /\b(sk-ant-(?:api[0-9]{2}-)?[a-zA-Z0-9_-]{32,120})\b/g,
    placeholder: '[REDACTED:ANTHROPIC_KEY]'
  },
  {
    type: 'OPENAI_API_KEY',
    regex: /\b(sk-(?!ant-)(?:proj-)?[a-zA-Z0-9_-]{32,120})\b/g,
    placeholder: '[REDACTED:OPENAI_KEY]'
  },
  {
    type: 'GITHUB_TOKEN',
    regex: /\b(gh[pousr]_[0-9a-zA-Z]{36,255}|github_pat_[0-9a-zA-Z_]{22,255})\b/g,
    placeholder: '[REDACTED:GITHUB_TOKEN]'
  },
  {
    type: 'SLACK_TOKEN',
    regex: /\b(xox[baprs]-[0-9a-zA-Z-]{20,100})\b/g,
    placeholder: '[REDACTED:SLACK_TOKEN]'
  },
  {
    type: 'STRIPE_KEY',
    regex: /\b([sr]k_(?:live|test)_[0-9a-zA-Z]{24,99})\b/g,
    placeholder: '[REDACTED:STRIPE_KEY]'
  },
  {
    type: 'GOOGLE_API_KEY',
    regex: /\b(AIza[0-9A-Za-z_-]{35})\b/g,
    placeholder: '[REDACTED:GOOGLE_API_KEY]'
  },
  {
    type: 'DATABASE_URL',
    regex: /\b([a-z0-9+]+:\/\/[^:\s'"]+:)([^@\s'"]+)(@[^/\s'"]+)/gi,
    replacement: (match, p1, p2, p3) => `${p1}[REDACTED:DB_PASSWORD]${p3}`
  },
  {
    type: 'PRIVATE_KEY',
    regex: /-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----[\s\S]+?-----END\s+(?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----/g,
    placeholder: '[REDACTED:PRIVATE_KEY]'
  },
  {
    type: 'JWT_TOKEN',
    regex: /\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b/g,
    placeholder: '[REDACTED:JWT_TOKEN]'
  },
  {
    type: 'BEARER_AUTH',
    regex: /(Bearer\s+)([a-zA-Z0-9_\-\.]{25,})/gi,
    replacement: (match, prefix) => `${prefix}[REDACTED:BEARER_TOKEN]`
  }
];

/**
 * Calculates Shannon entropy of a string (bits per symbol)
 */
function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const frequencies = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  const len = str.length;
  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

class SecretGuard {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.mode = options.mode || 'redact'; // 'redact' | 'block' | 'warn'
    this.detectors = SECRET_DETECTORS;
    this.entropyThreshold = options.entropyThreshold || 4.6; // High entropy threshold for random tokens
    this.minEntropyLength = options.minEntropyLength || 28;
  }

  /**
   * Sanitizes a string by detecting and masking secrets
   */
  sanitizeString(text) {
    if (!this.enabled || typeof text !== 'string') {
      return { text, redactedCount: 0, secretsFound: [] };
    }

    let result = text;
    let redactedCount = 0;
    const secretsFound = [];

    // 1. Run structured pattern detectors
    for (const detector of this.detectors) {
      const matches = result.match(detector.regex);
      if (matches) {
        redactedCount += matches.length;
        secretsFound.push({ type: detector.type, count: matches.length });

        if (detector.replacement) {
          result = result.replace(detector.regex, detector.replacement);
        } else {
          result = result.replace(detector.regex, detector.placeholder);
        }
      }
    }

    return {
      text: result,
      redactedCount,
      secretsFound
    };
  }

  /**
   * Recursively traverses and sanitizes an object or array in place
   */
  sanitizeObject(obj) {
    if (!this.enabled || !obj) return { data: obj, redactedCount: 0, secretsFound: [] };

    let totalRedacted = 0;
    const allFound = [];

    const traverse = (current) => {
      if (typeof current === 'string') {
        const res = this.sanitizeString(current);
        if (res.redactedCount > 0) {
          totalRedacted += res.redactedCount;
          allFound.push(...res.secretsFound);
          return res.text;
        }
        return current;
      }

      if (Array.isArray(current)) {
        return current.map(item => traverse(item));
      }

      if (current && typeof current === 'object') {
        const copy = {};
        for (const [k, v] of Object.entries(current)) {
          copy[k] = traverse(v);
        }
        return copy;
      }

      return current;
    };

    const sanitizedData = traverse(obj);

    return {
      data: sanitizedData,
      redactedCount: totalRedacted,
      secretsFound: allFound
    };
  }
}

module.exports = {
  SecretGuard,
  SECRET_DETECTORS,
  calculateShannonEntropy
};
