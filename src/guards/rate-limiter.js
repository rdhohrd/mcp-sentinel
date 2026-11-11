'use strict';

class RateLimiter {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.maxCallsPerMinute = options.maxCallsPerMinute || 60;
    this.toolOverrides = options.toolOverrides || {}; // { 'execute_command': 10 }
    this.buckets = new Map(); // key -> { tokens, lastRefill }
    this.windowMs = 60000;
  }

  _getBucket(key, limit) {
    const now = Date.now();
    let bucket = this.buckets.get(key);

    if (!bucket) {
      bucket = { tokens: limit, lastRefill: now };
      this.buckets.set(key, bucket);
      return bucket;
    }

    // Refill tokens based on elapsed time
    const elapsed = now - bucket.lastRefill;
    if (elapsed > 0) {
      const refill = (elapsed / this.windowMs) * limit;
      bucket.tokens = Math.min(limit, bucket.tokens + refill);
      bucket.lastRefill = now;
    }

    return bucket;
  }

  /**
   * Attempts to consume 1 token for a tool call
   */
  consume(toolName = 'global') {
    if (!this.enabled) return { allowed: true, remaining: 999 };

    // 1. Check global limit
    const globalBucket = this._getBucket('__global__', this.maxCallsPerMinute);
    if (globalBucket.tokens < 1) {
      const waitMs = Math.ceil(((1 - globalBucket.tokens) / this.maxCallsPerMinute) * this.windowMs);
      return {
        allowed: false,
        reason: `Global rate limit exceeded (${this.maxCallsPerMinute} calls/min). Try again in ${Math.ceil(waitMs / 1000)}s`,
        waitMs
      };
    }

    // 2. Check tool-specific limit if configured
    const toolLimit = this.toolOverrides[toolName];
    if (toolLimit && toolLimit > 0) {
      const toolBucket = this._getBucket(`tool:${toolName}`, toolLimit);
      if (toolBucket.tokens < 1) {
        const waitMs = Math.ceil(((1 - toolBucket.tokens) / toolLimit) * this.windowMs);
        return {
          allowed: false,
          reason: `Rate limit exceeded for tool "${toolName}" (${toolLimit} calls/min). Try again in ${Math.ceil(waitMs / 1000)}s`,
          waitMs
        };
      }
      toolBucket.tokens -= 1;
    }

    globalBucket.tokens -= 1;

    return {
      allowed: true,
      remaining: Math.floor(globalBucket.tokens)
    };
  }

  reset() {
    this.buckets.clear();
  }
}

module.exports = {
  RateLimiter
};
