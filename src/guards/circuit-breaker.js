'use strict';

class CircuitBreaker {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.defaultTimeoutMs = options.defaultTimeoutMs || 30000; // 30s
    this.toolTimeouts = options.toolTimeouts || {};            // { 'heavy_tool': 60000 }
    this.failureThreshold = options.failureThreshold || 5;    // Open after 5 consecutive failures
    this.resetTimeoutMs = options.resetTimeoutMs || 60000;    // Try half-open after 60s

    this.consecutiveFailures = 0;
    this.state = 'CLOSED'; // 'CLOSED' | 'OPEN' | 'HALF_OPEN'
    this.lastStateChange = Date.now();
  }

  getTimeoutForTool(toolName) {
    if (this.toolTimeouts[toolName]) {
      return this.toolTimeouts[toolName];
    }
    return this.defaultTimeoutMs;
  }

  canExecute() {
    if (!this.enabled) return { allowed: true };

    const now = Date.now();

    if (this.state === 'OPEN') {
      if (now - this.lastStateChange > this.resetTimeoutMs) {
        this.state = 'HALF_OPEN';
        this.lastStateChange = now;
        return { allowed: true, state: 'HALF_OPEN' };
      }
      return {
        allowed: false,
        reason: `Circuit breaker is OPEN. Upstream server has failed repeatedly (${this.consecutiveFailures} failures). Fast-failing to protect agent resources.`
      };
    }

    return { allowed: true, state: this.state };
  }

  recordSuccess() {
    this.consecutiveFailures = 0;
    if (this.state === 'HALF_OPEN') {
      this.state = 'CLOSED';
      this.lastStateChange = Date.now();
    }
  }

  recordFailure() {
    this.consecutiveFailures += 1;
    if (this.consecutiveFailures >= this.failureThreshold) {
      this.state = 'OPEN';
      this.lastStateChange = Date.now();
    }
  }

  reset() {
    this.consecutiveFailures = 0;
    this.state = 'CLOSED';
    this.lastStateChange = Date.now();
  }
}

module.exports = {
  CircuitBreaker
};
