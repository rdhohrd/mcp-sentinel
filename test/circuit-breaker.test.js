'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { CircuitBreaker } = require('../src/guards/circuit-breaker');

test('CircuitBreaker - transitions from CLOSED to OPEN after failure threshold', () => {
  const breaker = new CircuitBreaker({
    failureThreshold: 3,
    resetTimeoutMs: 500
  });

  assert.strictEqual(breaker.canExecute().allowed, true);
  assert.strictEqual(breaker.state, 'CLOSED');

  // Record 2 failures -> still closed
  breaker.recordFailure();
  breaker.recordFailure();
  assert.strictEqual(breaker.canExecute().allowed, true);
  assert.strictEqual(breaker.state, 'CLOSED');

  // 3rd failure -> trips to OPEN
  breaker.recordFailure();
  assert.strictEqual(breaker.state, 'OPEN');

  const check = breaker.canExecute();
  assert.strictEqual(check.allowed, false);
  assert.match(check.reason, /Circuit breaker is OPEN/i);
});

test('CircuitBreaker - recovers to HALF_OPEN after reset timeout', async () => {
  const breaker = new CircuitBreaker({
    failureThreshold: 1,
    resetTimeoutMs: 50 // 50ms fast reset for test
  });

  breaker.recordFailure();
  assert.strictEqual(breaker.state, 'OPEN');

  await new Promise(r => setTimeout(r, 60));

  const check = breaker.canExecute();
  assert.strictEqual(check.allowed, true);
  assert.strictEqual(check.state, 'HALF_OPEN');

  // Success in half-open resets to closed
  breaker.recordSuccess();
  assert.strictEqual(breaker.state, 'CLOSED');
});

test('CircuitBreaker - retrieves per-tool timeouts', () => {
  const breaker = new CircuitBreaker({
    defaultTimeoutMs: 10000,
    toolTimeouts: {
      long_task: 60000
    }
  });

  assert.strictEqual(breaker.getTimeoutForTool('normal_task'), 10000);
  assert.strictEqual(breaker.getTimeoutForTool('long_task'), 60000);
});
