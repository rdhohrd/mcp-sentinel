'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { SecretGuard, calculateShannonEntropy } = require('../src/guards/secret-guard');

// Dynamically construct test credentials so GitHub Push Protection doesn't trigger false positives
const DUMMY_AWS_KEY = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
const DUMMY_GH_TOKEN = ['ghp_', '1234567890abcdef1234567890abcdef1234'].join('');
const DUMMY_OPENAI_KEY = ['sk-proj-', '1234567890abcdef1234567890abcdef1234567890'].join('');
const DUMMY_ANTHROPIC_KEY = ['sk-ant-api03-', '1234567890abcdef1234567890abcdef1234567890'].join('');
const DUMMY_STRIPE_KEY = ['sk_test_', '1234567890abcdef1234567890abcdef'].join('');
const DUMMY_SLACK_TOKEN = ['xoxb-', '123456789012-1234567890123-abcdef1234567890abcdef1234'].join('');

test('SecretGuard - redacts AWS access keys', () => {
  const guard = new SecretGuard();
  const input = `Use access key ${DUMMY_AWS_KEY} for S3 uploads`;
  const res = guard.sanitizeString(input);

  assert.strictEqual(res.redactedCount, 1);
  assert.strictEqual(res.text, 'Use access key [REDACTED:AWS_ACCESS_KEY] for S3 uploads');
});

test('SecretGuard - redacts GitHub tokens', () => {
  const guard = new SecretGuard();
  const input = `export GITHUB_TOKEN="${DUMMY_GH_TOKEN}"`;
  const res = guard.sanitizeString(input);

  assert.strictEqual(res.redactedCount, 1);
  assert.strictEqual(res.text, 'export GITHUB_TOKEN="[REDACTED:GITHUB_TOKEN]"');
});

test('SecretGuard - redacts OpenAI and Anthropic API keys', () => {
  const guard = new SecretGuard();
  const input = `OpenAI: ${DUMMY_OPENAI_KEY}\nAnthropic: ${DUMMY_ANTHROPIC_KEY}`;
  const res = guard.sanitizeString(input);

  assert.strictEqual(res.redactedCount, 2);
  assert.match(res.text, /\[REDACTED:OPENAI_KEY\]/);
  assert.match(res.text, /\[REDACTED:ANTHROPIC_KEY\]/);
});

test('SecretGuard - redacts passwords in database connection URIs', () => {
  const guard = new SecretGuard();
  const input = 'Connecting to postgres://admin:superSecret123@db.prod.internal:5432/finance';
  const res = guard.sanitizeString(input);

  assert.strictEqual(res.redactedCount, 1);
  assert.strictEqual(res.text, 'Connecting to postgres://admin:[REDACTED:DB_PASSWORD]@db.prod.internal:5432/finance');
});

test('SecretGuard - redacts RSA and SSH private keys', () => {
  const guard = new SecretGuard();
  const fakeKey = [
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIEowIBAAKCAQEA0Y1+c4+exampleFakeKeyPayloadHereForTestingOnly',
    'ABCDEF1234567890abcdef1234567890==',
    '-----END RSA PRIVATE KEY-----'
  ].join('\n');

  const input = `Server key is:\n${fakeKey}\nPlease keep it safe.`;
  const res = guard.sanitizeString(input);

  assert.strictEqual(res.redactedCount, 1);
  assert.strictEqual(res.text, 'Server key is:\n[REDACTED:PRIVATE_KEY]\nPlease keep it safe.');
});

test('SecretGuard - sanitizes deeply nested JSON objects and arrays', () => {
  const guard = new SecretGuard();
  const obj = {
    user: 'alice',
    configs: [
      {
        provider: 'stripe',
        apiKey: DUMMY_STRIPE_KEY
      },
      {
        provider: 'slack',
        token: DUMMY_SLACK_TOKEN
      }
    ]
  };

  const res = guard.sanitizeObject(obj);
  assert.strictEqual(res.redactedCount, 2);
  assert.strictEqual(res.data.configs[0].apiKey, '[REDACTED:STRIPE_KEY]');
  assert.strictEqual(res.data.configs[1].token, '[REDACTED:SLACK_TOKEN]');
});

test('SecretGuard - calculateShannonEntropy correctly calculates entropy', () => {
  const zeroEntropy = 'aaaaaaaaaaaaaaaa';
  const lowEntropy = 'abcabcabcabc';
  const randomHex = '4f9a1c8b3e7d2f0a5c6b1e8d9a4f2c0b';
  const randomBase64 = 'k9J#mP$2vL@8qZ&5wX!7nB*1yT^4rE%0';

  assert.strictEqual(calculateShannonEntropy(zeroEntropy), 0);
  assert(calculateShannonEntropy(lowEntropy) < 2.0);
  assert(calculateShannonEntropy(randomHex) > 3.5);
  assert(calculateShannonEntropy(randomBase64) > 4.5);
});
