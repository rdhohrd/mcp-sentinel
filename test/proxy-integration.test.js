'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { PassThrough } = require('node:stream');
const { SentinelProxy } = require('../src/proxy');
const { ConfigLoader } = require('../src/config');

test('SentinelProxy - End-to-End Integration with Mock MCP Server', async () => {
  const mockServerPath = path.resolve(__dirname, 'helpers/mock-server.js');
  const config = ConfigLoader.load({
    preset: 'standard',
    rateLimit: 100
  });

  const proxy = new SentinelProxy(config, [process.execPath], [mockServerPath]);

  const clientIn = new PassThrough();
  const clientOut = new PassThrough();

  const responses = [];

  clientOut.on('data', (chunk) => {
    const lines = chunk.toString().trim().split('\n');
    for (const line of lines) {
      if (line) {
        try {
          responses.push(JSON.parse(line));
        } catch {}
      }
    }
  });

  proxy.start(clientIn, clientOut);

  // Helper to send request and await response
  const sendRequest = async (req) => {
    const prevLen = responses.length;
    clientIn.write(JSON.stringify(req) + '\n');

    // Poll until response arrives
    const start = Date.now();
    while (responses.length === prevLen && Date.now() - start < 2000) {
      await new Promise(r => setTimeout(r, 20));
    }

    return responses[responses.length - 1];
  };

  try {
    // 1. Initialize
    const initRes = await sendRequest({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {}
    });
    assert.strictEqual(initRes.id, 1);
    assert.strictEqual(initRes.result.serverInfo.name, 'mock-mcp-server');

    // 2. Safe tool call
    const safeRes = await sendRequest({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: {
        name: 'read_file',
        arguments: { path: 'src/main.js' }
      }
    });
    assert.strictEqual(safeRes.id, 2);
    assert.match(safeRes.result.content[0].text, /Content of file: src\/main\.js/);

    // 3. Path traversal attack: MUST BE BLOCKED BY SENTINEL
    const traversalRes = await sendRequest({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: {
        name: 'read_file',
        arguments: { path: '../../../../etc/passwd' }
      }
    });
    assert.strictEqual(traversalRes.id, 3);
    assert.strictEqual(traversalRes.result.isError, true);
    assert.strictEqual(traversalRes.result._sentinel.verdict, 'BLOCKED');
    assert.match(traversalRes.result.content[0].text, /traversal/i);

    // 4. Command injection attack: MUST BE BLOCKED BY SENTINEL
    const injectionRes = await sendRequest({
      jsonrpc: '2.0',
      id: 4,
      method: 'tools/call',
      params: {
        name: 'execute_command',
        arguments: { command: 'rm -rf / --no-preserve-root' }
      }
    });
    assert.strictEqual(injectionRes.id, 4);
    assert.strictEqual(injectionRes.result.isError, true);
    assert.strictEqual(injectionRes.result._sentinel.verdict, 'BLOCKED');
    assert.match(injectionRes.result.content[0].text, /destructive/i);

    // 5. Inbound Secret Leakage Scrubbing (DLP):
    // Server outputs tokens, Sentinel must scrub them before client receives them!
    const secretRes = await sendRequest({
      jsonrpc: '2.0',
      id: 5,
      method: 'tools/call',
      params: {
        name: 'get_api_secret',
        arguments: {}
      }
    });
    assert.strictEqual(secretRes.id, 5);
    const leakedText = secretRes.result.content[0].text;
    assert.doesNotMatch(leakedText, /ghp_1234567890/);
    assert.doesNotMatch(leakedText, /AKIAIOSFODNN7/);
    assert.match(leakedText, /\[REDACTED:GITHUB_TOKEN\]/);
    assert.match(leakedText, /\[REDACTED:AWS_ACCESS_KEY\]/);
  } finally {
    proxy.stop(0);
  }
});
