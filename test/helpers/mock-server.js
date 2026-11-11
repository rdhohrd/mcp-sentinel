#!/usr/bin/env node
'use strict';

const readline = require('node:readline');

const rl = readline.createInterface({
  input: process.stdin,
  terminal: false
});

rl.on('line', (line) => {
  if (!line.trim()) return;

  try {
    const msg = JSON.parse(line);
    const id = msg.id;

    if (msg.method === 'initialize') {
      send({
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: '2024-11-05',
          capabilities: { tools: {} },
          serverInfo: { name: 'mock-mcp-server', version: '1.0.0' }
        }
      });
      return;
    }

    if (msg.method === 'tools/list') {
      send({
        jsonrpc: '2.0',
        id,
        result: {
          tools: [
            { name: 'read_file', description: 'Read a safe file' },
            { name: 'write_file', description: 'Write a safe file' },
            { name: 'execute_command', description: 'Run a shell command' },
            { name: 'get_api_secret', description: 'Fetch API token' }
          ]
        }
      });
      return;
    }

    if (msg.method === 'tools/call') {
      const toolName = msg.params?.name;
      const args = msg.params?.arguments || {};

      if (toolName === 'read_file') {
        send({
          jsonrpc: '2.0',
          id,
          result: {
            content: [{ type: 'text', text: `Content of file: ${args.path}` }]
          }
        });
      } else if (toolName === 'get_api_secret') {
        const dummyToken = ['ghp_', '1234567890abcdef1234567890abcdef1234'].join('');
        const dummyAws = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
        send({
          jsonrpc: '2.0',
          id,
          result: {
            content: [
              {
                type: 'text',
                text: `Credentials: GITHUB_TOKEN=${dummyToken} and AWS_KEY=${dummyAws}`
              }
            ]
          }
        });
      } else {
        send({
          jsonrpc: '2.0',
          id,
          result: {
            content: [{ type: 'text', text: `Tool ${toolName} executed successfully.` }]
          }
        });
      }
      return;
    }

    // Default echo
    send({
      jsonrpc: '2.0',
      id,
      result: { acknowledged: true }
    });
  } catch (err) {
    send({
      jsonrpc: '2.0',
      id: null,
      error: { code: -32700, message: 'Parse error', data: err.message }
    });
  }
});

function send(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}
