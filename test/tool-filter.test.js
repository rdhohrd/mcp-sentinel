'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { ToolFilter, matchGlob } = require('../src/guards/tool-filter');

test('matchGlob - matches patterns correctly', () => {
  assert.strictEqual(matchGlob('read_*', 'read_file'), true);
  assert.strictEqual(matchGlob('read_*', 'write_file'), false);
  assert.strictEqual(matchGlob('*_tool', 'custom_tool'), true);
  assert.strictEqual(matchGlob('*', 'anything'), true);
  assert.strictEqual(matchGlob('exact_name', 'exact_name'), true);
  assert.strictEqual(matchGlob('exact_name', 'other'), false);
});

test('ToolFilter - blocks tools matching denylist', () => {
  const filter = new ToolFilter({
    denylist: ['delete_*', 'drop_*', 'dangerous_exec']
  });

  assert.strictEqual(filter.isToolAllowed('read_file').allowed, true);
  assert.strictEqual(filter.isToolAllowed('delete_database').allowed, false);
  assert.strictEqual(filter.isToolAllowed('drop_table').allowed, false);
  assert.strictEqual(filter.isToolAllowed('dangerous_exec').allowed, false);
});

test('ToolFilter - restricts access with allowlist', () => {
  const filter = new ToolFilter({
    allowlist: ['read_*', 'list_*']
  });

  assert.strictEqual(filter.isToolAllowed('read_file').allowed, true);
  assert.strictEqual(filter.isToolAllowed('list_directories').allowed, true);
  assert.strictEqual(filter.isToolAllowed('write_file').allowed, false);
  assert.strictEqual(filter.isToolAllowed('bash_exec').allowed, false);
});

test('ToolFilter - filters tools/list response for client discovery', () => {
  const filter = new ToolFilter({
    allowlist: ['read_*', 'query_*'],
    filterDiscovery: true
  });

  const response = {
    jsonrpc: '2.0',
    id: 1,
    result: {
      tools: [
        { name: 'read_file', description: 'Read a file' },
        { name: 'write_file', description: 'Write a file' },
        { name: 'query_db', description: 'Query database' },
        { name: 'delete_all', description: 'Delete all' }
      ]
    }
  };

  const filtered = filter.filterToolsList(response);
  const toolNames = filtered.result.tools.map(t => t.name);

  assert.deepStrictEqual(toolNames, ['read_file', 'query_db']);
  assert.strictEqual(filtered.result._sentinel.removedCount, 2);
});
