'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const testDir = path.resolve(__dirname);
const testFiles = fs.readdirSync(testDir)
  .filter(f => f.endsWith('.test.js'))
  .map(f => path.join(testDir, f));

const child = spawn(process.execPath, ['--test', ...testFiles], {
  stdio: 'inherit'
});

child.on('exit', (code) => {
  process.exit(code || 0);
});
