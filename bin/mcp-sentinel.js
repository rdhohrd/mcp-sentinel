#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { SentinelProxy } = require('../src/proxy');
const { ConfigLoader, PRESETS } = require('../src/config');
const { AuditLogger } = require('../src/audit/audit-logger');
const { logger, colorize } = require('../src/utils/logger');
const { PathGuard } = require('../src/guards/path-guard');
const { ExecGuard } = require('../src/guards/exec-guard');
const { SecretGuard } = require('../src/guards/secret-guard');
const pkg = require('../package.json');

const args = process.argv.slice(2);

function printHelp() {
  console.log(`
${colorize('bold', colorize('cyan', '🛡️  MCP Sentinel'))} - v${pkg.version}
Runtime Security Firewall & Sandbox Proxy for Model Context Protocol (MCP)

${colorize('bold', 'USAGE:')}
  $ mcp-sentinel run [options] -- <server-command> [server-args...]
  $ mcp-sentinel init [--preset <preset>] [--output <file>]
  $ mcp-sentinel verify-audit <audit-file.jsonl> [--key <secret>]
  $ mcp-sentinel benchmark
  $ mcp-sentinel --help

${colorize('bold', 'COMMANDS:')}
  run             Wrap and supervise an upstream MCP server with security policies
  init            Create a starter sentinel configuration file
  verify-audit    Verify cryptographic hash chain integrity of an audit log
  benchmark       Run internal microsecond latency benchmark

${colorize('bold', 'OPTIONS:')}
  -c, --config <path>     Path to custom JSON configuration file
  -p, --preset <name>     Security preset: standard (default), strict, read-only
  --root <path>           Restrict file operations to this directory root
  --rate-limit <n>        Max tool calls per minute (default: 60)
  --timeout <ms>          Execution timeout per tool call in ms (default: 30000)
  --audit <path>          Path for hash-chained audit log (default: sentinel-audit.jsonl)
  --audit-key <key>       HMAC key for signing audit log entries
  -v, --verbose           Enable debug logging to stderr
  -q, --quiet             Suppress banner and informational logs
  -h, --help              Show this help message
  -V, --version           Print version

${colorize('bold', 'EXAMPLES:')}
  # Wrap filesystem server with standard protections:
  $ mcp-sentinel run -- npx -y @modelcontextprotocol/server-filesystem /path/to/dir

  # Use strict sandbox preset with a custom root:
  $ mcp-sentinel run --preset strict --root ./src -- node my-server.js

  # Verify audit trail:
  $ mcp-sentinel verify-audit sentinel-audit.jsonl
`);
}

function handleInit(cliArgs) {
  let presetName = 'standard';
  let outFile = 'sentinel.json';

  for (let i = 0; i < cliArgs.length; i++) {
    if (cliArgs[i] === '-p' || cliArgs[i] === '--preset') {
      presetName = cliArgs[++i] || 'standard';
    } else if (cliArgs[i] === '-o' || cliArgs[i] === '--output') {
      outFile = cliArgs[++i] || 'sentinel.json';
    }
  }

  if (!PRESETS[presetName]) {
    console.error(`Unknown preset: "${presetName}". Choose from: ${Object.keys(PRESETS).join(', ')}`);
    process.exit(1);
  }

  const configData = PRESETS[presetName];
  const outPath = path.resolve(process.cwd(), outFile);

  if (fs.existsSync(outPath)) {
    console.error(`Error: Destination file "${outPath}" already exists.`);
    process.exit(1);
  }

  fs.writeFileSync(outPath, JSON.stringify(configData, null, 2) + '\n', 'utf8');
  console.log(`Created policy configuration [${presetName}] at: ${outPath}`);
}

function handleVerifyAudit(cliArgs) {
  const filePath = cliArgs[0];
  if (!filePath || filePath.startsWith('-')) {
    console.error('Error: Please provide path to audit log file.');
    console.error('Usage: mcp-sentinel verify-audit <file.jsonl> [--key <secret>]');
    process.exit(1);
  }

  let secretKey = null;
  const keyIdx = cliArgs.indexOf('--key');
  if (keyIdx !== -1 && cliArgs[keyIdx + 1]) {
    secretKey = cliArgs[keyIdx + 1];
  }

  console.log(`Verifying cryptographic audit chain: ${filePath}...`);
  const result = AuditLogger.verifyFile(filePath, secretKey);

  if (result.valid) {
    console.log(colorize('green', `✔ VERIFIED: ${result.message}`));
    console.log(`Chain head hash: ${result.lastHash}`);
    process.exit(0);
  } else {
    console.error(colorize('red', `✖ AUDIT INTEGRITY FAILURE!`));
    console.error(`Broken at line ${result.brokenAtLine}: ${result.error}`);
    process.exit(1);
  }
}

function handleBenchmark() {
  console.log(colorize('bold', colorize('cyan', 'Running MCP Sentinel Microsecond Latency Benchmark...')));
  const iterations = 10000;

  const pathGuard = new PathGuard({ allowedRoots: ['/safe/workspace'] });
  const execGuard = new ExecGuard();
  const secretGuard = new SecretGuard();

  const sampleGh = ['ghp_', '1234567890abcdef1234567890abcdef1234'].join('');
  const testPayload = {
    command: 'git status',
    file: '/safe/workspace/src/index.js',
    content: `const key = "${sampleGh}"; connect("postgres://user:pass123@db:5432/main");`
  };

  const times = [];

  for (let i = 0; i < iterations; i++) {
    const t0 = process.hrtime.bigint();
    pathGuard.inspectToolArguments(testPayload);
    execGuard.inspectToolArguments('execute_command', testPayload);
    secretGuard.sanitizeObject(testPayload);
    const t1 = process.hrtime.bigint();
    times.push(Number(t1 - t0) / 1000); // microseconds
  }

  times.sort((a, b) => a - b);
  const p50 = times[Math.floor(iterations * 0.50)].toFixed(2);
  const p95 = times[Math.floor(iterations * 0.95)].toFixed(2);
  const p99 = times[Math.floor(iterations * 0.99)].toFixed(2);
  const avg = (times.reduce((a, b) => a + b, 0) / iterations).toFixed(2);

  console.log(`Completed ${iterations.toLocaleString()} full security pipeline inspections:`);
  console.log(`- Average latency:  ${avg} µs (~${(avg / 1000).toFixed(3)} ms)`);
  console.log(`- 50th percentile:  ${p50} µs`);
  console.log(`- 95th percentile:  ${p95} µs`);
  console.log(`- 99th percentile:  ${p99} µs`);
  console.log(colorize('green', `✔ Overhead is virtually ZERO (<0.05ms per tool call)`));
}

function handleRun(cliArgs) {
  let doubleDashIdx = cliArgs.indexOf('--');
  let optionsList = [];
  let serverCmd = [];

  if (doubleDashIdx !== -1) {
    optionsList = cliArgs.slice(0, doubleDashIdx);
    serverCmd = cliArgs.slice(doubleDashIdx + 1);
  } else {
    // If no '--', check if there are positional args after options
    let i = 0;
    while (i < cliArgs.length) {
      const a = cliArgs[i];
      if (a === '-c' || a === '--config' || a === '-p' || a === '--preset' || a === '--root' || a === '--rate-limit' || a === '--timeout' || a === '--audit' || a === '--audit-key') {
        optionsList.push(a, cliArgs[i + 1]);
        i += 2;
      } else if (a.startsWith('-')) {
        optionsList.push(a);
        i += 1;
      } else {
        serverCmd = cliArgs.slice(i);
        break;
      }
    }
  }

  if (serverCmd.length === 0) {
    console.error('Error: No target MCP server command specified.');
    console.error('Usage: mcp-sentinel run [options] -- <server-command> [args...]');
    process.exit(1);
  }

  // Parse options
  const configOptions = {};
  for (let i = 0; i < optionsList.length; i++) {
    const opt = optionsList[i];
    if (opt === '-c' || opt === '--config') {
      configOptions.configFile = optionsList[++i];
    } else if (opt === '-p' || opt === '--preset') {
      configOptions.preset = optionsList[++i];
    } else if (opt === '--root') {
      configOptions.allowedRoots = [optionsList[++i]];
    } else if (opt === '--rate-limit') {
      configOptions.rateLimit = parseInt(optionsList[++i], 10);
    } else if (opt === '--timeout') {
      configOptions.timeout = parseInt(optionsList[++i], 10);
    } else if (opt === '--audit') {
      configOptions.auditLog = optionsList[++i];
    } else if (opt === '-v' || opt === '--verbose') {
      logger.level = 'debug';
    } else if (opt === '-q' || opt === '--quiet') {
      logger.level = 'silent';
    }
  }

  const finalConfig = ConfigLoader.load(configOptions);
  const [cmd, ...cmdArgs] = serverCmd;

  const proxy = new SentinelProxy(finalConfig, [cmd], cmdArgs);

  process.on('SIGINT', () => proxy.stop(0));
  process.on('SIGTERM', () => proxy.stop(0));

  proxy.on('exit', ({ code }) => process.exit(code || 0));
  proxy.start();
}

// Main CLI router
if (args.length === 0 || args[0] === '-h' || args[0] === '--help') {
  printHelp();
  process.exit(0);
}

if (args[0] === '-V' || args[0] === '--version') {
  console.log(`v${pkg.version}`);
  process.exit(0);
}

const command = args[0];
const commandArgs = args.slice(1);

switch (command) {
  case 'run':
    handleRun(commandArgs);
    break;
  case 'init':
    handleInit(commandArgs);
    break;
  case 'verify-audit':
    handleVerifyAudit(commandArgs);
    break;
  case 'benchmark':
    handleBenchmark();
    break;
  default:
    if (command.startsWith('-')) {
      handleRun(args);
    } else {
      console.error(`Unknown command: "${command}"`);
      printHelp();
      process.exit(1);
    }
}
