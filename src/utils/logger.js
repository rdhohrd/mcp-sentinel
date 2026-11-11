'use strict';

const isTTY = process.stderr.isTTY;

const Colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m'
};

function colorize(color, text) {
  if (!isTTY) return text;
  return `${Colors[color] || ''}${text}${Colors.reset}`;
}

class Logger {
  constructor(options = {}) {
    this.level = options.level || 'info'; // 'debug' | 'info' | 'warn' | 'error' | 'silent'
    this.prefix = options.prefix || '🛡️ [MCP-SENTINEL]';
  }

  debug(msg, ...args) {
    if (this.level !== 'debug') return;
    process.stderr.write(`${colorize('gray', `${this.prefix} [DEBUG] ${msg}`)} ${args.length ? JSON.stringify(args) : ''}\n`);
  }

  info(msg, ...args) {
    if (this.level === 'silent' || this.level === 'warn' || this.level === 'error') return;
    process.stderr.write(`${colorize('cyan', `${this.prefix}`)} ${msg} ${args.length ? JSON.stringify(args) : ''}\n`);
  }

  success(msg, ...args) {
    if (this.level === 'silent' || this.level === 'error') return;
    process.stderr.write(`${colorize('green', `${this.prefix} [OK]`)} ${msg} ${args.length ? JSON.stringify(args) : ''}\n`);
  }

  warn(msg, ...args) {
    if (this.level === 'silent' || this.level === 'error') return;
    process.stderr.write(`${colorize('yellow', `${this.prefix} [WARN]`)} ${colorize('yellow', msg)} ${args.length ? JSON.stringify(args) : ''}\n`);
  }

  block(msg, ...args) {
    if (this.level === 'silent') return;
    process.stderr.write(`${colorize('bold', colorize('red', `${this.prefix} [BLOCKED]`))} ${colorize('red', msg)} ${args.length ? JSON.stringify(args) : ''}\n`);
  }

  error(msg, ...args) {
    if (this.level === 'silent') return;
    process.stderr.write(`${colorize('bold', colorize('red', `${this.prefix} [ERROR]`))} ${msg} ${args.length ? JSON.stringify(args) : ''}\n`);
  }
}

module.exports = {
  Colors,
  colorize,
  Logger,
  logger: new Logger()
};
