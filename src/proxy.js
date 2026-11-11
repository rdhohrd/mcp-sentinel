'use strict';

const { spawn } = require('node:child_process');
const readline = require('node:readline');
const EventEmitter = require('node:events');

const { PathGuard } = require('./guards/path-guard');
const { ExecGuard } = require('./guards/exec-guard');
const { SecretGuard } = require('./guards/secret-guard');
const { ToolFilter } = require('./guards/tool-filter');
const { RateLimiter } = require('./guards/rate-limiter');
const { CircuitBreaker } = require('./guards/circuit-breaker');
const { AuditLogger } = require('./audit/audit-logger');
const { logger } = require('./utils/logger');
const {
  ErrorCodes,
  createErrorResponse,
  createToolBlockedResponse,
  parseMessage,
  isRequest,
  isResponse
} = require('./utils/jsonrpc');

class SentinelProxy extends EventEmitter {
  constructor(config = {}, serverCommand = [], serverArgs = []) {
    super();
    this.config = config;
    this.serverCommand = serverCommand;
    this.serverArgs = serverArgs;

    // Initialize security guards
    this.pathGuard = new PathGuard(config.pathGuard || {});
    this.execGuard = new ExecGuard(config.execGuard || {});
    this.secretGuard = new SecretGuard(config.secretGuard || {});
    this.toolFilter = new ToolFilter(config.toolFilter || {});
    this.rateLimiter = new RateLimiter(config.rateLimiter || {});
    this.circuitBreaker = new CircuitBreaker(config.circuitBreaker || {});
    this.auditLogger = new AuditLogger(config.audit || {});

    this.serverProcess = null;
    this.pendingCalls = new Map(); // id -> { toolName, startTime, timeoutHandle }
    this.isRunning = false;
  }

  /**
   * Starts the proxy supervisor and spawns target MCP server
   */
  start(inStream = process.stdin, outStream = process.stdout) {
    if (this.isRunning) return;
    this.isRunning = true;
    this.inStream = inStream;
    this.outStream = outStream;

    if (!this.serverCommand || this.serverCommand.length === 0) {
      throw new Error('No target MCP server command specified.');
    }

    const [cmd, ...args] = [...this.serverCommand, ...this.serverArgs];
    logger.info(`Starting MCP Sentinel proxy supervisor...`);
    logger.info(`Upstream target: ${cmd} ${args.join(' ')}`);

    this.serverProcess = spawn(cmd, args, {
      stdio: ['pipe', 'pipe', 'inherit'],
      env: { ...process.env }
    });

    this.serverProcess.on('error', (err) => {
      logger.error(`Failed to launch upstream MCP server: ${err.message}`);
      this.emit('error', err);
      this.stop(1);
    });

    this.serverProcess.on('exit', (code, signal) => {
      logger.info(`Upstream MCP server exited with code ${code} (${signal || 'none'})`);
      this.emit('exit', { code, signal });
      this.stop(code || 0);
    });

    // Setup line readers for stdio JSON-RPC streams
    this.clientReader = readline.createInterface({
      input: inStream,
      terminal: false
    });

    this.serverReader = readline.createInterface({
      input: this.serverProcess.stdout,
      terminal: false
    });

    this.clientReader.on('line', (line) => this.handleClientMessage(line));
    this.serverReader.on('line', (line) => this.handleServerMessage(line));
  }

  /**
   * Handles JSON-RPC messages arriving from the client (LLM Agent / Claude / Cursor)
   */
  handleClientMessage(rawLine) {
    const msg = parseMessage(rawLine);
    if (!msg) {
      // Forward unparseable lines directly to upstream if any
      this._sendToServerRaw(rawLine);
      return;
    }

    // Inspect tool calls: method === "tools/call"
    if (msg.method === 'tools/call') {
      const toolName = msg.params?.name;
      const toolArgs = msg.params?.arguments || {};
      const callId = msg.id;

      // 1. Circuit breaker health check
      const cbCheck = this.circuitBreaker.canExecute();
      if (!cbCheck.allowed) {
        logger.block(`Circuit breaker active: rejecting tool "${toolName}"`);
        this.auditLogger.logEvent({
          requestId: callId,
          type: 'TOOL_CALL',
          toolName,
          verdict: 'BLOCKED',
          reason: cbCheck.reason
        });
        this._sendToClient(createErrorResponse(callId, ErrorCodes.INTERNAL_ERROR, cbCheck.reason));
        return;
      }

      // 2. Tool permission filter
      const filterCheck = this.toolFilter.isToolAllowed(toolName);
      if (!filterCheck.allowed) {
        logger.block(`Tool filter blocked "${toolName}": ${filterCheck.reason}`);
        this.auditLogger.logEvent({
          requestId: callId,
          type: 'TOOL_CALL',
          toolName,
          verdict: 'BLOCKED',
          reason: filterCheck.reason
        });
        this._sendToClient(createToolBlockedResponse(callId, filterCheck.reason, { toolName }));
        return;
      }

      // 3. Rate limiter check
      const rateCheck = this.rateLimiter.consume(toolName);
      if (!rateCheck.allowed) {
        logger.block(`Rate limit exceeded for "${toolName}": ${rateCheck.reason}`);
        this.auditLogger.logEvent({
          requestId: callId,
          type: 'TOOL_CALL',
          toolName,
          verdict: 'BLOCKED',
          reason: rateCheck.reason
        });
        this._sendToClient(createToolBlockedResponse(callId, rateCheck.reason, { toolName }));
        return;
      }

      // 4. Path traversal & file sandbox check
      const pathCheck = this.pathGuard.inspectToolArguments(toolArgs);
      if (!pathCheck.allowed) {
        logger.block(`Path guard blocked "${toolName}": ${pathCheck.reason}`);
        this.auditLogger.logEvent({
          requestId: callId,
          type: 'TOOL_CALL',
          toolName,
          verdict: 'BLOCKED',
          reason: pathCheck.reason,
          arguments: toolArgs
        });
        this._sendToClient(createToolBlockedResponse(callId, pathCheck.reason, { toolName, args: toolArgs }));
        return;
      }

      // 5. Command injection & dangerous execution check
      const execCheck = this.execGuard.inspectToolArguments(toolName, toolArgs);
      if (!execCheck.allowed) {
        logger.block(`Exec guard blocked "${toolName}": ${execCheck.reason}`);
        this.auditLogger.logEvent({
          requestId: callId,
          type: 'TOOL_CALL',
          toolName,
          verdict: 'BLOCKED',
          reason: execCheck.reason,
          arguments: toolArgs
        });
        this._sendToClient(createToolBlockedResponse(callId, execCheck.reason, { toolName, args: toolArgs }));
        return;
      }

      // 6. Outbound secret leakage redaction
      const secretCheck = this.secretGuard.sanitizeObject(toolArgs);
      if (secretCheck.redactedCount > 0) {
        logger.warn(`Redacted ${secretCheck.redactedCount} sensitive secrets from outgoing arguments for "${toolName}"`);
        msg.params.arguments = secretCheck.data;
      }

      // 7. Track timeout handle
      const timeoutMs = this.circuitBreaker.getTimeoutForTool(toolName);
      const startTime = Date.now();

      const timeoutHandle = setTimeout(() => {
        if (this.pendingCalls.has(callId)) {
          this.pendingCalls.delete(callId);
          this.circuitBreaker.recordFailure();
          const reason = `Execution of tool "${toolName}" timed out after ${timeoutMs}ms`;
          logger.block(reason);
          this.auditLogger.logEvent({
            requestId: callId,
            type: 'TOOL_CALL',
            toolName,
            verdict: 'TIMEOUT',
            durationMs: timeoutMs
          });
          this._sendToClient(createToolBlockedResponse(callId, reason, { timeoutMs }));
        }
      }, timeoutMs);

      this.pendingCalls.set(callId, {
        toolName,
        startTime,
        timeoutHandle
      });

      this.auditLogger.logEvent({
        requestId: callId,
        type: 'TOOL_CALL',
        toolName,
        verdict: 'ALLOWED'
      });
    }

    // Forward message to upstream MCP server
    this._sendToServer(msg);
  }

  /**
   * Handles JSON-RPC responses arriving from the upstream MCP server
   */
  handleServerMessage(rawLine) {
    const msg = parseMessage(rawLine);
    if (!msg) {
      this._sendToClientRaw(rawLine);
      return;
    }

    // Intercept tools/list responses for discovery filtering
    if (isResponse(msg) && msg.result && Array.isArray(msg.result.tools)) {
      const filtered = this.toolFilter.filterToolsList(msg);
      this._sendToClient(filtered);
      return;
    }

    // Intercept tool call responses
    if (isResponse(msg) && msg.id !== undefined && this.pendingCalls.has(msg.id)) {
      const pending = this.pendingCalls.get(msg.id);
      this.pendingCalls.delete(msg.id);
      clearTimeout(pending.timeoutHandle);

      const durationMs = Date.now() - pending.startTime;

      if (msg.error) {
        this.circuitBreaker.recordFailure();
        this.auditLogger.logEvent({
          requestId: msg.id,
          type: 'TOOL_RESPONSE',
          toolName: pending.toolName,
          verdict: 'ERROR',
          durationMs,
          error: msg.error
        });
      } else {
        this.circuitBreaker.recordSuccess();

        // 8. Inbound Secret / DLP Sanitization on tool output content
        let responsePayload = msg.result;
        const secretCheck = this.secretGuard.sanitizeObject(responsePayload);
        if (secretCheck.redactedCount > 0) {
          logger.warn(`DLP: Redacted ${secretCheck.redactedCount} sensitive secrets in output of "${pending.toolName}"`);
          msg.result = secretCheck.data;
        }

        this.auditLogger.logEvent({
          requestId: msg.id,
          type: 'TOOL_RESPONSE',
          toolName: pending.toolName,
          verdict: 'SUCCESS',
          durationMs,
          redactedCount: secretCheck.redactedCount
        });
      }
    }

    this._sendToClient(msg);
  }

  _sendToServer(msg) {
    if (this.serverProcess && this.serverProcess.stdin && !this.serverProcess.stdin.destroyed) {
      this.serverProcess.stdin.write(JSON.stringify(msg) + '\n');
    }
  }

  _sendToServerRaw(rawLine) {
    if (this.serverProcess && this.serverProcess.stdin && !this.serverProcess.stdin.destroyed) {
      this.serverProcess.stdin.write(rawLine + '\n');
    }
  }

  _sendToClient(msg) {
    if (this.outStream) {
      this.outStream.write(JSON.stringify(msg) + '\n');
    }
  }

  _sendToClientRaw(rawLine) {
    if (this.outStream) {
      this.outStream.write(rawLine + '\n');
    }
  }

  stop(exitCode = 0) {
    if (!this.isRunning) return;
    this.isRunning = false;

    // Clear all pending timeouts
    for (const [, call] of this.pendingCalls.entries()) {
      clearTimeout(call.timeoutHandle);
    }
    this.pendingCalls.clear();

    if (this.clientReader) {
      this.clientReader.close();
    }
    if (this.serverReader) {
      this.serverReader.close();
    }

    if (this.serverProcess && !this.serverProcess.killed) {
      try {
        this.serverProcess.kill('SIGTERM');
      } catch {}
    }

    if (this.auditLogger) {
      this.auditLogger.close();
    }

    this.emit('stopped', exitCode);
  }
}

module.exports = {
  SentinelProxy
};
