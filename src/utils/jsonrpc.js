'use strict';

/**
 * Standard JSON-RPC 2.0 error codes and helper utilities
 */
const ErrorCodes = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,

  // Custom MCP Sentinel security codes (-32000 to -32099 reserved for implementation-defined)
  SECURITY_BLOCKED: -32001,
  RATE_LIMIT_EXCEEDED: -32002,
  EXECUTION_TIMEOUT: -32003,
  TOOL_NOT_ALLOWED: -32004,
  SCHEMA_DRIFT_DETECTED: -32005
};

/**
 * Formats a successful JSON-RPC response
 */
function createResponse(id, result) {
  return {
    jsonrpc: '2.0',
    id,
    result
  };
}

/**
 * Formats a standard JSON-RPC error response
 */
function createErrorResponse(id, code, message, data = null) {
  const errorObj = { code, message };
  if (data !== null && data !== undefined) {
    errorObj.data = data;
  }
  return {
    jsonrpc: '2.0',
    id: id !== undefined ? id : null,
    error: errorObj
  };
}

/**
 * Formats an MCP Tool call error block (which MCP clients like Claude/Cursor expect inside tool results or error)
 */
function createToolBlockedResponse(id, reason, details = {}) {
  return {
    jsonrpc: '2.0',
    id,
    result: {
      content: [
        {
          type: 'text',
          text: `[MCP-SENTINEL BLOCKED]: ${reason}`
        }
      ],
      isError: true,
      _sentinel: {
        verdict: 'BLOCKED',
        timestamp: new Date().toISOString(),
        details
      }
    }
  };
}

/**
 * Checks message type
 */
function parseMessage(raw) {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return null;

  try {
    const msg = JSON.parse(trimmed);
    return msg;
  } catch {
    return null;
  }
}

function isRequest(msg) {
  return msg && typeof msg === 'object' && msg.jsonrpc === '2.0' && typeof msg.method === 'string' && msg.id !== undefined;
}

function isNotification(msg) {
  return msg && typeof msg === 'object' && msg.jsonrpc === '2.0' && typeof msg.method === 'string' && msg.id === undefined;
}

function isResponse(msg) {
  return msg && typeof msg === 'object' && msg.jsonrpc === '2.0' && msg.id !== undefined && ('result' in msg || 'error' in msg);
}

module.exports = {
  ErrorCodes,
  createResponse,
  createErrorResponse,
  createToolBlockedResponse,
  parseMessage,
  isRequest,
  isNotification,
  isResponse
};
