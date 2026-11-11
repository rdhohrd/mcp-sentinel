'use strict';

const { SentinelProxy } = require('./proxy');
const { PathGuard, SENSITIVE_PATH_PATTERNS } = require('./guards/path-guard');
const { ExecGuard, DANGEROUS_COMMAND_PATTERNS } = require('./guards/exec-guard');
const { SecretGuard, SECRET_DETECTORS, calculateShannonEntropy } = require('./guards/secret-guard');
const { ToolFilter, matchGlob } = require('./guards/tool-filter');
const { RateLimiter } = require('./guards/rate-limiter');
const { CircuitBreaker } = require('./guards/circuit-breaker');
const { AuditLogger } = require('./audit/audit-logger');
const { ConfigLoader, PRESETS } = require('./config');
const { ErrorCodes, createResponse, createErrorResponse, createToolBlockedResponse } = require('./utils/jsonrpc');
const { logger, Logger, colorize } = require('./utils/logger');

module.exports = {
  SentinelProxy,
  PathGuard,
  SENSITIVE_PATH_PATTERNS,
  ExecGuard,
  DANGEROUS_COMMAND_PATTERNS,
  SecretGuard,
  SECRET_DETECTORS,
  calculateShannonEntropy,
  ToolFilter,
  matchGlob,
  RateLimiter,
  CircuitBreaker,
  AuditLogger,
  ConfigLoader,
  PRESETS,
  ErrorCodes,
  createResponse,
  createErrorResponse,
  createToolBlockedResponse,
  logger,
  Logger,
  colorize
};
