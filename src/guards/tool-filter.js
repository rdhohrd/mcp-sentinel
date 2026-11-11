'use strict';

/**
 * Matches a tool name against a glob pattern (e.g. "read_*", "filesystem_*", "delete_file")
 */
function matchGlob(pattern, str) {
  if (pattern === '*' || pattern === str) return true;
  const regexPattern = '^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$';
  return new RegExp(regexPattern).test(str);
}

class ToolFilter {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.allowlist = options.allowlist || []; // e.g. ['read_*', 'list_*', 'search_*']
    this.denylist = options.denylist || [];   // e.g. ['delete_*', 'drop_*', 'execute_*', 'format_*']
    this.filterDiscovery = options.filterDiscovery !== false; // Whether to filter tools/list response
  }

  /**
   * Checks if a tool name is permitted under current policy
   */
  isToolAllowed(toolName) {
    if (!this.enabled || !toolName) return { allowed: true };

    // 1. Check denylist first
    for (const pattern of this.denylist) {
      if (matchGlob(pattern, toolName)) {
        return {
          allowed: false,
          reason: `Tool "${toolName}" matches denylist rule "${pattern}"`
        };
      }
    }

    // 2. If allowlist is defined, tool must match at least one allow pattern
    if (this.allowlist.length > 0) {
      const allowed = this.allowlist.some(pattern => matchGlob(pattern, toolName));
      if (!allowed) {
        return {
          allowed: false,
          reason: `Tool "${toolName}" is not in the configured allowlist: [${this.allowlist.join(', ')}]`
        };
      }
    }

    return { allowed: true };
  }

  /**
   * Filters the tools/list response from the server before forwarding to the client
   */
  filterToolsList(toolsListResponse) {
    if (!this.enabled || !this.filterDiscovery || !toolsListResponse || !toolsListResponse.result) {
      return toolsListResponse;
    }

    const originalTools = toolsListResponse.result.tools;
    if (!Array.isArray(originalTools)) {
      return toolsListResponse;
    }

    const filteredTools = originalTools.filter(tool => {
      const check = this.isToolAllowed(tool.name);
      return check.allowed;
    });

    return {
      ...toolsListResponse,
      result: {
        ...toolsListResponse.result,
        tools: filteredTools,
        _sentinel: {
          originalCount: originalTools.length,
          filteredCount: filteredTools.length,
          removedCount: originalTools.length - filteredTools.length
        }
      }
    };
  }
}

module.exports = {
  ToolFilter,
  matchGlob
};
