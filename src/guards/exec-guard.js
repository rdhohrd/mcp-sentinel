'use strict';

// High-risk command patterns (OWASP Agentic Security / CWE-78)
const DANGEROUS_COMMAND_PATTERNS = [
  // Destructive file deletion
  { regex: /\brm\s+(-[a-zA-Z0-9-]*r[a-zA-Z0-9-]*f|-[a-zA-Z0-9-]*f[a-zA-Z0-9-]*r)\s+(?:[/~]|\/\*|\$HOME)(?:\s|$)/i, name: 'Destructive recursive root/home deletion (rm -rf /)' },
  { regex: /\brm\s+-[a-zA-Z0-9-]*r[a-zA-Z0-9-]*\s+(?:[/~]|\/\*|\$HOME)(?:\s|$)/i, name: 'Recursive system directory wipe' },
  { regex: /\brm\s+-[a-zA-Z0-9-]*r[a-zA-Z0-9-]*\s+--no-preserve-root\b/i, name: 'Explicit unpreserved root deletion' },
  
  // Storage & raw device wiping
  { regex: /\bdd\s+if=.*of=\/dev\/(sd[a-z]|nvme|vd[a-z]|hd[a-z]|disk)/i, name: 'Raw disk wipe (dd of=/dev/)' },
  { regex: /\bmkfs(\.[a-z0-9]+)?\s+\/dev\//i, name: 'Filesystem format (mkfs /dev/)' },

  // Fork bombs
  { regex: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/i, name: 'Classic shell fork bomb' },

  // System halt/reboot
  { regex: /\b(shutdown|reboot|poweroff|halt)\b(\s+-h|\s+-r|\s+now)?/i, name: 'System shutdown/halt command' },

  // Reverse shells
  { regex: /\b(nc|ncat|netcat)\s+.*-[a-zA-Z]*e\s+/i, name: 'Netcat executable reverse shell (nc -e)' },
  { regex: /\/dev\/(tcp|udp)\/[0-9a-zA-Z._-]+\/[0-9]+/i, name: 'Direct bash socket redirection (/dev/tcp)' },
  { regex: /python[0-9.]*\s+-c\s+['"].*socket.*pty\.spawn/i, name: 'Python PTY reverse shell' },
  { regex: /perl\s+-e\s+['"].*Socket.*exec/i, name: 'Perl reverse shell' },

  // Download-to-shell execution
  { regex: /\b(curl|wget|fetch)\b.*\|\s*(ba|z|k|t)?sh\b/i, name: 'Download pipe to shell execution (curl | sh)' },
  { regex: /powershell(\.exe)?\s+(-(enc|encodedcommand)|-[a-zA-Z]*e)\s+[a-zA-Z0-9+/=]{10,}/i, name: 'Encoded PowerShell payload' },

  // Dangerous permissions
  { regex: /\bchmod\s+(-[a-zA-Z]*R)?\s*(777|0777|a\+rwx)\s+([/~]|\/etc|\/usr|\/bin|\/sbin)/i, name: 'Global permission wipe (chmod 777 system directories)' },
  { regex: /\bchown\s+(-[a-zA-Z]*R)?\s+root\s+/i, name: 'Privileged user reassignment (chown root)' }
];

class ExecGuard {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.allowedCommands = options.allowedCommands || []; // e.g. ['git', 'npm', 'node', 'ls']
    this.blockedCommands = options.blockedCommands || ['sudo', 'su', 'doas', 'pkexec'];
    this.allowSudo = options.allowSudo === true;
    this.customPatterns = (options.customPatterns || []).map(p => ({
      regex: new RegExp(p.pattern, p.flags || 'i'),
      name: p.name || 'Custom security policy'
    }));
  }

  /**
   * Inspects a command line string for malicious signatures
   */
  inspectCommand(commandStr) {
    if (!this.enabled || typeof commandStr !== 'string') {
      return { allowed: true };
    }

    const trimmed = commandStr.trim();
    if (!trimmed) return { allowed: true };

    // Check sudo/privilege escalation if blocked
    if (!this.allowSudo) {
      if (/^\s*(sudo|su|doas|pkexec)\b/.test(trimmed) || /\b(sudo|su|doas|pkexec)\s+/.test(trimmed)) {
        return {
          allowed: false,
          reason: 'Privileged execution (sudo/su) is strictly forbidden by policy (CWE-250)'
        };
      }
    }

    // Check dangerous patterns
    for (const rule of [...DANGEROUS_COMMAND_PATTERNS, ...this.customPatterns]) {
      if (rule.regex.test(trimmed)) {
        return {
          allowed: false,
          reason: `Blocked dangerous command pattern: "${rule.name}" (CWE-78)`
        };
      }
    }

    // Check blocked command binaries
    for (const blocked of this.blockedCommands) {
      const regex = new RegExp(`(^|[\\s;|&])${blocked}\\b`, 'i');
      if (regex.test(trimmed)) {
        return {
          allowed: false,
          reason: `Command binary "${blocked}" is explicitly disallowed by policy`
        };
      }
    }

    // If allowedCommands list is populated, ensure command begins with an allowed binary
    if (this.allowedCommands.length > 0) {
      // Extract binary name from start
      const match = trimmed.match(/^([a-zA-Z0-9._-]+)/);
      if (match) {
        const bin = match[1];
        const isAllowed = this.allowedCommands.some(allowed => allowed === bin || bin.endsWith('/' + allowed));
        if (!isAllowed) {
          return {
            allowed: false,
            reason: `Command "${bin}" is not in the allowed commands whitelist: [${this.allowedCommands.join(', ')}]`
          };
        }
      }
    }

    return { allowed: true };
  }

  /**
   * Inspects tool arguments for command execution tools (e.g. bash, terminal, run_command)
   */
  inspectToolArguments(toolName, args) {
    if (!this.enabled || !args || typeof args !== 'object') {
      return { allowed: true };
    }

    const isExecTool = /^(execute|exec|run|terminal|bash|sh|cmd|command|shell)/i.test(toolName);
    const execKeys = /(command|cmd|script|code|shell_command|input)/i;

    for (const [key, val] of Object.entries(args)) {
      if (typeof val === 'string') {
        if (isExecTool || execKeys.test(key)) {
          const res = this.inspectCommand(val);
          if (!res.allowed) return res;
        }
      }
    }

    return { allowed: true };
  }
}

module.exports = {
  ExecGuard,
  DANGEROUS_COMMAND_PATTERNS
};
