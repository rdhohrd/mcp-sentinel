<div align="center">

# 🛡️ MCP Sentinel

**Zero-dependency runtime security firewall and sandbox proxy for Model Context Protocol (MCP)**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js CI](https://img.shields.io/badge/Node.js-%3E%3D18.0.0-green.svg)](https://nodejs.org/)
[![Dependencies: 0](https://img.shields.io/badge/Dependencies-0%20(Pure%20Stdlib)-success.svg)](package.json)
[![Security: OWASP Mapped](https://img.shields.io/badge/Security-OWASP%20Agentic%20Top%2010-orange.svg)](SECURITY.md)
[![Tests: Passing](https://img.shields.io/badge/Tests-32%2F32%20Passing-brightgreen.svg)](test/)

*Protect your AI coding agents, desktop clients, and developers from malicious tool misuse, prompt injection, and credential exfiltration.*

[Quick Start](#-quick-start) • [Architecture](#-architecture) • [Security Guards](#-security-guards) • [Configuration](#-configuration-presets) • [Audit Verifier](#-tamper-evident-audit-log) • [Benchmarks](#-performance-benchmarks)

---

</div>

## 📌 The Problem

Autonomous AI coding agents (Claude Desktop, Cursor, Hermes, Cline, Roo Code) connect directly to local tools via **Model Context Protocol (MCP)** with unrestricted access to your filesystem, terminal shell, and remote APIs.

If an agent reads an untrusted webpage, repository README, or issue containing an **Indirect Prompt Injection**, it can be tricked into:
- 🚨 Running destructive shell commands (`rm -rf /`, formatting disks, spawning reverse shells)
- 🚨 Climbing directories (`../../etc/passwd`, `~/.ssh/id_rsa`, `.env`) via path traversal
- 🚨 Leaking API tokens, database connection strings, and private keys back to the model
- 🚨 Burning token balances and hammering APIs in runaway infinite loops

**MCP Sentinel** is a drop-in, zero-overhead firewall that sits between your AI client and any MCP server, intercepting and sanitizing every JSON-RPC 2.0 message in real-time.

---

## 🏛️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       AI CLIENT                             │
│       Claude Desktop • Cursor • Hermes • Cline • VS Code    │
└──────────────────────────────┬──────────────────────────────┘
                               │
                       stdio (JSON-RPC 2.0)
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                      MCP SENTINEL                           │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │  1. Tool Visibility & Capability Filter (tools/list)    │ │
│ │  2. Token-Bucket Rate Limiter (anti-loop protection)    │ │
│ │  3. Path Sandbox Guard (CWE-22 directory traversal)     │ │
│ │  4. Exec Guard (CWE-78 command injection & rev shells)  │ │
│ │  5. Secret Guard DLP (bi-directional credential scrub)  │ │
│ │  6. Circuit Breaker & Timeout Supervisor (<30s)         │ │
│ │  7. Tamper-Evident SHA-256 Hash-Chained Audit Trail     │ │
│ └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────┬──────────────────────────────┘
                               │
                       stdio (JSON-RPC 2.0)
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                      MCP SERVER                             │
│        @modelcontextprotocol/server-filesystem, etc.        │
└─────────────────────────────────────────────────────────────┘
```

---

## ✨ Features

- 🔒 **Path Sandboxing (CWE-22):** Enforces canonical directory boundaries (`allowedRoots`). Blocks directory traversal (`../`, URL encodings, null bytes) and isolates sensitive system paths (`.ssh`, `.aws`, `.env`, `/etc/passwd`).
- ⚡ **Command Injection Shield (CWE-78):** Neutralizes destructive terminal commands (`rm -rf`, disk wipes, fork bombs, `curl | sh`, `/dev/tcp` reverse shells, unauthorized `sudo`).
- 🔑 **Bi-Directional DLP & Secret Scrubbing (CWE-200):** Inspects outgoing tool arguments and incoming tool results. Automatically redacts AWS keys, GitHub tokens, OpenAI/Anthropic API keys, Slack tokens, Stripe keys, database passwords, and private RSA/SSH keys.
- 🚦 **Adaptive Rate Limiting:** Enforces global and per-tool token-bucket limits to prevent runaway loops from burning API credits.
- ⏱️ **Circuit Breaker & Execution Timeout:** Automatically terminates hanging tool calls after configurable deadlines and opens the circuit upon repeated server failures.
- 📜 **Cryptographically Verifiable Audit Trail:** Every JSON-RPC interaction is recorded in a hash-chained SHA-256 HMAC JSONL ledger with sequence tracking to detect post-incident tampering.
- 📦 **Zero External Dependencies:** 100% pure Node.js standard library (`node:child_process`, `node:readline`, `node:crypto`, `node:fs`). Complete immunity from npm supply-chain compromises.
- 🚀 **Microsecond Latency:** Adds less than **0.02ms** (~16 µs) overhead per tool call.

---

## 🚀 Quick Start

### 1. Claude Desktop Integration

Add `mcp-sentinel` as a wrapper command in your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-sentinel",
        "run",
        "--preset", "strict",
        "--root", "/Users/yourname/workspace",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/yourname/workspace"
      ]
    }
  }
}
```

### 2. Cursor IDE Integration

In your Cursor MCP configuration (`cursor_mcp.json`):

```json
{
  "mcpServers": {
    "terminal-safe": {
      "command": "mcp-sentinel",
      "args": [
        "run",
        "--preset", "standard",
        "--timeout", "15000",
        "--",
        "node",
        "./servers/terminal-mcp.js"
      ]
    }
  }
}
```

### 3. Hermes Agent Integration

In `hermes.yaml`:

```yaml
mcp_servers:
  secured_filesystem:
    command: "mcp-sentinel"
    args:
      - "run"
      - "--preset"
      - "strict"
      - "--root"
      - "/root/workspace"
      - "--"
      - "npx"
      - "-y"
      - "@modelcontextprotocol/server-filesystem"
      - "/root/workspace"
```

---

## ⚙️ Configuration & Presets

Generate a policy template:
```bash
mcp-sentinel init --preset standard --output sentinel.json
```

### Available Presets

| Preset | Filesystem Policy | Exec Policy | DLP Mode | Rate Limit | Timeout |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`standard`** *(default)* | Traversal blocked, sensitive files blocked | Destructive commands & `sudo` blocked | Redact secrets | 60 calls/min | 30s |
| **`strict`** | Locked strictly to configured root directory | Whitelisted binaries only | Redact secrets | 30 calls/min | 15s |
| **`read-only`** | Traversal blocked | All terminal execution blocked | Redact secrets | 60 calls/min | 20s |

### Custom Configuration (`sentinel.json`)

```json
{
  "pathGuard": {
    "enabled": true,
    "allowedRoots": ["./workspace", "./public"],
    "blockSensitiveFiles": true
  },
  "execGuard": {
    "enabled": true,
    "allowSudo": false,
    "allowedCommands": ["git", "npm", "node", "ls", "grep"],
    "blockedCommands": ["curl", "wget", "nc", "bash"]
  },
  "secretGuard": {
    "enabled": true,
    "mode": "redact"
  },
  "toolFilter": {
    "enabled": true,
    "allowlist": ["read_*", "list_*", "query_*"],
    "denylist": ["delete_*", "drop_*"]
  },
  "rateLimiter": {
    "enabled": true,
    "maxCallsPerMinute": 45,
    "toolOverrides": {
      "write_file": 10
    }
  },
  "circuitBreaker": {
    "enabled": true,
    "defaultTimeoutMs": 25000,
    "failureThreshold": 3
  },
  "audit": {
    "enabled": true,
    "logPath": "sentinel-audit.jsonl"
  }
}
```

Run with your custom policy:
```bash
mcp-sentinel run --config sentinel.json -- <your-mcp-server>
```

---

## 🔍 Tamper-Evident Audit Log

Every tool call and verdict is recorded with a **SHA-256 cryptographic hash chain** (`prev_hash` + payload):

```json
{"seq":1,"timestamp":"2026-11-11T12:00:00.000Z","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","payload":{"type":"TOOL_CALL","toolName":"read_file","verdict":"ALLOWED"},"hash":"a8f9c2..."}
{"seq":2,"timestamp":"2026-11-11T12:00:01.000Z","prev_hash":"a8f9c2...","payload":{"type":"TOOL_CALL","toolName":"exec","verdict":"BLOCKED","reason":"Destructive recursive root deletion (rm -rf /)"},"hash":"b3e10d..."}
```

Verify log integrity:
```bash
$ mcp-sentinel verify-audit sentinel-audit.jsonl

Verifying cryptographic audit chain: sentinel-audit.jsonl...
✔ VERIFIED: Verification successful: 48 records verified with intact cryptographic hash chain.
Chain head hash: 7e2b1fa9c0498...
```

If an attacker modifies or deletes a line in the log file, the hash chain breaks and identifies the exact line of tampering.

---

## ⚡ Performance Benchmarks

Run the built-in microsecond benchmark:
```bash
$ npm run benchmark

Running MCP Sentinel Microsecond Latency Benchmark...
Completed 10,000 full security pipeline inspections:
- Average latency:  15.91 µs (~0.016 ms)
- 50th percentile:  13.28 µs
- 95th percentile:  18.84 µs
- 99th percentile:  47.52 µs
✔ Overhead is virtually ZERO (<0.05ms per tool call)
```

---

## 🧪 Testing

Run the automated test suite (32 unit & end-to-end integration tests using Node.js native test runner):

```bash
npm test
```

---

## 📄 License

[MIT License](LICENSE) © 2026 [Ridho Herdyansah](https://github.com/rdhohrd)
