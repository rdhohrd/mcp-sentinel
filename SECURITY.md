# Security Policy

## Threat Model & Security Posture

**MCP Sentinel** is designed as a defense-in-depth security firewall and sandbox proxy that operates at the protocol boundary (JSON-RPC 2.0 stdio / SSE) between LLM Agent Clients (e.g., Claude Desktop, Cursor, Hermes, Cline) and Model Context Protocol (MCP) servers.

### Mapped Threat Defenses (OWASP Agentic Security Top 10)

| Risk Category | Threat Vector | MCP Sentinel Defense |
| :--- | :--- | :--- |
| **Path Traversal (CWE-22)** | Agent tricked into reading `/etc/shadow`, `~/.ssh/id_rsa`, or `.env` via `../../` climbing | **PathGuard** enforces canonical root jail, normalizes URL/unicode encodings, rejects poison null bytes, and blocks sensitive system files. |
| **Command Injection (CWE-78)** | Indirect prompt injection executing `rm -rf /`, reverse shells (`nc -e`, `/dev/tcp`), or fork bombs | **ExecGuard** scans command trees for destructive commands, forbids unauthorized shell metacharacters, and blocks privilege escalation (`sudo`/`su`). |
| **Credential Exfiltration (CWE-200)** | Agent accidentally or maliciously returning API keys, tokens, or private keys to the LLM | **SecretGuard (DLP)** performs bi-directional redaction for AWS, GitHub, OpenAI, Anthropic, Slack, Stripe, and private keys. |
| **Denial of Service / Loop Drain** | Infinite looping agent draining token balance or hammering upstream endpoints | **RateLimiter** enforces global and per-tool token-bucket rate limits. |
| **Hanging Process Block** | Unresponsive tool blocking the agent indefinitely | **CircuitBreaker** terminates hanging requests upon configurable timeout and opens circuit upon repeated server failures. |
| **Audit Log Tampering** | Attacker or rogue process deleting or editing forensic trails post-incident | **AuditLogger** generates a cryptographically linked SHA-256 HMAC hash chain with sequence tracking. |

---

## Supply-Chain Security Guarantee

MCP Sentinel is authored with **zero runtime external dependencies**. It relies entirely on standard Node.js built-in APIs (`node:child_process`, `node:readline`, `node:crypto`, `node:path`, `node:fs`, `node:test`).

This architectural guarantee completely eliminates:
- Third-party npm dependency vulnerabilities
- Malicious package typosquatting
- Post-install script backdoors
- Upstream prototype pollution

---

## Reporting a Vulnerability

If you discover a security vulnerability within MCP Sentinel, please report it privately:

1. Open a confidential GitHub Security Advisory on the repository: https://github.com/rdhohrd/mcp-sentinel/security/advisories/new
2. Or contact the maintainer directly at: `rdhohrd@users.noreply.github.com`

Please include:
- A clear description of the vulnerability and attack vector
- Reproduction steps or proof-of-concept JSON-RPC payload
- Expected vs actual behavior

Vulnerabilities are typically triaged within 24 hours.
