# Contributing to MCP Sentinel

Thank you for your interest in contributing to **MCP Sentinel**! We welcome contributions from developers, security researchers, and AI engineers.

## Core Tenet: Zero Dependencies

MCP Sentinel is committed to maintaining **zero external npm runtime dependencies**. All features must be implemented using modern Node.js standard library APIs (`node:*`). This ensures maximal portability, auditability, and supply-chain safety.

---

## Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/rdhohrd/mcp-sentinel.git
   cd mcp-sentinel
   ```

2. **Run tests:**
   Node.js 18+ includes the native test runner. No dependencies to install:
   ```bash
   npm test
   ```

3. **Run microsecond latency benchmark:**
   ```bash
   npm run benchmark
   ```

4. **Test the CLI locally:**
   ```bash
   ./bin/mcp-sentinel.js --help
   ```

---

## Submitting Pull Requests

1. **Create a topic branch:**
   ```bash
   git checkout -b feat/your-feature-name
   ```

2. **Write unit tests:**
   Every new guard, regex pattern, or protocol modification must include automated tests in `test/*.test.js`.

3. **Adhere to Conventional Commits:**
   - `feat: add Google Cloud key detector to SecretGuard`
   - `fix: prevent traversal bypass with multiple forward slashes`
   - `docs: update Claude Desktop configuration instructions`
   - `test: add edge cases for circuit breaker transitions`

4. **Ensure 100% test pass rate:**
   ```bash
   npm test
   ```

5. **Open a Pull Request:**
   Submit your PR with a concise description of what problem it solves.
