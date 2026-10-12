# AppSec MCP

> Source: Chaika plan `2026-10-12-to-create-an-mcp-to-secure-application-f`
> (`%USERPROFILE%\.chaika\plans\` on the developer's Windows laptop), copied verbatim.

## Problem
People who build apps with AI tools ("vibe coders") ship websites, apps and programs without knowing how to check them for security problems. Existing scanners such as Semgrep, gitleaks and OSV-Scanner are strong, but:
- they are CLI tools with technical output and assume security knowledge,
- they don't explain what they read or how they reached a result,
- they don't connect to the AI assistant the user already builds with,
- fixing what they find is left to the user.

## Target users
- **Primary:** non-security developers who built an app with AI tools (Claude Code, Cursor, Copilot) and use those tools every day.
- **Secondary:** students and hackathon teams who need a fast security pass before a demo or submission.
- **Tertiary:** experienced developers who want an auditable, scriptable security pass inside their AI workflow.

## The first-session "aha" moment
Inside their AI assistant, the user says *"scan my project for security problems."* Within about 2 minutes:
1. They get a plain-language list of real problems, ranked by severity. For example: *"Your Stripe key is hard-coded in `config.js` line 12. Anyone who sees your code can charge cards."*
2. They open a local map of their app that shows entry points, routes, secrets, dependencies and external calls, with the risky spots highlighted.
3. They accept one proposed fix (for example, moving the secret to `.env` and adding security headers) and see the finding disappear on re-scan.

## Core features
1. **Vulnerability detector.** *As a user, I want to find security bugs in my code without knowing security, so I can fix them before attackers find them.*
   - Static analysis for TypeScript/JavaScript, HTML, Java, Python and C/C++ (Semgrep rules)
   - Leaked-secret detection (gitleaks)
   - Vulnerable-dependency detection (OSV-Scanner: npm, PyPI, Maven, Conan/vcpkg where lockfiles exist)
   - Built-in config checks: debug mode on, CORS `*`, missing security headers, `.env` committed
   - Plain-language explanation per finding: what it is, why it matters, how to fix it
   - Optional passive header/TLS check of a deployed website URL the user owns
2. **System mapping.** *As a user, I want to see what my app is made of and exactly what the tool read and checked, so I can trust the result.*
   - App map: components, entry points, HTTP routes, data stores, external services, secrets locations, dependencies
   - Audit ledger: every file read (with hash), every file skipped and why, every rule applied, every scanner run
   - Local web viewer: findings, map graph, ledger
3. **Optional patching and hardening.** *As a user, I want the tool to fix problems or add a security layer for me, but only when I approve.*
   - `propose_patch` returns a unified diff and a plain-language summary. Nothing is written yet.
   - `apply_patch` requires the token from the proposal, backs up the original files, then writes
   - `revert_patch` restores the backups
   - Hardening recipes ("add a security layer"): security headers, rate limiting, secrets moved to env vars, CSRF and input validation scaffolding for Express, Next.js, Flask, FastAPI and Spring Boot

## Differentiators
- **Built for AI tools first.** It is an MCP server, so it works in Claude Code, Cursor, Claude Desktop and any MCP client. The AI can chain scan → explain → patch.
- **Transparent.** The audit ledger shows exactly what was read and detected, so it is not a black box.
- **Free and open source** (MIT). It builds on proven open-source scanners instead of reinventing them.
- **Plain language by default.** Technical detail is still available for experts.
- **Local-first.** Code never leaves the machine.

## Retention
- **Access:** it is already inside the assistant they use daily, so "scan again" costs nothing.
- **Re-scan diffing:** "3 fixed, 1 new since last scan" gives a sense of progress.
- **Security score per project** that trends over time in the viewer.
- **New rules and recipes** arrive with each release, and old projects get new findings.
- **Pre-deploy habit:** a one-line `appsec-mcp scan` for CI and git hooks.

## User flows
**Flow 1: Detect**
1. User installs: `pipx install appsec-mcp`, then adds one config snippet to their MCP client.
2. User tells the AI: "scan this project."
3. AI calls `scan_project(path)`. The server walks files, records the ledger, runs the available scanners and stores the results.
4. AI calls `get_findings(scan_id)` and shows them ranked by severity, with plain-language text.
5. User asks "what does finding 3 mean?" AI calls `explain_finding`.
6. If a scanner binary is missing, the result says what was skipped and how to install it.

**Flow 2: Map**
1. After a scan, the user asks "show me how my app is structured."
2. AI calls `get_system_map(scan_id)` and summarises it in text.
3. User runs `appsec-mcp view`, which opens `http://127.0.0.1:<port>/?token=…`.
4. The viewer shows the map graph with risky nodes highlighted. Clicking a node shows its files and findings.
5. The Ledger tab lists every file read or skipped and every rule applied.

**Flow 3: Patch / harden**
1. User says "fix the hard-coded secret" or "add a security layer."
2. AI calls `propose_patch(finding_id)` or `propose_hardening(scan_id, recipe)` and gets a diff, a summary and a `proposal_token`.
3. AI shows the diff. The user approves.
4. AI calls `apply_patch(proposal_token)`. The server checks the files haven't changed since the proposal, backs them up, then writes.
5. AI calls `scan_project` again, and the finding is marked fixed.
6. If something breaks, the user asks to revert. AI calls `revert_patch(patch_id)`.

**Flow 4: Check a live website (optional)**
1. User says "check my deployed site https://myapp.com."
2. AI calls `check_website(url)`. It sends passive GET/HEAD requests only and reports headers, TLS and cookie flags.

## Non-goals
- Active exploitation, fuzzing, brute force, or scanning sites the user doesn't own
- Reverse engineering of compiled binaries, APKs or IPAs (source code only)
- Cloud account or infrastructure posture scanning (AWS/GCP IAM)
- Replacing a professional penetration test or compliance audit
- A hosted SaaS version or user accounts
- Writing its own rule engine (we wrap Semgrep, gitleaks and OSV-Scanner)

## Success criteria
- First scan of a 5k-file repo finishes in under 2 minutes on a laptop.
- On the bundled vulnerable fixture apps, every planted vulnerability is detected (recall 100% on fixtures).
- Every finding has a plain-language explanation of 120 words or fewer.
- The ledger accounts for 100% of files under the scan root (read, or skipped with a reason).
- Applied patches can always be reverted to byte-identical originals.
- Installs and runs on Windows, macOS and Linux.
- A non-security user can complete Flows 1 and 3 without reading the docs (validated with 3 testers).

## Assumptions
- "Website, app, programs" means **source-code repositories**, plus an optional passive check of a deployed URL.
- The core is **Python** because the MCP Python SDK is mature and the scanners are subprocess calls. The viewer is **TypeScript + HTML**. **Java** and **C++** are scan targets, not implementation languages.
- External scanners (Semgrep OSS, gitleaks, OSV-Scanner) are installed separately. The tool degrades gracefully and gives install hints when one is missing.
- Plain-language explanations come from a curated template library, so no LLM call is needed inside the server. The calling AI can elaborate further.
- Results are stored in a local SQLite DB at `~/.appsec-mcp/appsec.db`.
- The license is MIT.
