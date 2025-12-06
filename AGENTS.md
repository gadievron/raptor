# RAPTOR - Autonomous Offensive/Defensive Research Framework

Safe operations (install, scan, read, generate): DO IT.
Dangerous operations (apply patches, delete, git push): ASK FIRST.

---

## SESSION START

**On first message:**
1. Display the RAPTOR banner (from `raptor-offset`)
2. Display a random quote from `hackers-8ball`
3. Display: `Check the readme for dependencies before starting | Quick commands: /analyze, /agentic | Try with: /test/data`
4. Display: `For defensive security research, education, and authorized penetration testing.`
5. Display: `raptor:~$` followed by the selected quote

---

## OPERATIONS

### Safe Operations (DO IT)
- Install dependencies
- Scan code for vulnerabilities
- Read files and analyze code
- Generate exploits and patches (saved to `out/` directory)
- Run tests
- Clone repositories (for analysis)

### Dangerous Operations (ASK FIRST)
- Apply patches to production code
- Delete files or directories
- Git push or force push
- Modify system configuration
- Execute potentially destructive commands

---

## COMMANDS

RAPTOR provides 15 commands accessible via Python CLI. See `.cursor/rules/command-usage.mdc` for complete documentation.

**Core Security Testing:**
- `/agentic` - Full autonomous workflow (Semgrep + CodeQL + LLM + exploits + patches)
- `/scan` / `/raptor-scan` - Quick Semgrep scan
- `/fuzz` / `/raptor-fuzz` - Binary fuzzing with AFL++
- `/web` / `/raptor-web` - Web application scanning
- `/codeql` - CodeQL-only analysis
- `/analyze` - LLM analysis of existing SARIF files

**Exploit/Patch Generation (beta):**
- `/exploit` - Generate exploit PoCs
- `/patch` - Generate secure patches

**Specialized Workflows:**
- `/crash-analysis` - Autonomous crash root-cause analysis (see below)
- `/oss-forensics` - OSS GitHub forensics (see below)

**Utilities:**
- `/create-skill` - Save custom approaches as reusable skills
- `/raptor` - General RAPTOR assistant
- `/test-workflows` - Test suite runner

---

## CRASH ANALYSIS

The crash analysis workflow provides autonomous root-cause analysis for C/C++ crashes.

**Usage:** `python3 raptor.py crash-analysis <bug-tracker-url> <git-repo-url>`

**Agents:**
- `crash-analysis-agent` - Main orchestrator
- `crash-analyzer-agent` - Deep root-cause analysis using rr traces
- `crash-analyzer-checker-agent` - Validates analysis rigorously
- `function-trace-generator-agent` - Creates function execution traces
- `coverage-analysis-generator-agent` - Generates gcov coverage data

**Skills** (in `.claude/skills/crash-analysis/`):
- `rr-debugger` - Deterministic record-replay debugging
- `function-tracing` - Function instrumentation with -finstrument-functions
- `gcov-coverage` - Code coverage collection
- `line-execution-checker` - Fast line execution queries

**Requirements:** rr, gcc/clang (with ASAN), gdb, gcov

**Workflow:** See `.cursor/rules/crash-analysis-workflow.mdc` for complete pipeline documentation.

---

## OSS FORENSICS

The OSS forensics workflow provides evidence-backed forensic investigation for public GitHub repositories.

**Usage:** `python3 raptor.py oss-forensics <prompt> [--max-followups 3] [--max-retries 3]`

**Agents:**
- `oss-forensics-agent` - Main orchestrator
- `oss-investigator-gh-archive-agent` - Queries GH Archive via BigQuery
- `oss-investigator-gh-api-agent` - Queries live GitHub API
- `oss-investigator-gh-recovery-agent` - Recovers deleted content (Wayback/commits)
- `oss-investigator-local-git-agent` - Analyzes cloned repos for dangling commits
- `oss-investigator-ioc-extractor-agent` - Extracts IOCs from vendor reports
- `oss-hypothesis-former-agent` - Forms evidence-backed hypotheses
- `oss-evidence-verifier-agent` - Verifies evidence via `store.verify_all()`
- `oss-hypothesis-checker-agent` - Validates claims against verified evidence
- `oss-report-generator-agent` - Produces final forensic report

**Skills** (in `.claude/skills/oss-forensics/`):
- `github-archive` - GH Archive BigQuery queries
- `github-evidence-kit` - Evidence collection, storage, verification
- `github-commit-recovery` - Recover deleted commits
- `github-wayback-recovery` - Recover content from Wayback Machine

**Requirements:** `GOOGLE_APPLICATION_CREDENTIALS` for BigQuery

**Output:** `.out/oss-forensics-<timestamp>/forensic-report.md`

**Workflow:** See `.cursor/rules/oss-forensics-workflow.mdc` for complete pipeline documentation.

---

## PROGRESSIVE LOADING

**When scan completes:** Reference `tiers/analysis-guidance.md` for adversarial thinking patterns
**When errors occur:** Reference `tiers/recovery.md` for recovery protocols
**When requested:** Reference `tiers/personas/[name].md` for expert personas

**Available Personas:**
- Security Researcher
- Exploit Developer
- Crash Analyst
- Patch Engineer
- Penetration Tester
- Fuzzing Strategist
- Binary Exploitation Specialist
- CodeQL Dataflow Analyst
- CodeQL Finding Analyst

**Usage:** "Use [persona name] to analyze this" or "Load security researcher persona"

---

## STRUCTURE

**Python orchestrates everything.** Cursor shows results concisely.
**Never circumvent Python execution flow.**

**Key Directories:**
- `packages/` - Modular security capabilities
- `core/` - Shared utilities (config, logging, progress, sarif parsing)
- `engine/` - Rules and queries (semgrep rules, codeql suites)
- `tiers/` - Progressive loading system (analysis-guidance, recovery, expert personas)
- `.claude/agents/` - Agent definitions (for Claude Code compatibility)
- `.claude/commands/` - Command definitions (for Claude Code compatibility)
- `.claude/skills/` - Skill definitions (for Claude Code compatibility)
- `.cursor/rules/` - Cursor Rules documentation

**Documentation:**
- `.cursor/rules/` - Comprehensive Cursor Rules for code patterns and architecture
- `docs/` - User-facing documentation
- `README.md` - Project overview and quick start

---

## WORKFLOW GUIDANCE

### Running Scans
1. Identify target (repository, binary, or web application)
2. Choose appropriate command (scan, fuzz, web, agentic, codeql)
3. Review output in `out/` directory
4. Analyze findings and generated exploits/patches

### Agent Workflows
- **Crash Analysis**: Use for C/C++ crash root-cause analysis with full instrumentation
- **OSS Forensics**: Use for evidence-backed GitHub security incident investigations
- See `.cursor/rules/agent-workflows.mdc` for orchestration patterns

### Code Patterns
- Follow patterns in `.cursor/rules/code-patterns.mdc`
- Use `RaptorConfig` for all configuration values
- Use `get_logger()` for all logging
- See `.cursor/rules/code-style.mdc` for conventions

---

## NOTES FOR CURSOR

This is a Cursor adaptation of the original RAPTOR framework designed for Claude Code.

**Key Differences:**
- Cursor doesn't support agent invocation via Task tool (agents are documented but not directly invocable)
- Slash commands work natively via `.cursor/commands/` directory - type `/` in chat to see available commands
- Commands execute Python CLI (`python3 raptor.py <mode>`) automatically when invoked
- `.cursor/rules/` provides comprehensive documentation for code generation and editing
- `AGENTS.md` (this file) provides session guidance similar to `CLAUDE.md`

**Slash Commands:**
- All 15 RAPTOR commands are available as slash commands in Cursor
- Commands are defined in `.cursor/commands/` directory
- Type `/` in Cursor chat to see the command menu
- Commands automatically parse arguments and execute the appropriate Python CLI

**Compatibility:**
- Original `.claude/` structure maintained for Claude Code compatibility
- `.cursor/rules/` added for Cursor IDE integration
- `.cursor/commands/` added for native Cursor slash command support
- All three systems can coexist in the same repository
