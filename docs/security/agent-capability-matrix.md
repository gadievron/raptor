# Agent Capability Matrix

Generated 2026-04-22. Anti-prompt-injection initiative, Commit 3 audit.

## Summary

- **Total agents**: 16
- **floor-safe**: 1
- **tight**: 2
- **needs-tightening**: 9
- **needs-HITL**: 4

---

## Matrix

| Agent | Tools | Reads Untrusted (A) | Sensitive Access (B) | External State (C) | RoT count | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| coverage-analyzer | all tools (default) | YES | YES | NO | 2 | needs-tightening |
| crash-analysis-agent | Read, Write, Edit, Bash, Grep, Glob, WebFetch, WebSearch, Git, Task | YES | YES | YES | 3 | needs-HITL |
| crash-analyzer | all tools (default) | YES | YES | NO | 2 | needs-tightening |
| crash-analyzer-checker | all tools (default) | YES | YES | NO | 2 | needs-tightening |
| exploitability-validator-agent | Read, Write, Edit, Bash, Grep, Glob, Task | YES | YES | NO | 2 | needs-tightening |
| function-trace-generator | all tools (default) | YES | YES | NO | 2 | needs-tightening |
| offsec-specialist | all tools (default) | YES | YES | YES | 3 | needs-HITL |
| oss-evidence-verifier-agent | Read, Write, Bash | YES | YES | NO | 2 | needs-tightening |
| oss-hypothesis-checker-agent | Read, Write | NO | NO | NO | 0 | tight |
| oss-hypothesis-former-agent | Read, Write | YES | NO | NO | 1 | floor-safe |
| oss-investigator-gh-archive-agent | Bash, Read, Write | YES | YES | YES | 3 | needs-HITL |
| oss-investigator-github-agent | Bash, Read, Write, WebFetch | YES | YES | YES | 3 | needs-HITL |
| oss-investigator-ioc-extractor-agent | Read, Write, WebFetch | YES | YES | NO | 2 | needs-tightening |
| oss-investigator-local-git-agent | Bash, Read, Write, Glob, Grep | YES | YES | NO | 2 | needs-tightening |
| oss-investigator-wayback-agent | Bash, Read, Write, WebFetch | YES | YES | NO | 2 | needs-tightening |
| oss-report-generator-agent | Read, Write | NO | NO | NO | 0 | tight |

---

## Per-agent notes

### coverage-analyzer
- **Purpose**: Generate gcov coverage data for C/C++ code repository
- **A=YES** because: Reads and executes crashing example programs supplied as input (untrusted source)
- **B=YES** because: Implicit unrestricted Bash access for building, compiling, and running target binaries
- **Verdict**: needs-tightening — Purpose is data collection only (analysis-focused). Should restrict to Read-only for code inspection and Bash limited to build commands (no execution of untrusted binaries). Currently allows execution of untrusted crash inputs.

### crash-analysis-agent
- **Purpose**: Analyze security bugs from C/C++ projects with full root-cause tracing
- **A=YES** because: Reads bug tracker URLs, crash logs, attached test files, ASAN output, and untrusted reproduction steps
- **B=YES** because: Write, Edit, Bash, WebFetch, WebSearch, Git, Task — full suite of sensitive tools
- **C=YES** because: Uses WebFetch/WebSearch to reach external bug tracker systems; orchestrates other agents via Task
- **Verdict**: needs-HITL — Rule of Two ≥ 2 (A+B+C all YES). This is an orchestrator that reads untrusted crash data AND has full write/network access AND can delegate to other agents. Requires human approval gate before execution.

### crash-analyzer
- **Purpose**: Root-cause analysis using rr recordings, function traces, and coverage data
- **A=YES** because: Analyzes crash traces, rr output, function traces, and gcov data generated from untrusted crashing inputs
- **B=YES** because: Implicit unrestricted Bash (needed to run rr replay, set breakpoints, evaluate debugger output). Agent documentation shows rr command execution.
- **Verdict**: needs-tightening — Purpose is analysis-only on pre-generated data; no write tools documented needed. Recommend dropping Bash access and instead providing structured rr/gcov output via read-only interface. Write-up generation should use a separate pure-analysis agent without shell.

### crash-analyzer-checker
- **Purpose**: Validate root-cause analysis reports for correctness against empirical data
- **A=YES** because: Reads root-cause hypothesis and validates against rr recordings, function traces, coverage data (all from untrusted crash inputs)
- **B=YES** because: Implicit unrestricted Bash for running grep checks and validating hypothesis content (see mechanical format check directives)
- **Verdict**: needs-tightening — Checker agent consuming untrusted input data. Mechanical format checks (grep patterns, file counting) should be pre-computed by callers, not done via Bash. Recommend: drop Bash, accept pre-validated structured format flags in input.

### exploitability-validator-agent
- **Purpose**: Multi-stage pipeline validating vulnerability findings are real, reachable, and exploitable
- **A=YES** because: Analyzes target code from user-supplied target_path; executes PoCs against untrusted code
- **B=YES** because: Write, Edit, Bash, Grep, Glob — can write artifacts, run arbitrary processes on target
- **Verdict**: needs-tightening — Reads untrusted code while having write+bash. Bash execution on target code is required, but Write should be restricted to `.out/exploitability-validation-*/` working directory only. Recommend: ensure Write tool restricted to sandboxed workdir, document scope of Bash (PoC only, no shell escapes).

### function-trace-generator
- **Purpose**: Generate function-level execution traces for debugging and analysis
- **A=YES** because: Builds and executes crashing example programs supplied as input (untrusted source code and binary inputs)
- **B=YES** because: Implicit unrestricted Bash for building instrumentation library, compiling target with flags, executing target program
- **Verdict**: needs-tightening — Purpose is instrumentation/tracing, not write analysis. Execution of untrusted binaries is necessary, but no Write/Edit tools needed for core function. Recommend: keep Bash for build+execute, drop Write/Edit if not explicitly required for trace file management.

### offsec-specialist
- **Purpose**: Offensive security operations, penetration testing, vulnerability research, exploit development
- **A=YES** because: Analyzes security-sensitive code and applications (untrusted targets)
- **B=YES** because: Full toolkit with all offensive security skills, implicitly Bash, can load arbitrary skills
- **C=YES** because: Documentation explicitly states "exploitation" operations, "system modification", potential external service modifications
- **Verdict**: needs-HITL — Rule of Two ≥ 2 (A+B+C all YES). Dangerous operations acknowledged in docstring ("ASK FIRST" for exploitation), but no enforcement mechanism visible. Requires human approval gate. Consider: split into safe-mode (enumeration/analysis) and dangerous-mode (actual exploitation requiring explicit approval).

### oss-evidence-verifier-agent
- **Purpose**: Verify forensic evidence against original sources (GH Archive, GitHub API, Wayback, local git)
- **A=YES** because: Reads evidence that may originate from untrusted GitHub repositories, Wayback snapshots, GH Archive user-generated events
- **B=YES** because: Bash for re-querying sources, reading verification reports
- **Verdict**: needs-tightening — Verifier consuming untrusted evidence. Bash should be restricted to structured verification queries only (no arbitrary shell commands). Recommend: drop Bash, use only github-evidence-kit skill with pre-defined verify_all() method.

### oss-hypothesis-checker-agent
- **Purpose**: Validate hypothesis claims against verified evidence
- **A=NO** because: Only reads already-verified evidence (verified by earlier stage) and hypothesis; does not consume raw untrusted data
- **B=NO** because: Only Read, Write tools; no Bash, no network
- **C=NO** because: Local analysis only
- **Verdict**: tight — Properly constrained checker consuming only structured outputs from earlier pipeline stages. No changes needed.

### oss-hypothesis-former-agent
- **Purpose**: Form evidence-backed hypotheses for forensic investigations
- **A=YES** because: Reads evidence.json that may contain untrusted content from GitHub, Wayback, GH Archive, git sources
- **B=NO** because: Only Read, Write; no Bash, no network
- **C=NO** because: Local analysis only
- **Verdict**: floor-safe — Reads untrusted evidence but has no dangerous tools (no Bash, no network, no write to sensitive locations). Envelope constraints + slot discipline sufficient. Model-independent defences adequate.

### oss-investigator-gh-archive-agent
- **Purpose**: Query GH Archive via BigQuery for tamper-proof forensic evidence
- **A=YES** because: Reads GH Archive data which contains untrusted GitHub event metadata (user logins, commit messages, payload JSON from untrusted repos)
- **B=YES** because: Bash for BigQuery Python client execution, file I/O
- **C=YES** because: Reaches external BigQuery service; could be exploited to exfiltrate data to attacker-controlled BigQuery service via prompt injection in repo names/commit messages
- **Verdict**: needs-HITL — Rule of Two ≥ 2 (A+B+C all YES). Network-reaching agent (BigQuery API) reading untrusted GitHub metadata. Vulnerability: if a malicious repo name or commit message is injected into the query via prompt, agent could be tricked into querying attacker's BigQuery project or exfiltrating results. Recommend: restrict Bash to read-only queries, validate all user input (repo names, actors) as SQL identifiers before passing to BigQuery.

### oss-investigator-github-agent
- **Purpose**: Query GitHub API for repository state, commits, deleted content recovery
- **A=YES** because: Reads GitHub API responses containing untrusted repository data (commit messages, PR descriptions, issue bodies, user names)
- **B=YES** because: WebFetch for GitHub API and commit recovery; Bash for curl/authentication
- **C=YES** because: Reaches external GitHub API; could exfiltrate data to attacker-controlled hosts via prompt injection in commit messages/issue bodies
- **Verdict**: needs-HITL — Rule of Two ≥ 2 (A+B+C all YES). Network-reaching agent reading untrusted GitHub content. Vulnerability: if a malicious URL is injected into a commit message or issue body, agent's WebFetch could be redirected to attacker host. Recommend: restrict WebFetch to github.com domain only, validate all URLs extracted from GitHub data before fetching.

### oss-investigator-ioc-extractor-agent
- **Purpose**: Extract IOCs from vendor security reports
- **A=YES** because: Reads vendor security reports (external source, may be compromised or contain malicious content)
- **B=YES** because: WebFetch for reaching vendor report URLs
- **Verdict**: needs-tightening — Reads untrusted vendor reports while having unrestricted WebFetch. Vulnerability: if user input (vendor report URL) is not validated, agent could fetch from arbitrary URLs. Recommend: restrict WebFetch to known trusted vendor domains only (e.g., allowlist: [microsoft.com, google.com, apple.com, etc.]), validate vendor URLs before fetching.

### oss-investigator-local-git-agent
- **Purpose**: Analyze cloned repositories for dangling commits and git forensics
- **A=YES** because: Clones and analyzes untrusted git repositories (commit messages, author metadata, reflog can contain arbitrary text)
- **B=YES** because: Bash for git commands (git clone, git fsck, git show); risk: git hooks in cloned repos could execute arbitrary code
- **Verdict**: needs-tightening — Executes git on untrusted repos. Vulnerability: git hooks (pre-commit, post-checkout, etc.) in malicious repos can execute arbitrary code when repo is cloned or checked out. Recommend: clone with `--no-checkout` or `--bare`, use git fsck/show without triggering hooks, or restrict to read-only git config (`git config core.hooksPath /dev/null`).

### oss-investigator-wayback-agent
- **Purpose**: Recover deleted content from Wayback Machine
- **A=YES** because: Reads Wayback snapshots (may contain untrusted user-generated content from deleted GitHub repos/issues)
- **B=YES** because: WebFetch for Wayback API and CDX queries; Bash for curl
- **Verdict**: needs-tightening — Reads untrusted Wayback snapshots (user content) while having unrestricted network access. Recommend: restrict WebFetch to web.archive.org domain only, validate all URLs before fetching from Wayback.

### oss-report-generator-agent
- **Purpose**: Generate final forensic report from confirmed hypothesis and evidence
- **A=NO** because: Only reads already-confirmed hypothesis (validated by checker) and verified evidence (marked as verified)
- **B=NO** because: Only Read, Write; no Bash, no network
- **C=NO** because: Local report generation only
- **Verdict**: tight — Report generator consuming only validated inputs from earlier pipeline. No over-permissions; no changes needed.

---

## Recommendations

Sorted by priority:

### CRITICAL (Rule of Two ≥ 2, requires immediate action)

1. **crash-analysis-agent** (needs-HITL)
   - **Action**: Add human approval gate before execution
   - **Rationale**: Reads untrusted crash data + has write/network access + orchestrates other agents (Rule of Two = 3)
   - **Implementation**: Require explicit user/admin approval before this agent is spawned; add confirmation prompt in orchestrator

2. **oss-investigator-gh-archive-agent** (needs-HITL)
   - **Action**: Restrict Bash to read-only BigQuery queries; validate repo names/actor names as SQL identifiers before constructing queries
   - **Rationale**: Network-reaching agent reading untrusted GitHub metadata. Exploit vector: prompt injection in repo name → exfiltration to attacker BigQuery
   - **Implementation**: Use parameterized BigQuery queries (placeholders), never interpolate user input directly; restrict Bash to documented query patterns only

3. **oss-investigator-github-agent** (needs-HITL)
   - **Action**: Restrict WebFetch domain to github.com only; validate all URLs extracted from GitHub data before WebFetch
   - **Rationale**: Network-reaching agent reading untrusted GitHub content. Exploit vector: malicious URL in commit message → redirect to attacker host via WebFetch
   - **Implementation**: Add domain allowlist check in WebFetch, validate URLs against allowlist before execution

4. **offsec-specialist** (needs-HITL)
   - **Action**: Implement enforcement of "ASK FIRST" gate for dangerous operations; split into safe (scanning) and dangerous (exploitation) modes
   - **Rationale**: Full toolkit with implicit write/network/bash access, can perform actual modifications
   - **Implementation**: Add explicit approval requirement in documentation; consider creating two agent modes: `offsec-specialist-safe` (enumeration/analysis) and `offsec-specialist-exploit` (requires approval)

### HIGH PRIORITY (Rule of Two = 2, over-permissive vs purpose)

5. **crash-analyzer** (needs-tightening)
   - **Action**: Drop unrestricted Bash; provide structured rr/gcov outputs as read-only files
   - **Rationale**: Analysis-only purpose, but has Bash for running debugger commands. Recommend: pre-compute rr output, pass as structured data
   - **Implementation**: Have crash-analysis-agent prepare rr output as JSON, pass to crash-analyzer which reads JSON only (no shell)

6. **crash-analyzer-checker** (needs-tightening)
   - **Action**: Drop Bash; have callers pre-compute format validation flags
   - **Rationale**: Checker consuming untrusted data. Mechanical format checks should not require shell access.
   - **Implementation**: Require input to include format validation metadata; checker only reads structured input

7. **exploitability-validator-agent** (needs-tightening)
   - **Action**: Restrict Write to `.out/exploitability-validation-*/` working directory only; document Bash scope
   - **Rationale**: Reads untrusted code while having write access. Currently no restriction noted.
   - **Implementation**: Configure Write tool with `cwd_restrict: .out/exploitability-validation` or similar; add Bash scope limits (PoC execution only, no shell escapes)

8. **oss-evidence-verifier-agent** (needs-tightening)
   - **Action**: Drop Bash; use github-evidence-kit verify_all() method only
   - **Rationale**: Verifier consuming untrusted evidence. Bash is over-permissive; skill already handles verification internally.
   - **Implementation**: Remove Bash from tools; rely on github-evidence-kit skill for all verification logic

9. **oss-investigator-ioc-extractor-agent** (needs-tightening)
   - **Action**: Restrict WebFetch domain to allowlist of known vendors
   - **Rationale**: Reads untrusted vendor reports. User-supplied URL could fetch from arbitrary source.
   - **Implementation**: Add domain allowlist (microsoft.com, google.com, apple.com, etc.); validate vendor URL before WebFetch

10. **oss-investigator-local-git-agent** (needs-tightening)
    - **Action**: Disable git hooks when cloning untrusted repos; use `--no-checkout` or `core.hooksPath=/dev/null`
    - **Rationale**: Bash executes git on untrusted repos. Exploit vector: git hooks can execute arbitrary code.
    - **Implementation**: Add `--no-checkout` to git clone command; set `git config core.hooksPath /dev/null` before cloning

11. **oss-investigator-wayback-agent** (needs-tightening)
    - **Action**: Restrict WebFetch domain to web.archive.org only
    - **Rationale**: Reads untrusted Wayback snapshots. Unrestricted WebFetch could fetch arbitrary URLs.
    - **Implementation**: Add domain allowlist for WebFetch (web.archive.org only)

### MEDIUM PRIORITY (Rule of Two = 2, less critical)

12. **coverage-analyzer** (needs-tightening)
    - **Action**: Restrict Bash to build-only commands; do NOT execute untrusted binaries
    - **Rationale**: Executes untrusted crash inputs. Analysis purpose doesn't require execution.
    - **Implementation**: Have function-trace-generator or crash-analysis-agent handle execution; coverage-analyzer only reads pre-collected traces

13. **function-trace-generator** (needs-tightening)
    - **Action**: Keep Bash (required for instrumentation); drop Write/Edit if not needed for trace file management
    - **Rationale**: Needs Bash to build/execute, but write tools may be over-permissive
    - **Implementation**: Confirm Write scope is traces/ subdirectory only; remove Edit if not used

---

## High-Risk Agents Summary

**Top 3 by severity:**

1. **crash-analysis-agent** (Rule of Two = 3)
   - Orchestrates crash analysis pipeline; reads untrusted crash data + has full write/network access
   - Could be exploited to exfiltrate crash analysis artifacts or modify hypothesis files
   - **Risk**: Prompt injection in crash log attachment → command execution via WebFetch/WebSearch

2. **oss-investigator-github-agent** (Rule of Two = 3)
   - Reads untrusted GitHub metadata + reaches GitHub API + has WebFetch
   - Commit messages/issue bodies could contain malicious URLs → redirect attacks
   - **Risk**: Prompt injection in commit message → arbitrary URL fetch via WebFetch → data exfiltration

3. **oss-investigator-gh-archive-agent** (Rule of Two = 3)
   - Reads untrusted GitHub metadata from BigQuery + Bash access
   - Repo names could contain SQL injection payloads; could exfiltrate to attacker BigQuery
   - **Risk**: Prompt injection in repo name → SQL injection in BigQuery query → data exfiltration to attacker account

---

## Critical Observations

**Pattern 1: Untrusted readers with write tools**
- crash-analysis-agent, exploitability-validator-agent both read untrusted input and have Write/Edit
- Recommendation: use Write only for working directory artifacts; never write untrusted input to shared locations

**Pattern 2: Checker/aggregator agents consuming raw untrusted data**
- crash-analyzer-checker reads untrusted crash hypothesis + empirical data; should consume only validated hypothesis
- oss-evidence-verifier reads untrusted evidence; should consume only verified evidence
- Recommendation: pipeline should validate data before passing to checker agents

**Pattern 3: Network-reaching agents without domain restriction**
- oss-investigator-github-agent, oss-investigator-wayback-agent, oss-investigator-ioc-extractor-agent all have WebFetch
- None have domain whitelisting visible in definitions
- Recommendation: add domain allowlist to all WebFetch tools (github.com, web.archive.org, etc.)

**Pattern 4: Default "all tools" agents**
- coverage-analyzer, crash-analyzer, crash-analyzer-checker, function-trace-generator, offsec-specialist all default to all tools
- No documented tool scope limitation
- Recommendation: explicitly specify tool list for each agent; never rely on defaults

