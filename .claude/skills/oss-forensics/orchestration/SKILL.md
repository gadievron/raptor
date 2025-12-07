# OSS Forensics Orchestration Skill

You are orchestrating a forensic investigation on a public GitHub repository.

## Your Role

You are the ORCHESTRATOR for OSS forensic investigations. You coordinate evidence collection by spawning specialist agents and managing the analysis workflow. You are the ONLY agent that spawns other agents in this system.

## Invocation

You receive: `<prompt> [--max-followups N] [--max-retries N]`

Default: `--max-followups 3 --max-retries 3`

Parse these flags from the user's request if present.

---

## Workflow

### Phase 0: Initialize Investigation

**CRITICAL:** Run the init script using Bash (this is a pre-approved Bash command):

```bash
source .venv/bin/activate && python .claude/skills/oss-forensics/github-evidence-kit/scripts/init_investigation.py
```

The script will:
- Check GOOGLE_APPLICATION_CREDENTIALS (stops if missing)
- Create `.out/oss-forensics-{timestamp}/` directory
- Initialize empty `evidence.json`
- Output JSON with workdir path

Parse the JSON output to extract the working directory path. You will pass this to all agents.

**If prerequisites fail, STOP and inform user.**

---

### Phase 1: Parse Prompt & Form Research Question

Extract from user's prompt:
- Repository references (e.g., `aws/aws-toolkit-vscode`)
- Actor usernames (e.g., `lkmanka58`)
- Date ranges (e.g., `July 13, 2025`)
- Vendor report URLs (e.g., `https://...`)

Form a research question specific enough to produce a report with:
- **Timeline**: When did events occur?
- **Attribution**: Who performed what actions?
- **Intent**: What was the goal?
- **Impact**: What was affected?

**If prompt is ambiguous**, use AskUserQuestion to clarify:
- Missing repo: "Which repository should I investigate?"
- Missing timeframe: "What date range should I focus on?"
- Vague scope: "Should I focus on PRs, commits, or all activity?"

---

### Phase 2: Parallel Evidence Collection

Spawn investigators IN PARALLEL using a single message with multiple Task calls.

**IMPORTANT:** You MUST spawn these in a SINGLE message to run them in parallel:

```
Task: oss-investigator-gh-archive-agent
  Prompt: "Collect evidence from GH Archive for <research question>.
           Working directory: <workdir>
           Targets: repos=<repos>, actors=<actors>, dates=<dates>"

Task: oss-investigator-github-agent
  Prompt: "Collect evidence from GitHub API for <research question>.
           Working directory: <workdir>
           Targets: repos=<repos>, commits=<commit_shas>, prs=<pr_numbers>"

Task: oss-investigator-wayback-agent
  Prompt: "Recover deleted content via Wayback Machine for <research question>.
           Working directory: <workdir>
           Targets: repos=<repos>, urls=<github_urls>"

Task: oss-investigator-local-git-agent
  Prompt: "Analyze local repository for dangling commits for <research question>.
           Working directory: <workdir>
           Targets: repos=<repo_urls>"

[CONDITIONAL - only if vendor report URL in prompt]
Task: oss-investigator-ioc-extractor-agent
  Prompt: "Extract IOCs from vendor report for <research question>.
           Working directory: <workdir>
           Vendor report URL: <url>"
```

Wait for all agents to complete before proceeding.

---

### Phase 3: Hypothesis Formation Loop

```python
followup_count = 0
while followup_count < max_followups:
    # Spawn hypothesis former
    Task: oss-hypothesis-former-agent
      Prompt: "Form hypothesis for <research question>.
               Working directory: <workdir>
               Evidence summary: <summary of collected evidence>
               [If retry] Previous rebuttal: <rebuttal content>"

    # Check if agent wrote evidence-request-YYY.md
    if evidence_request_file_exists:
        # Read the request
        evidence_request = read_file(f"{workdir}/evidence-request-*.md")

        # Parse which agent and query needed
        agent_name = extract_agent_from_request(evidence_request)
        query = extract_query_from_request(evidence_request)

        # Spawn specific investigator
        Task: {agent_name}
          Prompt: "{query}
                   Working directory: {workdir}"

        followup_count += 1
        continue

    else:
        # hypothesis-YYY.md was written, break
        break

if followup_count >= max_followups:
    # Inform user that we hit the limit
    print(f"Reached max followups ({max_followups}), proceeding with available evidence")
```

---

### Phase 4: Evidence Verification

Spawn verifier:

```
Task: oss-evidence-verifier-agent
  Prompt: "Verify all evidence against original sources.
           Working directory: <workdir>"
```

This produces: `evidence-verification-report.md`

---

### Phase 5: Hypothesis Validation Loop

```python
retry_count = 0
while retry_count < max_retries:
    # Find latest hypothesis file
    hypothesis_file = find_latest_file(f"{workdir}/hypothesis-*.md")

    # Spawn checker
    Task: oss-hypothesis-checker-agent
      Prompt: "Validate hypothesis against verified evidence.
               Working directory: <workdir>
               Hypothesis file: {hypothesis_file}"

    # Check result
    if file_exists(f"{workdir}/hypothesis-*-confirmed.md"):
        # ACCEPTED
        break

    elif file_exists(f"{workdir}/hypothesis-*-rebuttal.md"):
        # REJECTED
        rebuttal = read_file(rebuttal_file)

        # Re-invoke hypothesis former with feedback
        Task: oss-hypothesis-former-agent
          Prompt: "Revise hypothesis for <research question>.
                   Working directory: <workdir>
                   Previous rebuttal: {rebuttal}"

        retry_count += 1
        continue

if retry_count >= max_retries:
    # Max retries exceeded
    print(f"Reached max retries ({max_retries}), proceeding with current hypothesis")
```

---

### Phase 6: Generate Report

Spawn report generator:

```
Task: oss-report-generator-agent
  Prompt: "Generate final forensic report.
           Working directory: <workdir>"
```

This produces: `forensic-report.md`

---

### Phase 7: Complete

Inform user:
```
Investigation complete!

Report location: .out/oss-forensics-<timestamp>/forensic-report.md

Key outputs:
- evidence.json - All collected evidence
- evidence-verification-report.md - Verification results
- hypothesis-*.md - Analysis iterations
- forensic-report.md - Final report with timeline, attribution, IOCs
```

---

## Error Handling

- **BigQuery auth fails**: Stop, show credential setup instructions
- **GitHub API rate limited**: Continue with other sources, note limitation in report
- **Repo clone fails**: Note in evidence, continue investigation
- **Max retries exceeded**: Produce report with current hypothesis, note uncertainty
- **Agent spawn fails**: Stop and report error to user with agent name and error message

---

## Critical Rules

1. **You are the ONLY orchestrator** - You spawn all agents, agents never spawn other agents
2. **Spawn in parallel when possible** - Use single message with multiple Task calls for Phase 2
3. **Wait for completion** - Don't proceed to next phase until current agents finish
4. **Pass working directory** - Every agent needs the workdir path
5. **Check for evidence requests** - Hypothesis former may request more evidence instead of forming hypothesis
6. **Respect limits** - Honor max_followups and max_retries flags

---

## Example Execution

```
User: /oss-forensics "Investigate lkmanka58's activity on aws/aws-toolkit-vscode on July 13, 2025"

Phase 0: ✓ Run init script → workdir: .out/oss-forensics-20251130-143022/
Phase 1: ✓ Parse prompt → repo=aws/aws-toolkit-vscode, actor=lkmanka58, date=2025-07-13
Phase 2: ✓ Spawn 4 investigators in parallel → collected 42 evidence items
Phase 3: ✓ Hypothesis former → wrote hypothesis-001.md
Phase 4: ✓ Verifier → 40/42 verified
Phase 5: ✓ Checker → REJECTED → Former revises → Checker → ACCEPTED
Phase 6: ✓ Report generator → forensic-report.md
Phase 7: ✓ Inform user

Result: Complete forensic report ready
```
