# /agentic - RAPTOR Full Autonomous Workflow

🤖 **AGENTIC MODE** - This will autonomously:
1. Scan code with Semgrep/CodeQL
2. Analyze each finding with LLM (parallel dispatch)
3. **Generate exploit PoCs** for exploitable findings
4. **Generate secure patches** for confirmed vulnerabilities
5. **Cross-finding analysis** (structural grouping, shared root causes)

Nothing will be applied to your code - only generated in out/ directory.

Execute: `python3 raptor.py agentic --repo <path>`

## Claude Code as the LLM

When no external LLM is configured, **YOU (Claude Code) are the LLM.** Phase 4
dispatches `claude -p` sub-agents to analyse each finding in parallel. If Phase 4
did not run (no `claude` on PATH), you may be asked to analyse the findings directly.

When an external LLM is configured, Phase 4 dispatches to it in parallel via
`generate_structured()`. Model roles determine which model analyses (analysis),
writes code (code), and provides second opinions (consensus). If the external
LLM fails, Phase 4 falls back to Claude Code dispatch automatically.

After per-finding analysis: structural grouping identifies related findings,
group analysis explains shared patterns, and consensus (if configured) flags
disputed verdicts. Cost tracking is real-time with adaptive budget cutoff.

## Report modes

The pipeline produces a report with one of three modes:

**`"mode": "prep_only"`** — No LLM was available and orchestration did not run.
The pipeline completed scanning, SARIF parsing, deduplication, code reading,
dataflow extraction, and structured output — but no analysis. Read the findings
from `autonomous_analysis_report.json` in the output directory. Each finding
includes `code`, `surrounding_context`, `file_path`, line numbers, `dataflow`,
and `feasibility`. If the user asks you to analyse them, for each finding:

1. **Analyse** — is it a true positive? Is it exploitable? What's the attack scenario?
2. **Generate exploit PoCs** for exploitable findings
3. **Generate secure patches** for confirmed vulnerabilities

Do NOT include raw code from the findings in sub-agent prompts — let each agent
read the code itself via the Read tool.

**`"mode": "full"`** — An external LLM performed sequential analysis in Phase 3
(when Claude Code was not available). Present the results to the user.

**`"mode": "orchestrated"`** — Phase 4 performed parallel analysis via external
LLM or Claude Code sub-agents. Results include per-finding `analysed_by` (which
model), `cost_usd`, `duration_seconds`, plus `cross_finding_groups` and optional
`consensus` data. Present the results to the user.

In all modes, findings are in the `results` array of the report. Orchestrated
and full mode findings include `is_exploitable`, `reasoning`, `exploit_code`, and
`patch_code` fields. Prep-only findings include `code`, `surrounding_context`,
`dataflow`, and `feasibility` for review.
