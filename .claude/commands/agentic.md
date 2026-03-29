# /agentic - RAPTOR Full Autonomous Workflow

🤖 **AGENTIC MODE** - This will autonomously:
1. Scan code with Semgrep/CodeQL
2. Analyze each finding with LLM
3. **Generate exploit PoCs** (proof-of-concept code)
4. **Generate secure patches**

Nothing will be applied to your code - only generated in out/ directory.

Execute: `python3 raptor.py agentic --repo <path>`

## Claude Code as the LLM

When no external LLM is configured, **YOU (Claude Code) are the LLM.** Phase 4
dispatches `claude -p` sub-agents to analyse each finding in parallel. If Phase 4
did not run (no `claude` on PATH), you may be asked to analyse the findings directly.

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

**`"mode": "full"`** — An external LLM performed analysis in Phase 3.
Present the results to the user.

**`"mode": "orchestrated"`** — Claude Code sub-agents performed parallel
analysis in Phase 4 via `claude -p` subprocesses. Present the results to
the user.

In all modes, findings are in the `results` array of the report. Orchestrated
and full mode findings include `analysis`, `exploitable`, `exploit_code`, and
`patch_code` fields. Prep-only findings include `code`, `surrounding_context`,
`dataflow`, and `feasibility` for review.
