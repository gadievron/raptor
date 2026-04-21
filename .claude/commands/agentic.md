---
description: Full autonomous security workflow — scan, dedup, prep, analyse, consensus, exploit, patch, group
---

# /agentic - RAPTOR Full Autonomous Workflow

🤖 **AGENTIC MODE** - This will autonomously:
1. Scan code with Semgrep/CodeQL (parallel)
2. Deduplicate findings
3. Prep findings (read code, extract dataflow)
4. **Validate + analyse** each finding (exploitation-validator methodology, Stages A-D)
5. **Self-review** — catch contradictions, retry low confidence (Stage F)
6. **Consensus** — multi-model second opinion (if configured)
7. **Generate exploit PoCs** for exploitable findings
8. **Generate secure patches** for confirmed vulnerabilities
9. **Cross-finding analysis** (structural grouping, shared root causes)

Nothing will be applied to your code - only generated in out/ directory.

Execute: `python3 raptor.py agentic --repo <path>`

## How analysis works

Findings are dispatched for parallel analysis via one of two paths:

- **Claude Code on PATH**: dispatches `claude -p` sub-agents (separate processes)
- **External LLM configured**: dispatches via `generate_structured()` API calls
- **Both available**: uses external LLM, falls back to Claude Code if it fails

Model roles determine which model analyses (analysis), writes code (code), and
provides second opinions (consensus).

If **neither** is available, the pipeline produces prep-only output. In that case,
**YOU (Claude Code) are the LLM** — the user may ask you to analyse the findings
directly in conversation. See the prep_only report mode below for instructions.

Analysis follows the exploitation-validator methodology (Stages A-D):
- **Stage A**: One-shot verification — is the vulnerability pattern real?
- **Stage B**: Attack path analysis — what are the preconditions and blockers?
- **Stage C**: Sanity check — does the code match? is the flow real? is it reachable?
- **Stage D**: Ruling — test code? unrealistic preconditions? hedging?

If `--binary` is provided, Stage E (binary feasibility analysis) runs before
scanning and its results (chain_breaks, mitigations) are included in each
finding's analysis prompt.

The dispatch pipeline runs these tasks in sequence:

1. **AnalysisTask** — Stages A-D per finding (validation + analysis in one call)
2. **RetryTask** — Stage F: self-consistency check, retry contradictions + low confidence
3. **ConsensusTask** — second model votes on true positives (if configured)
4. **ExploitTask** — PoCs for final-verdict exploitable findings
5. **PatchTask** — secure fixes for exploitable findings
6. **GroupAnalysisTask** — cross-finding patterns (shared root cause, attack chaining)

Cost tracking is real-time with adaptive budget cutoff.

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

**`"mode": "full"`** — An external LLM performed sequential analysis (when
`--sequential` was used or Claude Code was not available). Present the results.

**`"mode": "orchestrated"`** — Parallel analysis via external LLM or Claude Code
sub-agents. Results include per-finding `analysed_by` (which model), `cost_usd`,
`duration_seconds`, plus `cross_finding_groups` and optional `consensus` data.
Present the results to the user.

In all modes, findings are in the `results` array of the report. Orchestrated
and full mode findings include `is_exploitable`, `reasoning`, `exploit_code`, and
`patch_code` fields. Prep-only findings include `code`, `surrounding_context`,
`dataflow`, and `feasibility` for review.

**After the pipeline completes**, read `agentic-report.md` from the output directory
and add a 1-2 sentence summary paragraph after the `# RAPTOR Agentic Security Report`
header — e.g., "Scanned 26 findings across 10 C files. 8 are exploitable buffer overflows
and command injections; 2 were ruled out as false positives." Use only facts from the
report data. The report should stand on its own without this paragraph.
