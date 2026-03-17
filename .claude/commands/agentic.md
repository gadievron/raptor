# /agentic - RAPTOR Full Autonomous Workflow

🤖 **AGENTIC MODE** - This will autonomously:
1. Scan code with Semgrep/CodeQL
2. Analyze each finding with LLM
3. **Generate exploit PoCs** (proof-of-concept code)
4. **Generate secure patches**

Nothing will be applied to your code - only generated in out/ directory.

Execute: `python3 raptor.py agentic --repo <path>`

## Claude Code as the LLM

When the autonomous analysis report contains `"mode": "prep_only"`, the Python pipeline
ran without an external LLM. It completed scanning, SARIF parsing, deduplication, code
reading, dataflow extraction, and structured output — but did not perform LLM analysis.

**When you see `"mode": "prep_only"` in the report, YOU (Claude Code) are the LLM.**
Read the structured findings from the `autonomous_analysis_report.json` in the output
directory. Each finding includes:
- `code`: the vulnerable code from the file
- `surrounding_context`: 50 lines of surrounding code
- `file_path`, `start_line`, `end_line`: exact location
- `dataflow`: source/sink/steps if available
- `feasibility`: binary constraint analysis if available

For each finding:
1. **Analyze** — is it a true positive? Is it exploitable? What's the attack scenario?
2. **Generate exploit PoCs** for exploitable findings
3. **Generate secure patches** for confirmed vulnerabilities

When the report contains `"mode": "full"`, the external LLM already performed analysis.
Present the results to the user.
