# Agentic - Full Autonomous Security Workflow

Execute RAPTOR's complete end-to-end security testing with Semgrep, CodeQL, LLM analysis, exploit generation, and patch creation.

## Usage

`/agentic [--repo <path>] [options]`

## Examples

- `/agentic --repo ./myapp`
- `/agentic --repo /path/to/repo --max-findings 10`
- `/agentic --repo ./myapp --codeql-only`
- `/agentic --repo ./myapp --no-codeql`

## Execution Steps

1. **Parse arguments**:
   - Extract `--repo` (required, default to current workspace if not provided)
   - Extract optional flags: `--max-findings`, `--codeql`, `--no-codeql`, `--codeql-only`, `--policy-groups`, `--languages`, `--no-exploits`, `--no-patches`
   - If `--repo` is missing, ask the user or infer from workspace context

2. **Execute command**:
   ```bash
   python3 raptor.py agentic --repo <path> [options]
   ```

3. **Monitor execution**: Wait for command to complete, handle errors gracefully

4. **Read results** from `out/agentic_<repo>_<timestamp>/`:
   - `findings.sarif` - All findings
   - `exploits/` - Generated exploit PoCs
   - `patches/` - Generated patches
   - `analysis/` - LLM analysis reports

5. **Summarize findings**:
   - Parse SARIF file and count vulnerabilities by severity
   - List generated exploits and patches
   - Offer to show details, explain vulnerabilities, or apply patches

## Workflow

This command runs:
1. Semgrep scan (unless `--codeql-only`)
2. CodeQL analysis (unless `--no-codeql`)
3. LLM analysis for each finding (up to `--max-findings`, default: 5)
4. Exploit PoC generation (unless `--no-exploits`)
5. Secure patch generation (unless `--no-patches`)

## Prerequisites

- Semgrep CLI
- CodeQL CLI (if CodeQL enabled)
- LLM API key (ANTHROPIC_API_KEY or OPENAI_API_KEY)

## Reference

See `.cursor/rules/command-usage.mdc` for complete argument documentation and examples.
