# Scan - Quick Semgrep Security Scan

Run a fast static code analysis using Semgrep only.

## Usage

`/scan [--repo <path>] [--policy-groups <groups>] [options]`

## Examples

- `/scan --repo ./myapp`
- `/scan --repo /path/to/repo --policy-groups secrets,owasp`
- `/scan --repo ./myapp --config custom-rules.yaml`

## Execution Steps

1. **Parse arguments**:
   - Extract `--repo` (required, default to current workspace if not provided)
   - Extract optional: `--policy-groups`, `--config`, `--output`
   - If `--repo` is missing, ask the user or infer from workspace context

2. **Execute command**:
   ```bash
   python3 raptor.py scan --repo <path> [options]
   ```

3. **Monitor execution**: Wait for command to complete, handle errors gracefully

4. **Read results** from `out/scan_<repo>_<timestamp>/`:
   - `findings.sarif` - Semgrep findings

5. **Summarize findings**:
   - Parse SARIF file and count vulnerabilities by severity
   - List top findings by severity
   - Offer to show details or run `/analyze` for deeper analysis

## Workflow

This command:
1. Detects languages in repository
2. Runs Semgrep with specified policy groups
3. Generates SARIF output
4. Parses and deduplicates findings

## Prerequisites

- Semgrep CLI

## Reference

See `.cursor/rules/command-usage.mdc` for complete argument documentation and examples.
