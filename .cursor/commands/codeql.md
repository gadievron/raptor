# CodeQL - Deep Static Analysis

Run deep static analysis using CodeQL only (no Semgrep).

## Usage

`/codeql [--repo <path>] [--languages <langs>] [options]`

## Examples

- `/codeql --repo ./myapp`
- `/codeql --repo /path/to/repo --languages java,python`
- `/codeql --repo ./myapp --extended`
- `/codeql --repo ./myapp --force-db`

## Execution Steps

1. **Parse arguments**:
   - Extract `--repo` (required, default to current workspace if not provided)
   - Extract optional: `--languages`, `--suite`, `--extended`, `--force-db`
   - If `--repo` is missing, ask the user or infer from workspace context

2. **Execute command**:
   ```bash
   python3 raptor.py codeql --repo <path> [options]
   ```

3. **Monitor execution**: CodeQL database creation and analysis can take time. Monitor progress.

4. **Read results** from `out/codeql_<repo>_<timestamp>/`:
   - `findings.sarif` - CodeQL findings
   - `databases/` - CodeQL databases (cached for future runs)

5. **Summarize findings**:
   - Parse SARIF file and count vulnerabilities by severity
   - List top findings
   - Offer to show details or run `/analyze` for deeper analysis

## Workflow

This command:
1. Detects languages in repository
2. Detects build systems
3. Creates CodeQL databases (with caching)
4. Runs CodeQL security analysis suites
5. Generates SARIF output

## Prerequisites

- CodeQL CLI installed

## Reference

See `.cursor/rules/command-usage.mdc` for complete argument documentation and examples.
