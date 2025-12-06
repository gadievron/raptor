# Analyze - LLM Analysis of SARIF Files

Analyze existing SARIF files with LLM for deeper vulnerability analysis, exploit generation, and patch creation.

## Usage

`/analyze [--repo <path>] [--sarif <sarif-file>] [options]`

## Examples

- `/analyze --repo ./myapp --sarif findings.sarif`
- `/analyze --repo ./myapp --sarif out/scan_*/findings.sarif --max-findings 10`
- `/analyze --repo ./myapp --sarif findings.sarif --no-exploits`

## Execution Steps

1. **Parse arguments**:
   - Extract `--repo` (required, default to current workspace if not provided)
   - Extract `--sarif` (required - path to SARIF file)
   - Extract optional: `--max-findings` (default: 5), `--no-exploits`, `--no-patches`
   - If `--sarif` is missing, look for recent SARIF files in `out/` directory or ask user

2. **Execute command**:
   ```bash
   python3 raptor.py analyze --repo <path> --sarif <sarif-file> [options]
   ```

3. **Monitor execution**: Wait for LLM analysis to complete

4. **Read results** from `out/analyze_<repo>_<timestamp>/`:
   - `exploits/` - Generated exploit PoCs
   - `patches/` - Generated patches
   - `analysis/` - LLM analysis reports

5. **Summarize findings**:
   - List analyzed vulnerabilities
   - Show generated exploits and patches
   - Offer to explain vulnerabilities, show exploit code, or apply patches

## Workflow

This command:
1. Loads SARIF file
2. Parses and deduplicates findings
3. For each finding (up to `--max-findings`):
   - Creates `VulnerabilityContext`
   - Reads vulnerable code
   - Performs LLM analysis
   - Generates exploit (unless `--no-exploits`)
   - Generates patch (unless `--no-patches`)

## Prerequisites

- LLM API key (ANTHROPIC_API_KEY or OPENAI_API_KEY)
- Existing SARIF file (from previous `/scan` or `/codeql` run)

## Reference

See `.cursor/rules/command-usage.mdc` for complete argument documentation and examples.
