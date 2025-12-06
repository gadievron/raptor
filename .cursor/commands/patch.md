# Patch - Generate Secure Patches

Generate secure patches to fix vulnerabilities found in previous scans.

## Usage

`/patch [--repo <path>] [--sarif <sarif-file>] [--max-findings <N>]`

## Examples

- `/patch --repo ./myapp --sarif out/scan_*/findings.sarif`
- `/patch --repo ./myapp --sarif findings.sarif --max-findings 10`

## Execution Steps

1. **Parse arguments**:
   - Extract `--repo` (required, default to current workspace if not provided)
   - Extract `--sarif` (required - path to SARIF file from previous scan)
   - Extract optional: `--max-findings` (default: 5)
   - If `--sarif` is missing, look for recent SARIF files in `out/` directory or ask user

2. **Execute command**:
   ```bash
   python3 raptor.py agentic --repo <path> --sarif <sarif-file> --no-exploits --max-findings <N>
   ```

3. **Monitor execution**: Wait for patch generation to complete

4. **Read results** from `out/agentic_<repo>_<timestamp>/patches/`:
   - Generated patch files

5. **Summarize findings**:
   - List generated patches
   - Offer to show patch contents
   - Offer to apply patches (ask user first - this is a dangerous operation)

## Workflow

This command runs the same workflow as `/agentic` but:
- Skips exploit generation (`--no-exploits`)
- Only generates secure patches for vulnerabilities

## Prerequisites

- LLM API key (ANTHROPIC_API_KEY or OPENAI_API_KEY)
- Existing SARIF file (from previous `/scan` or `/codeql` run)

## Important Note

**Applying patches is a dangerous operation** - always ask the user before applying patches to their code.

## Reference

See `.cursor/rules/command-usage.mdc` for complete argument documentation and examples.
