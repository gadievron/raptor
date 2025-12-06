# Raptor-Scan - Quick Semgrep Security Scan (Alias)

Alias for `/scan` - Run a fast static code analysis using Semgrep only.

## Usage

`/raptor-scan [--repo <path>] [--policy-groups <groups>] [options]`

## Examples

- `/raptor-scan --repo ./myapp`
- `/raptor-scan --repo /path/to/repo --policy-groups secrets,owasp`

## Execution

This command is identical to `/scan`. See `/scan` command documentation for details.

Execute: `python3 raptor.py scan --repo <path> [options]`

## Reference

See `.cursor/rules/command-usage.mdc` for complete argument documentation.
