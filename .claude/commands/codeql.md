---
description: CodeQL deep static analysis with dataflow validation
---

# /codeql - RAPTOR CodeQL Analysis

Runs CodeQL deep static analysis with dataflow validation. Slower but finds complex vulnerabilities that Semgrep misses (tainted flows, use-after-free, injection chains).

## Usage

```
python3 raptor.py codeql --repo <path> [options]
```

## Options

| Option | Description |
|--------|-------------|
| `--repo <path>` | Repository path (required) |
| `--languages <list>` | Comma-separated languages (auto-detected if omitted) |
| `--scan-only` | Scan only — produce SARIF, skip LLM analysis (default) |
| `--analyze` | Enable LLM-powered autonomous analysis + exploit generation |
| `--build-command <cmd>` | Custom build command for database creation |
| `--extended` | Use extended security suites (more rules, slower) |
| `--force` | Force database recreation |
| `--max-findings <n>` | Max findings to analyse (with `--analyze`) |

## Examples

```bash
# Scan only (default) — produces SARIF
/codeql --repo /tmp/vulns

# Full autonomous analysis
/codeql --repo /tmp/vulns --analyze

# Specific language with custom build
/codeql --repo /tmp/vulns --languages cpp --build-command "make"
```
