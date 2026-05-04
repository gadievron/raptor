# /openant — OpenAnt LLM-powered source-code vulnerability scan

Run OpenAnt against a repository to find vulnerabilities using AST analysis and
per-function LLM reasoning. Unlike Semgrep/CodeQL (pattern matching), OpenAnt
reads and understands each function in context — catching business-logic flaws,
authentication bypasses, and subtle injection patterns that static tools miss.

**Execution:** `libexec/raptor-openant --repo <path> [options]`

---

## Prerequisites

Set `OPENANT_CORE` to the `openant-core` directory:

```bash
export OPENANT_CORE=/path/to/OpenAnt/libs/openant-core
```

Or pass `--openant-core <path>` directly.

---

## Usage

```
/openant --repo /path/to/code [options]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--repo <path>` | `$RAPTOR_CALLER_DIR` | Repository to scan (required) |
| `--model <name>` | `sonnet` | LLM model: `sonnet` or `opus` |
| `--level <name>` | `reachable` | Depth: `all`, `reachable`, `codeql`, `exploitable` |
| `--language <lang>` | `auto` | Override language detection |
| `--no-enhance` | off | Skip OpenAnt enhance phase (faster, less accurate) |
| `--verify` | off | Enable stage-2 LLM verification pass |
| `--workers <n>` | `4` | Parallel analysis workers |
| `--max-findings <n>` | `50` | Cap findings in report |
| `--openant-core <path>` | `$OPENANT_CORE` | Path to openant-core |

### Analysis levels

- `all` — every function, regardless of reachability (thorough, expensive)
- `reachable` — functions reachable from entry points (balanced, recommended)
- `codeql` — functions flagged by CodeQL dataflow (targeted, cheapest)
- `exploitable` — only functions already marked exploitable

---

## Supported languages

Python, JavaScript/TypeScript, PHP, Ruby, C/C++, Java, Go, Zig

---

## Output files

| File | Description |
|------|-------------|
| `openant_findings.json` | Translated findings in Raptor schema |
| `openant-report.md` | Human-readable markdown report |
| `raptor_openant_report.json` | Machine-readable run summary |
| `openant_scan/pipeline_output.json` | Raw OpenAnt output |

---

## Examples

```bash
# Quick scan with default settings
/openant --repo /path/to/myapp

# Deep scan — all functions, verification pass, opus model
/openant --repo /path/to/myapp --level all --verify --model opus

# Fast scan — skip enhance, limit to 20 findings
/openant --repo /path/to/myapp --no-enhance --max-findings 20

# Target Python only
/openant --repo /path/to/myapp --language python

# Use OpenAnt alongside agentic (Semgrep+CodeQL+LLM) workflow
/agentic --repo /path/to/myapp --openant
```

---

## Notes

- OpenAnt findings have no line numbers — deduplication with SARIF tools uses
  `(file, CWE)` as the key.
- `vulnerable` + `confirmed` findings translate to Raptor `error` level.
- `vulnerable` without stage-2 confirmation translates to `warning`.
- `safe` findings are suppressed.
- Use `--verify` to get stage-2 confirmation (costs ~2× tokens).
