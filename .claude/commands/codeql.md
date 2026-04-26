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

## SMT Dataflow Pre-Check

When `--analyze` is enabled, dataflow findings are routed through an SMT
pre-check before the full LLM analysis (`packages/codeql/smt_path_validator.py`):

1. The LLM extracts branch conditions from each path step as structured predicates
   (`"size > 0"`, `"offset + length <= buffer_size"`, etc.)
2. Z3 checks whether those conditions are **jointly satisfiable**
3. **unsat** → path is provably unreachable; finding skipped (no LLM call)
4. **sat** → concrete satisfying values returned; fed as candidate inputs into the
   LLM prompt and `prerequisites` field of `DataflowValidation`
5. **None** → Z3 unavailable or conditions unparseable; full LLM analysis runs

Requires `z3-solver` (`pip install z3-solver`). Degrades gracefully when absent.

**Best coverage:** CWE-190 (integer overflow, **including 32-bit wraparound** —
the extraction LLM emits per-path width/signedness hints so Z3 models the right
C type semantics), CWE-120/122 (buffer size checks), CWE-193 (off-by-one),
CWE-476 (null deref). String-based findings (CWE-89) fall through to LLM analysis.

## Examples

```bash
# Scan only (default) — produces SARIF
/codeql --repo /tmp/vulns

# Full autonomous analysis (includes SMT dataflow pre-check if z3 installed)
/codeql --repo /tmp/vulns --analyze

# Specific language with custom build
/codeql --repo /tmp/vulns --languages cpp --build-command "make"
```

---
