---
description: OpenAnt LLM-powered source-code vulnerability scan
dispatch: libexec/raptor-openant $ARGUMENTS
---

# /openant — OpenAnt LLM-powered source-code vulnerability scan

Run OpenAnt against a repository to find vulnerabilities using AST analysis and
per-function LLM reasoning. Unlike Semgrep/CodeQL (pattern matching), OpenAnt
reads and understands each function in context — catching business-logic flaws,
authentication bypasses, and subtle injection patterns that static tools miss.

**Execution:** `libexec/raptor-openant --repo <path> [options]`

---

## Prerequisites

Check out OpenAnt at the pinned commit (commit id, not a movable
tag/branch — see `packages/openant/config.py:OPENANT_PINNED_COMMIT`)
and make its `libs/openant-core` directory visible at the auto-detect
layout `<raptor-parent>/libs/openant-core` (a symlink works):

```bash
git clone https://github.com/knostic/OpenAnt /path/to/OpenAnt
git -C /path/to/OpenAnt checkout abd1dcf416a1ca329441c4bf8ebb68f70dd0f3cf
ln -s /path/to/OpenAnt/libs <raptor-parent>/libs
```

Alternatively pass the path per run with `--openant-core
/path/to/OpenAnt/libs/openant-core` (consent-gated, see below).

Do NOT rely on `export OPENANT_CORE` for `/openant` runs: the
dispatch lane rebuilds the child environment from the safe-env
allowlist, which deliberately excludes it (it names a directory whose
Python executes with network access and the Anthropic API key — the
exec-path class the allowlist keeps out), so the export never reaches
the pipeline. The env var works only for direct `raptor_openant.py`
invocations from an unscrubbed shell.

Via auto-detection, a checkout at any other commit still runs — the
run report records the provenance and the scan warns loudly (schema
drift in a newer OpenAnt can change verdict spellings).

Passing `--openant-core <path>` directly is CONSENT-GATED: the flag
lives on pre-approved launcher argv, and the named directory's Python
executes with network access and the Anthropic API key — so a core
that is not a CLEAN checkout of the pinned commit REFUSES at startup:
a different commit, unverifiable non-git provenance, or a working
tree that deviates from the pinned content (tracked files
modified/missing, or untracked files present — ignored files
included, since a matching HEAD is content-blind to on-disk edits).
Consent deliberately with `--openant-core-unpinned` (this run) or the
project `config` trust marker (`/project trust config`, standing).
The clean pinned checkout passes the gate without either. Note: a
checkout you have RUN OpenAnt from carries untracked files — the
`.venv/` its tree-sitter grammars live in, `__pycache__/` — and is
flagged; a FUNCTIONAL install therefore never passes the gate clean.
Re-clone at the pin, or consent — and know the trade: a consented run
executes the untracked venv interpreter the survey cannot verify,
while a bare re-clone (no `.venv`) falls back to the launching Python
and loses the c/ruby/php/javascript grammars (the fallback now warns,
naming the lost languages; recreate the venv to restore them).

When the gate refuses in an interactive session, this is a run
boundary: run `libexec/raptor-may-ask` first; only if it prints
`interactive` AND the AskUserQuestion tool is available, offer the
trust decision as a structured choice (see CLAUDE.md § INTERACTIVE
PROMPTS). Quote the actual refusal text in the question — with
non-printables escaped (the quoted core path is unconstrained argv) —
and offer: (1) **Check out the pin (Recommended)**: re-clone/checkout
at the pinned commit and re-run; (2) **Consent for this run**: re-run
with `--openant-core-unpinned`; (3) **Standing consent**:
`/project trust config`. Non-interactive fallback: refuse — report
the refusal text and stop; never add the consent flag on the
operator's behalf.

---

## Usage

```
/openant --repo /path/to/code [options]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--repo <path>` | active project target, then vetted caller dir | Repository to scan (required; no-path runs resolve per DEFAULT TARGET DIRECTORY, volatile-target gate included) |
| `--model <name>` | `sonnet` | LLM model: `sonnet` or `opus` |
| `--level <name>` | `reachable` | Depth: `all`, `reachable`, `codeql`, `exploitable` |
| `--language <lang>` | `auto` | Override language detection: `python`, `javascript`, `go`, `c`, `ruby`, `php` (out-of-set values fall back to `auto`) |
| `--no-enhance` | off | Skip OpenAnt enhance phase (faster, less accurate) |
| `--verify` | off | Enable stage-2 LLM verification pass |
| `--workers <n>` | `4` | Parallel analysis workers |
| `--gateway-budget <usd>` | `$25` | Per-run raise of the dispatcher-gateway spend cap on gateway-minted runs (any positive finite USD; the anti-runaway request cap scales with it, never below 10k). No uncapped spelling — dispatcher child tokens carry a finite budget by contract. Argv-only (no env twin); no effect on direct-credential runs (noted loudly) |
| `--timeout-seconds <n>` | `1800` | Wall-clock deadline for the OpenAnt child (hard-killed at it, every credential posture). Positive integer, no ceiling; on gateway-minted runs the token TTL follows it (timeout + 600s slack), so raising it never strands a live child on an expired token |
| `--max-findings <n>` | `50` | Cap findings rendered in the markdown report (severity-first, truncation stated; must be >= 1). `openant_findings.json` is never capped |
| `--resume <run-dir>` | off | Complete a truncated prior run, paying only for the remainder (see § Resume) |
| `--forecast` | off | Free phases only (parse + unit census): print a pre-spend cost forecast and exit with $0 LLM spend (report `outcome=forecast_only` — not a scan, no findings artifact). Combines with `--resume` to price completing a truncated run |
| `--openant-core <path>` | auto-detect at `<raptor-parent>/libs/openant-core` (`$OPENANT_CORE` applies to direct unscrubbed invocations only — the dispatch lane's safe-env rebuild drops it) | Path to openant-core (flag surface is consent-gated: a core that is not a clean pinned checkout refuses at startup) |
| `--openant-core-unpinned` | off | Consent to run a `--openant-core` checkout that is not a clean pinned checkout this run (the project `config` trust marker grants the same, standing) |

### Analysis levels

- `all` — every function, regardless of reachability (thorough, expensive)
- `reachable` — functions reachable from entry points (balanced, recommended)
- `codeql` — functions flagged by CodeQL dataflow (targeted, cheapest)
- `exploitable` — only functions already marked exploitable

---

## Resume

`--resume <prior-run-dir>` completes a truncated scan (budget
exhaustion, timeout, kill) for the cost of the remainder. It creates a
NEW run directory (own lifecycle) seeded from the prior run's
`openant_scan` state — the prior directory is never mutated — and
re-invokes the pinned scan against it: the upstream checkpoint
machinery restores completed units at zero LLM cost, retries errored
units, and rebuilds the outputs (findings, `pipeline_output.json`)
over the union. A fresh gateway token is minted for the resume with
the standard (or `--gateway-budget`) budget applying to the remainder;
all credential hygiene (staging, scrub, revocation, settlement)
applies unchanged.

- The prior run's scan-shape config (model, level, enhance, verify,
  language) is ADOPTED — a resume completes the same scan; conflicting
  flags are overridden with a loud warning. Operational knobs
  (`--workers`, `--timeout-seconds`, `--gateway-budget`,
  `--max-findings`) stay per-run.
- Detected drift REFUSES loudly (exit 2, report
  `outcome=resume_refused`): a different target path, a git target
  whose tree changed since the prior run, or an openant-core / pin
  change. Upstream checkpoints are path-keyed and content-blind, so
  this validation is the only target/core drift gate a resume has;
  undetectable drift (non-git target, prior run predating fingerprint
  recording) warns loudly instead.
- **Trust:** the prior run dir is trusted as THIS installation's own
  output. Its checkpoint contents shape the resumed run's verdicts —
  upstream adopts completed checkpoints without content
  authentication (the identity sidecar filters unknown writers, it is
  not an authenticity seal), and the drift gates verify
  target/pin/core IDENTITY only. Resume only run dirs you trust.
  Mitigations: the report the gates read is parent-written at the
  run-dir top level, outside the scan child's sandbox bind, and
  seeding refuses anything but regular files/dirs (a planted symlink,
  FIFO, or device in the prior scan state refuses the whole resume
  and leaves nothing behind).
- Resuming a COMPLETE run refuses with "nothing to resume".
- The resumed run's report records `resume.resumed_from`, the prior
  cost, this run's cost, and the combined figure. Note the small
  honest re-spend: the app-context step regenerates (one small LLM
  call) — it is included in the forecast.

```bash
/openant --resume out/openant_<timestamp>            # finish it
/openant --resume out/openant_<timestamp> --forecast # price finishing it
```

## Cost forecast

`--forecast` runs only the free phases — parse + unit census (the
pinned `parse` step is LLM-free; context generation is NOT, so it is
excluded) — prints a forecast RANGE and exits with $0 LLM spend. The
run's report carries `outcome=forecast_only` and writes no
`openant_findings.json`, so it can never read as a scan.

Every gateway-minted real run prints the same forecast line before its
child token is minted — informational, never blocking (a forecast
failure warns and the scan proceeds). Resumed runs always print it,
priced over the remainder only. The estimator is measured-calibration
(see `packages/openant/forecast.py`): analyze input tokens track unit
size nearly exactly; enhance is agent-iteration-dominated, hence the
wider band. `--verify` is noted but not priced (uncalibrated).

---

## Supported languages

Python, JavaScript/TypeScript, PHP, Ruby, C/C++, Java, Go, Zig

The `--language` override accepts only `auto`, `python`, `javascript`,
`go`, `c`, `ruby`, and `php`. Languages outside that set (e.g. Java,
Zig) are auto-detected but cannot be forced — an out-of-set
`--language` value silently falls back to `auto`.

---

## Output files

| File | Description |
|------|-------------|
| `openant_findings.json` | Translated findings in Raptor schema |
| `openant-report.md` | Human-readable markdown report |
| `raptor_openant_report.json` | Machine-readable run summary |
| `openant_scan/pipeline_output.json` | Raw OpenAnt output |
| `openant_scan/openant-gateway-spend.json` | Dispatcher-gateway runs only: the scoped child token's booked spend (public token id, USD, request count) |

---

## Credentials

No setup is needed beyond RAPTOR's own: with a direct credential
(`ANTHROPIC_API_KEY` in env, or a key-bearing `anthropic` provider in
the operator's OpenAnt `config.json`) the child calls the Anthropic
API itself; on a keyless host running under the RAPTOR LLM dispatcher
the scan automatically routes the child through a dispatcher child
token on the loopback gateway — spend-capped ($25 default; raise per
run with `--gateway-budget`), model-pinned, TTL'd to the scan, revoked
at exit. Direct always wins; the gateway is the fallback. Keyless *and* dispatcher-less runs fail honestly at the
child's startup credential probe. See docs/environment.md § OpenAnt
integration for the full posture rules.

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
