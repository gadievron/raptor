# Developer Guide

[Documentation index](README.md)

This is the technical reference for contributors: architecture, package
responsibilities, rule authoring, sandbox assumptions, test execution,
and hermetic test patterns. [CONTRIBUTING.md](../CONTRIBUTING.md) covers the
contribution workflow, [initial setup](../CONTRIBUTING.md#getting-started),
[test-writing requirements](../CONTRIBUTING.md#tests), style, and security
rules. Start there when preparing a change; use this page for implementation
and testing details.

Keep this reference focused on orientation and practical developer workflows.
The tree, docstrings, and `--help` output own API and CLI details;
[CI controls](ci-controls.md) owns the full check inventory.

**Related documentation:**
[Contributing](../CONTRIBUTING.md) |
[Architecture](architecture.md) |
[CI controls](ci-controls.md)

**On this page:**

- [The two-layer split](#the-two-layer-split)
- [Layering rules](#layering-rules)
- [Package map](#package-map)
- [engine/: authoring detection rules](#engine-authoring-detection-rules)
- [CLI help-text standard](#cli-help-text-standard)
- [Sandbox: what code may assume](#sandbox-what-code-may-assume)
- [Running tests](#running-tests)
- [Writing hermetic tests](#writing-hermetic-tests)
- [Mechanical gates you will hit](#mechanical-gates-you-will-hit)

## The two-layer split

RAPTOR is a Python **execution layer** (scanning, subprocess
management, SARIF parsing, LLM dispatch, cost tracking — no judgement
calls) driven by a Claude Code **decision layer** (`.claude/`,
`tiers/`, `CLAUDE.md`) that prioritises findings, interprets results,
and decides what to do next. The split is deliberate: the Python layer
runs standalone in CI, the decision layer drives it interactively.
When you add a capability, the mechanical part goes in Python and the
judgement part goes in a skill or command file — never the other way
round.

## Layering rules

- **`core/`** is shared infrastructure. Dependencies point one way:
  everything may import `core/`, `core/` does not import `packages/`
  at module level (the few exceptions are lazy, function-level imports
  for feature probes such as `doctor`).
- **`packages/`** holds independent security capabilities. Each
  package owns its CLI, tests, and domain logic. Cross-package imports
  stay minimal; where capabilities genuinely compose, one package may
  drive a sibling (e.g. `static-analysis` runs the `semgrep` and
  `coccinelle` stages).
- **`libexec/`** scripts are thin dispatch shims for the decision
  layer; they delegate to `core/` or `packages/` and hold no logic
  worth testing on its own.
- **`engine/`** separates detection rules from the packages that run
  them, so rule updates never touch package code.
- Structural facts vs reasoning: `core/inventory/` captures what the
  code *is* (file enumeration, function extraction, call graph);
  `core/analysis/` reasons about it (reachability, taint summaries,
  the binary oracle). Keep new code on the right side of that line.
- `core/llm/` is the only place provider APIs are touched. It gives
  every caller cost tracking, retries, caching, and the per-model
  reliability scorecard for free.

## Package map

One line of purpose per real capability (run `ls packages/` for the
authoritative list; each package's README or module docstring is the
detail):

- **`static-analysis`** — Semgrep policy-group scanning plus the
  Coccinelle stage; normalises everything to SARIF (`scanner.py`).
- **`semgrep`** / **`coccinelle`** — rule-pack management and the
  `.cocci` runner behind the scan stage, consumed by
  `static-analysis` and the audit tool chain.
- **`codeql`** — CodeQL database creation, suite execution, and
  dataflow validation (SMT path feasibility plus LLM review).
- **`llm_analysis`** — LLM exploitability analysis of findings; the
  orchestrator dispatches `claude -p` sub-agents and correlates
  multi-model verdicts.
- **`exploitability_validation`** — the staged `/validate` pipeline
  proving findings real, reachable, and exploitable.
- **`fuzzing`** — AFL++ campaign orchestration, corpus management,
  crash collection and ranking.
- **`binary_analysis`** — GDB-driven crash triage and context
  extraction for externally- or fuzzer-discovered crashes.
- **`exploit_feasibility`** — binary mitigation analysis; produces the
  `exploitation_paths` verdicts the exploit workflow is gated on.
- **`sca`** — dependency scanning against OSV/KEV/EPSS advisory data,
  SBOM generation, CI gating.
- **`web`** — crawler, fuzzer, and OWASP-style scanner for web
  applications (alpha).
- **`code_understanding`** — the `/understand` modes (map, trace,
  hunt, teach, study).
- **`checker_synthesis`** — turns one confirmed bug into a Semgrep or
  Coccinelle rule and sweeps the codebase for variants.
- **`frida`** — dynamic instrumentation runs (attach/spawn, JS hooks,
  event capture).
- **`joern`** — Joern CPG server lifecycle and queries for the audit
  tool chain.

The hypothesis-driven audit itself lives in `core/audit/`
(orchestrator, strategies, gates) because several packages and the
decision layer share it.

## engine/: authoring detection rules

Where rules live:

- `engine/semgrep/rules/<category>/*.yaml` — in-repo Semgrep rules.
- `engine/coccinelle/rules/*.cocci` — Coccinelle semantic patches;
  `prereqs/` holds inventory patches, `source_intel/` the
  source-intel rules.
- `engine/codeql/queries/` and `engine/codeql/suites/` — custom CodeQL
  queries and suite configs. Defaults are the official per-language
  `security-and-quality` suites; see `engine/codeql/suites/README.md`.

Conventions a new rule must follow:

- **Fixture gate.** Every in-repo Semgrep rule ships a positive
  fixture (must fire) and a negative fixture (must stay silent) under
  `engine/semgrep/tests/fixtures/`; the real semgrep binary
  adjudicates in `engine/semgrep/tests/test_rule_fixtures.py`.
- **Negative controls.** `engine/negative_controls/` holds known-safe
  code that superficially resembles each bug family (e.g. a
  parameterised query whose SQL text still contains `SELECT` and a
  `LIKE '%'`). Synthesized per-hypothesis rules are run against the
  matching control at sweep time (`core/audit/sweep.py`); a rule that
  fires on it is a presence detector and its verdict is capped at
  inconclusive. A new bug-family keyword needs a control fixture.
- **Data packs over hardcoding.** Identifier vocabularies live in
  JSON packs, not in rule or Python logic:
  `engine/coccinelle/source_intel/crypto/packs/` (schema and growth
  rules in its README — a new library is a new pack file, no `.cocci`
  edit; invalid entries are dropped with a warning, a structurally
  broken pack is skipped, never fatal),
  `core/audit/data/vocab_packs/`, and
  `core/function_taxonomy/data/packs/`. The vocab-lists CI gate
  (below) enforces this.

## CLI help-text standard

Every CLI entry point (package agents, `libexec/` scripts) ships a
`--help` with:

1. a one-paragraph description of what it does;
2. required arguments;
3. optional arguments with their defaults;
4. at least two usage examples.

`--help` is authoritative. End-user docs describe the operator
surface and defer to it — do not add flag inventories to `docs/`
pages when you add a flag; update the help text.

## Sandbox: what code may assume

[sandbox.md](sandbox.md) is the operator surface; the `sandbox()` /
`run()` docstrings in `core/sandbox/` are the kwarg reference. The
model in ten lines:

- Isolation composes up to six layers — user, network, PID, IPC, and
  mount namespaces plus Landlock/seccomp/rlimits. Each layer falls
  back gracefully with a one-time warning; nothing silently downgrades
  to "no isolation", and the untrusted entry points fail closed
  rather than degrade silently.
- Egress-proxy enforcement is tiered, strongest available first:
  empty network namespace bridged to the proxy; Landlock pin to the
  proxy port plus a UDP block; environment variables alone as the
  last resort.
- New code picks a **trust level**, not kwargs: `run_untrusted()` /
  `run_untrusted_networked()` for anything attacker-derived,
  `run_trusted()` only when the full command line is RAPTOR-owned.

What code must **never** assume: that a specific layer engaged on a
given host — the run's `sandbox_info` stamps (`proxy_enforcement`,
`mount_ns_degraded`, `degraded_net_deny`, `audit_engaged`) are the
truth, so read them instead of assuming; that `$HOME`, `/tmp`, or the
network inside a sandbox are the host's; or that it may bypass
`core.sandbox` for subprocess work touching untrusted input.

## Running tests

Run from the repository root. Install the locked development tools and
optional source parsers, then use the project environment through `uv run`:

```bash
uv sync --locked --group dev --extra grammars
uv run --extra grammars python -m pytest core packages -n 4 --dist worksteal -q
```

Keep `--extra grammars` on subsequent `uv run` commands so syncing retains
the optional parsers. No virtualenv activation is needed. If another
virtualenv is active, `env -u VIRTUAL_ENV uv run ...` avoids the environment
mismatch warning while using the project's `.venv`.

On macOS, run natively to exercise Seatbelt; Linux ELF and `/proc` tests
require a Linux host (or the devcontainer). Binary-oracle integration
tests need GNU binutils as well as a compiler. Installing binutils on a
Mac does not turn native Mach-O fixtures into ELF fixtures.

The default test tier excludes slow, network integration, and corpus tests.
Add `-m ""` to select all tiers; optional tools and service credentials are
still required for their respective tests. Tests should gate missing
prerequisites explicitly while keeping product failures visible.

`-n 4` runs four pytest-xdist worker processes; `--dist worksteal` lets
workers share remaining tests to reduce idle time. pytest-xdist is included
in the `dev` dependency group installed above. Start with four workers and
adjust for available memory; `-n auto` uses the detected CPU count and can
start many workers. Omit `-n 4 --dist worksteal` for a serial run.

To run with four workers while keeping terminal output and a diagnostic
log, including native Python crash tracebacks when available:

```bash
results_dir=$(mktemp -d /tmp/raptor-tests.XXXXXX)
echo "Results: $results_dir"
set -o pipefail

PYTHONFAULTHANDLER=1 env -u VIRTUAL_ENV uv run --extra grammars python -m pytest \
  core packages .github/tests .github/scripts/tests \
  -n 4 --dist worksteal -v --tb=short -ra \
  --junitxml="$results_dir/results.xml" \
  2>&1 | tee "$results_dir/tests.log"
```

Each run saves its log and JUnit XML in the printed directory under `/tmp`,
keeping those outputs out of the checkout.

`-v` records test names as they run, `2>&1` includes stderr, and `pipefail`
preserves a failing pipeline status. The text log remains useful if the
process crashes; JUnit XML may be incomplete if pytest cannot finish.

### Intentional native crashes

Ordinary runs exclude tests marked `intentional_crash`, even with `-m ""`.
Default tests still exercise subprocess isolation, unexpected child exits,
real signal delivery with SIGTERM, and output capture. Tests that must prove
recovery from a real fatal native signal require `--run-crash-tests`.

The dedicated nightly job runs these tests on Linux and macOS. To reproduce
that coverage explicitly (this may generate OS crash reports or dialogs):

```bash
results_dir=$(mktemp -d /tmp/raptor-crash-tests.XXXXXX)
echo "Results: $results_dir"
set -o pipefail
PYTHONFAULTHANDLER=1 env -u VIRTUAL_ENV uv run --extra grammars python -m pytest \
  core/symbolic/tests -m intentional_crash --run-crash-tests -v --tb=short -ra \
  --junitxml="$results_dir/results.xml" 2>&1 | tee "$results_dir/tests.log"
```

Disabling core dumps does not prevent macOS diagnostic reports. Keep crash
reporting enabled for unexpected product failures. Mark tests that really
need fatal signals; test parsing/classification with ordinary child exits
and supplied result data when kernel signal delivery is not the assertion.

## Writing hermetic tests

A test must pass independently and leave the process ready for the next
test, including after an assertion, import failure, or timeout. Pytest
workers reuse processes; xdist does not isolate tests from earlier tests
on the same worker or from files shared by other workers.

- **Own writable state.** Put homes, registries, caches, output directories,
  sockets, and configuration under `tmp_path` or a managed temporary
  directory. Pass explicit paths where supported. Do not discover the
  operator's active project, credentials, or installed tool cache unless
  that host integration is the stated, appropriately marked test scope.
- **Register cleanup before mutation.** Use `monkeypatch`, context managers,
  or fixture finalizers for environment variables, cwd, globals, logging
  handlers, signals, and module replacements. Register cleanup immediately
  after acquiring a resource, before work that can fail; code after a
  fixture's `yield` does not run if setup fails before reaching it.
- **Preserve inherited values.** A missing environment key differs from an
  empty value. A missing `sys.modules` entry differs from an entry set to
  `None`. Restore the original object when callers may retain references.
  If production code writes an environment key directly, register that
  key with monkeypatch before calling it; deleting an already-absent key
  alone does not register a restoration value.
- **Isolate CLI execution.** Imported scripts and `main()` calls can change
  `sys.path`, `sys.argv`, session pins, and logging. Scope both loading and
  execution where needed. Use a temporary path list rather than inserting
  a path and later removing the first equal string. Prefer a subprocess
  when the behavior requires interpreter startup or process-lifetime
  initialization. Library imports should leave path setup to entry points.
- **Finish background work.** Stop and join owned threads, shut down
  executors and servers, and terminate and reap owned children in teardown.
  A daemon flag does not provide test cleanup. Use events or a readiness
  handshake instead of sleeps, and report bounded timeout failures with
  child output. A deadline-calculation test should not start a real worker.
- **Keep fakes local to the seam.** Patch the consumer's binding rather
  than changing a shared module such as `threading.Event` for every user.
  Stub incidental network, paid LLM, JVM, or tool startup when testing a
  different behavior. Preserve real execution when that boundary is the
  behavior under test, and use the corresponding integration markers.
- **Choose stable assertions.** Verify outcomes and bounded work rather
  than fragile elapsed-time ratios. Include actionable diagnostics for
  child startup failures and ensure resources are cleaned up on failure.

For example, loading a dispatch script should preserve the caller's path
object and restore its trust marker:

```python
import sys
from unittest.mock import patch

def load_cli(monkeypatch, loader, module):
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    with patch.object(sys, "path", sys.path.copy()):
        loader.exec_module(module)
    return module
```

This example scopes import-time path changes only; check `main()` separately
if it also mutates process state. A module-scoped fixture cannot depend on
the function-scoped `monkeypatch` fixture: use `pytest.MonkeyPatch.context()`
with the required lifetime instead.

For a change involving shared state, run the affected tests alone and with
their related tests in one process. Then exercise randomized order and
multiple workers, for example:

```bash
RAPTOR_RANDOMISE_TESTS=123 pytest -q path/to/tests
RAPTOR_RANDOMISE_TESTS=456 pytest -q -n 4 path/to/tests
```

Use real test paths and retain a failing seed when reporting a flake.
Randomization and xdist are useful checks, not proof of isolation. For a
suspected leak, compare the relevant state before setup and after teardown,
including object identity or live resources where relevant. Do not hide
leaks with a blanket teardown reset: clean up at the owning fixture or fix
the shared helper or library import that causes them.

## Mechanical gates you will hit

The full control inventory, triggers, and reproduce-locally commands
are in [ci-controls.md](ci-controls.md). The ones that bite
contributors, one line each:

- **ruff** (PR-blocking) — `F401`/`F811`/`F821`/`F841` over changed
  Python files; config in `pyproject.toml`.
- **command-metadata** (PR-blocking,
  `.github/scripts/check_command_metadata.py`) — every
  `.claude/commands/*.md` needs a parseable `dispatch:` field whose
  target exists on disk.
- **env-docs** (PR gate + daily sweep, `.github/scripts/check_env_docs.py`) — extracts
  every environment variable the tree reads or writes; an undocumented
  operator-facing variable fails, and so does a stale entry in
  [environment.md](environment.md).
- **vocab-lists** (PR gate + daily sweep, `.github/scripts/check_vocab_lists.py`) —
  literal function-name lists longer than nine names outside the
  data-pack seams fail; route the names through a pack.
- **miswiring** (PR gate + daily sweep, `.github/scripts/check_miswiring.py`) — dead
  definitions, kwarg/signature mismatches, swallowed exceptions,
  parsed-but-never-read flags. Note it counts textual mentions in
  `docs/`, `.claude/`, `bin/`, `tiers/`, and `.github/` as
  references — a doc line can keep a symbol "alive".
- **optional-dep-imports** (PR gate + daily sweep) — test files importing optional
  packages need an import guard, or they pass on developer hosts and
  fail on bare CI.
- **canonical-json** (PR gate + daily sweep, `.github/scripts/check_canonical_json.py`)
  — canonical JSON byte forms are frozen: inside the MAC/hash module
  list every raw `json.dumps` must be `core.json.dumps_canonical` or
  baselined with a note, and a `json.dumps` result flowing into
  `hashlib`/`hmac` anywhere is a new canonical site that must be
  routed through `dumps_canonical` or baselined.
- **ci-controls doc guard** (PR,
  `.github/tests/test_ci_controls_docs.py`) — every path named in
  [ci-controls.md](ci-controls.md) must exist on disk.
- **preflight hazards** (PR, `.github/workflows/preflight.yml`) —
  re-runs the PR's changed tests under CI-reality hazards (hidden
  optional deps, shuffle legs, duration guard).

Each baseline file under `.github/scripts/*_baseline.json` is an
exception list whose target size is zero: fix the finding, or baseline
it deliberately with a note.
