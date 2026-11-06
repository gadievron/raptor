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

- [Working on the development version](#working-on-the-development-version)
- [The two-layer split](#the-two-layer-split)
- [Layering rules](#layering-rules)
- [Package map](#package-map)
- [engine/: authoring detection rules](#engine-authoring-detection-rules)
- [CLI help-text standard](#cli-help-text-standard)
- [Sandbox: what code may assume](#sandbox-what-code-may-assume)
- [Running tests](#running-tests)
- [Writing hermetic tests](#writing-hermetic-tests)
- [Mechanical gates you will hit](#mechanical-gates-you-will-hit)

## Working on the development version

End-user [installation instructions](installation.md) use the stable RAPTOR
release. For development, clone `main` and install its locked dependencies:

```bash
git clone --branch main https://github.com/gadievron/raptor.git
cd raptor
uv sync --locked --group dev --extra grammars
```

The [current tools image](https://hub.docker.com/r/danielcuthbert/raptor/tags?name=latest)
provides the tool environment. It does not contain RAPTOR's source; mount your
working checkout to run the code you are developing:

```bash
docker pull docker.io/danielcuthbert/raptor:latest@sha256:c0c9526481f34dc402d86419767f85b98f5c9996ee667aa47828323a8907c121
docker run -it \
  -v "$PWD:/workspaces/raptor" \
  -v "/path/to/target-folder:/workspaces/target" \
  docker.io/danielcuthbert/raptor:latest@sha256:c0c9526481f34dc402d86419767f85b98f5c9996ee667aa47828323a8907c121
```

Run these commands from the checkout; replace the target path with your own or
omit that mount. The tools image is shared by releases and development checkouts.
Pulling it updates tools, while switching branches or tags changes RAPTOR itself.
These commands pin the current published tools image by digest; a successful
image publication updates the pin automatically. It does not pin the mounted source. VS Code can also build the
checkout's `.devcontainer` configuration locally.

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

Give payload-heavy parametrizations explicit, short scenario IDs with
`ids=[...]` or `pytest.param(..., id="...")`. The root pytest configuration
also gives unsafe automatic IDs compact labels with stable suffixes: source
text, binary/control characters and oversized values stay out of progress
lines and JUnit names. Ordinary short values and explicit IDs retain their
names. The hook changes display names only; parameter values and test coverage
are preserved.

ASAN execution tests require a clean instrumented program to complete outside
RAPTOR's sandbox, using the same compiler as the exploit validator. This probe
is cached per compiler; an unusable runtime produces a prerequisite skip.
Compile-only tests continue to run, and failures inside RAPTOR's sandbox remain
test failures. This catches startup failures such as the macOS 26 deadlock
reported in [LLVM issue 200447](https://github.com/llvm/llvm-project/issues/200447)
without disabling ASAN tests for an entire operating-system version. See
[AddressSanitizer on macOS](#addresssanitizer-on-macos) if the probe times out.

`-n 4` runs four pytest-xdist worker processes; `--dist worksteal` lets
workers share remaining tests to reduce idle time. pytest-xdist is included
in the `dev` dependency group installed above. Start with four workers and
adjust for available memory; `-n auto` uses the detected CPU count and can
start many workers. Omit `-n 4 --dist worksteal` for a serial run.

To run with four workers while keeping terminal output and a diagnostic
log, including native Python crash tracebacks when available:

```bash
(
results_dir=$(mktemp -d /tmp/raptor-tests.XXXXXX) || exit
set -o pipefail
test_status=0
echo "Results: $results_dir"

PYTHONFAULTHANDLER=1 env -u VIRTUAL_ENV uv run --extra grammars python -m pytest \
  core packages .github/tests .github/scripts/tests \
  -n 4 --dist worksteal -v --tb=short -ra \
  --junitxml="$results_dir/results.xml" \
  2>&1 | tee "$results_dir/tests.log" || test_status=$?

printf '\nTest log: %s\nJUnit XML: %s\n' \
  "$results_dir/tests.log" "$results_dir/results.xml"
exit "$test_status"
)
```

Each run saves its log and JUnit XML in the printed directory under `/tmp`,
keeping those outputs out of the checkout. Both filenames are printed again
at the end, including when tests fail. The subshell returns the test pipeline
status after printing the paths, without exiting your interactive shell.

`-v` records test names as they run, `2>&1` includes stderr, and `pipefail`
preserves a failing pipeline status. The text log remains useful if the
process crashes; JUnit XML may be incomplete if pytest cannot finish.

### AddressSanitizer on macOS

A sanitizer-enabled program can hang before `main()` with an older selected
Xcode runtime, even when newer Command Line Tools are installed. This affects
both test fixtures and normal sanitizer-enabled exploit verification. RAPTOR
adds toolchain advice to Mac ASAN/TSAN execution timeouts and ASAN prerequisite
skips; a witness timeout remains `UNKNOWN`, since the program itself could also
have looped. The advice is not evidence of a sanitizer failure.

Check which tools are selected:

```bash
xcode-select -p
xcrun --find clang++
xcrun clang++ --version
xcodebuild -version
pkgutil --pkg-info=com.apple.pkg.CLTools_Executables
```

The Xcode and standalone Command Line Tools versions can differ. Apple
[documents sanitizer startup hangs with Xcode 26.3 or older and recommends
Xcode 26.4](https://developer.apple.com/documentation/xcode-release-notes/xcode-26_4-release-notes).
Updating macOS or installing newer tools does not necessarily change the
selected developer directory. A matching stack is described in
[LLVM issue 200447](https://github.com/llvm/llvm-project/issues/200447).

Finish running tests/builds before switching. If the standalone Command Line
Tools are newer and installed at the standard location, select them with:

```bash
sudo xcode-select --switch /Library/Developer/CommandLineTools
xcrun clang++ --version
```

This changes the developer directory for other builds too. Alternatively,
update the selected Xcode to a fixed release. To select Xcode again later:

```bash
sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer
```

RAPTOR sanitizes subprocess environments: `DEVELOPER_DIR` is not preserved by
`get_safe_env()`, so an override in the parent shell can disappear before
compilation. An interactive compiler-version check with that override alone
does not prove the compiler used by RAPTOR changed. The prerequisite skip now
includes its compiler path; verify the actual selected toolchain and rerun the
ASAN tests in a fresh pytest process. The probe checks whether a clean program
runs, rather than deciding from a compiler version string. Compile-only tests
and sandbox failures remain separate from this prerequisite gate. RAPTOR does
not automatically switch tools or disable requested instrumentation.

### Containing deliberate desktop crashes

Some fixtures deliberately abort an interpreter outside RAPTOR's normal
containment. Use the shared test-only helper in
`core/testing/expected_crash.py` for those fixtures. On Linux and macOS it
traces a direct, owned child, records the attempted signal, then kills and
reaps the stopped child before forwarding that signal to the OS crash
handler. This avoids deliberate-crash reports on desktop machines without
changing production execution or system crash-reporting settings.

Use the `expected_crash_runner` fixture when a test needs an attempted
fatal signal but does not need the child's final fatal exit status:

```python
def test_owned_abort(tmp_path, expected_crash_runner):
    import signal
    import sys

    ready = tmp_path / "ready"
    result = expected_crash_runner(
        [sys.executable, "-c",
         f"from pathlib import Path; import os; Path({str(ready)!r}).touch(); os.abort()"],
        ready_file=ready,
        expected_signal=signal.SIGABRT,
    )
    assert result.observed_signal == signal.SIGABRT
    assert result.process.returncode == -signal.SIGKILL
```

Use a fresh readiness marker written immediately before the intentional
operation so an interpreter startup failure cannot satisfy the assertion.
The helper preserves stdout/stderr and supports stdin, timeouts, cwd, and
environment overrides. Unexpected signals, failed exec, missing readiness,
and timeouts fail the test. Unsupported hosts or denied tracing skip at the
fixture's non-crashing capability probe; nightly CI requires execution
without skips on Linux and macOS. A fresh interpreter forks the tracee,
which also supports threaded pytest plugins and xdist workers.

Prefer SIGTERM for tests that need only unexpected worker loss, and supplied
result data for parsing or classification tests. Apply suppression to the
fixture that would notify the desktop crash handler, rather than gating
all tests with fatal-signal assertions. Sandbox signal and evidence tests
keep their real execution, existing tier markers, and prerequisites on
every supported host. They do not require an additional crash opt-in or
CI-only permission. Never replace their actual wait status with an invented
SIGABRT/SIGSEGV status from the wrapper.

Use the wrapper only for direct test-owned children, not arbitrary process
trees or processes already controlled by a debugger. Do not loosen sandbox
policy to permit tracing. Keep prerequisite probes inside test execution;
a fatal probe at module import runs before pytest can select tests.
Disabling core dumps alone does not prevent desktop crash notifications.
Unexpected product crashes retain their normal reporting behavior.

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

### Detecting accidental LLM calls

The fast CI unit-test job loads `core.testing.llm_tripwire`. Every worker
gets a loopback OpenAI error endpoint and private model configuration;
subprocesses inherit that configuration. Any traffic fails the session,
even when the test passes because production code swallowed the error.
Request journals retain test IDs and bounded prompt excerpts, never
authorization headers. Explicit fake HTTP servers remain usable.

Run this layer locally, including on macOS, with:

```bash
python -m pytest -p core.testing.llm_tripwire --llm-tripwire-dir /tmp/llm-evidence core packages
```

Linux CI also redirects published provider/broker hostnames and configured
regional endpoints to an untrusted TLS sink. Certificate failures still
count: before rejecting TLS, the sink maps the connection tuple to a socket
inode, owning PID, and pytest worker via `/proc`. Exec-inherited
`PYTEST_CURRENT_TEST` identifies child origins; the worker publishes its
active and previous tests across setup, call, and teardown. These fields
can differ when background work survives its originating test. Unknown
ownership still fails CI. A final independent connection check also runs
when pytest exits unsuccessfully. CI restores its original hosts file.

This is a tripwire, not a complete network firewall: arbitrary new endpoint
hosts, literal IPs, external forward proxies, and private resolver/hosts
namespaces can bypass hostname redirection. Add configured endpoints with
the prepare command's `--models` option. Keep new provider endpoints in the
catalog and mock every model transport in CI; a live provider is never a
valid fallback for missing test fixtures. HTTP journals and connection
evidence are uploaded as CI artifacts.

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
