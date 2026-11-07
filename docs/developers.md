# Developer Guide

[Documentation index](README.md)

This is the technical reference for contributors: architecture, package
responsibilities, rule authoring, sandbox assumptions, test execution,
and hermetic test patterns. [CONTRIBUTING.md](../CONTRIBUTING.md) covers the
contribution workflow, [initial setup](../CONTRIBUTING.md#getting-started),
[test-writing requirements](../CONTRIBUTING.md#tests), style, and security
rules. Start there when preparing a change; use this page for implementation
and testing details.

When using an AI coding agent, ask it to read this guide and
[CONTRIBUTING.md](../CONTRIBUTING.md) before editing code. Have it follow the
relevant test and companion-check requirements, and revisit the affected
sections when the task changes. Changes written by an agent have the same
review and validation requirements as other contributions.

Keep this reference focused on orientation and practical developer workflows.
The tree, docstrings, and `--help` output own API and CLI details;
[CI controls](ci-controls.md) owns the full check inventory.

**Related documentation:**
[Contributing](../CONTRIBUTING.md) |
[Architecture](architecture.md) |
[CI controls](ci-controls.md)

**On this page:**

- [Documentation audiences](#documentation-audiences)
- [Working on the development version](#working-on-the-development-version)
- [The two-layer split](#the-two-layer-split)
- [Layering rules](#layering-rules)
- [Package map](#package-map)
- [engine/: authoring detection rules](#engine-authoring-detection-rules)
- [CLI help-text standard](#cli-help-text-standard)
- [Sandbox: what code may assume](#sandbox-what-code-may-assume)
- [Running tests](#running-tests)
- [Sandbox wrapper tests](#sandbox-wrapper-tests)
- [Writing hermetic tests](#writing-hermetic-tests)
- [Mechanical gates you will hit](#mechanical-gates-you-will-hit)

## Documentation audiences

Most pages under `docs/` are user-facing. Keep them focused on user tasks,
configuration, observable behavior, and limitations. Contributor process,
CI mechanics, and implementation detail belong in explicitly technical
references such as this guide, the architecture reference, and CI controls.
Follow each page's stated audience and purpose; link to the appropriate
reference instead of duplicating its detail in user instructions.

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
docker pull docker.io/danielcuthbert/raptor:latest@sha256:1887536162310b2ba841d4036f80b769dfcd4343a21a0d79985fec9f6a8bc1f2
docker run -it \
  -v "$PWD:/workspaces/raptor" \
  -v "/path/to/target-folder:/workspaces/target" \
  docker.io/danielcuthbert/raptor:latest@sha256:1887536162310b2ba841d4036f80b769dfcd4343a21a0d79985fec9f6a8bc1f2
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

### Sandbox wrapper tests

Every policy-owning sandbox wrapper must have an executable test case. The
registry in `.github/sandbox-wrapper-tests.json` binds each source file and its
sandbox entrypoints to reviewed pytest cases. The CI census detects direct public
sandbox calls, including import aliases, outside the sandbox backend itself.
Self-confining or delegated workers without a direct call need an explicit
registry row and discovery rationale. Backend implementations remain covered by
`core/sandbox/tests`.

A binding must exercise the adapter's dispatch or refusal path and assert its
security contract; an import-only test is insufficient. Multiple dispatch paths
need cases for their different policies. Update the bindings when adding an
entrypoint. The census enforces registration and selector existence; reviewing
whether the assertions cover the policy remains part of code review.

Run the selected contracts with the project environment:

```sh
python .github/scripts/run_sandbox_wrapper_tests.py --lane contracts --report-dir out/wrapper-contracts
```

The `Sandbox wrapper acceptance` workflow runs those contracts on Linux and
macOS, followed by existing native suites for binary inspection, streamed output,
pwntools, SMT, radare2, Python/Ruby gadget parsers, Joern's guard, PoC execution,
fuzz/build dispatch and symbolic workers. Linux additionally exercises loader and
procfs probes. These are real platform backends: expected execution counts are
checked, and a required skipped case fails acceptance. Linux containment results
do not substitute for Seatbelt results.

```sh
python .github/scripts/run_sandbox_wrapper_tests.py --lane native --report-dir out/wrapper-native
```

The plan and summary distinguish native execution from cells not exercised.
Vendor-dependent Joern service and CodeQL traced-build cases, and rr cases that
need compatible Linux perf/PMU hardware, require explicit selection on a prepared
host. They are not counted as hosted CI passes. For example:

```sh
python .github/scripts/run_sandbox_wrapper_tests.py --lane native --family rr-record-pack --include-manual --report-dir out/wrapper-rr
```

Other vendor adapters have portable dispatch contracts; the matrix does not claim
that every installed vendor tool has been exercised natively. Add native families
as their dependencies can be provisioned reliably. The runner uses disposable
HOME, output and scratch directories, copies no account state, and launches no
frontend. Native probes use owned files and processes.

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
- **Choose the child's launch context.** A subprocess inherits the caller's
  environment; a fresh interpreter alone does not isolate launcher credentials
  or scratch metadata. Standalone CLI tests should use
  `core.testing.standalone_cli` to own that state. Tests of session inheritance
  must instead construct a valid owned launch context. When parent and child
  exchange signed artifacts, explicitly share a test-owned signing directory
  for the required lifetime, including module-scoped setup. Exercise rejection
  of stale inherited state without weakening production guards.
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

For mocks on borrowed modules, use `core.testing.module_bindings` to own
only the consumer's binding. Both `patch_module_attribute` and
`mock_module_attribute` accept dotted bindings such as `"os.path"` or
`"importlib.util"`. They copy every module in that path and restore the
original root binding when the owning scope exits. Unselected branches
remain borrowed. Existing literal dotted bindings from
`scoped_function_imports` retain their existing meaning. The complete private
path is built before publication,
so an invalid nested binding cannot leave a partially replaced root.
For function-local imports, use `scoped_function_imports`. If a dictionary
registry already stores the selected functions, pass its module binding in
`registries=("registry_name",)` so dispatch uses private wrappers too. The
registry is shallow copied and restored by identity with the function bindings;
unselected entries retain their original values.

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

### Companion checks for test changes

A changed test can pass while its ownership or transport census fails in
another shard. Include the relevant companion change in the same patch,
and rerun its check after rebasing onto changes to the same helpers.

| Change | Companion update and validation |
| --- | --- |
| Add, rename, or remove a live compiler, Semgrep, or preprocessor test | Use the guarded runner in `core/audit/tests/_live_transport.py`; update the corresponding exact caller inventory in `core/audit/tests/test_live_transport_guards.py` and run that file. Keep expected callers explicit so new unguarded calls remain detectable. |
| Move a fault injection from a native OS/module attribute to a helper, or change its consumer | Update the relevant inventory under `core/testing/tests/`, such as `test_os_fault_fixture_scope.py`. Remove obsolete native-patch entries only when that patch no longer exists; retain the domain test for the replacement helper's behavior. Run the inventory and the affected domain tests. |
| Change a fixture helper's API | Update fake adapters used by ownership and fault-injection tests. For example, a monkeypatch adapter must forward supported `raising=` arguments and `setitem` operations. Preserve undo behavior, borrowed object identities, and error/interrupt coverage; run affected ownership tests in randomized serial and xdist modes. |
| Change a curated rule's evidence role | Update tests that pin that rule's role and its result semantics. A confirm-only rule's zero-match is inconclusive; do not restore refutation authority merely to satisfy an old assertion. |
| Add a workflow or checker test under `.github/tests` or `.github/scripts/tests` | Keep it compatible with the `ci-lint-tests` lane, which installs only pinned pytest and uses the standard library. A developer environment with PyYAML installed can hide a collection failure. Reuse the existing scoped workflow-block extraction patterns; do not skip required workflow assertions when an optional parser is absent. |

For live-tool test changes, the quick companion check is:

```bash
python -m pytest core/audit/tests/test_live_transport_guards.py -q
```

For fixture changes, run the specific ownership harness and domain tests,
using the randomized-order commands above. Run CI-filter tests in the
pytest-only environment defined by `.github/workflows/tests.yml`, rather
than relying solely on the fully provisioned development environment.

When changing an evidence format or moving records between fields, trace the
writer, authentication binding, and downstream readers together. Keep data
quality separate from behavior classification: filtering bookkeeping records
must not erase capture loss or turn an unobserved event into proven absence.
Include an end-to-end reader check alongside local serialization tests.

### Refactors and audit records

Audit baselines and registries may be keyed by file and symbol. When moving
or renaming code, review affected records and honor their notes; update or
remove entries according to whether their rationale still applies. Run the
relevant tree-wide gates alongside functional tests after the refactor or
rebase. A new finding paired with a stale entry can indicate that an audit
record was separated from its code. Gate commands live in [CI controls](ci-controls.md).

## Mechanical gates you will hit

Run the repository-invariant checks relevant to your change alongside its
functional tests and lint. These gates also inspect relationships that a
passing unit test does not establish, such as registered call sites, artifact
consumers, and reviewed exceptions. Documentation references can affect some
findings, so include relevant gates after documentation changes or a rebase.

[CI controls](ci-controls.md#gate-details-and-local-reproduction) owns the
control inventory, triggers, and local commands.
[Reviewing invariant findings](ci-controls.md#reviewing-invariant-findings)
explains baseline review, fixed schemas, and deferred cleanup notes.
