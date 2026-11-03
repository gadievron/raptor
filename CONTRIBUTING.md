# Contributing to RAPTOR

RAPTOR is mostly built with AI under human direction. Contributions are
welcome — whether you're writing code by hand, with an AI, or a mix of
both. The conventions below keep the codebase consistent regardless of how
the code was written.

This page covers the contribution workflow: setup, change requirements,
test-writing conventions, style, and security rules. The
[developer reference](docs/developers.md) explains architecture, package
responsibilities, detailed test execution, and hermetic test patterns.


## Getting started

```bash
git clone https://github.com/gadievron/raptor.git
cd raptor
uv sync --locked --group dev --extra grammars  # test tools and source parsers
uv tool install semgrep                # required for /scan
```

Run the test suite:

```bash
uv run --extra grammars python -m pytest core/ packages/ -x -q
```

For platform prerequisites, test tiers, and logging, see the
[developer testing reference](docs/developers.md#running-tests).

Launch RAPTOR itself:

```bash
claude    # from the repo root
```


## Code organisation

See the developer reference for [layering](docs/developers.md#layering-rules)
and the [package map](docs/developers.md#package-map).

- **`core/`** — shared infrastructure. Each subdirectory is a Python
  package with its own `tests/` directory. Core packages are imported by
  everything else; avoid module-level imports from `packages/` (the layering
  reference documents the limited lazy-import exceptions).

- **`packages/`** — independent security capabilities (scanning, fuzzing,
  CodeQL, SCA, etc.). Each package owns its domain logic, CLI, and tests.
  Packages import from `core/` only — no cross-package imports.

- **`libexec/`** — CLI entry points called by the LLM via slash commands.
  These exist so that Claude Code can invoke them as shell commands. Thin
  wrappers that delegate to `core/` or `packages/`.

No bare `.py` files in `core/` or `packages/` — every module lives in a
subdirectory package. New modules go in `core/` if they're shared
infrastructure, `packages/` if they're a self-contained capability.


## Use existing infrastructure

Before writing new code, check whether `core/` already has what you need.
Don't reinvent things that already have components in core, and don't pull
in new dependencies when an existing module covers it.

- **LLM calls** go through `core/llm/` — never call provider APIs
  directly. This gives you cost tracking, retries, caching, scorecard,
  and multi-provider support for free.
- **Subprocess execution** goes through `core/sandbox/` — never use
  `os.system` or bare `subprocess.run`.
- **Configuration** goes through `core/config/` — don't invent ad-hoc env
  vars or hardcode values.
- **Findings** follow the standard schema in `core/models/` — don't invent
  new finding shapes.
- **New dependencies** need justification. Check `pyproject.toml` first;
  if something similar is already available in core, use that instead.


## Adding commands

Slash commands live in `.claude/commands/<name>.md` with a `dispatch:`
frontmatter field pointing at the CLI entry point. The entry point goes in
`libexec/`:

- Guard with `_RAPTOR_TRUSTED` (the launcher sets this; direct invocation
  is rejected)
- Set up paths via `Path(__file__).resolve().parents[1]` — don't rely on
  `RAPTOR_DIR`
- Delegate to `core/` or `packages/` — keep the script thin


## Tests

For execution and prerequisites, see [Running tests](docs/developers.md#running-tests);
for isolation and cleanup patterns, see
[Writing hermetic tests](docs/developers.md#writing-hermetic-tests).

- Tests live in `tests/` subdirectories alongside the code they test.
- Use `pytest`. No `jsonschema` validation — assert on actual data shapes.
- Test against production-class object shapes, not toy stubs.
- Keep tests hermetic: own temporary state and restore process state and
  resources on success and failure. Follow the
  [hermetic test guidelines](docs/developers.md#writing-hermetic-tests),
  including the CLI-loading and randomized-order checks.
- When testing sandbox behaviour, use the sandbox itself (don't mock it).
- Gate slow tests (network, LLM, subprocess) with the marker
  doctrine: `@pytest.mark.slow` / `integration` / `corpus` (deselected
  by default via pytest.ini, run by the nightly lanes), or
  `@pytest.mark.skipif` for environment-dependent cases — the fast
  suite stays under a few seconds.


## Style

- Run `ruff check --fix` on every file you touch before committing.
- Match the style of surrounding code.


## CI checks

Beyond the test suite and lint (which run on every PR — including
`check_command_metadata.py`, which requires every `.claude/commands/*.md`
to carry a parseable `dispatch:` field whose target exists on disk), the
repo-invariant detectors are PR gates too: the `repo-invariants` job in
`.github/workflows/lint.yml` runs them on every pull request, push to
`main`, and merge-queue entry, and
`.github/workflows/miswiring-scan.yml` re-runs the same set daily as a
belt-and-braces sweep. A new finding fails the job; deliberate
exceptions go in the detector's baseline JSON with a note. The two you
are most likely to hit:

- **Miswiring scan** (`.github/scripts/check_miswiring.py`) — detects
  kwarg/signature mismatches, broken in-repo imports, dead definitions,
  write-only or reader-orphan run artifacts, silently-swallowed
  exceptions, and config fields / CLI flags / env vars that are parsed
  but never read. New findings fail against
  `.github/scripts/miswiring_baseline.json`: fix the miswiring, or
  (deliberately, with a note) add the key to the baseline.

- **Vocab-list guardrail** (`.github/scripts/check_vocab_lists.py`) —
  flags new literal function-name lists (or regex alternations) longer
  than nine names outside the data-pack and taxonomy seams. Vocabulary
  belongs in a data pack (`core/audit/data/vocab_packs/`,
  `core/function_taxonomy/data/packs/`,
  `engine/coccinelle/source_intel/crypto/packs/`), the study-learned
  domain model, or the central taxonomy — not hardcoded in logic. New
  findings fail against `.github/scripts/vocab_baseline.json`; route the
  names through one of those seams, or baseline the entry with a note.


### Deliberate keep-blocks (REVISIT)

The miswiring baseline carries two blocks of dead-code entries that
were deliberately KEPT by operator decision (2026-08-16) rather than
deleted — each entry's `note` says why:

- `kept: public API surface … — revisit` —
  `packages/exploit_feasibility` names kept as library surface with
  zero in-repo consumers.
- `kept: pending work — autonomous fuzzing loop feature seed …` —
  `packages/autonomous` seeds for the planned autonomous fuzzing loop,
  unwired since introduction.

The convention is grep, not automation (deliberate — these are
judgement calls, not mechanically decidable): when you touch one of
those modules, grep the baseline for its keep-block phrasing
(`grep 'kept:' .github/scripts/miswiring_baseline.json`) and re-ask
whether the block still deserves keeping — wire the entries you are
adopting, or delete the ones your change obsoletes and drain their
baseline entries in the same commit.


## Security conventions

RAPTOR scans untrusted repositories. Code that processes untrusted input
must follow these conventions:

- **Sandbox:** run external tools via `core.sandbox.run` (Linux namespaces,
  Landlock, seccomp). Don't shell out with `os.system` or unsandboxed
  `subprocess.run`.
- **Clean environment:** use `RaptorConfig.get_safe_env()` when spawning
  subprocesses — it strips everything except an explicit allowlist.
- **No shell interpolation:** never interpolate file paths from scanned
  repos into shell command strings. Use list-based subprocess arguments.
- **Path traversal:** reject `..` segments and absolute paths in any
  user/repo-supplied file path before writing.
- **Prompt injection:** LLM prompts that include content from scanned repos
  (file contents, commit messages, finding descriptions) must escape or
  fence that content so it cannot be interpreted as instructions.
- **Output escaping:** findings surfaced in terminal, JSON, or markdown
  must not allow repo-controlled strings to inject formatting or markup.


## What not to do

- Don't add paths to `sys.path` beyond `os.environ["RAPTOR_DIR"]`.
- Don't hardcode LLM model names — use the config system.
- Don't commit API keys, server addresses, or internal infrastructure
  details.


## Where help is welcome

- Browser-engine crawling and DOM XSS coverage for the web scanner (Playwright is pinned but unused)
- SSRF rule coverage for annotation-driven frameworks (Spring `@RequestParam`, FastAPI typed params) — semgrep cannot match these sources, so alternative approaches are welcome
- YARA signature generation
- Ports to other AI coding tools (Cursor, Windsurf, Copilot, Cline)
- Better firmware analysis coverage
- Anything you think is missing

## Releases and changelog

Releases are tagged as `vX.Y.Z` and built automatically by CI. Commit prefixes determine
what goes in the changelog: `feat:` for new features, `fix:` for bug fixes, `security:`
for security changes, `docs:` for documentation. Anything without a prefix lands in
"Other changes". No strict convention required, but it helps.

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
