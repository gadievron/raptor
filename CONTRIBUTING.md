# Contributing to RAPTOR

RAPTOR is mostly built with AI under human direction. Contributions are
welcome — whether you're writing code by hand, with an AI, or a mix of
both. The conventions below keep the codebase consistent regardless of how
the code was written.

When using an AI coding agent, ask it to read this document and the
[developer guide](docs/developers.md) before editing code, and to run the
relevant checks described there.

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
- Follow the [companion checks for test changes](docs/developers.md#companion-checks-for-test-changes).
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


### Sandbox wrapper tests

Policy-owning sandbox wrappers need reviewed executable tests for their
security contract. Follow the [wrapper testing guide](docs/developers.md#sandbox-wrapper-tests)
when adding or changing an entrypoint.


## Style

- Run `ruff check --fix` on every file you touch before committing.
- Match the style of surrounding code.


## Documentation

Most `docs/` pages are user-facing. Keep contributor and implementation
instructions in the appropriate technical references; follow the
[documentation audience guidance](docs/developers.md#documentation-audiences).


## CI checks

Changes must pass the relevant tests, lint, and repository-invariant gates.
Fix new findings, or document a deliberate exception with its review note.
Include the [companion checks](docs/developers.md#companion-checks-for-test-changes)
and [audit-record review](docs/developers.md#refactors-and-audit-records) that
apply to your change, including after a rebase.

See [CI controls](docs/ci-controls.md) for the gate inventory, local commands,
and baseline review rules.


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
