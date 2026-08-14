# Contributing to RAPTOR

RAPTOR is mostly built with AI under human direction. Contributions are
welcome — whether you're writing code by hand, with an AI, or a mix of
both. The conventions below keep the codebase consistent regardless of how
the code was written.


## Getting started

```bash
git clone https://github.com/gadievron/raptor.git
cd raptor
pip install -r requirements.txt
pip install -r requirements-dev.txt   # ruff, mypy
pip install semgrep                    # required for /scan
```

Run the test suite:

```bash
python -m pytest core/ packages/ -x -q
```

Launch RAPTOR itself:

```bash
claude    # from the repo root
```


## Code organisation

- **`core/`** — shared infrastructure. Each subdirectory is a Python
  package with its own `tests/` directory. Core packages are imported by
  everything else; they must not import from `packages/`.

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
- **New pip dependencies** need justification. Check `requirements.txt`
  first; if something similar is already available in core, use that
  instead.


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

- Tests live in `tests/` subdirectories alongside the code they test.
- Use `pytest`. No `jsonschema` validation — assert on actual data shapes.
- Test against production-class object shapes, not toy stubs.
- When testing sandbox behaviour, use the sandbox itself (don't mock it).
- Gate slow tests (network, LLM, subprocess) with
  `@pytest.mark.skipif` or the `RAPTOR_SLOW_TESTS` env var so the fast
  suite stays under a few seconds.


## Style

- Run `ruff check --fix` on every file you touch before committing.
- Match the style of surrounding code.


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
