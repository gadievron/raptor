# CI Controls

This is the honest version of how RAPTOR checks its own code.

Some of these things genuinely block a PR. Some just run on a timer and tell us when things are drifting. That distinction matters: having a dependency in the `dev` group is not the same as having a control that stops bad code getting merged.

This page is split into:

- merge and PR gates;
- scheduled assurance jobs;
- workflow hardening;
- tools that are installed but not currently enforced.

## What Actually Blocks A PR

| Control | Tool | Scope |
|---|---|---|
| Python lint gate | Ruff | Changed Python files in a PR |
| Full-tree Python lint audit | Ruff | Entire repository tree |
| Fast Python test suite | Pytest | `core/`, `packages/`, split into subsystem tiers |
| Prompt-envelope audit | Pytest | Registered prompt construction paths |
| Code scanning | GitHub CodeQL Advanced | Python, C/C++, GitHub Actions |
| Slash-command metadata lint | In-tree Python checker | `.claude/commands/*.md` dispatch metadata |
| Dependency regression gate | RAPTOR SCA | PR head versus `main` dependency surface |
| Corpus label schema lint | In-tree Python linter | Corpus label JSON files |
| Corpus label pin lint (PR) | In-tree Python linter | Changed label files in a PR |
| SARIF known-FP suppressions | In-tree Python script | CodeQL SARIF output |
| CI controls doc guard | Pytest | This page and its referenced paths |
| PR preflight hazards | In-tree runner | The PR's changed test files |

### Gate details and local reproduction

- **Python lint gate** — [`lint.yml`](../.github/workflows/lint.yml) on `pull_request` and `merge_group`. Rules `F401`, `F811`, `F821`, `F841`; Python 3.10 target (config in `pyproject.toml`). Locally: `ruff check <changed .py files>`.
- **Full-tree Python lint audit** — [`lint.yml`](../.github/workflows/lint.yml) on `push: main`, weekly cron, manual run. Same rule set as the PR gate. Locally: `ruff check .`.
- **Fast Python test suite** — [`tests.yml`](../.github/workflows/tests.yml) on PRs, pushes, merge queue; tiers computed by [`test_scope.py`](../.github/scripts/test_scope.py). Default excludes `slow` and `integration` (markers in `pytest.ini`); `RAPTOR_MAX_TEST_SECONDS=10` per-test wall-clock guard. Locally: `python3 -m pytest core packages`.
- **Prompt-envelope audit** — [`tests.yml`](../.github/workflows/tests.yml), `python-prompt-audit` job. Narrow AST-based audit. Locally: `python3 -m pytest core/security/tests/test_prompt_envelope_audit.py -q`.
- **Code scanning** — [`codeql.yml`](../.github/workflows/codeql.yml) on PRs, pushes, merge queue, weekly cron. Languages `python`, `c-cpp`, `actions`; path exclusions in [`codeql-config.yml`](../.github/codeql/codeql-config.yml); import-graph scope narrowing via [`codeql_scope.py`](../.github/scripts/codeql_scope.py) for PRs. Local CodeQL requires the CLI and packs — use the GitHub workflow.
- **Slash-command metadata lint** — [`lint.yml`](../.github/workflows/lint.yml) on every lint run. Validates `dispatch:` targets and exclusion-list drift. Locally: `python3 .github/scripts/check_command_metadata.py`.
- **Dependency regression gate** — [`sca-pr-gate.yml`](../.github/workflows/sca-pr-gate.yml) on manifest, lockfile, workflow, and container changes. Fails on new findings at `high` severity or above. Locally: `bin/raptor-sca . --out /tmp/sca-pr`, then `bin/raptor-sca diff <base>/findings.json <pr>/findings.json --fail-on-severity high`.
- **Corpus label schema lint** — [`corpus-labels.yml`](../.github/workflows/corpus-labels.yml) on PRs, pushes, merge queue, over `core/audit/corpus/labels/**/*.label.json`. Field sanity, no network, pure stdlib. Locally: `python3 -m core.audit.corpus.lint --mode schema`.
- **Corpus label pin lint (PR)** — [`corpus-labels.yml`](../.github/workflows/corpus-labels.yml) on PRs and merge queue. Sparse-fetches pinned upstream trees to verify pins still resolve. Locally: `python3 -m core.audit.corpus.lint --mode pins --fetch-missing <changed files>`.
- **SARIF known-FP suppressions** — [`codeql.yml`](../.github/workflows/codeql.yml) post-analysis step. Suppresses known false-positive flow classes (e.g. path variables named `*_secret_key` that hold file paths, not secrets). Locally: `python3 .github/scripts/sarif_known_fp_suppressions.py`.
- **CI controls doc guard** — [`tests.yml`](../.github/workflows/tests.yml) on PRs. Validates ruff config lives in `pyproject.toml`, the lint workflow uses config-file discovery, the README links to this doc, and all documented paths exist on disk. Locally: `python3 -m pytest .github/tests/test_ci_controls_docs.py -v`.
- **PR preflight hazards** — [`preflight.yml`](../.github/workflows/preflight.yml) on PRs. Re-runs the PR's changed tests under CI-reality hazards: hidden optional deps, hidden tree-sitter, duration guard, tree hygiene, two shuffle legs. Locally: run the changed tests with the hazard env toggles from the workflow.

## Stuff That Runs On A Timer

| Workflow | Purpose | Cadence | Output / evidence |
|---|---|---|---|
| [`nightly.yml`](../.github/workflows/nightly.yml) | Runs slow and live integration tests that are intentionally excluded from the PR gate | Daily | Workflow logs and test reports; slow step carries a `RAPTOR_MAX_SESSION_SECONDS` wallclock budget (tripwire summary on drift) |
| [`nightly_shuffled.yml`](../.github/workflows/nightly_shuffled.yml) | Re-runs fast-tier tests with distinct random seeds to flush out order-dependent failures (module-grouped shuffle: module order, then intra-module order) | Daily | A failing seed is identified by its matrix job's `seed=` line; each iteration carries a `RAPTOR_MAX_SESSION_SECONDS` wallclock budget |
| [`weekly_corpus.yml`](../.github/workflows/weekly_corpus.yml) | Corpus-scale binary-oracle precision drivers (`-m corpus`): clone + build + coverage over real third-party projects to re-derive the published precision numbers | Weekly (and on demand via dispatch) | Workflow logs and junit artifact |
| [`tests.yml`](../.github/workflows/tests.yml) (cron) | Full test suite, including tiers excluded from the PR gate | Twice weekly | Workflow logs |
| [`miswiring-scan.yml`](../.github/workflows/miswiring-scan.yml) `miswiring` | Dead-code / wrong-call / swallowed-exception sweep via AST analysis ([`check_miswiring.py`](../.github/scripts/check_miswiring.py)) | Daily | New findings fail the job; baseline in `miswiring_baseline.json` |
| [`miswiring-scan.yml`](../.github/workflows/miswiring-scan.yml) `env-docs` | Extracts every env var the tree reads/writes and compares against documentation ([`check_env_docs.py`](../.github/scripts/check_env_docs.py)); undocumented operator-facing variables and stale doc entries fail | Daily | Baseline in `env_docs_baseline.json` |
| [`miswiring-scan.yml`](../.github/workflows/miswiring-scan.yml) `vocab-lists` | Flags new large literal function-name lists that should be data rather than hardcoded ([`check_vocab_lists.py`](../.github/scripts/check_vocab_lists.py)) | Daily | Baseline in `vocab_baseline.json` |
| [`miswiring-scan.yml`](../.github/workflows/miswiring-scan.yml) `optional-dep-imports` | Flags test files importing optional packages without an import guard ([`check_optional_dep_imports.py`](../.github/scripts/check_optional_dep_imports.py)); unguarded imports pass on developer hosts and fail on bare CI | Daily | Baseline in `optional_dep_imports_baseline.json` |
| [`miswiring-scan.yml`](../.github/workflows/miswiring-scan.yml) `canonical-json` | Freezes canonical JSON byte forms: raw `json.dumps` in a MAC/hash module, or any dumps-into-hashlib/hmac flow, must use `core.json.dumps_canonical` or be baselined ([`check_canonical_json.py`](../.github/scripts/check_canonical_json.py)) | Daily | Baseline in `canonical_json_baseline.json` |
| [`corpus-labels.yml`](../.github/workflows/corpus-labels.yml) `pin-lint-sweep` | Full pin lint over ALL corpus labels with `--fetch-missing`; catches upstream drift (force-pushed branches, deleted tags) between PRs | Weekly | `pin-lint.log` in workflow artefacts |
| [`sca-self-bump.yml`](../.github/workflows/sca-self-bump.yml) | Runs RAPTOR SCA against RAPTOR's own dependency surfaces and proposes clean upgrades | Weekly | Auto-PR with `raptor-sca fix --harden` and `raptor-sca bump` output |
| [`sca-compromise-check.yml`](../.github/workflows/sca-compromise-check.yml) | Verifies known supply-chain incidents are still detected from metadata alone | Weekly and relevant PRs | Per-fixture PASS / FAIL over `test/data/sca-e2e/compromise-corpus/` |
| [`sca-stress-sweep.yml`](../.github/workflows/sca-stress-sweep.yml) | Detects parser, advisory, and performance drift across a broad OSS project sample set | Weekly | `stress_baseline.json` under `packages/sca/data/calibration/` plus sweep artefacts |
| [`refresh-sca-calibration.yml`](../.github/workflows/refresh-sca-calibration.yml) | Refreshes KEV / EPSS / exploit-signal calibration data and validates scoring quality | Weekly | `packages/sca/data/calibration/validation/*.json` |
| [`refresh-sca-project-samples.yml`](../.github/workflows/refresh-sca-project-samples.yml) | Refreshes RAPTOR-generated SCA output for curated OSS project samples | Monthly | `packages/sca/data/calibration/project_samples/` |
| [`refit-sca-calibration.yml`](../.github/workflows/refit-sca-calibration.yml) | Re-fits risk-score multipliers when the calibration corpus says the current weights drifted | Monthly | Auto-PR against `packages/sca/risk.py` and refit reports |
| [`refresh-sca-data.yml`](../.github/workflows/refresh-sca-data.yml) | Refreshes bundled popular-package data used by typosquat detection | Weekly | Auto-PR against `packages/sca/data/popular/` |
| [`typosquat-reaudit.yml`](../.github/workflows/typosquat-reaudit.yml) | Re-checks previously reviewed-legit typosquat names against current registry state | Monthly | Issue comment or new issue when a contradiction appears |

Baseline files (`.github/scripts/*_baseline.json`) are per-detector
exception lists. Each entry requires a review note, and the target for
all baselines is empty: fix the finding or document the variable, do
not baseline.

## Workflow Hardening Bits

| Control | Where it lives |
|---|---|
| Third-party GitHub Actions are pinned to commit SHAs rather than floating tags | `.github/workflows/*.yml` |
| Workflows declare the smallest practical `permissions:` block instead of relying on broad defaults | `.github/workflows/*.yml` |
| Workflows that create sandboxed worktrees avoid persisting checkout credentials into `.git/config` | [`sca-self-bump.yml`](../.github/workflows/sca-self-bump.yml) and other hardened jobs |
| CodeQL uploads are combined after all matrix entries finish, avoiding partial/missing-language baseline races | [`codeql.yml`](../.github/workflows/codeql.yml) |
| Intentionally vulnerable fixtures are excluded from self-scanning where they would otherwise generate guaranteed false positives | `.semgrepignore`, [`codeql-config.yml`](../.github/codeql/codeql-config.yml) |
| SCA data-refresh workflow confines the write token to the job that needs it | [`refresh-sca-data.yml`](../.github/workflows/refresh-sca-data.yml) |
| Squash-merge dedup prevents redundant CI runs when the push-to-main SHA differs from the PR head SHA | `pre_check` job pattern across `tests.yml`, `lint.yml`, `codeql.yml`, `corpus-labels.yml` |

## Stuff We Have But Do Not Really Enforce Yet

| Tool | Current state |
|---|---|
| `mypy` | Pinned in the `lint` dependency group, but there is no CI job running it yet |
| Python 3.10 floor (runtime) | The README states Python 3.10+. Ruff's `target-version = "py310"` (root `pyproject.toml`) enforces this at the syntax level on every lint run, but the CI test suite executes on a single recent interpreter — 3.10-only API regressions would not be caught by tests |
| Ruff formatter | Ruff linting is enforced; `ruff format` is not |
| Semgrep self-scan | RAPTOR ships and uses Semgrep for target analysis, but the repo does not currently have a dedicated Semgrep-against-RAPTOR CI workflow |

If one of these becomes a real gate, we should move it into the proper table above in the same change that wires the workflow in. Otherwise it is just theatre.
