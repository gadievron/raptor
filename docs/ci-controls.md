# CI Controls

This is the honest version of how RAPTOR checks its own code.

Some of these things genuinely block a PR. Some just run on a timer and tell us when things are drifting. Some are benchmark corpora we keep around because otherwise it is very easy to convince yourself the scanner is getting better when it is actually just getting louder.

This page is split into:

- merge and PR gates;
- scheduled assurance jobs;
- committed benchmark corpora and reproducible evidence;
- CI infrastructure;
- tools that are installed but not currently enforced.

That distinction matters. Having a dependency in `requirements-dev.txt` is not the same as having a control that stops bad code getting merged.

## What Actually Blocks A PR

| Control | Tool | Scope | Trigger | Parameters | Reproduce locally |
|---|---|---|---|---|---|
| Python lint gate | Ruff | Changed Python files in a PR | `.github/workflows/lint.yml` on `pull_request` and `merge_group` | `F401`, `F811`, `F821`, `F841`; Python 3.10 target | `ruff check <changed.py files>` |
| Full-tree Python lint audit | Ruff | Entire repository tree | `.github/workflows/lint.yml` on `push: main`, weekly cron, manual run | Same rule set as PR gate | `ruff check .` |
| Fast Python test suite | Pytest | `core/`, `packages/`, split into subsystem tiers by `test_scope.py` | `.github/workflows/tests.yml` on PRs, pushes, merge queue | Default excludes `slow` and `integration`; `RAPTOR_MAX_TEST_SECONDS=10`; per-test wall-clock guard | `python3 -m pytest core packages` |
| Prompt-envelope audit | Pytest | Registered prompt construction paths | `.github/workflows/tests.yml` `python-prompt-audit` job | Narrow AST-based audit | `python3 -m pytest core/security/tests/test_prompt_envelope_audit.py -q` |
| Code scanning | GitHub CodeQL Advanced | Python, C/C++, GitHub Actions | `.github/workflows/codeql.yml` on PRs, pushes, merge queue, weekly cron | Languages: `python`, `c-cpp`, `actions`; path exclusions in `.github/codeql/codeql-config.yml`; import-graph scope narrowing via `codeql_scope.py` for PRs | Use GitHub workflow; local CodeQL requires the CLI and packs |
| Slash-command metadata lint | In-tree Python checker | `.claude/commands/*.md` dispatch metadata | `.github/workflows/lint.yml` on every lint run | Validates `dispatch:` targets and exclusion-list drift | `python3 .github/scripts/check_command_metadata.py` |
| Dependency regression gate | RAPTOR SCA | PR head versus `main` dependency surface | `.github/workflows/sca-pr-gate.yml` on manifest, lockfile, workflow, and container changes | Fails on new findings at `high` severity or above | `bin/raptor-sca . --out /tmp/sca-pr` then `bin/raptor-sca diff <base>/findings.json <pr>/findings.json --fail-on-severity high` |
| Corpus label schema lint | In-tree Python linter | `core/audit/corpus/labels/**/*.label.json` | `.github/workflows/corpus-labels.yml` on PRs, pushes, merge queue | Field sanity, no network, pure stdlib | `python3 -m core.audit.corpus.lint --mode schema` |
| Corpus label pin lint (PR) | In-tree Python linter | Changed label files in a PR | `.github/workflows/corpus-labels.yml` on PRs and merge queue | Sparse-fetches pinned upstream trees to verify pins still resolve | `python3 -m core.audit.corpus.lint --mode pins --fetch-missing <changed files>` |
| SARIF known-FP suppressions | In-tree Python script | CodeQL SARIF output | `.github/workflows/codeql.yml` post-analysis step | Suppresses known false-positive flow classes (e.g. path variables named `*_secret_key` that hold file paths, not secrets) | `python3 .github/scripts/sarif_known_fp_suppressions.py` |
| CI controls doc guard | Pytest | This page and its referenced paths | `.github/workflows/tests.yml` on PRs | Validates ruff config lives in `pyproject.toml`, lint workflow uses config-file discovery, README links to this doc, and all documented paths exist on disk | `python3 -m pytest .github/tests/test_ci_controls_docs.py -v` |

## Stuff That Runs On A Timer

| Workflow | Purpose | Cadence | Output / evidence |
|---|---|---|---|
| `.github/workflows/nightly.yml` | Runs slow and live integration tests that are intentionally excluded from the PR gate | Daily | Workflow logs and test reports |
| `.github/workflows/nightly_shuffled.yml` | Re-runs fast-tier tests multiple times with distinct random seeds to flush out order-dependent failures | Daily (07:15 UTC) | First failure aborts; failing seed is visible at the bottom of the log |
| `.github/workflows/miswiring-scan.yml` `miswiring` | Dead-code / wrong-call / swallowed-exception sweep via AST analysis | Daily (05:30 UTC) | New findings fail the job; baseline in `.github/scripts/miswiring_baseline.json` |
| `.github/workflows/miswiring-scan.yml` `env-docs` | Extracts every env var the tree reads/writes and compares against documentation; undocumented operator-facing variables and stale doc entries fail | Daily | Baseline in `.github/scripts/env_docs_baseline.json` |
| `.github/workflows/miswiring-scan.yml` `vocab-lists` | Flags new large literal function-name lists that should be data (DomainVocabulary / IRIS / study loop) rather than hardcoded | Daily | Baseline in `.github/scripts/vocab_baseline.json` |
| `.github/workflows/miswiring-scan.yml` `optional-dep-imports` | Flags test files importing optional packages (anthropic SDK, botocore, tree-sitter grammars) without an import guard; unguarded imports pass on developer hosts and fail on bare CI | Daily | Baseline in `.github/scripts/optional_dep_imports_baseline.json` |
| `.github/workflows/corpus-labels.yml` `pin-lint-sweep` | Full pin lint over ALL corpus labels with `--fetch-missing`; catches upstream drift (force-pushed branches, deleted tags) between PRs | Weekly (Tue 06:00 UTC) | `pin-lint.log` in workflow artefacts |
| `.github/workflows/sca-self-bump.yml` | Runs RAPTOR SCA against RAPTOR's own dependency surfaces and proposes clean upgrades | Weekly | Auto-PR with `raptor-sca fix --harden` and `raptor-sca bump` output |
| `.github/workflows/sca-compromise-check.yml` | Verifies known supply-chain incidents are still detected from metadata alone | Weekly and relevant PRs | Per-fixture PASS / FAIL over `test/data/sca-e2e/compromise-corpus/` |
| `.github/workflows/sca-stress-sweep.yml` | Detects parser, advisory, and performance drift across a broad OSS project sample set | Weekly | `packages/sca/data/calibration/stress_baseline.json` plus sweep artefacts |
| `.github/workflows/refresh-sca-calibration.yml` | Refreshes KEV / EPSS / exploit-signal calibration data and validates scoring quality | Weekly | `packages/sca/data/calibration/validation/*.json` |
| `.github/workflows/refresh-sca-project-samples.yml` | Refreshes RAPTOR-generated SCA output for curated OSS project samples | Monthly | `packages/sca/data/calibration/project_samples/` |
| `.github/workflows/refit-sca-calibration.yml` | Re-fits risk-score multipliers when the calibration corpus says the current weights drifted | Monthly | Auto-PR against `packages/sca/risk.py` and refit reports |
| `.github/workflows/refresh-sca-data.yml` | Refreshes bundled popular-package data used by typosquat detection | Weekly | Auto-PR against `packages/sca/data/popular/` |
| `.github/workflows/typosquat-reaudit.yml` | Re-checks previously reviewed-legit typosquat names against current registry state | Monthly | Issue comment or new issue when a contradiction appears |

## Benchmarks And Receipts

| Corpus / artefact | What it proves | Reproduce |
|---|---|---|
| `core/dataflow/corpus/` | Validator precision, recall, F1, and false-positive-category tracking across CodeQL, Semgrep, OWASP Benchmark, WebGoat, Juice Shop, and source-intel fixtures | `core/dataflow/scripts/corpus-run ...` then `core/dataflow/scripts/corpus-metrics <csv> --check-pivot-gate` |
| `core/audit/corpus/labels/` | Audit hypothesis quality: each label file under `labels/<bug_class>/` pins one function in an upstream tree, schema-linted and pin-verified in CI as labels land. The linter and workflow are committed; no label sets are committed in-tree yet | `python3 -m core.audit.corpus.lint --mode schema` then `--mode pins --fetch-missing` |
| `test/data/smt_codeql_testbench/` | Z3 / SMT path feasibility behaviour for SAT, UNSAT, and indeterminate paths | `python3 -m pytest packages/codeql/tests/test_smt_path_validator.py` |
| `test/data/sca-e2e/compromise-corpus/` | SCA detects known compromise classes such as Log4Shell, event-stream, ua-parser-js, node-ipc, Spring4Shell, and typosquat/install-hook cases | `packages/sca/scripts/raptor-sca-compromise-check test/data/sca-e2e/compromise-corpus` |
| `test/data/sca-e2e/modes-corpus/` | SCA operator modes (`scan`, `bump`, `fix`, `check`, `whatif`) still behave correctly on real-shape fixtures | `packages/sca/scripts/raptor-sca-modes-check test/data/sca-e2e/modes-corpus` |
| `packages/sca/data/calibration/validation/*.json` | Current SCA risk-score quality against committed exploit signals | `packages/sca/scripts/raptor-sca-validate-corpus` |
| `packages/sca/data/calibration/stress_baseline.json` | Drift baseline for dependency counts, vulnerability counts, ecosystem breakdown, and scan latency across curated OSS projects | Run the `SCA stress sweep` workflow or `packages.sca.calibration.stress` locally |

We keep the raw evidence in version control rather than hand-copying shiny numbers into this page and watching them go stale a week later. The latest SCA calibration verdict is always the newest JSON file under `packages/sca/data/calibration/validation/`, and the current stress sample count plus capture commit live in the `_source` block of `packages/sca/data/calibration/stress_baseline.json`.

## CI Infrastructure

These are not security controls, but they support the controls above.

| Component | Purpose |
|---|---|
| `.github/scripts/test_scope.py` | Import-graph-based test dispatch: builds the reverse import graph from `core/` and `packages/`, computes the transitive closure from the changed-file set, and maps affected test files to their CI tier. Replaced the old glob-based filter lists |
| `.github/scripts/codeql_scope.py` | Same import-graph approach for CodeQL PR scans: restricts the CodeQL database to the transitive closure of changed files, falling back to a full scan when the closure is large |
| `.github/scripts/test_impact.py` | Evaluation tool for file-level vs tier-level test selection; not wired into CI but used to measure selection accuracy |
| `.github/workflows/_tier.yml` | Reusable per-tier test runner with two execution paths: `image` (pre-built GHCR container with deps baked in, fast) and `runner` (builds deps on the bare runner via uv, works for fork PRs that cannot pull the private image) |
| `.github/workflows/ci-deps-image.yml` | Builds and pushes the CI dependency image to GHCR; the test tiers run inside this instead of each rebuilding a venv |
| `.github/workflows/release.yml` | Automated release from `v*.*.*` tags: changelog generation, GitHub Release creation |
| `.github/workflows/dockerhub-publish.yml` | Builds and publishes the operator-facing devcontainer image to Docker Hub |
| Baseline files (`.github/scripts/*_baseline.json`) | Per-detector exception lists for the miswiring scan jobs. Each entry requires a review note. The target for all baselines is empty: fix the finding or document the variable, do not baseline |

## Where The Knobs Live

| Parameter | Source of truth |
|---|---|
| Ruff rule set | `pyproject.toml` |
| Pytest markers and default exclusions | `pytest.ini` |
| CI test wall-clock guard | `.github/workflows/tests.yml` (`RAPTOR_MAX_TEST_SECONDS=10`) |
| CodeQL language matrix and scan schedule | `.github/workflows/codeql.yml` |
| CodeQL excluded fixtures and duplicate worktrees | `.github/codeql/codeql-config.yml` |
| CodeQL known-FP suppression classes | `.github/scripts/sarif_known_fp_suppressions.py` |
| SCA PR failure threshold | `.github/workflows/sca-pr-gate.yml` (`--fail-on-severity high`) |
| SCA calibration pass thresholds | `packages/sca/calibration/validate.py` (`top_20_precision >= 0.5`, `spearman_rho >= 0.4`) |
| SCA stress drift thresholds | `packages/sca/calibration/stress.py` (`vuln warn/fail 25%/50%`, `deps warn/fail 10%/30%`, `elapsed warn/fail 3x/5x`) |
| Dataflow pivot gate | `core/dataflow/corpus_metrics.py` (`missing_sanitizer_model >= 10%` of labelled FPs) |
| Miswiring detector exceptions | `.github/scripts/miswiring_baseline.json` |
| Vocabulary-list exceptions | `.github/scripts/vocab_baseline.json` |
| Env-docs drift exceptions | `.github/scripts/env_docs_baseline.json` |
| Optional-dep import exceptions | `.github/scripts/optional_dep_imports_baseline.json` |

## Workflow Hardening Bits

| Control | Where it lives |
|---|---|
| Third-party GitHub Actions are pinned to commit SHAs rather than floating tags | `.github/workflows/*.yml` |
| Workflows declare the smallest practical `permissions:` block instead of relying on broad defaults | `.github/workflows/*.yml` |
| Workflows that create sandboxed worktrees avoid persisting checkout credentials into `.git/config` | `.github/workflows/sca-self-bump.yml` and other hardened jobs |
| CodeQL uploads are combined after all matrix entries finish, avoiding partial/missing-language baseline races | `.github/workflows/codeql.yml` |
| Intentionally vulnerable fixtures are excluded from self-scanning where they would otherwise generate guaranteed false positives | `.semgrepignore`, `.github/codeql/codeql-config.yml` |
| SCA data-refresh workflow confines the write token to the job that needs it | `.github/workflows/refresh-sca-data.yml` |
| Squash-merge dedup prevents redundant CI runs when the push-to-main SHA differs from the PR head SHA | `pre_check` job pattern across `tests.yml`, `lint.yml`, `codeql.yml`, `corpus-labels.yml` |

## Stuff We Have But Do Not Really Enforce Yet

| Tool | Current state |
|---|---|
| `mypy` | Pinned in `requirements-dev.txt`, but there is no CI job running it yet |
| Python 3.10 floor (runtime) | The README states Python 3.10+. Ruff's `target-version = "py310"` (root `pyproject.toml`) enforces this at the syntax level on every lint run, but the CI test suite executes on a single recent interpreter — 3.10-only API regressions would not be caught by tests |
| Ruff formatter | Ruff linting is enforced; `ruff format` is not |
| Semgrep self-scan | RAPTOR ships and uses Semgrep for target analysis, but the repo does not currently have a dedicated Semgrep-against-RAPTOR CI workflow |

If one of these becomes a real gate, we should move it into the proper table above in the same change that wires the workflow in. Otherwise it is just theatre.
