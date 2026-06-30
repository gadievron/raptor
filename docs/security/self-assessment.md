# How RAPTOR Checks Itself

This is the honest version of how RAPTOR checks its own code.

Some of these things genuinely block a PR. Some just run on a timer and tell us when things are drifting. Some are benchmark corpora we keep around because otherwise it is very easy to convince yourself the scanner is getting better when it is actually just getting louder.

This page is split into:

- merge and PR gates;
- scheduled assurance jobs;
- committed benchmark corpora and reproducible evidence;
- tools that are installed but not currently enforced.

That distinction matters. Having a dependency in `requirements-dev.txt` is not the same as having a control that stops bad code getting merged.

## What Actually Blocks A PR

| Control | Tool | Scope | Trigger | Parameters | Reproduce locally |
|---|---|---|---|---|---|
| Python lint gate | Ruff | Changed Python files in a PR | `.github/workflows/lint.yml` on `pull_request` and `merge_group` | `F401`, `F811`, `F821`, `F841`; Python 3.12 | `ruff check <changed.py files>` |
| Full-tree Python lint audit | Ruff | Entire repository tree | `.github/workflows/lint.yml` on `push: main`, weekly cron, manual run | Same rule set as PR gate | `ruff check .` |
| Fast Python test suite | Pytest | `core/`, `packages/`, split into subsystem tiers | `.github/workflows/tests.yml` on PRs, pushes, merge queue | Default excludes `slow` and `integration`; `RAPTOR_MAX_TEST_SECONDS=10`; `--durations=25` | `python -m pytest core packages` |
| Prompt-envelope audit | Pytest | Registered prompt construction paths | `.github/workflows/tests.yml` `python-prompt-audit` job | Narrow AST-based audit | `python -m pytest core/security/tests/test_prompt_envelope_audit.py -q` |
| Code scanning | GitHub CodeQL Advanced | Python, C/C++, GitHub Actions | `.github/workflows/codeql.yml` on PRs, pushes, merge queue, weekly cron | Languages: `python`, `c-cpp`, `actions`; path exclusions in `.github/codeql/codeql-config.yml` | Use GitHub workflow; local CodeQL requires the CLI and packs |
| Slash-command metadata lint | In-tree Python checker | `.claude/commands/*.md` dispatch metadata | `.github/workflows/lint.yml` on every lint run | Validates `dispatch:` targets and exclusion-list drift | `python3 .github/scripts/check_command_metadata.py` |
| Dependency regression gate | RAPTOR SCA | PR head versus `main` dependency surface | `.github/workflows/sca-pr-gate.yml` on manifest, lockfile, workflow, and container changes | Fails on new findings at `high` severity or above | `bin/raptor-sca . --out /tmp/sca-pr` then `bin/raptor-sca diff <base>/findings.json <pr>/findings.json --fail-on-severity high` |

## Stuff That Runs On A Timer

| Workflow | Purpose | Cadence | Output / evidence |
|---|---|---|---|
| `.github/workflows/nightly.yml` | Runs slow and live integration tests that are intentionally excluded from the PR gate | Daily | Workflow logs and test reports |
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
| `test/data/smt_codeql_testbench/` | Z3 / SMT path feasibility behaviour for SAT, UNSAT, and indeterminate paths | `python -m pytest packages/codeql/tests/test_smt_path_validator.py` |
| `test/data/sca-e2e/compromise-corpus/` | SCA detects known compromise classes such as Log4Shell, event-stream, ua-parser-js, node-ipc, Spring4Shell, and typosquat/install-hook cases | `packages/sca/scripts/raptor-sca-compromise-check test/data/sca-e2e/compromise-corpus` |
| `test/data/sca-e2e/modes-corpus/` | SCA operator modes (`scan`, `bump`, `fix`, `check`, `whatif`) still behave correctly on real-shape fixtures | `packages/sca/scripts/raptor-sca-modes-check test/data/sca-e2e/modes-corpus` |
| `packages/sca/data/calibration/validation/*.json` | Current SCA risk-score quality against committed exploit signals | `packages/sca/scripts/raptor-sca-validate-corpus` |
| `packages/sca/data/calibration/stress_baseline.json` | Drift baseline for dependency counts, vulnerability counts, ecosystem breakdown, and scan latency across curated OSS projects | Run the `SCA stress sweep` workflow or `packages.sca.calibration.stress` locally |

We keep the raw evidence in version control rather than hand-copying shiny numbers into this page and watching them go stale a week later. The latest SCA calibration verdict is always the newest JSON file under `packages/sca/data/calibration/validation/`, and the current stress sample count plus capture commit live in the `_source` block of `packages/sca/data/calibration/stress_baseline.json`.

## Where The Knobs Live

| Parameter | Source of truth |
|---|---|
| Ruff rule set | `pyproject.toml` |
| Pytest markers and default exclusions | `pytest.ini` |
| CI test wall-clock guard | `.github/workflows/tests.yml` (`RAPTOR_MAX_TEST_SECONDS=10`) |
| CodeQL language matrix and scan schedule | `.github/workflows/codeql.yml` |
| CodeQL excluded fixtures and duplicate worktrees | `.github/codeql/codeql-config.yml` |
| SCA PR failure threshold | `.github/workflows/sca-pr-gate.yml` (`--fail-on-severity high`) |
| SCA calibration pass thresholds | `packages/sca/calibration/validate.py` (`top_20_precision >= 0.5`, `spearman_rho >= 0.4`) |
| SCA stress drift thresholds | `packages/sca/calibration/stress.py` (`vuln warn/fail 25%/50%`, `deps warn/fail 10%/30%`, `elapsed warn/fail 3x/5x`) |
| Dataflow pivot gate | `core/dataflow/corpus_metrics.py` (`missing_sanitizer_model >= 10%` of labelled FPs) |

## Workflow Hardening Bits

| Control | Where it lives |
|---|---|
| Third-party GitHub Actions are pinned to commit SHAs rather than floating tags | `.github/workflows/*.yml` |
| Workflows declare the smallest practical `permissions:` block instead of relying on broad defaults | `.github/workflows/*.yml` |
| Workflows that create sandboxed worktrees avoid persisting checkout credentials into `.git/config` | `.github/workflows/sca-self-bump.yml` and other hardened jobs |
| CodeQL uploads are combined after all matrix entries finish, avoiding partial/missing-language baseline races | `.github/workflows/codeql.yml` |
| Intentionally vulnerable fixtures are excluded from self-scanning where they would otherwise generate guaranteed false positives | `.semgrepignore`, `.github/codeql/codeql-config.yml` |

## Stuff We Have But Do Not Really Enforce Yet

| Tool | Current state |
|---|---|
| `mypy` | Pinned in `requirements-dev.txt`, but there is no CI job running it yet |
| Ruff formatter | Ruff linting is enforced; `ruff format` is not |
| Semgrep self-scan | RAPTOR ships and uses Semgrep for target analysis, but the repo does not currently have a dedicated Semgrep-against-RAPTOR CI workflow |

If one of these becomes a real gate, we should move it into the proper table above in the same change that wires the workflow in. Otherwise it is just theatre.
