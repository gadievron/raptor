# CI Controls

This is the honest version of how RAPTOR checks its own code.

Some of these things genuinely block a PR. Some just run on a timer and tell us when things are drifting. That distinction matters: having a dependency in `requirements-dev.txt` is not the same as having a control that stops bad code getting merged.

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
| Fast Python test suite | Pytest | `core/`, `packages/`, and `engine/`, split into subsystem tiers; changes under the top-level `test/` data root dispatch via the resource arms |
| Sandbox slow/integration tier | Pytest | `slow`/`integration`-marked tests under `core/sandbox` and `packages/exploit_feasibility`, on sandbox-gated PRs (package-scoped mirror on exploit-feasibility-gated PRs) |
| Sandbox feature-matrix PR subset | In-tree matrix harness | u24 image, `full` + `default` lanes, on sandbox-gated PRs (fork PRs build the image on the runner) |
| Darwin-emulation gate | Pytest | Sandbox test files re-run with `RAPTOR_TEST_EMULATE_PLATFORM=darwin` (`sys.platform` patched pre-collection, darwin-shaped basetemp, `*_native` tests deselected), on sandbox-gated PRs |
| Prompt-envelope audit | Pytest | Registered prompt construction paths |
| Code scanning | GitHub CodeQL Advanced | Python, C/C++, GitHub Actions |
| Slash-command metadata lint | In-tree Python checker | `.claude/commands/*.md` dispatch metadata |
| Dependency regression gate | RAPTOR SCA | PR merge result versus `main` dependency surface |
| Corpus label schema lint | In-tree Python linter | Corpus label JSON files |
| Corpus label pin lint (PR) | In-tree Python linter | Changed label files in a PR |
| SARIF known-FP suppressions | In-tree Python script | CodeQL SARIF output |
| CI controls doc guard | Pytest | This page and its referenced paths |
| PR preflight hazards | In-tree runner | The PR's changed test files |
| Miswiring sweep | In-tree Python detector | Full-repo AST scan vs `miswiring_baseline.json` |
| Env-var documentation drift | In-tree Python detector | Env vars read/written vs the docs and `env_docs_baseline.json` |
| Vocabulary-list guardrail | In-tree Python detector | New large literal function-name lists vs `vocab_baseline.json` |
| Canonical-JSON byte-form guardrail | In-tree Python detector | `json.dumps` flows into MAC/hash vs `canonical_json_baseline.json` |
| Optional-dep import lint | In-tree Python detector | Unguarded optional-package imports in test files vs `optional_dep_imports_baseline.json` |
| Report-writer closure gate | In-tree Python detector | Unregistered report-writer call sites across tracked Python files and `libexec/`/`bin/` scripts vs `report_writer_closure_baseline.json` |
| Console-chokepoint closure gate | In-tree Python detector | Console-handler acquisition in runtime source outside `core.logging.configure_cli_logging` |
| Tracked-file census | In-tree Python detector | Tracked files in the rule-pack subsystems vs each subsystem's declared file shapes |

### Gate details and local reproduction

- **Python lint gate** — [`lint.yml`](../.github/workflows/lint.yml) on `pull_request` and `merge_group`. Rules `F401`, `F811`, `F821`, `F841`; Python 3.10 target (config in `pyproject.toml`). Locally: `ruff check <changed .py files>`.
- **Full-tree Python lint audit** — [`lint.yml`](../.github/workflows/lint.yml) on `push: main`, weekly cron, manual run. Same rule set as the PR gate. Locally: `ruff check .`.
- **Fast Python test suite** — [`tests.yml`](../.github/workflows/tests.yml) on PRs, pushes, merge queue; tiers computed by [`test_scope.py`](../.github/scripts/test_scope.py). Default excludes `slow` and `integration` (markers in `pytest.ini`); `RAPTOR_MAX_TEST_SECONDS=10` per-test wall-clock guard. Locally: `python3 -m pytest core packages engine` (the `engine/` rule-precision tests skip themselves when coccinelle/semgrep are not installed).
- **Sandbox slow/integration tier** — [`tests.yml`](../.github/workflows/tests.yml), second step of the sandbox job on sandbox-gated PRs, with a package-scoped mirror step in the exploit-feasibility job for PRs that fire only that gate. Any CI-equivalent local gate run must include it: `python3 -m pytest -m "slow or integration" core/sandbox packages/exploit_feasibility` (~90s serial).
- **Darwin-emulation gate** — [`tests.yml`](../.github/workflows/tests.yml), third step of the sandbox job on sandbox-gated PRs. Re-runs the sandbox test files with `RAPTOR_TEST_EMULATE_PLATFORM=darwin` so Linux-authored assertions against platform-resolved values (or the Linux tmp layout) fail in the cheap Linux lane instead of on the macOS runner; `*_native`-marked tests are deselected because emulation never stacks on real kernel behaviour. Locally: `RAPTOR_TEST_EMULATE_PLATFORM=darwin python3 -m pytest core/sandbox` (~45s serial).
- **Sandbox feature-matrix PR subset** — [`tests.yml`](../.github/workflows/tests.yml), `sandbox-feature-matrix` job, on sandbox-gated PRs. Runs the u24 × {`full`, `default`} cells of the weekly feature matrix against the prebuilt GHCR image (published by [`sandbox-matrix-image.yml`](../.github/workflows/sandbox-matrix-image.yml); the package is owner-managed and private, like `raptor-ci-deps`). Fork PRs cannot pull it and build the image on the runner instead (slower, never blocked); the weekly matrix is the unfiltered backstop. Locally: `core/sandbox/scripts/feature-matrix/run-matrix.sh --image 24 --lanes full,default` (drop `--skip-build` unless the image is already built).
- **Prompt-envelope audit** — [`tests.yml`](../.github/workflows/tests.yml), `python-prompt-audit` job. Narrow AST-based audit. Locally: `python3 -m pytest core/security/tests/test_prompt_envelope_audit.py -q`.
- **Code scanning** — [`codeql.yml`](../.github/workflows/codeql.yml) on PRs, pushes, merge queue, weekly cron. Languages `python`, `c-cpp`, `actions`; path exclusions in [`codeql-config.yml`](../.github/codeql/codeql-config.yml); import-graph scope narrowing via [`codeql_scope.py`](../.github/scripts/codeql_scope.py) for PRs. Local CodeQL requires the CLI and packs — use the GitHub workflow.
- **Slash-command metadata lint** — [`lint.yml`](../.github/workflows/lint.yml) on every lint run. Validates `dispatch:` targets and exclusion-list drift. Locally: `python3 .github/scripts/check_command_metadata.py`.
- **Dependency regression gate** — [`sca-pr-gate.yml`](../.github/workflows/sca-pr-gate.yml) on manifest, lockfile, workflow, and container changes. Fails on new findings at `high` severity or above. Locally: `bin/raptor-sca . --out /tmp/sca-pr`, then `bin/raptor-sca diff <base>/findings.json <pr>/findings.json --fail-on-severity high`.
- **Corpus label schema lint** — [`corpus-labels.yml`](../.github/workflows/corpus-labels.yml) on PRs, pushes, merge queue, over `core/audit/corpus/labels/**/*.label.json`. Field sanity, no network, pure stdlib. Locally: `python3 -m core.audit.corpus.lint --mode schema`.
- **Corpus label pin lint (PR)** — [`corpus-labels.yml`](../.github/workflows/corpus-labels.yml) on PRs and merge queue. Sparse-fetches pinned upstream trees to verify pins still resolve. Locally: `python3 -m core.audit.corpus.lint --mode pins --fetch-missing <changed files>`.
- **SARIF known-FP suppressions** — [`codeql.yml`](../.github/workflows/codeql.yml) post-analysis step. Suppresses known false-positive flow classes (e.g. path variables named `*_secret_key` that hold file paths, not secrets). Locally: `python3 .github/scripts/sarif_known_fp_suppressions.py`.
- **CI controls doc guard** — [`tests.yml`](../.github/workflows/tests.yml) on PRs. Validates ruff config lives in `pyproject.toml`, the lint workflow uses config-file discovery, the README links to this doc, and all documented paths exist on disk. Locally: `python3 -m pytest .github/tests/test_ci_controls_docs.py -v`.
- **PR preflight hazards** — [`preflight.yml`](../.github/workflows/preflight.yml) on PRs. Re-runs the PR's changed tests under CI-reality hazards: hidden optional deps, hidden tree-sitter, duration guard, tree hygiene, two shuffle legs. Locally: run the changed tests with the hazard env toggles from the workflow.
- **Repo-invariant detectors (miswiring, env-docs, vocab-lists, canonical-json, optional-dep-imports, report-writer-closure, console-chokepoint, workflow-pipefail, tracked-file-census)** — [`lint.yml`](../.github/workflows/lint.yml) `repo-invariants` job on PRs, pushes to `main`, and the merge queue; no paths filter (the invariants are repo-global and the whole set runs in ~2 minutes). A NEW finding fails the job; deliberate exceptions go in the detector's baseline JSON with a review note (the console-chokepoint and tracked-file-census gates are baseline-less — fix the finding or extend their in-script allowed shapes, with rationale). The whole set also runs in the daily [`miswiring-scan.yml`](../.github/workflows/miswiring-scan.yml) sweep (see below); exact-set parity between the two lists is test-enforced. Locally: `python3 .github/scripts/check_miswiring.py`, and likewise `check_env_docs.py`, `check_vocab_lists.py`, `check_canonical_json.py`, `check_optional_dep_imports.py`, `check_report_writer_closure.py`, `check_console_chokepoint.py`, `check_workflow_pipefail.py`, `check_tracked_file_census.py`.
- **Per-lane skip budget** — [`check_skip_budget.py`](../.github/scripts/check_skip_budget.py) after the pytest step of the `_tier.yml` tiers and the nightly lanes. Compares the lane's junit skip count against the count recorded in [`skip_budget_baseline.json`](../.github/scripts/skip_budget_baseline.json); a count above the recorded one fails the lane. Lanes without a recorded count report the observed number and pass — record it from a CI run with `--write-baseline` and commit the baseline. Locally: `python3 .github/scripts/check_skip_budget.py --lane <name> --junit-xml <pytest junitxml>`.

## Stuff That Runs On A Timer

| Workflow | Purpose | Cadence | Output / evidence |
|---|---|---|---|
| [`nightly.yml`](../.github/workflows/nightly.yml) | Runs slow and live integration tests that are intentionally excluded from the PR gate | Daily | Workflow logs and test reports; slow step carries a `RAPTOR_MAX_SESSION_SECONDS` wallclock budget (tripwire summary on drift) |
| [`nightly_shuffled.yml`](../.github/workflows/nightly_shuffled.yml) | Re-runs fast-tier tests with distinct random seeds to flush out order-dependent failures (module-grouped shuffle: module order, then intra-module order) | Daily | A failing seed is identified by its matrix job's `seed=` line; each iteration carries a `RAPTOR_MAX_SESSION_SECONDS` wallclock budget |
| [`nightly-self-test.yml`](../.github/workflows/nightly-self-test.yml) | Runs the tier-0 self-test suite — process/kernel/filesystem/network boundary cases over the full command surface with all LLM paths unrouted (no API cost); a refuse step reddens the run when the gcc/radare2 install silently failed so a toolchain-less night cannot read as green | Daily | `self-test-results.json` artifact and workflow logs |
| [`wsl.yml`](../.github/workflows/wsl.yml) | Real-WSL2 live leg on a `windows-2022` runner (setup-wsl): runs the `[verify-live]` checklist (`.github/scripts/wsl_verify_live.py` — environment facts recorded, expected values asserted), `pytest -m wsl` plus the CRLF fixture set on ext4 / autocrlf-twin / drvfs checkouts, the consent-ceremony and sandbox-profile live probes, and a WSL1 capture job. An availability probe gates the WSL2 jobs and reports a detected skip when the runner image cannot host WSL2 | Daily (and on demand via dispatch) | Per-section checklist JSON artefacts (`wsl-verify-*`, 14-day retention) and workflow logs |
| [`weekly_corpus.yml`](../.github/workflows/weekly_corpus.yml) | Corpus-scale binary-oracle precision drivers (`-m corpus`): clone + build + coverage over real third-party projects to re-derive the published precision numbers | Weekly (and on demand via dispatch) | Workflow logs and junit artifact |
| [`sandbox-matrix.yml`](../.github/workflows/sandbox-matrix.yml) | Full sandbox feature matrix: both runner-shaped images, all five degradation lanes, fresh image builds — the unfiltered backstop behind the PR-time two-lane subset | Weekly (and on demand via dispatch) | `matrix.md` / `matrix.json` / per-lane probe + pytest artefacts |
| [`ubuntu26-canary.yml`](../.github/workflows/ubuntu26-canary.yml) | Runs the sandbox empirical feature probe and the sandbox fast tier on the explicit `ubuntu-26.04` runner label ahead of the `ubuntu-latest` migration to Ubuntu 26.04 (actions/runner-images#14748, rolling out 2026-10-19 → 2026-11-19). Asserts the ubuntu-24.04 capability baseline (Landlock present, unprivileged userns, mount + fresh procfs in a userns) still holds on the new runner VM's kernel/AppArmor policy — degraded lanes only SKIP in pytest, so the probe-shape assertion is the loud failure. Retire after the migration completes green | Weekly (and on demand via dispatch) | Probe JSON artefacts (stock image + userns-enabled) and workflow logs |
| [`sandbox-matrix-image.yml`](../.github/workflows/sandbox-matrix-image.yml) | Builds and publishes the u24 matrix image to GHCR (via `run-matrix.sh --build-only`) and prunes versions (untagged digests + tagged anchors beyond the newest 10). Ownership split: CI publishes and manages VERSIONS; the user-owned package's lifecycle (visibility, deletion) belongs to the repository owner — a post-push check emits a warning (never a failure) if the package is not private, and the one-time private flip is the owner's, in the package settings | On input changes, weekly refresh, dispatch | GHCR tags `:u24` and content tag `:u24-<hash>`; visibility warning in the job log when owner action is needed |
| [`tests.yml`](../.github/workflows/tests.yml) (cron) | Full test suite, including tiers excluded from the PR gate | Twice weekly | Workflow logs |
| [`miswiring-scan.yml`](../.github/workflows/miswiring-scan.yml) | Daily belt-and-braces re-run of the full repo-invariant detector set that gates PRs (exact-set parity with lint's `repo-invariants` job is test-enforced) — miswiring [`check_miswiring.py`](../.github/scripts/check_miswiring.py), env-docs [`check_env_docs.py`](../.github/scripts/check_env_docs.py), vocab-lists [`check_vocab_lists.py`](../.github/scripts/check_vocab_lists.py), canonical-json [`check_canonical_json.py`](../.github/scripts/check_canonical_json.py), optional-dep-imports [`check_optional_dep_imports.py`](../.github/scripts/check_optional_dep_imports.py), report-writer closure [`check_report_writer_closure.py`](../.github/scripts/check_report_writer_closure.py), console-chokepoint [`check_console_chokepoint.py`](../.github/scripts/check_console_chokepoint.py), workflow-pipefail [`check_workflow_pipefail.py`](../.github/scripts/check_workflow_pipefail.py), tracked-file census [`check_tracked_file_census.py`](../.github/scripts/check_tracked_file_census.py) — see the PR-gates table; the calm-cadence triage surface for stale-baseline warnings | Daily | New findings fail the job; per-detector baselines in `.github/scripts/*_baseline.json` (the console-chokepoint and tracked-file-census gates are baseline-less — fix the finding or extend their in-script allowed shapes) |
| [`corpus-labels.yml`](../.github/workflows/corpus-labels.yml) `pin-lint-sweep` | Full pin lint over ALL corpus labels with `--fetch-missing`; catches upstream drift (force-pushed branches, deleted tags) between PRs | Weekly | `pin-lint.log` in workflow artefacts |
| [`sca-self-bump.yml`](../.github/workflows/sca-self-bump.yml) | Runs RAPTOR SCA against RAPTOR's own dependency surfaces and proposes clean upgrades | Weekly | Auto-PR with `raptor-sca fix --harden` and `raptor-sca bump` output |
| [`sca-compromise-check.yml`](../.github/workflows/sca-compromise-check.yml) | Verifies known supply-chain incidents are still detected from metadata alone | Weekly and relevant PRs | Per-fixture PASS / FAIL over `test/data/sca-e2e/compromise-corpus/` |
| [`sca-stress-sweep.yml`](../.github/workflows/sca-stress-sweep.yml) | Detects parser, advisory, and performance drift across a broad OSS project sample set. Warn-level drift opens an automatic baseline-refresh PR; fail-level drift stays red until an operator investigates and re-dispatches with `refresh-baseline: true`, which captures the new baseline via the same reviewable PR — refused whenever any scan errored, the sweep is incomplete, or the driver itself crashed (never a baseline from a broken run) | Weekly | `stress_baseline.json` under `packages/sca/data/calibration/` plus sweep artefacts |
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
| `mypy` | Pinned in `requirements-dev.txt`, but there is no CI job running it yet |
| Python 3.10 floor (runtime) | The README states Python 3.10+. Ruff's `target-version = "py310"` (root `pyproject.toml`) enforces this at the syntax level on every lint run, but the CI test suite executes on a single recent interpreter — 3.10-only API regressions would not be caught by tests |
| Ruff formatter | Ruff linting is enforced; `ruff format` is not |
| Semgrep self-scan | RAPTOR ships and uses Semgrep for target analysis, but the repo does not currently have a dedicated Semgrep-against-RAPTOR CI workflow |

If one of these becomes a real gate, we should move it into the proper table above in the same change that wires the workflow in. Otherwise it is just theatre.
