# CI Controls

[Documentation index](README.md)

This is the honest version of how RAPTOR checks its own code.

Some of these things genuinely block a PR. Some just run on a timer and tell us when things are drifting. That distinction matters: having a dependency in `pyproject.toml` is not the same as having a control that stops bad code getting merged.

This page is split into:

- merge and PR gates;
- scheduled assurance jobs;
- workflow hardening;
- tools that are installed but not currently enforced.

**Related documentation:**
[Contributing](../CONTRIBUTING.md) |
[Developer guide](developers.md) |
[Security model](security.md)

**On this page:**

- [What Actually Blocks A PR](#what-actually-blocks-a-pr)
- [Reviewing invariant findings](#reviewing-invariant-findings)
- [Stuff That Runs On A Timer](#stuff-that-runs-on-a-timer)
- [Workflow Hardening Bits](#workflow-hardening-bits)
- [Runner Sizing](#runner-sizing)
- [Stuff We Have But Do Not Really Enforce Yet](#stuff-we-have-but-do-not-really-enforce-yet)

## What Actually Blocks A PR

| Control | Tool | Scope |
|---|---|---|
| Python lint gate | Ruff | Changed Python, stub and notebook files; full tree for configuration changes or uncertain inputs |
| Full-tree Python lint audit | Ruff | Entire repository tree |
| Fast Python test suite | Pytest | `core/`, `packages/`, and `engine/`, split into subsystem tiers; changes under the top-level `test/` data root dispatch via the resource arms |
| Sandbox slow/integration tier | Pytest | `slow`/`integration`-marked tests under `core/sandbox` and `packages/exploit_feasibility`, on sandbox-gated PRs (package-scoped mirror on exploit-feasibility-gated PRs) |
| Sandbox feature-matrix PR subset | In-tree matrix harness | u24 image, `full` + `default` lanes, on sandbox-gated PRs (fork PRs build the image on the runner) |
| Darwin-emulation gate | Pytest | Sandbox test files re-run with `RAPTOR_TEST_EMULATE_PLATFORM=darwin` (`sys.platform` patched pre-collection, darwin-shaped basetemp, `*_native` tests deselected), on sandbox-gated PRs |
| Prompt-envelope audit | Pytest | Registered prompt construction paths |
| Code scanning | GitHub CodeQL Advanced | Python, C/C++, GitHub Actions |
| Slash-command metadata lint | In-tree Python checker | `.claude/commands/*.md` dispatch metadata |
| Dependency regression gate | RAPTOR SCA | PR merge result versus `main` dependency surface |
| ZKPoX native checks | Cargo + Pytest | Path-filtered native statement/parser checks; opt-in full-proof validation on a provisioned SP1 runner |
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
| Replay-determinism gate | In-tree Python detector + Pytest | Transcript-seam census vs `transcript_seam_baseline.json`, plus hermetic record/replay suites and the private-case replay lane, on PRs touching prompt/orchestration/classifier-context paths |

### Gate details and local reproduction

- **ZKPoX native checks** — [`zkpox-native.yml`](../.github/workflows/zkpox-native.yml) on PRs touching the configured ZKPoX/witness paths, pushes to `main` touching the package/workflow paths, and manual dispatch. The hosted `statement-and-parser` job uses Rust 1.95.0 and locked dependencies to test the shared statement and structural verifier, including inspection-mode CLI behavior. Real Groth16 positive/negative, production CLI and delivery tests run when manually dispatched with `full_proofs=true`, on a provisioned `[self-hosted, linux, x64, sp1]` runner; setup is documented in [`packages/zkpox/README.md`](../packages/zkpox/README.md). Locally: `cargo test --locked --manifest-path packages/zkpox/native/Cargo.toml -p zkpox-statement` and `cargo test --locked --manifest-path packages/zkpox/native/Cargo.toml -p zkpox-verify --no-default-features --features structural`.
- **Python lint gate** — [`lint.yml`](../.github/workflows/lint.yml) on `pull_request` and `merge_group`. Rules `F401`, `F811`, `F821`, `F841`; Python 3.12 target (config in `pyproject.toml`). Locally: `ruff check <changed .py files>`.
- **Full-tree Python lint audit** — [`lint.yml`](../.github/workflows/lint.yml) on `push: main`, weekly cron, manual run. Same rule set as the PR gate. Locally: `ruff check .`.
- **Fast Python test suite** — [`tests.yml`](../.github/workflows/tests.yml) on PRs, pushes, merge queue; tiers computed by [`test_scope.py`](../.github/scripts/test_scope.py). Default excludes `slow` and `integration` (markers in `pytest.ini`); `RAPTOR_MAX_TEST_SECONDS=10` per-test wall-clock guard. Locally: `python3 -m pytest core packages engine` (the `engine/` rule-precision tests skip themselves when coccinelle/semgrep are not installed).
- **Sandbox slow/integration tier** — [`tests.yml`](../.github/workflows/tests.yml), second step of the sandbox job on sandbox-gated PRs, with a package-scoped mirror step in the exploit-feasibility job for PRs that fire only that gate. Any CI-equivalent local gate run must include it: `python3 -m pytest -m "slow or integration" core/sandbox packages/exploit_feasibility` (~90s serial).
- **Darwin-emulation gate** — [`tests.yml`](../.github/workflows/tests.yml), third step of the sandbox job on sandbox-gated PRs. Re-runs the sandbox test files with `RAPTOR_TEST_EMULATE_PLATFORM=darwin` so Linux-authored assertions against platform-resolved values (or the Linux tmp layout) fail in the cheap Linux lane instead of on the macOS runner; `*_native`-marked tests are deselected because emulation never stacks on real kernel behaviour. Locally: `RAPTOR_TEST_EMULATE_PLATFORM=darwin python3 -m pytest core/sandbox` (~45s serial).
- **Sandbox feature-matrix PR subset** — [`tests.yml`](../.github/workflows/tests.yml), `sandbox-feature-matrix` job, on sandbox-gated PRs. Runs the u24 × {`full`, `default`} cells of the weekly feature matrix against the prebuilt GHCR image (published by [`sandbox-matrix-image.yml`](../.github/workflows/sandbox-matrix-image.yml); the package is owner-managed and private, like `raptor-ci-deps`). Fork PRs cannot pull it and build the image on the runner instead (slower, never blocked); the weekly matrix is the unfiltered backstop. Locally: `core/sandbox/scripts/feature-matrix/run-matrix.sh --image 24 --lanes full,default` (drop `--skip-build` unless the image is already built).
- **Prompt-envelope audit** — [`tests.yml`](../.github/workflows/tests.yml), `python-prompt-audit` job. Narrow AST-based audit. Locally: `python3 -m pytest core/security/tests/test_prompt_envelope_audit.py -q`.
- **Code scanning** — [`codeql.yml`](../.github/workflows/codeql.yml) on PRs, pushes, merge queue, weekly cron. Languages `python`, `c-cpp`, `actions`; path exclusions in [`codeql-config.yml`](../.github/codeql/codeql-config.yml); import-graph scope narrowing via [`codeql_scope.py`](../.github/scripts/codeql_scope.py) for PRs. Local CodeQL requires the CLI and packs — use the GitHub workflow.

- **Slash-command metadata lint** — [`lint.yml`](../.github/workflows/lint.yml) on every lint run. Validates `dispatch:` targets and exclusion-list drift.

  **Run locally:**

  ```bash
  python3 .github/scripts/check_command_metadata.py
  ```

- **Dependency regression gate** — [`sca-pr-gate.yml`](../.github/workflows/sca-pr-gate.yml) on manifest, lockfile, workflow, and container changes. Compares the PR merge result with its exact first-parent base tree using a shallow checkout; fails on new findings at `high` severity or above.

  **Run locally:** `bin/raptor-sca . --out /tmp/sca-pr`, then `bin/raptor-sca diff <base>/findings.json <pr>/findings.json --fail-on-severity high`.

- **Corpus label schema lint** — [`corpus-labels.yml`](../.github/workflows/corpus-labels.yml) on PRs, pushes, merge queue, over `core/audit/corpus/labels/**/*.label.json`. Field sanity, no network, pure stdlib.

  **Run locally:**

  ```bash
  python3 -m core.audit.corpus.lint --mode schema
  ```

- **Corpus label pin lint (PR)** — [`corpus-labels.yml`](../.github/workflows/corpus-labels.yml) on PRs and merge queue when event-range changes include labels, corpus tooling, or its execution metadata. The schema job skips allocating the pin runner for unrelated changes; unknown history checks all labels. Sparse-fetches pinned upstream trees to verify pins still resolve.

  **Run locally:**

  ```bash
  python3 -m core.audit.corpus.lint --mode pins --fetch-missing <changed files>
  ```

- **SARIF known-FP suppressions** — [`codeql.yml`](../.github/workflows/codeql.yml) post-analysis step. Suppresses known false-positive flow classes (e.g. path variables named `*_secret_key` that hold file paths, not secrets).

  **Run locally:**

  ```bash
  python3 .github/scripts/sarif_known_fp_suppressions.py
  ```

- **CI controls doc guard** — [`tests.yml`](../.github/workflows/tests.yml) on PRs. Validates ruff config lives in `pyproject.toml`, the lint workflow uses config-file discovery, the README links to this doc, and all documented paths exist on disk.

  **Run locally:**

  ```bash
  python3 -m pytest .github/tests/test_ci_controls_docs.py -v
  ```

- **PR preflight hazards** — [`preflight.yml`](../.github/workflows/preflight.yml) on PRs. Re-runs the PR's changed tests under CI-reality hazards: hidden optional deps, hidden tree-sitter, duration guard, tree hygiene, two shuffle legs. Each runner selects the complete immutable Git range and passes paths directly to pytest; unknown history fails selection instead of silently skipping simulations.

  **Run locally:** run the changed tests with the hazard env toggles from the workflow.

- **Repo-invariant detectors (miswiring, env-docs, vocab-lists, canonical-json, optional-dep-imports, report-writer-closure, console-chokepoint, workflow-pipefail, tracked-file-census, run-dir-reads)** — [`lint.yml`](../.github/workflows/lint.yml) `repo-invariants` job on PRs, pushes to `main`, and the merge queue; no workflow paths filter. Only env-docs and the ReDoS rider skip steps when complete Git history proves their input families unchanged; unknown history and scheduled/manual runs retain them. Other detectors remain global because documentation references can affect findings. A NEW finding fails the job; deliberate exceptions go in the detector's baseline JSON with a review note (the console-chokepoint and tracked-file-census gates are baseline-less — fix the finding or extend their in-script allowed shapes, with rationale). The whole set also runs in the daily [`miswiring-scan.yml`](../.github/workflows/miswiring-scan.yml) sweep (see below); exact-set parity between the two lists is test-enforced.

  **Run locally:** `python3 .github/scripts/check_miswiring.py`, and likewise `check_env_docs.py`, `check_vocab_lists.py`, `check_canonical_json.py`, `check_optional_dep_imports.py`, `check_report_writer_closure.py`, `check_console_chokepoint.py`, `check_workflow_pipefail.py`, `check_tracked_file_census.py`, `check_run_dir_reads.py`.

- **Replay-determinism gate** — [`replay-determinism.yml`](../.github/workflows/replay-determinism.yml) on PRs and pushes touching the LLM prompt/orchestration/classifier-context paths (derivation documented in the workflow header), plus a daily no-path-filter sweep. Three jobs: the transcript-seam census ([`check_transcript_seam.py`](../.github/scripts/check_transcript_seam.py) vs [`transcript_seam_baseline.json`](../.github/scripts/transcript_seam_baseline.json)) fails on any LLM dispatch construction outside the frozen-transcript record/replay seam; the public hermetic tier runs the transcript unit + acceptance suites and the synthetic-corpus harness tests (replay determinism, loud miss, leftover detection); the private-case lane replays locally supplied case bundles under `core/audit/corpus/replay-cases` and skips with notice where none exist, with the skip recorded against the lane's skip budget. Dependency metadata, root pytest configuration, and the census/skip-budget helpers also trigger the workflow. The private-case lane installs only pinned pytest when discovery confirms no local cases; its real pytest collection and skip-budget check still run. Present cases retain the full dependency install.

  **Run locally:** `python3 .github/scripts/check_transcript_seam.py` and `python3 -m pytest .github/evals`.

- **Per-lane skip budget** — [`check_skip_budget.py`](../.github/scripts/check_skip_budget.py) after the pytest step of the `_tier.yml` tiers and the nightly lanes. Compares the lane's junit skip count against the count recorded in [`skip_budget_baseline.json`](../.github/scripts/skip_budget_baseline.json); a count above the recorded one fails the lane. Lanes without a recorded count report the observed number and pass — record it from a CI run with `--write-baseline` and commit the baseline.

  **Run locally:**

  ```bash
  python3 .github/scripts/check_skip_budget.py --lane <name> --junit-xml <pytest junitxml>
  ```

- **Nightly integration retries** — a full first pass records every result. Only ordinary test failures with a matching isolated pytest cache qualify for one failed-case retry; collection and session-level failures return immediately. The effective `integration.xml` retains first-pass successes and skips, replacing only failed cases. Missing, extra or skipped retry cases fail validation. Both raw attempts are retained for diagnosis, and skip budgeting uses the complete effective report.

### Reviewing invariant findings

Baselines under `.github/scripts/*_baseline.json` are reviewed exception
lists. Prefer fixing findings; record a deliberate exception only with a
note explaining its scope and why it is accepted. Retire exceptions as their
underlying findings are fixed. Review entries affected
by a refactor according to the [developer guidance](developers.md#refactors-and-audit-records).

- **Miswiring** detects signature/import mismatches, dead definitions,
  unread artifacts, swallowed errors, and unused configuration. Textual
  references in documentation and command files also count, so a doc line
  can keep a symbol apparently live.
- **Vocabulary lists** flag new literal identifier lists or regex alternations
  longer than nine names outside the vocabulary seams. Domain names belong
  in a data pack (`core/audit/data/vocab_packs/`,
  `core/function_taxonomy/data/packs/`, or
  `engine/coccinelle/source_intel/crypto/packs/`), the study-learned domain
  model, or the central taxonomy. Fixed event, report, and persistence field
  schemas can trigger the same census. For a reviewed schema exception,
  record the exact key, kind, count, and producer/consumer rationale in
  `.github/scripts/vocab_baseline.json`; include the review with the schema
  change and rerun `python3 .github/scripts/check_vocab_lists.py`.
- **Canonical JSON** protects frozen MAC/hash byte forms. Use
  `core.json.dumps_canonical` for hash lanes and the appropriate display or
  artifact serializer elsewhere. A deliberate byte-form exception requires
  a review note; preserve compatibility when moving an existing hash lane.
- **Optional dependencies** need guarded test imports where applicable.
  CI-filter tests must still run their required assertions in the pytest-only
  lane; see [companion checks](developers.md#companion-checks-for-test-changes).

#### Deliberate keep-blocks (REVISIT)

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

## Stuff That Runs On A Timer

| Workflow | Purpose | Cadence | Output / evidence |
|---|---|---|---|
| [`nightly.yml`](../.github/workflows/nightly.yml) | Runs slow tests with two workers on the existing runner and live integration tests excluded from the PR gate, plus contained expected-crash tests on Linux and macOS and normal sandbox signal contracts on Linux | Daily | Workflow logs and test reports; native-crash artifacts are named `intentional-crashes-Linux` / `intentional-crashes-macOS`, include contained-crash, sandbox-signal (Linux), and toolchain (macOS) XML; any skipped crash case fails coverage; slow step carries a `RAPTOR_MAX_SESSION_SECONDS` wallclock budget (tripwire summary on drift) |
| [`nightly_shuffled.yml`](../.github/workflows/nightly_shuffled.yml) | Re-runs fast-tier tests with distinct random seeds to flush out order-dependent failures (module-grouped shuffle: module order, then intra-module order) | Daily | A failing seed is identified by its matrix job's `seed=` line; each iteration carries a `RAPTOR_MAX_SESSION_SECONDS` wallclock budget; the PR fast tier's LLM request and hostname tripwires run in every iteration, with request journals and server diagnostics retained alongside the test report |
| [`mypy-nightly.yml`](../.github/workflows/mypy-nightly.yml) | Full-tree mypy type check across all production and test files; not a PR gate — regressions are fixed when convenient. Config lives in `pyproject.toml` `[tool.mypy]` | Daily | Workflow logs |
| [`nightly-self-test.yml`](../.github/workflows/nightly-self-test.yml) | Runs the tier-0 self-test suite — process/kernel/filesystem/network boundary cases over the full command surface with all LLM paths unrouted (no API cost); a refuse step reddens the run when the gcc/radare2 install silently failed so a toolchain-less night cannot read as green | Daily | `self-test-results.json` artifact and workflow logs |
| [`wsl.yml`](../.github/workflows/wsl.yml) | Real-WSL2 live leg on a `windows-2022` runner (first-party `.github/actions/wsl-setup` composite, sha256-pinned rootfs): runs the `[verify-live]` checklist (`.github/scripts/wsl_verify_live.py` — environment facts recorded, expected values asserted), `pytest -m wsl` plus the CRLF fixture set on ext4 / autocrlf-twin / drvfs checkouts, the consent-ceremony and sandbox-profile live probes, and a WSL1 capture job. An availability probe gates the WSL2 jobs and reports a detected skip when the runner image cannot host WSL2 | Daily (and on demand via dispatch) | Per-section checklist JSON artefacts (`wsl-verify-*`, 14-day retention) and workflow logs |
| [`weekly_corpus.yml`](../.github/workflows/weekly_corpus.yml) | Corpus-scale binary-oracle precision drivers (`-m corpus`): clone + build + coverage over real third-party projects to re-derive the published precision numbers | Weekly (and on demand via dispatch) | Workflow logs and junit artifact |
| [`macos-runner-recovery.yml`](../.github/workflows/macos-runner-recovery.yml) | Retries one unallocated macOS job and its dependents after GitHub confirms a runner-acquisition failure; executed failures and stale runs remain untouched | Failed/timed-out first attempts of Test Suite, wrapper acceptance, Nightly and CodeQL; a short Ubuntu inspection job only | Recovery decision in the job summary; original run retains attempt history |
| [`sandbox-wrappers.yml`](../.github/workflows/sandbox-wrappers.yml) | Registered wrapper dispatch contracts and native confinement suites on Linux and macOS; required cases fail on skips or count drift. rr hardware and vendor-dependent cells remain explicit operator acceptance | Source/tooling PRs and main pushes, merge queue, daily and on demand | Per-platform contract/native JUnit, logs, execution plans and exclusions |
| [`sandbox-matrix.yml`](../.github/workflows/sandbox-matrix.yml) | Full sandbox feature matrix: both runner-shaped images, all five degradation lanes, fresh image builds — the unfiltered backstop behind the PR-time two-lane subset | Weekly (and on demand via dispatch) | `matrix.md` / `matrix.json` / per-lane probe + pytest artefacts |
| [`ubuntu26-canary.yml`](../.github/workflows/ubuntu26-canary.yml) | Runs the sandbox empirical feature probe and the sandbox fast tier on the explicit `ubuntu-26.04` runner label ahead of the `ubuntu-latest` migration to Ubuntu 26.04 (actions/runner-images#14748, rolling out 2026-10-19 → 2026-11-19). Asserts the ubuntu-24.04 capability baseline (Landlock present, unprivileged userns, mount + fresh procfs in a userns) still holds on the new runner VM's kernel/AppArmor policy — degraded lanes only SKIP in pytest, so the probe-shape assertion is the loud failure. Retire after the migration completes green | Weekly (and on demand via dispatch) | Probe JSON artefacts (stock image + userns-enabled) and workflow logs |
| [`sandbox-matrix-image.yml`](../.github/workflows/sandbox-matrix-image.yml) | Builds and publishes the u24 matrix image to GHCR (via `run-matrix.sh --build-only`) and prunes versions (untagged digests + tagged anchors beyond the newest 10). Ownership split: CI publishes and manages VERSIONS; the user-owned package's lifecycle (visibility, deletion) belongs to the repository owner — a post-push check emits a warning (never a failure) if the package is not private, and the one-time private flip is the owner's, in the package settings | On input changes, weekly refresh, dispatch | GHCR tags `:u24` and content tag `:u24-<hash>`; visibility warning in the job log when owner action is needed |
| [`tests.yml`](../.github/workflows/tests.yml) (cron) | Full test suite, including tiers excluded from the PR gate | Twice weekly | Workflow logs |
| [`dockerhub-publish.yml`](../.github/workflows/dockerhub-publish.yml) | Publish the dependency image after its image and confinement checks; pushes compare actual Dockerfile COPY and build inputs against the fingerprint label of the published image; missing labels or registry failures request a build. Audit-only changes use their ordinary test lanes. `latest` is restricted to main, its build commit is pinned, and publication rechecks current main inputs to reject superseded builds; stamped releases keep versioned dispatches | Weekly security refresh, changed image inputs, or manual/release dispatch | Existing immutable-image verification and SBOM artifacts |
| [`miswiring-scan.yml`](../.github/workflows/miswiring-scan.yml) | Daily belt-and-braces re-run of the full repo-invariant detector set that gates PRs (exact-set parity with lint's `repo-invariants` job is test-enforced) — miswiring [`check_miswiring.py`](../.github/scripts/check_miswiring.py), env-docs [`check_env_docs.py`](../.github/scripts/check_env_docs.py), vocab-lists [`check_vocab_lists.py`](../.github/scripts/check_vocab_lists.py), canonical-json [`check_canonical_json.py`](../.github/scripts/check_canonical_json.py), optional-dep-imports [`check_optional_dep_imports.py`](../.github/scripts/check_optional_dep_imports.py), report-writer closure [`check_report_writer_closure.py`](../.github/scripts/check_report_writer_closure.py), console-chokepoint [`check_console_chokepoint.py`](../.github/scripts/check_console_chokepoint.py), workflow-pipefail [`check_workflow_pipefail.py`](../.github/scripts/check_workflow_pipefail.py), tracked-file census [`check_tracked_file_census.py`](../.github/scripts/check_tracked_file_census.py), run-dir read census [`check_run_dir_reads.py`](../.github/scripts/check_run_dir_reads.py) — see the PR-gates table; the calm-cadence triage surface for stale-baseline warnings | Daily | Three balanced runner groups retain separate detector steps and continue checking after an individual failure. New findings fail the job; per-detector baselines in `.github/scripts/*_baseline.json` (the console-chokepoint and tracked-file-census gates are baseline-less — fix the finding or extend their in-script allowed shapes) |
| [`replay-determinism.yml`](../.github/workflows/replay-determinism.yml) | Daily no-path-filter re-run of the replay-determinism gate: transcript-seam census over the whole tree (the backstop for dispatch sites added outside the PR path list) plus the hermetic replay suites and the private-case lane | Daily | New census findings fail the job; baseline in [`transcript_seam_baseline.json`](../.github/scripts/transcript_seam_baseline.json); lane skip counts checked against `skip_budget_baseline.json` |
| [`corpus-labels.yml`](../.github/workflows/corpus-labels.yml) `pin-lint-sweep` | Fresh-cache pin lint over ALL corpus labels with `--fetch-missing`; catches upstream drift (force-pushed branches, deleted tags) between PRs | Weekly | `pin-lint.log` in workflow artefacts |
| [`sca-self-bump.yml`](../.github/workflows/sca-self-bump.yml) | Runs RAPTOR SCA against RAPTOR's own dependency surfaces and proposes clean upgrades | Weekly | Auto-PR with `raptor-sca fix --harden` and `raptor-sca bump` output |
| [`sca-compromise-check.yml`](../.github/workflows/sca-compromise-check.yml) | Verifies known supply-chain incidents are still detected from metadata alone | Weekly and relevant PRs | Per-fixture PASS / FAIL over `test/data/sca-e2e/compromise-corpus/` |
| [`sca-stress-sweep.yml`](../.github/workflows/sca-stress-sweep.yml) | Detects parser, advisory, and performance drift across a broad OSS project sample set. Warn-level drift opens an automatic baseline-refresh PR; fail-level drift stays red until an operator investigates and re-dispatches with `refresh-baseline: true`, which captures the new baseline via the same reviewable PR — refused whenever any scan errored, the sweep is incomplete, or the driver itself crashed (never a baseline from a broken run) | Weekly | `stress_baseline.json` under `packages/sca/data/calibration/` plus sweep artefacts |
| [`refresh-sca-calibration.yml`](../.github/workflows/refresh-sca-calibration.yml) | Refreshes KEV / EPSS / exploit-signal calibration data and validates scoring quality | Weekly | `packages/sca/data/calibration/validation/*.json` |
| [`refresh-sca-project-samples.yml`](../.github/workflows/refresh-sca-project-samples.yml) | Refreshes RAPTOR-generated SCA output for curated OSS project samples | Monthly | `packages/sca/data/calibration/project_samples/` |
| [`refit-sca-calibration.yml`](../.github/workflows/refit-sca-calibration.yml) | Re-fits risk-score multipliers when the calibration corpus says the current weights drifted | Monthly | Auto-PR against `packages/sca/risk.py` and refit reports |
| [`refresh-public-suffix-list.yml`](../.github/workflows/refresh-public-suffix-list.yml) | Downloads and validates the bundled Public Suffix List (ICANN and PRIVATE rules), runs domain-boundary regression tests, and opens or updates a refresh PR; also tests facility changes on relevant PRs | Weekly (Tuesday 07:23 UTC, and on demand via dispatch) | Auto-PR against `core/domains/data/public_suffix_list.dat` and workflow logs |
| [`refresh-sca-data.yml`](../.github/workflows/refresh-sca-data.yml) | Refreshes bundled popular-package data used by typosquat detection | Weekly | Auto-PR against `packages/sca/data/popular/` |
| [`typosquat-reaudit.yml`](../.github/workflows/typosquat-reaudit.yml) | Re-checks previously reviewed-legit typosquat names against current registry state | Monthly | Issue comment or new issue when a contradiction appears |
| [`python-floor-canary.yml`](../.github/workflows/python-floor-canary.yml) | Verifies the documented Python 3.12 floor still holds: installs the lockfile on 3.12, import-smokes floor-sensitive runtime modules, and runs a small fast test subset. Also fires on PRs that touch dependency policy (`pyproject.toml`, `uv.lock`, `uv.toml`), its workflow, or its worker-count helper | Weekly (and on dependency/setup PRs) | Workflow logs |

## Workflow Hardening Bits

| Control | Where it lives |
|---|---|
| Third-party GitHub Actions are pinned to commit SHAs rather than floating tags | `.github/workflows/*.yml` |
| Workflows declare the smallest practical `permissions:` block instead of relying on broad defaults | `.github/workflows/*.yml` |
| Workflows that create sandboxed worktrees avoid persisting checkout credentials into `.git/config` | [`sca-self-bump.yml`](../.github/workflows/sca-self-bump.yml) and other hardened jobs |
| CodeQL uploads are combined after all matrix entries finish, avoiding partial/missing-language baseline races | [`codeql.yml`](../.github/workflows/codeql.yml) |
| Intentionally vulnerable fixtures are excluded from self-scanning where they would otherwise generate guaranteed false positives | `.semgrepignore`, [`codeql-config.yml`](../.github/codeql/codeql-config.yml) |
| SCA data-refresh workflow confines the write token to the job that needs it | [`refresh-sca-data.yml`](../.github/workflows/refresh-sca-data.yml) |
| Each workflow validates its current event; a successful PR head cannot substitute for the main-push merge result or its selected checks | `tests.yml`, `lint.yml`, `codeql.yml`, `corpus-labels.yml` |

These workflows no longer query prior successful runs to skip current
validation. A PR head SHA does not establish equivalence of the checked-out
merge result or the test selection for a later push. Changed-file scoping
still limits the work; main pushes and explicit reruns execute the checks
selected for their event.

## Cache identities and fallback behavior

Caches accelerate setup; a failed restore must leave the checks runnable.
Assembled virtualenvs use exact keys only. Misses rebuild with the selected
interpreter and locked dependencies; restore errors retry that exact key before
rebuilding. Old-lock prefix hits are never accepted as executable environments.
The first run after this key migration rebuilds the affected caches. Sync-mode
callers retain `uv sync --locked` on misses; their environments cannot collide
with export/install-mode caches.

Every current shared-venv consumer saves a successful locked fallback rebuild.
Jobs that need uv only for that rebuild leave its installation and download-cache
restore to the helper on misses; standalone tool installers retain their own uv setup.
The SCA PR gate, compromise corpus and typosquat re-audit share a separate
`venv-runtime` profile with `--no-dev`; subsequent steps use that environment
through `GITHUB_PATH`, and test/dev environments cannot satisfy its cache key.
The compromise workflow also owns exact dependency and provisioning inputs in
its PR path filters; the monthly re-audit remains scheduled or manually dispatched.
Stress sweeps and project-sample refreshes use `venv-runtime-cvss` with
`--no-dev --extra cvss`; self-bump retains dev dependencies in `venv-cvss`
with `--extra cvss`. These profiles obtain the CVSS version from the lockfile.

| Cache family | Identity and validation |
|---|---|
| Virtualenvs | Host OS/release/image, architecture/libc, full interpreter build/ABI/base path, workspace, project/lock/uv config, install recipe/method and selected extras; producers and consumers share `ci_cache_key.py`, including PR preflight, the self-test nightly, Ubuntu 26 canary and weekly corpus; shuffled-fast uses the grammar sync profile; callers needing only the restored Python defer uv setup/download-cache restore to cache misses |
| uv downloads/builds | setup-uv supplies platform/architecture/Python identity and explicit keys cover lock, project and uv config; nested setup respects an existing cache owner; parser jobs also hash their installation requirements, separating them from base-only jobs; Semgrep consumers include the shared `semgrep-cli.txt` pin; macOS retains source-built wheels |
| Python bytecode | Exact venv identity plus core/package/root Python source hashes; checked-hash imports validate restored files; misses, prefix hits and restore errors recompile |
| Native APT packages | Host image/architecture and toolchain generation, refreshed weekly; partial restores are discarded and only successful installs are saved |
| CodeQL CLI | Platform/architecture plus the version and archive checksum from `codeql-cli.json`; Java/C++ share that archive and the pinned library revision; download checksums remain mandatory |
| CodeQL overlay databases | Managed by the pinned CodeQL action with language/configuration/tool-version identities and per-run suffixes; these are distinct from the CLI archive cache |
| Corpus sparse checkouts | Label content hash plus per-repository/pin directories; Git HEAD is checked against the requested pin; partial restores are discarded and prefix hits only seed source fetching |
| Published images | The dependency-image fast path checks project/lock hashes, and present uv config forces exact dependency synchronization. DockerHub uses COPY/build-input fingerprints, including ignore files and checkout attributes. GHCR content tags are documented moving source anchors with weekly refreshes, rather than immutable digests. No persistent BuildKit cache is configured |
| Local impact graph | Source contents, interpreter and graph-building rules; preserved mtimes cannot keep stale graph edges alive |

Cache-service failures do not bypass tests, pin validation or integrity checks.
Requirements and venv recipe/key changes retain the consuming test dispatch.

## Runner Sizing

The fast-tier batch jobs in [`tests.yml`](../.github/workflows/tests.yml) and the shuffled iterations in [`nightly_shuffled.yml`](../.github/workflows/nightly_shuffled.yml) pick their runner from the repository variable `RAPTOR_FAST_RUNNER` via `runs-on: ${{ vars.RAPTOR_FAST_RUNNER || 'ubuntu-latest' }}`. Setting the variable (Settings → Secrets and variables → Actions → Variables) to a larger hosted-runner label upsizes those jobs without a workflow change; unset or empty, the expression falls back to `ubuntu-latest`. Every other job keeps its own explicit label.

## Stuff We Have But Do Not Really Enforce Yet

| Tool | Current state |
|---|---|
| `mypy` | Pinned in `pyproject.toml` and run daily by [`mypy-nightly.yml`](../.github/workflows/mypy-nightly.yml); type checking is not a PR gate |
| Python 3.12 floor (runtime) | The README states Python 3.12+ (`requires-python` in `pyproject.toml`; the sandbox hard-requires `os.unshare`, 3.12+). Ruff's `target-version = "py312"` enforces the floor at the syntax level on every lint run, and the weekly [`python-floor-canary.yml`](../.github/workflows/python-floor-canary.yml) lane import-smokes and runs a small fast subset on 3.12 — but the full CI test suite still executes on a single recent interpreter, so 3.12-only API regressions outside that subset would not be caught by tests |
| Ruff formatter | Ruff linting is enforced; `ruff format` is not |
| Semgrep self-scan | RAPTOR ships and uses Semgrep for target analysis, but the repo does not currently have a dedicated Semgrep-against-RAPTOR CI workflow |

If one of these becomes a real gate, we should move it into the proper table above in the same change that wires the workflow in. Otherwise it is just theatre.

Main pushes in Test Suite, sandbox-wrapper acceptance, CodeQL and lint compare
against their own last successful cumulative-scope checkpoint. The resolver
[`ci_push_base.py`](../.github/scripts/ci_push_base.py) checks the repository,
workflow, branch, commit and latest scope-job attempt, plus the successful
`Record verified push scope v1` step. The entire workflow must have succeeded.
An older green run without that marker cannot establish coverage of changes
from cancelled predecessors. The first run under this policy therefore uses
full coverage. Unavailable metadata, incomplete job lists and non-ancestor
checkpoints also retain full coverage. Test Suite and CodeQL reuse the verified
compare response and retain their 300-file truncation backstop.

Main pushes no longer cancel active runs; GitHub may replace intermediate
pending runs with a newer pending run. The surviving run includes all net changes since its
verified checkpoint, including changes from replaced or failed runs. A newer
push may therefore wait for an active run instead of cancelling its work.
PR runs still cancel superseded PR runs and scope the complete PR diff;
merge-queue, scheduled and manual runs retain their existing concurrency and
coverage policies.
Only completed green push runs advance the checkpoint; a successful scope job
inside an otherwise failed or cancelled workflow does not advance it.
Targeted retries, including macOS allocation recovery, may retain a successful
scope job from an earlier attempt of the same run and commit. The resolver
accepts that retained result only when the whole run is green and no newer
scope-job execution supersedes it.

Wrapper acceptance selection runs the full registration census before choosing
per-platform contract selectors and native families. Its independent full-tree
pytest assertion runs in the nightly slow tier instead of repeating the census
in shuffled-fast; hermetic registration and failure-direction tests stay fast.
Selection follows shared Python imports and parent package initializers. Parent conftests attach to each
platform's collected test files, including platform-specific and native-only
bindings. Importing a production or support module does not load its parent
fixtures; explicit Python imports of conftests remain dependencies. Registered
test inputs and their fixture candidates remain relevant outside the usual
source roots, and the workflow trigger guard checks their path coverage.
Selection broadens resource
changes to their owning component. Sandbox backend, dependency or harness edits,
deleted modules, missing history and unreadable dependencies retain full
acceptance. Unresolved dynamic imports broaden selection for runtime edits.
A wrapper-only change selects its contract cases and any native family whose
dependencies include that wrapper. Merge-queue runs scope the complete group
against its base SHA, retaining changes from every queued PR. Missing history
still retains full acceptance; documentation-only groups can skip platform
runners while keeping registration and the required result gate. Scheduled/manual
runs retain full coverage. The current shared root fixtures contain opaque dependencies, so
ordinary runtime edits still fall back to full acceptance; granular selection
is used only when the dependency analysis can establish its bounds. The scope
job logs its selection reasons and writes the changed paths, selected cases and
fallback sources to the job summary. Contract-only selections skip optional parser
installation, retaining Linux confinement prerequisites. Native selections retain base platform tools, adding radare2 only
for its family and Ruby only for the gadget-parser family. Python parser
dependencies serve both gadget-parser and ELF-worker families; full selections
retain every required tool. Parser dependencies come from
[their pinned requirements](../.github/scripts/requirements-sandbox-wrappers.txt),
which enters the uv cache key only for parser families. Contract-only jobs retain
the shared lockfile cache. macOS parser jobs prune downloadable wheels before
saving, retaining source-built wheels for subsequent runs; cache misses still
perform the complete install. Requirements changes retain full wrapper acceptance.
Parser setup steps have eight-minute limits within the existing thirty-minute acceptance job.
Native acceptance runs at most two families concurrently on each existing runner,
with separate homes, scratch directories, registries and reports. A failed family
stops queued families; active families finish and clean up. Contract cases remain
in one group, and skipped cases or execution-count drift still fail acceptance.
`sandbox-wrappers-passed` reports selection and acceptance failures even
when unrelated platform jobs are skipped.

### macOS runner allocation recovery

Queue waits happen before steps run, so step retries cannot reduce them.
The recovery workflow gives a confirmed acquisition failure one new allocation
attempt after the source workflow completes. It requires an empty step list,
no assigned runner, the expected macOS job and label, and GitHub's specific
runner-acquisition failure annotation. Setup failures, test failures, test
timeouts, successful runs and cancelled workflows are not retried.

Recovery checks the latest run and live PR/ref metadata, refusing superseded
runs, closed or updated PRs and deleted queue refs. Scheduled/manual snapshots
remain eligible until a newer matching run supersedes them. Only the failed
macOS job and its dependent gates are rerun; successful unrelated jobs are kept.
A second attempt is never automatically retried. If attempt 2 fails, a small
Ubuntu reporting job explains the exhausted retry budget in the recovery
workflow summary. It performs no checkout or API calls and cannot request
another macOS runner. Later manual attempts do not start this reporting job.

The inspector runs on Ubuntu with limited job permissions and loads only its
trusted default-branch revision. It reads GitHub metadata, never source-run
artifacts or PR code. Decisions appear in its step summary, and test failures
remain visible in the source workflow. This recovers failed allocations; it
does not shorten a job that is still waiting in GitHub's queue.
