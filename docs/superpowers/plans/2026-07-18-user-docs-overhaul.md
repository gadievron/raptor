# RAPTOR User-Documentation Overhaul Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restructure RAPTOR's user documentation into a clear, scannable, single-source-of-truth set — closing the install and command-reference gaps — while proving nothing is lost and every removal is stale-with-receipt.

**Architecture:** Markdown-only reorganization of `docs/**` + root `README.md`. A verbatim archive is taken first; content is then consolidated (merges/splits/rewrites), internal design docs are moved off the user path via `git mv`, and the result is verified with content/link/coverage checks whose output becomes the PR's evidence bundle.

**Tech Stack:** Markdown, `git` (esp. `git mv`), POSIX shell + `grep` for verification, a throwaway Python link-checker (run locally, never committed).

**Spec:** `docs/superpowers/specs/2026-07-18-user-docs-overhaul-design.md` — read it before starting. Task salvage lists reference its §7 ledger; do not re-derive them.

## Global Constraints

> **Revision 2026-07-18 — Option B:** a mid-execution doc↔code audit (see the PR findings log) confirmed several internal design docs are referenced by hardcoded code paths, and that Task 11's original consolidation would break a golden-file test. Per operator decision, scope was widened from docs-only to **docs + reference-only code edits**: the internal design docs move to `docs/internals/` as intended, and the hardcoded `docs/...` path strings in a fixed, enumerated set of code files are repointed. **No code logic changes.** The audit also confirmed the code is correct and the docs merely lagged — so doc→code content (paths/counts/plan-narratives) is corrected in Task 19.

Every task's requirements implicitly include these (verbatim from the spec, as amended by the revision above):

- **Scope (revised — Option B):** the diff touches `docs/**`, root `README.md`, **and only the enumerated code files in Task 11** whose sole change is repointing a hardcoded `docs/...` path string (plus the regenerated golden fixture). Nothing under `.claude/`, `engine/`, `tiers/`, `CITATION.cff`, `LICENSE`, and no OTHER code file, may change. No logic, no new deps, no CI edits.
- **`.claude/` is read-only** — read `.claude/commands/*.md` as a source for `commands.md`; make zero edits there.
- **Code edits are reference-only + must keep tests green.** The only permitted non-doc changes are: updating `docs/...` path strings in the Task 11 file list, updating the golden-fixture test's path, and regenerating the golden fixture. The affected `core/dataflow` tests MUST be run and pass (this is no longer a docs-only PR).
- **Document `pip` as-is** — the repo has `requirements.txt` + pip and no `pyproject.toml`/`uv.lock`. Do not advocate or add uv.
- **All relocations use `git mv`** (history = receipt). Never delete-then-create a file whose content survives.
- **Nothing lost:** the archive (Task 0) + 100% salvage coverage (Task 21). Every pre-existing fact ends either relocated or dropped-with-a-verified-receipt.
- **Structure rules:** single source of truth per fact; max 2 hops from `README.md`; no fluff.
- **Commits:** conventional, `docs:` prefix. Commit at the end of every task.
- **Branch:** `docs/user-documentation-overhaul` (already created).

### Verification toolkit (referenced by tasks)

- **Salvage grep:** `grep -F -- '<token>' <file>` → expect exit 0 (present).
- **Absence check (pre-write):** `test ! -e <path>` → expect exit 0.
- **Move-history check:** `git log --follow --oneline -- <newpath> | head` → expect the pre-move commits to appear.
- **Per-file link check (lightweight):** for each `[text](rel/path)` in the file, `test -e "$(dirname <file>)/rel/path"`. The full recursive checker lives in Task 20.
- **Diff-scope check:** `git diff --name-only main...HEAD | grep -vE '^(docs/|README.md)' ` → expect **no output**.

---

## Task 0: Archive snapshot + scope guard

**Files:**
- Create: `docs/_archive/2026-07-18/` (verbatim copy of the current `docs/` tree, excluding `_archive/` itself, plus a copy of the pre-overhaul `README.md`)
- Create: `docs/_archive/README.md` (snapshot note)

**Interfaces:**
- Produces: the immutable pre-overhaul reference every later task and the salvage-coverage check (Task 21) compares against.

- [ ] **Step 1: Verify clean starting tree**

Run: `git status --porcelain` → Expected: empty (only the committed spec/plan present).

- [ ] **Step 2: Snapshot docs/ + README verbatim**

```bash
mkdir -p docs/_archive/2026-07-18
# copy everything currently under docs/ EXCEPT the archive dir and the superpowers workspace
rsync -a --exclude '_archive' --exclude 'superpowers' docs/ docs/_archive/2026-07-18/docs/
cp README.md docs/_archive/2026-07-18/README.md
```

- [ ] **Step 3: Write the archive note**

Create `docs/_archive/README.md`:

```markdown
# Documentation archive

`2026-07-18/` is a verbatim snapshot of `docs/` and the root `README.md` taken
immediately before the user-documentation overhaul (branch
`docs/user-documentation-overhaul`). It exists so nothing from the old docs is
lost. **Live documentation is in `docs/`.** Maintainers may prune this directory
once the overhaul is trusted.
```

- [ ] **Step 4: Verify snapshot completeness**

Run: `diff <(cd docs && find . -path ./_archive -prune -o -path ./superpowers -prune -o -type f -print | sort) <(cd docs/_archive/2026-07-18/docs && find . -type f -print | sort)`
Expected: no differences (every live doc file is in the archive).

- [ ] **Step 5: Commit**

```bash
git add docs/_archive
git commit -m "docs: archive pre-overhaul documentation snapshot (2026-07-18)"
```

---

## Task 1: `docs/install.md` (NEW — closes gap a)

**Files:**
- Create: `docs/install.md`
- Source (read): `docs/_archive/2026-07-18/docs/DEPENDENCIES.md`, `README.md` (Quick Start), `docs/_archive/.../docs/CLAUDE_CODE_QUICKSTART.md`, `requirements.txt`, `.devcontainer/Dockerfile`

**Interfaces:**
- Produces: the canonical install page. `README.md` (Task 12) and `commands.md` (Task 2) link here. Absorbs the per-feature tool→command map from `DEPENDENCIES.md`.

- [ ] **Step 1: Confirm target absent**

Run: `test ! -e docs/install.md` → Expected: exit 0.

- [ ] **Step 2: Write `docs/install.md`**

Required sections:
1. **Must vs optional** — a table: tool → which command needs it → required-for-basic-`/scan` vs optional-per-feature. Required baseline = Python 3.12 deps (`pip install -r requirements.txt`), Semgrep, one LLM provider. Optional = AFL++ (`/fuzz`), CodeQL (`/codeql`, non-commercial caveat), rr+gcov+ASan (`/crash-analysis`), gdb/binutils (binary), BigQuery (`/oss-forensics`), Frida (`/frida`).
2. **Install (pip, as-is)** — `pip install -r requirements.txt`; devcontainer path (`docker pull danielcuthbert/raptor:latest`, run `--privileged` for rr, ~6 GB).
3. **Auth / API key** — `claude` needs Anthropic auth (API key or subscription); note env vars (`ANTHROPIC_API_KEY`, etc.) → link `configuration.md`.
4. **First run + where output lands** — `out/`, `report.md`, `findings.json`.

Include all salvage from **spec §7** rows `DEPENDENCIES.md` (install half) and the `README.md` install bullets. Do NOT mention uv.

- [ ] **Step 3: Verify required salvage present**

```bash
for t in "docker pull danielcuthbert/raptor" "--privileged" "requirements.txt" "Semgrep" "ANTHROPIC_API_KEY" "out/"; do grep -Fq -- "$t" docs/install.md || echo "MISSING: $t"; done
```
Expected: no `MISSING` lines. Also: `grep -iq 'uv ' docs/install.md && echo "UV LEAK"` → Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add docs/install.md
git commit -m "docs: add consolidated install guide (must vs optional)"
```

---

## Task 2: `docs/commands.md` (NEW — closes gap b, the reference hub)

**Files:**
- Create: `docs/commands.md`
- Source (read, READ-ONLY): `.claude/commands/*.md`, `CLAUDE.md` (COMMANDS section)

**Interfaces:**
- Produces: the command reference hub. Links out to the 8 guide pages (`validate.md`, `sca.md`, `fuzzing.md`, `crash-analysis.md`, `binary-understanding.md`, `frida/QUICKSTART.md`, `agentic.md`, `understand.md`). `README.md` links here.

- [ ] **Step 1: Enumerate the command surface**

Run: `ls .claude/commands/*.md` and read each frontmatter (`dispatch`, `description`) + documented flags. Do not edit them.

- [ ] **Step 2: Write `docs/commands.md`**

Structure (from spec §6): grouped by workflow stage, NOT alphabetical —
`Plan/Setup → Discover → Understand → Analyse → Validate → Exploit/Patch → Runtime → Report/Manage` (+ Forensics standalone).
Per command: name, one-line purpose, key params, workflow position, maturity (beta/alpha marked). **Full flag lists defer to `--help`** — do not paste exhaustive flag tables.
- The 8 guide-worthy commands get a one-liner + **link to their guide page**.
- All other commands are documented **in full here**.
- Document aliases (`/raptor-scan`, `/raptor-fuzz`, `/raptor-web`, `/raptor-sca`, `/raptor-frida`) and the `/audit`→`/understand` rename; include `/tune` and `/doctor`.

- [ ] **Step 3: Verify all 31 commands + stages present**

```bash
for c in scan codeql sca fuzz binary web understand annotate agentic analyze validate exploit patch crash-analysis frida oss-forensics cve-diff diagram project threat-model describe scorecard version commands create-skill tune doctor; do grep -Fq -- "/$c" docs/commands.md || echo "MISSING CMD: $c"; done
for s in "Discover" "Understand" "Analyse" "Validate" "Exploit" "Report"; do grep -Fq -- "$s" docs/commands.md || echo "MISSING STAGE: $s"; done
```
Expected: no `MISSING` lines.

- [ ] **Step 4: Verify guide links resolve** (guides don't exist yet — record which links must be satisfied by Tasks 5/6/7/15/16/17; re-run in Task 19)

Run: `grep -oE '\]\(([a-z/-]+\.md)\)' docs/commands.md` → note targets; existence is enforced in Task 19.

- [ ] **Step 5: Commit**

```bash
git add docs/commands.md
git commit -m "docs: add canonical command reference"
```

---

## Task 3: `docs/configuration.md` (NEW)

**Files:**
- Create: `docs/configuration.md`
- Source (read): `docs/_archive/.../docs/README.md` (Bedrock block — most detailed), `README.md` (models.json/env/roles), `docs/_archive/.../docs/DEPENDENCIES.md` (providers)

**Interfaces:**
- Produces: the single LLM/config page. `install.md`, `README.md`, `python-cli.md` link here.

- [ ] **Step 1:** `test ! -e docs/configuration.md` → Expected: exit 0.
- [ ] **Step 2: Write it.** Sections: `~/.config/raptor/models.json` shape; env auto-detect (ANTHROPIC/OPENAI/GEMINI/MISTRAL/OLLAMA); model-roles table; Bedrock (Mantle vs Runtime, bearer/SigV4, `RAPTOR_BEDROCK_API`); Ollama-unreliable caveat; `RAPTOR_MAX_COST`; **corrected offline** (state the real behaviour: `registry-cache/` ships empty). Include salvage from spec §7 (`docs/README.md` Bedrock/provider rows).
- [ ] **Step 3: Verify.** `for t in "models.json" "Bedrock" "RAPTOR_MAX_COST" "OLLAMA" "SigV4"; do grep -Fq -- "$t" docs/configuration.md || echo "MISSING: $t"; done` → Expected: none.
- [ ] **Step 4: Commit.** `git add docs/configuration.md && git commit -m "docs: add unified LLM/configuration guide"`

---

## Task 4: `docs/attribution.md` (NEW) + retire `DEPENDENCIES.md`

**Files:**
- Create: `docs/attribution.md`
- Delete: `docs/DEPENDENCIES.md` (content now split between `install.md` and this file; original in archive)

**Interfaces:**
- Consumes: install-half of `DEPENDENCIES.md` already moved to `install.md` (Task 1).
- Produces: the legal/attribution page.

- [ ] **Step 1: Write `docs/attribution.md`.** Per-tool license table + CodeQL non-commercial caveat (salvage: spec §7 `DEPENDENCIES.md` attribution half).
- [ ] **Step 2: Verify.** `grep -Fq -- "non-commercial" docs/attribution.md && grep -Fiq -- "license" docs/attribution.md` → Expected: exit 0.
- [ ] **Step 3: Confirm install-half already salvaged** (guards against losing content when removing the source): `grep -Fq -- "Semgrep" docs/install.md` → Expected: exit 0.
- [ ] **Step 4: Remove the consumed source.** `git rm docs/DEPENDENCIES.md`
- [ ] **Step 5: Commit.** `git add -A && git commit -m "docs: split DEPENDENCIES into attribution.md; install half folded into install.md"`

---

## Task 5: `docs/getting-started-claude-code.md` (MERGE 2→1)

**Files:**
- Create: `docs/getting-started-claude-code.md`
- Delete: `docs/CLAUDE_CODE_QUICKSTART.md`, `docs/CLAUDE_CODE_USAGE.md` (originals in archive)

**Interfaces:**
- Produces: the primary "drive RAPTOR via Claude Code" onboarding page. `README.md` links here as the first stop.

- [ ] **Step 1: Read both sources** from `docs/_archive/2026-07-18/docs/`.
- [ ] **Step 2: Write the merged page.** Spine = QUICKSTART (clone → `claude` → install + Semgrep → API-key OR Ollama → run). Reference half = USAGE (grouped catalog scaffold → link `commands.md`; persona invocation idiom + persona→purpose map; adversarial order Secrets→Input→Auth→Crypto→Config; `out/` structure; troubleshooting: no-findings needs `.git`, LLM-error checklist). Cut fluff ("That's it! 🎉"). Fix stale: "/scan Semgrep only" is wrong; personas = 10; do mention `/agentic`. Salvage: spec §7 rows for both files.
- [ ] **Step 3: Verify salvage.** `for t in "Ollama" "out/" ".git" "Secrets" "/agentic"; do grep -Fq -- "$t" docs/getting-started-claude-code.md || echo "MISSING: $t"; done` → Expected: none. And `grep -Fq "Semgrep only" docs/getting-started-claude-code.md && echo "STALE COPIED"` → Expected: no output.
- [ ] **Step 4: Remove consumed sources.** `git rm docs/CLAUDE_CODE_QUICKSTART.md docs/CLAUDE_CODE_USAGE.md`
- [ ] **Step 5: Commit.** `git add -A && git commit -m "docs: merge Claude Code quickstart+usage into one getting-started guide"`

---

## Task 6: `docs/fuzzing.md` (MERGE, guide)

**Files:**
- Rename+rewrite: `git mv docs/FUZZING_QUICKSTART.md docs/fuzzing.md` then edit
- Source: the renamed file (history preserved)

**Interfaces:**
- Produces: the `/fuzz` guide. `commands.md` `/fuzz` entry links here.

- [ ] **Step 1:** `git mv docs/FUZZING_QUICKSTART.md docs/fuzzing.md`
- [ ] **Step 2: Edit to fix + trim.** Fix stale: replace legacy `raptor_fuzzing.py` invocation with the real `/fuzz` dispatch; remove nonexistent `test/compile_test.sh` / `test/vulnerable_test` references; complete the Params table (`--dict`/`--input-mode`/`--orchestrator`); Linux-first (env is Linux). Keep salvage (spec §7): seed-corpus fallback + `--export-seed-corpus`; autonomous-mode mechanics; Goal Options table; ASan rationale + compile cmds; troubleshooting; output structure; source-vs-binary table.
- [ ] **Step 3: Verify.** `git log --follow --oneline -- docs/fuzzing.md | head -1` → Expected: shows prior history. `grep -Fq "raptor_fuzzing.py" docs/fuzzing.md && echo "STALE REMAINS"` → Expected: no output. `for t in "--export-seed-corpus" "ASan"; do grep -Fq -- "$t" docs/fuzzing.md || echo "MISSING: $t"; done` → Expected: none.
- [ ] **Step 4: Commit.** `git add -A && git commit -m "docs: rework fuzzing quickstart into fuzzing guide; fix legacy invocation"`

---

## Task 7: `docs/validate.md` (NEW guide)

**Files:**
- Create: `docs/validate.md`
- Delete: `docs/exploitability-validation-integration.md` (user salvage moves here; methodology stays in the untouched `.claude/skills/exploitability-validation/`)
- Source: `docs/_archive/.../docs/exploitability-validation-integration.md`, `docs/_archive/.../docs/DATAFLOW_VALIDATION_SUMMARY.md`

**Interfaces:**
- Produces: the `/validate` guide. `commands.md` `/validate` entry links here.

- [ ] **Step 1: Write `docs/validate.md`.** Sections: what `/validate` does (staged pipeline, high level); two-layer framing; when-each-layer table; verdict→`final_status` map; MUST-GATEs (GATE-1..8); validation output tree; the DATAFLOW 5-question teaching framework + worked examples. Correct the stale "auto-run, no flags" UX (it's the staged `/validate`). No ALL_CAPS verdicts; no ✅/❌. Salvage: spec §7 rows for both sources.
- [ ] **Step 2: Verify.** `for t in "two-layer" "GATE-1" "final_status"; do grep -Fq -- "$t" docs/validate.md || echo "MISSING: $t"; done` → Expected: none. `grep -Eq '✅|❌' docs/validate.md && echo "EMOJI STATUS"` → Expected: no output.
- [ ] **Step 3: Remove consumed source.** `git rm docs/exploitability-validation-integration.md`
- [ ] **Step 4: Commit.** `git add -A && git commit -m "docs: add /validate user guide; retire orphan integration doc"`

---

## Task 8: Split `ARCHITECTURE.md` → `concepts.md` + `internals/architecture-internals.md`

**Files:**
- Create: `docs/concepts.md` (user slice)
- Create: `docs/internals/architecture-internals.md` (internal slice)
- Delete: `docs/ARCHITECTURE.md` (both slices salvaged; original in archive)
- Source: `docs/_archive/.../docs/ARCHITECTURE.md`

**Interfaces:**
- Produces: `concepts.md` (user "how it works") linked from `README.md`; `internals/architecture-internals.md` (contributor).

- [ ] **Step 1: Create `docs/internals/` dir.** `mkdir -p docs/internals`
- [ ] **Step 2: Write `docs/concepts.md`** (user): three-mode model + source-vs-binary rule; packages design principles; where-things-live map; crash-types; frontier-vs-local reasoning; Python 3.10+. Fix stale: remove `sys.path.insert` example (forbidden by CLAUDE.md); no fake `claude-code raptor.py`.
- [ ] **Step 3: Write `docs/internals/architecture-internals.md`**: file:line inventory; `calibrated_aggregation` internals.
- [ ] **Step 4: Verify.** `grep -Fq "sys.path.insert" docs/concepts.md && echo "FORBIDDEN COPIED"` → Expected: no output. `for t in "source" "binary" "three"; do grep -Fiq -- "$t" docs/concepts.md || echo "MISSING: $t"; done` → Expected: none.
- [ ] **Step 5: Remove source.** `git rm docs/ARCHITECTURE.md`
- [ ] **Step 6: Commit.** `git add -A && git commit -m "docs: split ARCHITECTURE into user concepts.md + internals"`

---

## Task 9: Split `sandbox.md` → operator page + `internals/sandbox-internals.md`

**Files:**
- Modify: `docs/sandbox.md` (reduce to operator slice)
- Create: `docs/internals/sandbox-internals.md`
- Source: `docs/_archive/.../docs/sandbox.md`

**Interfaces:**
- Produces: `docs/sandbox.md` (operator security guarantees, incl. new "is it safe to scan an untrusted repo?" section — nugget from `security/adversarial-repo-threat-model.md`); `internals/sandbox-internals.md`.

- [ ] **Step 1: Rewrite `docs/sandbox.md` to the operator slice.** Keep (spec §7): entry-point table + `run_untrusted()` default; **Ubuntu 24.04 mount-ns fix**; `restrict_reads`/`fake_home`; egress-proxy GHCR allowlist; `--audit` triage; `sandbox-summary.json` recovery; troubleshooting; macOS tables; **add "is it safe to scan an untrusted repo?" section**. Fix: profile table is 7 profiles (not 5); `--sandbox` accepts all 7.
- [ ] **Step 2: Write `docs/internals/sandbox-internals.md`:** ptrace / pid1-shim / token-bucket internals; full module layout.
- [ ] **Step 3: Verify.** `for t in "Ubuntu 24.04" "run_untrusted" "untrusted repo"; do grep -Fq -- "$t" docs/sandbox.md || echo "MISSING: $t"; done` → Expected: none.
- [ ] **Step 4: Commit.** `git add -A && git commit -m "docs: split sandbox doc into operator guide + internals"`

---

## Task 10: Move simple internal docs → `docs/internals/`

**Files (all via `git mv`, then light edits):**
- `git mv docs/EXTENDING_LAUNCHER.md docs/internals/extending-launcher.md`
- `git mv docs/VISUAL_DESIGN.md docs/internals/brand.md`
- `git mv docs/DATAFLOW_VALIDATION_SUMMARY.md docs/internals/validation-design.md`
- `git mv docs/design-aggregation-dominators-wp.md docs/internals/aggregation-dominators.md`
- `git mv docs/design-inventory-metadata.md docs/internals/inventory-metadata.md`
- `mkdir -p docs/internals/security` then `git mv docs/security/adversarial-repo-threat-model.md docs/security/agent-capability-matrix.md docs/security/prompt-injection-research.md docs/internals/security/`

**Interfaces:**
- Produces: living internal docs off the user path. Note: the DATAFLOW teaching examples were also salvaged into `validate.md` (Task 7) — this move keeps the design-level copy.

- [ ] **Step 1: Run all `git mv` commands above.**
- [ ] **Step 2: Fix `extending-launcher.md`:** correct `run_script` → `_run_script` (raptor.py:688); complete the mode dict; resolve hyphen/underscore naming; add slash-command/dispatch + run-lifecycle wiring.
- [ ] **Step 3: Add "shipped?" status header to `internals/security/prompt-injection-research.md`** (PR-1/2/3 are shipped). Add `name:`-field-is-dispatch-key note is destined for `commands.md`/getting-started (already covered) — leave a pointer.
- [ ] **Step 4: Verify moves preserved history.** `for f in extending-launcher brand validation-design aggregation-dominators inventory-metadata; do git log --follow --oneline -- docs/internals/$f.md | head -1 || echo "NO HISTORY: $f"; done` → Expected: each shows a prior commit. `grep -Fq "_run_script" docs/internals/extending-launcher.md && ! grep -Eq '[^_]run_script' docs/internals/extending-launcher.md` → Expected: exit 0.
- [ ] **Step 5: Commit.** `git add -A && git commit -m "docs: relocate internal design/security docs under docs/internals"`

---

## Task 11: Relocate sanitizer-cut design docs to `internals/` + repoint code→doc references (Option B)

**Context:** the prior consolidation commit `7c652c56` deleted 5 sanitizer-cut docs into `internals/sanitizer-cut.md`. That broke a golden-file test (`first-report.md` is a committed test fixture) and orphaned code path-references. Option B instead moves each doc to `docs/internals/` (keeping it a file) and repoints the code that references it. **This is the docs + reference-only-code task.**

**Files:**
- Revert consolidation: undo `7c652c56` (restores the 5 docs, removes `docs/internals/sanitizer-cut.md`).
- `git mv` (keep filenames, recreate the two subdirs under `internals/`):
  - `docs/design-sanitizer-cut-value-binding.md` → `docs/internals/design-sanitizer-cut-value-binding.md`
  - `docs/sanitizer-cut-parity/{CLOSURE,HORIZON,first-report}.md` → `docs/internals/sanitizer-cut-parity/`
  - `docs/phase-8-substrate-spike/DECISION.md` → `docs/internals/phase-8-substrate-spike/DECISION.md`
- Reference-only code edits (repoint a `docs/...` path string ONLY — no logic): `core/dataflow/smt_barrier.py`, `core/dataflow/sanitizer_cut_parity_report.py`, `core/dataflow/tests/test_lexical_removal_switch.py`, `core/dataflow/tests/test_sanitizer_cut_parity_report.py`, `core/analysis/cfg_builder_cpp.py`, `core/analysis/sanitizer_cut.py`, `core/llm/scorecard/audit.py`, `core/inventory/extractors.py`, `packages/llm_analysis/orchestrator.py`
- Regenerate: `docs/internals/sanitizer-cut-parity/first-report.md` (golden fixture)

**Interfaces:**
- Produces: all 7 internal design docs under `docs/internals/` (aggregation-dominators.md + inventory-metadata.md already moved in Task 10). Every code→doc reference resolves to the new path. Affected tests pass.

- [ ] **Step 1: Revert the consolidation.** `git revert --no-edit 7c652c56` (restores the 5 docs, removes `internals/sanitizer-cut.md`). Confirm: `ls docs/sanitizer-cut-parity/ docs/phase-8-substrate-spike/ && test ! -e docs/internals/sanitizer-cut.md`.
- [ ] **Step 2: Relocate via `git mv`** (the moves above; `mkdir -p docs/internals/sanitizer-cut-parity docs/internals/phase-8-substrate-spike` first). Verify history: `git log --follow --oneline -- docs/internals/sanitizer-cut-parity/HORIZON.md | head -1`.
- [ ] **Step 3: Repoint code→doc references** (change ONLY the `docs/...` path substring):
  - `smt_barrier.py`: `docs/sanitizer-cut-parity/HORIZON.md` → `docs/internals/sanitizer-cut-parity/HORIZON.md`
  - `sanitizer_cut_parity_report.py` (the emitted "see …HORIZON.md" line): same swap
  - `test_lexical_removal_switch.py` (assertion message path): same swap
  - `cfg_builder_cpp.py` docstring: `docs/phase-8-substrate-spike/DECISION.md` → `docs/internals/phase-8-substrate-spike/DECISION.md`
  - `test_sanitizer_cut_parity_report.py`: the `committed = repo_root/"docs"/"sanitizer-cut-parity"/"first-report.md"` path AND the regen-command docstring → `docs/internals/sanitizer-cut-parity/first-report.md`
  - `audit.py`, `sanitizer_cut.py`, `orchestrator.py`: `docs/design-aggregation-dominators-wp.md` → `docs/internals/aggregation-dominators.md`
  - `extractors.py`: `docs/design-inventory-metadata.md` → `docs/internals/inventory-metadata.md`
- [ ] **Step 4: Regenerate the golden fixture** at its new path (do this AFTER Step 3 so the emitted HORIZON path is already updated): `RAPTOR_SANITIZER_CUT=1 core/dataflow/scripts/sanitizer-cut-parity-report > docs/internals/sanitizer-cut-parity/first-report.md`
- [ ] **Step 5: Run affected tests — MUST pass.** `python -m pytest core/dataflow/tests/test_sanitizer_cut_parity_report.py core/dataflow/tests/test_lexical_removal_switch.py -q` and an import smoke: `python -c "import core.analysis.cfg_builder_cpp, core.analysis.sanitizer_cut, core.llm.scorecard.audit, core.inventory.extractors, core.dataflow.smt_barrier, core.dataflow.sanitizer_cut_parity_report, packages.llm_analysis.orchestrator"`
- [ ] **Step 6: Verify no stale doc-path strings remain in code.** `grep -rn "docs/sanitizer-cut-parity\|docs/phase-8-substrate-spike\|docs/design-aggregation-dominators-wp\|docs/design-inventory-metadata" core/ packages/ | grep -v "docs/internals/"` → Expected: **no output**.
- [ ] **Step 7: Commit.** `git add -A && git commit -m "docs: relocate sanitizer-cut design docs to internals/ and repoint code references"`

**Deferred to Task 19:** the doc→code CONTENT-accuracy fixes (core/inventory→core/analysis paths, the "5→6 fields"/"4→3 entries" miscounts, drifted line anchors, and the 7 "⚠ Superseded" plan-narrative notes) inside these relocated docs. This task only relocates + repoints references; Task 19 corrects the docs' internal content.

---

## Task 12: Rewrite root `README.md`

**Files:**
- Modify: `README.md`
- Source: `docs/_archive/2026-07-18/README.md`

**Interfaces:**
- Consumes: `install.md`, `commands.md`, `configuration.md`, `concepts.md`, `getting-started-claude-code.md` (all must exist — Tasks 1,2,3,8,5).
- Produces: the lean landing page + doc index that links the whole set.

- [ ] **Step 1: Rewrite `README.md`** to beginner→advanced order: what/why (short); install (both paths, pip — link `install.md`); a 5-minute first-run example + `/binary` variant; a command table w/ maturity (link `commands.md`); "built on Claude Code, not tied to it"; two-layer arch + dir map (link `concepts.md`); config pointer (link `configuration.md`); doc index; Slack invite, changelog prefixes, CodeQL non-commercial caveat, authors/URLs. **Move OUT** (into their pages): Z3 SMT, air-gapped, fast-tier scorecard deep-dives. Fix stale: correct offline claim; personas = 10; SSRF rule exists; drop the specific illustrative model IDs or mark them illustrative.
- [ ] **Step 2: Verify salvage + links.** `for t in "docker pull danielcuthbert/raptor" "Claude Code" "install.md" "commands.md" "configuration.md"; do grep -Fq -- "$t" README.md || echo "MISSING: $t"; done` → Expected: none. Confirm no false offline claim remains (manually re-read the offline sentence against `configuration.md`).
- [ ] **Step 3: Commit.** `git add README.md && git commit -m "docs: rewrite README as lean landing page + doc index"`

---

## Task 13: Rewrite `docs/python-cli.md`

**Files:**
- Rename+rewrite: `git mv docs/PYTHON_CLI.md docs/python-cli.md` then edit
- Source: the renamed file + `raptor.py` `_HELP_EPILOG` (read-only) for the canonical flags

**Interfaces:**
- Produces: the non-Claude-Code CLI guide. `commands.md` / `README.md` link here for scripting/CI.

- [ ] **Step 1:** `git mv docs/PYTHON_CLI.md docs/python-cli.md`
- [ ] **Step 2: Rewrite.** Fix stale: drop `RAPTOR_ROOT`/`LLM_PROVIDER` (not read by code) — only `RAPTOR_DIR`/`RAPTOR_OUT_DIR`; correct policy-group keys (`secrets/injection/auth/flows/sinks/best-practices`); add the 5 missing modes (sca/binary/describe/doctor/frida); add binary-oracle/multi-model flags. Keep salvage: non-CC value prop; CI recipe (`--mode fast`/`--max-findings`/`--no-exploits`/exit code); prereqs + API-key envs; mode→purpose lines; `--understand`/`--validate` enrichment; `help <mode>` discovery.
- [ ] **Step 3: Verify.** `git log --follow --oneline -- docs/python-cli.md | head -1` → Expected: prior history. `grep -Fq "RAPTOR_ROOT" docs/python-cli.md && echo "STALE ENV REMAINS"` → Expected: no output. `grep -Fq -- "--mode fast" docs/python-cli.md` → Expected: exit 0.
- [ ] **Step 4: Commit.** `git add -A && git commit -m "docs: rewrite Python CLI guide; fix bogus env vars and missing modes"`

---

## Task 14: Rewrite `docs/threat-model.md`

**Files:**
- Modify: `docs/threat-model.md`; move its Strict Sandbox section into `docs/sandbox.md`
- Source: `docs/_archive/.../docs/threat-model.md`

**Interfaces:**
- Produces: the user threat-model feature doc; reconciled with the `/threat-model` command.

- [ ] **Step 1: Rewrite.** Keep salvage: "What To Put In It" field list; out-of-scope nuance; flag semantics; operator-owned-context framing + accepted-proof list. Add the `/threat-model` command surface (subcommands lint/diff/report/sync/add/remove). Move the off-topic Strict Sandbox section → append to `docs/sandbox.md` (dedup with existing content).
- [ ] **Step 2: Verify.** `grep -Fiq "what to put" docs/threat-model.md && grep -Fq "/threat-model" docs/threat-model.md` → Expected: exit 0. Confirm Strict Sandbox now lives in `docs/sandbox.md`: `grep -Fiq "strict sandbox" docs/sandbox.md` → Expected: exit 0 (or content merged equivalently).
- [ ] **Step 3: Commit.** `git add -A && git commit -m "docs: rewrite threat-model guide; reconcile with /threat-model command"`

---

## Task 15: `docs/agentic.md` (NEW guide)

**Files:**
- Create: `docs/agentic.md`
- Source (read-only): `.claude/commands/agentic.md`, `CLAUDE.md` (/agentic notes)

**Interfaces:**
- Produces: the flagship `/agentic` guide. `commands.md` `/agentic` entry links here.

- [ ] **Step 1: Write it.** Sections: what `/agentic` does (scan → dedup → prep → analysis with validation methodology); the flow; flags with meaning: `--understand`, `--validate`, `--sequential`, `--model` (repeatable), `--consensus`, `--judge`, `--aggregate`; multi-model correlation; binary-oracle default behaviour + `--no-binary-oracle`. Defer exhaustive flags to `--help`.
- [ ] **Step 2: Verify.** `for t in "--understand" "--validate" "--consensus" "scan"; do grep -Fq -- "$t" docs/agentic.md || echo "MISSING: $t"; done` → Expected: none.
- [ ] **Step 3: Commit.** `git add docs/agentic.md && git commit -m "docs: add /agentic flagship workflow guide"`

---

## Task 16: `docs/understand.md` (NEW guide)

**Files:**
- Create: `docs/understand.md`
- Source (read-only): `.claude/commands/understand.md`, `CLAUDE.md` (CODE UNDERSTANDING)

**Interfaces:**
- Produces: the `/understand` guide (closes the "when to use each mode" gap). `commands.md` `/understand` entry links here.

- [ ] **Step 1: Write it.** Sections: when to use each mode — `--map` (attack surface → `context-map.json`), `--trace <entry>` (one flow → `flow-trace-*.json`), `--hunt <pattern>` (variants → `variants.json`), `--teach <subject>` (inline). Pipeline handoff to `/validate`. Beta maturity noted.
- [ ] **Step 2: Verify.** `for t in "--map" "--trace" "--hunt" "--teach"; do grep -Fq -- "$t" docs/understand.md || echo "MISSING: $t"; done` → Expected: none.
- [ ] **Step 3: Commit.** `git add docs/understand.md && git commit -m "docs: add /understand guide with mode selection"`

---

## Task 17: Fix/trim the kept guide pages

**Files:**
- Modify: `docs/frida/SETUP_LINUX.md` (fix false `doctor` claim), `docs/frida/SETUP_MACOS.md` (trim), `docs/crash-analysis.md` (trim skills/agents ref to pointers), `docs/binary-understanding.md` (unify example paths to `understand_`-prefix; add prereqs section)
- Verify-only: `docs/sca.md`, `docs/exploit-feasibility.md`, `docs/frida/QUICKSTART.md` (already canonical/current)

**Interfaces:**
- Produces: corrected kept pages; all salvage per spec §7 retained.

- [ ] **Step 1: `SETUP_LINUX.md`** — remove the false "raptor doctor reports ptrace_scope" claim (doctor never does); keep the `ptrace_scope` 0-3 table + `sysctl -w` + hardening. Verify: `grep -Fiq "doctor" docs/frida/SETUP_LINUX.md` → should only appear (if at all) in a corrected form; manually confirm no false claim.
- [ ] **Step 2: `binary-understanding.md`** — replace `out/binary-app` examples with the real `out/understand_<name>_...` default; add a short prereqs section. Verify: `grep -Fq "understand_" docs/binary-understanding.md` → Expected: exit 0.
- [ ] **Step 3: `crash-analysis.md`** — trim the Skills/Agents Reference to pointer lists; keep the setup/troubleshooting salvage.
- [ ] **Step 4: `SETUP_MACOS.md`** — light trim; keep `task_for_pid`/`csrutil`/hardened-runtime salvage.
- [ ] **Step 5: Verify canonical pages untouched-but-current** — confirm `docs/sca.md`, `docs/exploit-feasibility.md`, `docs/frida/QUICKSTART.md` still contain their key salvage tokens (spec §7). No edits required unless a token is missing.
- [ ] **Step 6: Commit.** `git add -A && git commit -m "docs: fix stale claims and trim kept guide pages"`

---

## Task 18: Remove archive-only files from the live tree

**Files:**
- Delete: `docs/README.md`, `docs/security/prompt-injection-audit.md` (both preserved in archive; salvage already migrated / superseded)

**Interfaces:**
- Consumes: all `docs/README.md` salvage confirmed placed (Tasks 3,5,7,8,1) before removal.

- [ ] **Step 1: Pre-removal salvage guard.** Confirm the migrations landed:
```bash
grep -Fq "Bedrock" docs/configuration.md && grep -Fiq "three" docs/concepts.md && grep -Fq "Semgrep" docs/install.md || echo "SALVAGE GAP — DO NOT REMOVE"
```
Expected: no `SALVAGE GAP` line.
- [ ] **Step 2: Remove.** `git rm docs/README.md docs/security/prompt-injection-audit.md`
- [ ] **Step 3: Verify archive still holds them.** `test -e docs/_archive/2026-07-18/docs/README.md && test -e docs/_archive/2026-07-18/docs/security/prompt-injection-audit.md` → Expected: exit 0.
- [ ] **Step 4: Commit.** `git add -A && git commit -m "docs: retire stale docs/README.md and superseded prompt-injection-audit (archived)"`

---

## Task 19: Cross-doc wiring + doc index + internal-doc reference accuracy

**Files:**
- Modify: any pages whose relative links point at moved/renamed/removed targets; ensure `README.md` doc index and `commands.md` guide links all resolve.
- Modify: the relocated internal design docs under `docs/internals/` (doc→code content-accuracy fixes — audit-verified).

**Interfaces:**
- Produces: a fully connected doc set (max 2 hops, no orphans) whose internal design docs reference current code paths/names/counts, with stale plan-narratives flagged (not rewritten).

- [ ] **Step 1: Find dangling internal links.**
```bash
grep -rEno '\]\(([A-Za-z0-9_./-]+\.md)(#[A-Za-z0-9_-]+)?\)' docs README.md | while IFS= read -r line; do :; done
```
(Use the Task 20 checker for the authoritative pass; here, manually update links from renamed sources: `ARCHITECTURE.md`→`concepts.md`, `PYTHON_CLI.md`→`python-cli.md`, `FUZZING_QUICKSTART.md`→`fuzzing.md`, `CLAUDE_CODE_*`→`getting-started-claude-code.md`, `DEPENDENCIES.md`→`install.md`/`attribution.md`, `exploitability-validation-integration.md`→`validate.md`.)
- [ ] **Step 2: Verify `commands.md` guide links resolve** (now that all 8 guides exist):
```bash
for g in validate.md sca.md fuzzing.md crash-analysis.md binary-understanding.md frida/QUICKSTART.md agentic.md understand.md; do test -e docs/$g || echo "MISSING GUIDE: $g"; done
```
Expected: none.
- [ ] **Step 3: Verify `README.md` doc index targets exist.** For each `docs/*.md` link in README, `test -e`. Expected: all present.
- [ ] **Step 3b: Fix stale doc→code references inside the relocated internal design docs** (audit-verified; docs only — no code):
  - **(a) Path fixes:** `core/inventory/<M>.py` → `core/analysis/<M>.py` **only for modules that moved**: `cfg_builder`, `cfg_builder_cpp`, `dataflow`, `dominators`, `sanitizer_cut`, `binary_oracle`, `binary_oracle_edges`, `finding_resolver`, `reach_chokepoint`, `taint_summaries`, `interproc`, `callgraph`→`python_module_callgraph`, and their `tests/`. **Do NOT change** `core/inventory/{extractors,builder,lookup,call_graph}.py` — those stayed. Affects `design-sanitizer-cut-value-binding.md`, `aggregation-dominators.md`, `phase-8-substrate-spike/DECISION.md`, `sanitizer-cut-parity/CLOSURE.md`.
  - **(a) Counts/renames:** `inventory-metadata.md`: "5 metadata fields" → 6 (`class_attributes`, `extractors.py:84`); `build_analysis_prompt(` → `build_analysis_prompt_bundle(`. `design-sanitizer-cut-value-binding.md`: "4 GLib/SQLite entries" → 3. `aggregation-dominators.md`: drop/fix `binary_oracle_edges.py` "591 lines" (→688). Fix drifted `smt_barrier.py` line anchors (746/940 → 936/1183) or switch to `::symbol`.
  - **(b) Add a one-line `⚠ Superseded — actually shipped: …` note** (do NOT rewrite the narrative) at each of the 7 stale-plan spots: dominator pre-filter (code does none — unsound), D-S `dispatch.py:226` wiring, `--consensus=vote` flag, `--sanitizer-cut` on `/validate` + persist, "SARIF→analysis without checklist", prompt metadata-arg "not yet", `multi_model_panel.jsonl`. (Exact per-note text is in the PR findings log.)
  - **Untouched:** `sanitizer-cut-parity/HORIZON.md` (audited consistent) and `sanitizer-cut-parity/first-report.md` (generated fixture — never hand-edit).
- [ ] **Step 3c: Verify accuracy fixes.** `grep -rn "core/inventory/\(cfg_builder\|dataflow\|dominators\|sanitizer_cut\|binary_oracle\|finding_resolver\|reach_chokepoint\|taint_summaries\|interproc\)" docs/internals/ | grep -v _archive` → Expected: no output. `grep -rl "Superseded" docs/internals/ | wc -l` → expect ≥5 files carrying the notes.
- [ ] **Step 4: Commit.** `git add -A && git commit -m "docs: fix cross-references and internal-doc code references; wire doc index"`

---

## Task 20: Link-integrity check (full) — receipt #1

**Files:**
- Create (scratchpad, NOT committed): `/tmp/.../linkcheck.py`

**Interfaces:**
- Produces: a zero-broken-links report for the PR evidence bundle.

- [ ] **Step 1: Write the throwaway checker** in the scratchpad: walk every `.md` under `docs/` (excluding `_archive/`) + `README.md`; for each relative Markdown link, resolve against the file's dir and assert the target exists; for `#anchor` links, assert a matching heading slug exists in the target.
- [ ] **Step 2: Run it.** Run: `python3 /tmp/.../linkcheck.py` → Expected: `0 broken links`. Fix any reported break in the offending doc and re-run until clean.
- [ ] **Step 3: Save the clean report** to the scratchpad for the PR body. (No commit — tooling is not part of the docs diff.)

---

## Task 21: Salvage-coverage verification — receipt #2

**Interfaces:**
- Produces: the salvage-coverage checklist (every spec §7 salvage item → new home), 100%, for the PR body.

- [ ] **Step 1: Build the checklist.** For each row in spec §7, list its named salvage items and the destination page. For each item, grep the destination for a representative token.
- [ ] **Step 2: Run coverage greps.** Produce a table `salvage item → destination → present? (grep exit)`. Any `absent` item is either (a) a real gap — go back and add it — or (b) intentionally dropped, which must have a receipt in Task 22.
- [ ] **Step 3: Assert two-bucket invariant.** Every archived file's content is either relocated (found in a live page) or listed in the removal-receipt ledger (Task 22). No third bucket.
- [ ] **Step 4: Save the coverage table** to the scratchpad for the PR body.

---

## Task 22: Removal-receipt re-verification — receipt #3

**Interfaces:**
- Produces: the stale-content receipts ledger (each removed claim → live-repo evidence), independently re-checked.

- [ ] **Step 1: For each removal/rewrite in spec §9,** re-verify the staleness claim against the LIVE repo (not the doc): e.g. `test -e engine/semgrep/rules/registry-cache/*` (offline claim), `ls | grep RAPTOR-daniel-modular` (dead dir), `grep -rn "def _run_script" raptor.py` (name), `grep -rn "ptrace_scope" core/startup/doctor.py` (false doctor claim). Record the command + result as the receipt.
- [ ] **Step 2: Gate.** If any staleness claim cannot be confirmed, RESTORE that content (do not remove it) and note the reversal.
- [ ] **Step 3: Save the receipts ledger** to the scratchpad for the PR body.

---

## Task 23: Assemble PR evidence bundle + final acceptance check

**Interfaces:**
- Produces: the PR description with all three receipts; final go/no-go against spec §12.

- [ ] **Step 1: Diff-scope check (Option B allowlist).** Only `docs/**`, `README.md`, and the Task-11 enumerated code files may appear:
```bash
git diff --name-only main...HEAD | grep -vE '^(docs/|README\.md$|core/dataflow/smt_barrier\.py$|core/dataflow/sanitizer_cut_parity_report\.py$|core/dataflow/tests/test_lexical_removal_switch\.py$|core/dataflow/tests/test_sanitizer_cut_parity_report\.py$|core/analysis/cfg_builder_cpp\.py$|core/analysis/sanitizer_cut\.py$|core/llm/scorecard/audit\.py$|core/inventory/extractors\.py$|packages/llm_analysis/orchestrator\.py$)'
```
→ Expected: **no output**. Then confirm the code diffs are **reference-only**: `git diff main...HEAD -- <those 9 files>` must show only `docs/...` path-string changes (plus the regenerated fixture) — no logic edits.
- [ ] **Step 2: Affected tests green.** Re-run `python -m pytest core/dataflow/tests/test_sanitizer_cut_parity_report.py core/dataflow/tests/test_lexical_removal_switch.py -q` → all pass. Also run the diff-scoped ruff gate on changed `.py`: `git diff --name-only main...HEAD -- '*.py' | xargs -r ruff check --select F401,F811,F821,F841`.
- [ ] **Step 3: Net line-count check.** Compare live user-facing doc line totals before (archive) vs after; assert net negative or flat. Record the numbers.
- [ ] **Step 4: Assemble PR body** = migration ledger (spec §7) + **findings log** (docs fixed · code-side flags not fixed · out-of-scope contributor-doc staleness) + doc↔code audit summary (code correct, docs lagged) + link-check report (Task 20) + salvage-coverage table (Task 21) + removal receipts (Task 22) + net-line-count + the Option-B code-reference change list.
- [ ] **Step 5: Walk spec §12 acceptance criteria** (as amended by the Option-B revision) and tick each with evidence. Any unchecked box blocks the PR.
- [ ] **Step 6: Report to the operator** that the branch is ready; do NOT push or open the PR (dangerous op — ask first per project CLAUDE.md).

---

## Self-Review

- **Spec coverage:** every spec §7 ledger row maps to a task (Tasks 1–18); §6 command plan → Task 2; §8 archive → Task 0; §9 receipts → Task 22; §10 gaps → Tasks 1,2,3,16; §11 proof → Tasks 20–23; §12 acceptance → Task 23; §5.4 `.claude` read-only → Global Constraints + enforced by Task 23 diff-scope.
- **Placeholder scan:** no TBD/TODO; each content task lists concrete required sections + grep-able salvage tokens + exact verification commands.
- **Consistency:** page filenames match across tasks and the spec tree (`concepts.md`, `python-cli.md`, `fuzzing.md`, `getting-started-claude-code.md`, `docs/internals/*`); guide-link targets in Task 2/19 match the files created in Tasks 5/6/7/15/16/17.
