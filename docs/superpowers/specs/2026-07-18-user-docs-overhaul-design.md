# RAPTOR User-Documentation Overhaul — Design Spec

- **Date:** 2026-07-18
- **Status:** Approved design — pre-implementation
- **Branch:** `docs/user-documentation-overhaul`
- **Scope:** User-facing documentation only

---

## 1. Problem

RAPTOR's user documentation has decayed through duplication that drifted out of sync. A full inventory (73 doc records across the repo, all 31 commands catalogued) found:

- **Two competing top-level docs.** Root `README.md` and `docs/README.md` (887 lines) contradict each other — including a different acronym expansion ("Recursive Autonomous Penetration Testing and Observation Robot" vs. "Autonomous Offensive/Defensive Research Framework").
- **`docs/` is a flat folder mixing three audiences** — user guides, contributor/internal design docs, and security research — with no index and no separation.
- **The command list exists in 6 drifting copies** (README, both Claude-Code docs, `.claude/README.md`, `ARCHITECTURE.md`, `VISUAL_DESIGN.md`); none is complete.
- **Install facts are smeared across 6 files**; there is no must-vs-optional matrix.
- **LLM configuration lives in 4 places**; there are 3 overlapping threat-model docs with no stated authority.
- **Concrete stale/false content** exists throughout (see §9), e.g. a false "offline" claim, "nine personas" (there are 10), a dead directory reference, a doc that invokes a legacy script, and an architecture example using a pattern `CLAUDE.md` explicitly forbids.

The result is a "documentation rabbit hole": users can't find the answer, and when they do it may be wrong.

## 2. Goals & non-goals

### Goals
1. Clear, ordered, **scannable** user docs — beginner → advanced, no forced detours.
2. Close the two named gaps: **install (must vs optional)** and a **command reference** (what you can use, its parameters, and in what order).
3. Eliminate duplication and stale contradictions, **with proof** (see §11).
4. Preserve everything — **nothing relevant is lost**.
5. **Net user-facing line count goes down**, not up.

### Non-goals (explicit — do not do these here)
- **No uv migration and no install-mechanics change.** Document the repo's *current* reality (`pip` + `requirements.txt`). A future uv move is a separate effort with its own PR.
- **No code, no CI changes, no generator scripts.** This PR is Markdown-only (writing, moving via `git mv`, deleting).
- **No `.claude/` edits.** `.claude/commands/*.md`, `.claude/skills/*`, `.claude/agents/*` are read-only sources only (see §5.4).
- **No changes to contributor docs co-located with code** (`core/`, `packages/`, `engine/`, `tiers/`, `test/`, `CITATION.cff`, etc.). Staleness there is logged as a follow-up (§13), not fixed here.

## 3. Guiding principles

1. **One page = one job.** Each page fully answers one question; links are further-reading, never required steps.
2. **Single source of truth per fact.** No fact stated in two places (duplication is what caused the drift).
3. **Max 2 hops.** `README.md` → a `docs/*` page; `commands.md` → a guide page. No page→page→page chains.
4. **Reference vs. guide separation** (§4).
5. **Nothing lost** — archive (§8) + salvage ledger (§7).
6. **No fluff.** If a page doesn't answer a question a real user asks, it doesn't exist.

## 4. The reference-vs-guide rule

`commands.md` is the **reference** — every command in one scannable place, one entry each (purpose, key params, maturity, workflow order). A command earns a **separate guide page only if** it has how-to depth that cannot fit a reference entry — specifically at least one of: **prerequisites to install**, a **multi-file output structure**, or a **troubleshooting section**.

- **Guide page (8):** `/validate`, `/sca`, `/fuzz`, `/crash-analysis`, `/binary`, `/frida`, `/agentic`, `/understand`.
- **`commands.md` entry only:** `/scan`, `/codeql`, `/analyze`, `/web`, `/annotate`, `/diagram`, `/exploit`, `/patch`, `/project`, `/oss-forensics`, `/cve-diff`, `/threat-model`, `/describe`, `/scorecard`, `/version`, `/commands`, and the alias/hidden commands.

`commands.md` is the hub: it contains everything else in full and links out to the eight guides. Deep content lives in exactly one place; the reference carries a one-liner + link. (`/exploit`, `/patch`, `/threat-model` reference entries link to the existing concept pages `exploit-feasibility.md` / `threat-model.md`.)

## 5. Target information architecture

### 5.1 Tree

```
README.md                          [rewrite]  landing: what · install (both paths) · command table · first-run · doc index
CLAUDE.md                          [unchanged framework file]
LICENSE                            [unchanged]
CITATION.cff                       [unchanged — version bump deferred, §13]

docs/                              (user-facing — flat)
├── install.md                     [NEW]      must-vs-optional matrix (pip, as-is) · auth/API-key · first-run · output layout
├── commands.md                    [NEW]      command reference — all 31, grouped by workflow stage; links to 8 guides
├── configuration.md               [NEW]      models.json · env auto-detect · roles · Bedrock · Ollama caveat · RAPTOR_MAX_COST · offline (corrected)
├── getting-started-claude-code.md [MERGE]    ← CLAUDE_CODE_QUICKSTART.md + CLAUDE_CODE_USAGE.md
├── python-cli.md                  [REWRITE]  ← PYTHON_CLI.md
├── concepts.md                    [SPLIT]    ← ARCHITECTURE.md (user half)
├── attribution.md                 [NEW]      ← DEPENDENCIES.md (license/attribution half)
├── validate.md                    [NEW guide]   ← exploitability-validation-integration + DATAFLOW_VALIDATION_SUMMARY salvage
├── agentic.md                     [NEW guide]   ← CLAUDE.md /agentic + .claude/commands/agentic.md (read-only source)
├── understand.md                  [NEW guide]   "when to use each mode" (map/trace/hunt/teach) — closes a gap
├── sca.md                         [keep — canonical guide]
├── fuzzing.md                     [MERGE guide] ← FUZZING_QUICKSTART.md
├── crash-analysis.md              [keep — trim guide]
├── binary-understanding.md        [keep — trim guide]
├── exploit-feasibility.md         [keep — concept guide]
├── sandbox.md                     [SPLIT]    operator slice + "is it safe to scan an untrusted repo?" section
├── threat-model.md                [rewrite]
├── frida/                         (justified: 3 real files, guide cluster)
│   ├── QUICKSTART.md              [keep]
│   ├── SETUP_LINUX.md             [keep — fix false doctor claim]
│   └── SETUP_MACOS.md             [keep — trim]
├── internals/                     [NEW folder — living contributor/design docs, off the user path]
│   ├── architecture-internals.md  ← ARCHITECTURE.md internal slice
│   ├── sandbox-internals.md       ← sandbox.md internal slice
│   ├── validation-design.md       ← DATAFLOW_VALIDATION_SUMMARY.md
│   ├── sanitizer-cut.md           ← design-sanitizer-cut + parity CLOSURE/HORIZON + phase-8 DECISION (collapses 2 subdirs)
│   ├── aggregation-dominators.md  ← design-aggregation-dominators-wp.md
│   ├── inventory-metadata.md      ← design-inventory-metadata.md
│   ├── extending-launcher.md      ← EXTENDING_LAUNCHER.md (bugs fixed)
│   ├── brand.md                   ← VISUAL_DESIGN.md
│   └── security/                  ← adversarial-repo-threat-model + agent-capability-matrix + prompt-injection-research
└── _archive/2026-07-18/           [NEW — verbatim snapshot of the pre-overhaul docs/ tree + old README; see §8]
```

### 5.2 Removed from the live tree (preserved only in `_archive/`)
- `docs/README.md` — salvage migrated (§7); dropped.
- `docs/sanitizer-cut-parity/first-report.md` — superseded/regenerable; dropped.
- `docs/security/prompt-injection-audit.md` — stale + unfinished, superseded by shipped `prompt_envelope`; dropped.

### 5.3 New structure justification (each new file/folder earns its place)
| New | Why |
|---|---|
| `install.md` | Closes named gap (a); install facts are smeared across 6 docs today. |
| `commands.md` | Closes named gap (b); 6 drifting command lists exist, none complete. |
| `configuration.md` | LLM/model config lives in 4 places with none authoritative. |
| `validate.md` / `agentic.md` / `understand.md` | Guide-worthy per §4; user-facing "how/when" content has no home today (the deep methodology lives only in agent-facing `.claude/skills`, which is untouched). |
| `attribution.md` | Separates legal/attribution from operational install. |
| `docs/internals/` | Collapses ~13 internal design/security/parity docs plus two ad-hoc subdirs off the user browse path — a net structural *simplification*. |

### 5.4 `.claude/` handling — read-only

`.claude/` is out of scope. `.claude/commands/*.md` are CI-enforced executable dispatch definitions; `.claude/skills/*` and `.claude/agents/*` are loaded at runtime. The overhaul **reads** `.claude/commands/*.md` as the source of truth for `commands.md` and makes **zero edits** anywhere under `.claude/`. Agent skills stay self-contained — duplication between a user doc and an agent skill (e.g. `docs/frida/QUICKSTART.md` ↔ `.claude/skills/frida/SKILL.md`) is intended and left as-is.

## 6. Command reference plan (`commands.md`)

- **Grouped by workflow stage, not alphabetical:**
  `Plan/Setup → Discover → Understand → Analyse → Validate → Exploit/Patch → Runtime → Report/Manage` (Forensics is a standalone track).
- **Per-command entry:** purpose · key params · workflow position · maturity. **Full flag details defer to `--help`/argparse** — the single source of truth, and the reason the 6 prior lists drifted.
- **Maturity flags shown:** beta (`/understand`, `/diagram`, `/exploit`, `/patch`), alpha (`/web`, `/frida`, `/create-skill`).
- **Aliases/hidden:** `/raptor-scan`, `/raptor-fuzz`, `/raptor-web`, `/raptor-sca`, `/raptor-frida` documented as aliases pointing to canonical names; `/audit` noted as renamed to `/understand`.
- **Include `/tune` and `/doctor`** (real but absent from `CLAUDE.md`'s COMMANDS list) — flagged in §13 as a `CLAUDE.md` gap to close later.

## 7. Nothing-lost disposition ledger

`docs/_archive/2026-07-18/` holds a **verbatim copy of the entire current `docs/` tree + old `README.md`** taken before any change, so every file below also exists frozen there.

### Live user docs — rewritten / kept / split
| File | Disposition | Salvage that must carry forward |
|---|---|---|
| `README.md` | rewrite | both install paths (pip + devcontainer `docker pull …danielcuthbert/raptor`, `--privileged`-for-rr, ~6 GB); command table w/ maturity; "built on Claude Code, not tied to it"; happy-path example + `/binary` variant; two-layer arch + dir map; `models.json` block; corrected offline behaviour; doc index; Slack invite; changelog prefixes; CodeQL non-commercial caveat; authors/URLs |
| `docs/sca.md` | keep (canonical) | `bin/raptor-sca` env-strip + `_RAPTOR_TRUSTED`; inline-install extraction + recognised-command list; sub-commands (diff/verify/render/purl/health); data-sources + 10-registry list; 6-verdict reachability + two-tier + render filters; `sca-pr-gate.yml`; Limitations |
| `docs/exploit-feasibility.md` | keep (concept) | verdict table; `chain_breaks`/`what_would_help`; 3 scenarios; Target Profiles table; empirical-vs-theoretical (two-probe %n); web-vuln alias list; "what it does NOT do" |
| `docs/crash-analysis.md` | keep (trim) | `perf_event_paranoid` setup; ASAN `-O0`→`-O1`; CFLAGS+LDFLAGS `--coverage` gotcha; not-reproducible checklist; output tree; Perfetto; rr-trace sharing; Linux/x86_64/C-C++ limits |
| `docs/binary-understanding.md` | keep (trim) | artefact-type + evidence-tier tables; static-only gating (`--runtime`/`--fuzz`/`--active`); `--slice-arch`/`--max-decompile`; `conditions.json` schema; `parser_boundary` + graph edge names; watched-API list; `fuzz_suitability` enum; `binary-validation-handoff.json` |
| `docs/frida/QUICKSTART.md` | keep | 3 frida-server shapes; run examples incl. `--spawn-by-bundle-id`; output layout; 4-row failure table |
| `docs/frida/SETUP_LINUX.md` | keep (fix false `doctor` claim) | `ptrace_scope` 0-3 table; `sysctl -w`; spawn-and-attach; remote bind + SSH-forward hardening; `ss` diagnostic; SELinux `setenforce 0` |
| `docs/frida/SETUP_MACOS.md` | keep (trim) | `task_for_pid` same-UID; `csrutil disable --without debug` + VM warning; hardened-runtime re-sign; `codesign` entitlements; arm64 arch-match |
| `docs/PYTHON_CLI.md` | rewrite → `docs/python-cli.md` | non-CC CLI value prop; CI recipe (`--mode fast`/`--max-findings`/`--no-exploits`/exit code); prereqs + API-key envs; mode→purpose lines; `--understand`/`--validate` enrichment; `help <mode>` discovery |
| `docs/threat-model.md` | rewrite | "What To Put In It" fields; out-of-scope nuance; flag semantics; operator-owned-context framing + accepted-proof list (move Strict Sandbox → `sandbox.md`; reconcile with `/threat-model` command) |
| `docs/ARCHITECTURE.md` | split → `concepts.md` + `internals/architecture-internals.md` | user: three-mode model + source-vs-binary rule; packages design principles; where-things-live map; crash-types; frontier-vs-local; Python 3.10+ · internal: file:line inventory; `calibrated_aggregation` internals |
| `docs/sandbox.md` | split → `sandbox.md` (operator) + `internals/sandbox-internals.md` | operator: entry-point table + `run_untrusted()` default; **Ubuntu 24.04 mount-ns fix**; `restrict_reads`/`fake_home`; egress-proxy GHCR allowlist; `--audit` triage; `sandbox-summary.json` recovery; macOS tables; **+ new "is it safe to scan an untrusted repo?" section** · internal: ptrace/pid1-shim/token-bucket |

### Merged away → consolidation page (old standalone removed from live)
| File | Merges into | Salvage |
|---|---|---|
| `docs/CLAUDE_CODE_QUICKSTART.md` | `getting-started-claude-code.md` | short/long-form alias rule; 4-step setup; optional-tools list; "talk naturally" framing |
| `docs/CLAUDE_CODE_USAGE.md` | `getting-started-claude-code.md` | grouped-catalog scaffold; persona invocation idiom + persona→purpose map; adversarial order (Secrets→Input→Auth→Crypto→Config); `out/` tree; troubleshooting (no-findings needs `.git`; LLM-error checklist) |
| `docs/DEPENDENCIES.md` | `install.md` + `attribution.md` | per-feature tool→command map → install; license-per-tool table + CodeQL non-commercial → attribution |
| `docs/FUZZING_QUICKSTART.md` | `fuzzing.md` | seed-corpus fallback order + `--export-seed-corpus`; autonomous-mode mechanics; Goal Options table; ASan rationale + compile cmds; troubleshooting; provider quality; output structure; source-vs-binary table |
| `docs/exploitability-validation-integration.md` | `validate.md` (methodology stays in untouched `.claude` skill) | two-layer framing; when-each-layer table; verdict→`final_status` map; `_derive_verdict_from_source` rules; GATE-1..8; SARIF dedup key; integration examples; validation output tree |

### New consolidation / guide pages
| New file | Consolidates / sources | Contents |
|---|---|---|
| `install.md` | install-in-6-places | must-vs-optional matrix (pip, as-is); auth/API-key; first-run; output layout |
| `commands.md` | 6 command lists | all 31, grouped by stage; maturity; params → `--help`; links to 8 guides |
| `configuration.md` | LLM config in 4 places | `models.json`; env auto-detect; roles; Bedrock; Ollama caveat; `RAPTOR_MAX_COST`; corrected offline |
| `validate.md` | validation-integration + DATAFLOW salvage | what `/validate` does; two-layer; verdict→status; teaching examples |
| `agentic.md` | `CLAUDE.md` /agentic + command file (read-only) | scan→dedup→prep→analysis flow; `--understand`/`--validate`/`--model`/`--consensus`/`--judge`/`--aggregate`/`--sequential`; multi-model correlation |
| `understand.md` | command file + gap | when to use each mode: `--map`/`--trace`/`--hunt`/`--teach`; outputs |
| `attribution.md` | DEPENDENCIES license half | per-tool license table + CodeQL non-commercial |

### `docs/` internal design/research → `docs/internals/`
| File | Destination | Salvage |
|---|---|---|
| `docs/EXTENDING_LAUNCHER.md` | `internals/extending-launcher.md` | 5-step recipe; `RAPTOR_DIR` sys.path pattern; **`_run_script` (name corrected)**; output convention; + dispatch/run-lifecycle wiring |
| `docs/VISUAL_DESIGN.md` | `internals/brand.md` | tagline bank (15); glyph legend (marked proposed) |
| `docs/DATAFLOW_VALIDATION_SUMMARY.md` | `internals/validation-design.md` (+ examples → `validate.md`) | 5-question framework + 3 worked examples |
| `docs/design-aggregation-dominators-wp.md` | `internals/aggregation-dominators.md` | `calibrated_aggregation` field + ~0.5 sparse-cell expectation + suppression ordering |
| `docs/design-inventory-metadata.md` | `internals/inventory-metadata.md` | `checklist.json` schema; 3-tier extraction chain; tree-sitter install fact |
| `docs/design-sanitizer-cut-value-binding.md` | `internals/sanitizer-cut.md` | `--sanitizer-cut` operator interface + `--sanitizer-cut-parity-log` |
| `docs/phase-8-substrate-spike/DECISION.md` | `internals/sanitizer-cut.md` (ADR) | tree-sitter-vs-libclang-vs-r2 decision + revisit trigger |
| `docs/sanitizer-cut-parity/CLOSURE.md` | `internals/sanitizer-cut.md` | `strict` end-state semantics |
| `docs/sanitizer-cut-parity/HORIZON.md` | `internals/sanitizer-cut.md` | `shadow` + parity-log usage + regen command |
| `docs/security/adversarial-repo-threat-model.md` | `internals/security/` (+ nugget → `sandbox.md`) | defense-in-depth table; 7 scenarios; honest "not-defended" list |
| `docs/security/agent-capability-matrix.md` | `internals/security/` (+ nugget → `commands.md`) | A/B/C verdict table; **`name:`-field-is-dispatch-key gotcha**; git-hooks-on-clone risk; WebFetch-allowlist |
| `docs/security/prompt-injection-research.md` | `internals/security/` (add "shipped?" header) | vendor-guidance asks; "Attacker Moves Second"; name-map; classifier-skip reasoning; Sources |

### Removed from live, no successor (archive-only)
| File | Why | Salvage |
|---|---|---|
| `docs/README.md` | 887-line stale duplicate; wrong acronym; superseded | all migrated (Bedrock→`configuration`, exploit §4→`exploit-feasibility`, dataflow→`validate`, providers/Ollama→`configuration`, corpus/ASan→`fuzzing`, three-mode→`concepts`, prereqs→`install`) |
| `docs/sanitizer-cut-parity/first-report.md` | superseded by CLOSURE/HORIZON; regenerable | none (conclusion preserved) |
| `docs/security/prompt-injection-audit.md` | stale + unfinished; superseded by shipped `prompt_envelope` | callsite map + untrusted-field taint set noted for re-verify-before-reuse |

## 8. Archive mechanism

- Location: `docs/_archive/2026-07-18/`, mirroring original relative paths.
- Content: a verbatim copy of the entire current `docs/` tree **and** the pre-overhaul `README.md`, taken **before** any edit/move/delete.
- A short `docs/_archive/README.md` note explains: "Pre-overhaul snapshot, 2026-07-18. Live docs are in `docs/`. Maintainers may prune this directory." — deletion is the maintainers' decision, not ours.
- Rationale: guarantees "removed from live" never means "gone," and de-risks the `internals/` curation.

## 9. Stale / contradiction ledger (removal receipts fodder)

Every removal/rewrite is backed by concrete, code-verified evidence. Highlights (full per-file list carried from the inventory):

- **Two-README acronym conflict** (`docs/README.md` L1 vs `CLAUDE.md`/root README).
- **`README.md`:** false offline claim (`engine/semgrep/rules/registry-cache/` is an empty `.gitkeep`); "SSRF has no rule" wrong (`sinks/ssrf.yaml`, taint-mode); "Nine personas" (10 files); stale banner version; illustrative model IDs presented as real.
- **`docs/README.md`:** "Version 2.0"; dead dir `RAPTOR-daniel-modular/`; nonexistent `packages/llm_analysis/llm/` (real: `core/llm/`); packages tree 9-of-27; "What's Not Working" lists shipped features; dead test link; empty Licence section.
- **`docs/PYTHON_CLI.md`:** `RAPTOR_ROOT`/`LLM_PROVIDER` never read by code; wrong policy-group keys; 5 modes missing.
- **`docs/FUZZING_QUICKSTART.md`:** invokes legacy `raptor_fuzzing.py` (bypasses lifecycle); references nonexistent `test/compile_test.sh` / `test/vulnerable_test`.
- **`docs/ARCHITECTURE.md`:** `sys.path.insert(...)` contradicts `CLAUDE.md`'s `RAPTOR_DIR`-only rule; fake `claude-code raptor.py`; broken TOC.
- **`docs/frida/SETUP_LINUX.md`:** false — `raptor doctor` does **not** report `ptrace_scope`.
- (Plus `DEPENDENCIES.md`, `CLAUDE_CODE_USAGE.md`, `sandbox.md`, `threat-model.md`, `EXTENDING_LAUNCHER.md`, `VISUAL_DESIGN.md`, `DATAFLOW_VALIDATION_SUMMARY.md`, security/* — see inventory.)

Every "stale" verdict here is **independently re-verified against the live repo before the content is removed** (§11).

## 10. Gap list (justifies the new writing)

Ranked by how commonly a user hits it: (1) must-vs-optional install matrix; (2) single canonical command reference; (3) first-run happy path + where output lands; (4) uv-vs-pip clarity → documented as pip; (5) which onboarding doc first; (6) first-run troubleshooting; (7) one-page LLM configuration; (8) what a project is / when to scope one; (9) corrected offline truth; (10) `/web` actual capability; (11) supplying a debug binary to the binary-oracle; (12) which threat-model doc is canonical.

## 11. Proof / receipts plan for the PR

Three evidence artifacts, each independently checkable, delivered in the PR description (not committed as tooling):

1. **Migration ledger** — `source → destination → why` for every file; all moves done with **`git mv`** so `git log --follow` shows content continuity.
2. **Removal receipts** — each removed/dropped chunk paired with concrete evidence it was stale (contradicts `CLAUDE.md`/code with `file:line`, references a nonexistent path/command, or is superseded). Each verdict is **adversarially re-verified against the live repo before removal**; if staleness can't be confirmed, the content stays.
3. **Salvage-coverage checklist** — every `salvage` item in §7 mapped to its new home (`file + section`), verified at **100%**. Invariant: every pre-existing fact ends in exactly one bucket — **relocated** (ledger 1) or **dropped-with-receipt** (ledger 2). No silent-loss bucket.

Plus a **link-integrity check**: a throwaway local script walks every `.md`, resolves every relative link + anchor, and must report **zero** broken links; its output goes in the PR body. No committed CI tooling (keeps the PR docs-only).

## 12. Acceptance criteria

- [ ] Diff touches **only** `docs/**` and `README.md`. Nothing under `.claude/`, `core/`, `packages/`, `engine/`, `tiers/`, `test/` changed.
- [ ] `docs/_archive/2026-07-18/` contains a verbatim pre-overhaul snapshot.
- [ ] Named gaps closed: `install.md` (must vs optional) and `commands.md` (all 31, params, order) exist and are complete.
- [ ] All 8 guide pages exist; `commands.md` links to each; every other command fully documented in `commands.md`.
- [ ] Zero broken internal links (checker output attached).
- [ ] 100% salvage coverage; every removal has a re-verified receipt.
- [ ] Net user-facing line count is **negative or flat**.
- [ ] No page requires more than 2 hops from `README.md`.

## 13. Known follow-ups (out of scope — logged, not fixed here)

- Stale contributor/code-adjacent docs: `core/oci/README.md` (`/audit`→`/understand`), `CITATION.cff` version lag, `packages/codeql` "Phase 1/2" framing, `core/sage/docs/SAGE_INTEGRATION.md` counts post-upgrade, `.claude/skills/oss-forensics/.../self_improvement_prompt.md` leftover.
- `CLAUDE.md` COMMANDS list missing `/tune` and `/doctor`.
- Auto-generating `commands.md` from `.claude/commands/*.md` frontmatter (+ a CI drift check).
- Project-wide uv migration.

## 14. Risks & open items

- **Link churn:** moving files can break inbound links from README/other docs and external references. Mitigated by the link-check (§11) for internal links; external inbound links to moved paths are unavoidable but rare for a repo doc reorg.
- **`internals/` judgment:** some "internal" classifications are judgment calls; de-risked by the archive (original one folder away).
- **Salvage fidelity:** the risk is subtle content loss during merges; mitigated by the salvage-coverage checklist reviewed against the archive.

## 15. Implementation phasing (preview for the plan)

0. Branch + write archive snapshot + archive README note.
1. New consolidation pages: `install.md`, `commands.md`, `configuration.md`, `attribution.md`.
2. Merges: `getting-started-claude-code.md`, `fuzzing.md`, `validate.md`.
3. Splits: `concepts.md` + `internals/architecture-internals.md`; `sandbox.md` + `internals/sandbox-internals.md`.
4. `git mv` internal design/security docs → `docs/internals/`.
5. Rewrites: `README.md`, `python-cli.md`, `threat-model.md`.
6. New guides: `agentic.md`, `understand.md`.
7. Verification: link-check, salvage-coverage, stale re-verification; assemble PR evidence bundle.
