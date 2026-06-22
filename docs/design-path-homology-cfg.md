# Path Homology as a Reverse-Engineering Structural Signal

Proposal to add **path homology** — a directed-graph generalization of
cyclomatic complexity — to RAPTOR as a per-function *structural* signal in
the binary reverse-engineering path. It is a metric / triage / decompiler-
confidence signal, **not** a soundness primitive: it never licenses a
suppression and never touches the sanitizer-cut chokepoint.

Status: **Phases 1–3 shipped (reported-only); Phase 4 gate returned
NO-GO; Phases 5–7 not pursued.** The β_2 / irreducibility signal proved
*vacuous on real binaries* (1 / 8,459 functions) — the evidence gate
working as designed. The reported-only telemetry stays; nothing feeds
ranking. Constructive next step is a β_1 (not β_2) experiment — see
"Phase 4 result". This is a follow-on metrics arc to
`design-aggregation-dominators-wp.md` (Project B built the CFG / `Graph`
substrate this reuses).

---

## 1. Summary

Cyclomatic complexity `v(G) = |E| − |V| + 1` is the first Betti number of
the **undirected** control-flow graph: it counts independent cycles and is
identically zero in every dimension above 1. **Path homology** (Grigor'yan–
Lin–Muranov–Yau; applied to control flow by Huntsman 2020) is a homology
theory for **directed** graphs whose Betti numbers `β_p` can be nonzero in
*arbitrary* dimension. For *structured* control flow (if / while / repeat)
it coincides with cyclomatic complexity (`β_1 = v(G)`, `β_{p≥2} = 0`). The
two **diverge only on unstructured control flow** — assembly jumps, gotos,
irreducible loops, control-flow flattening — where `β_2, β_3, …` become
nonzero.

(A refinement learned while building the Phase 1 core: on the bare CFG,
direction-aware `β_1` *fills the commutative square* between the two
branches of an if/else, so `β_1 ≤ cyclomatic` — it agrees with cyclomatic
on genuine loops but counts loops and higher voids rather than
branchiness. Adding the virtual exit→entry arc, McCabe's strongly-
connected convention, recovers strict `β_1 = cyclomatic` for structured
code. The implementation computes on the graph as given and reports both
numbers.)

That divergence regime is exactly the binary / disassembly / decompiler
surface. This proposal adds:

1. a pure-Python path-homology core over RAPTOR's existing `Graph`
   protocol (`core/inventory/dominators.py`);
2. per-function basic-block CFG extraction in the r2-driven RE path
   (`packages/binary_analysis/radare2_understand.py`);
3. a Betti vector per function, surfaced as (a) a triage / fuzz-priority
   term and (b) a **decompiler-confidence** tag — gated behind a corpus
   reproduction before it influences ranking.

## 2. Motivation

Two concrete RE problems RAPTOR has no signal for today:

- **Decompiler-output confidence.** Decompilers (r2 `pdc` / `pdg`, Ghidra)
  run *control-flow structuring* to recover `if`/`while`/`for`. When a
  function's CFG is **irreducible**, structuring fails and the decompiler
  emits gotos, duplicated blocks, or `while(true){…}` soup. Irreducibility
  is exactly the `β_2 > 0` case. So path homology is a direct proxy for
  "the decompiled C the LLM is about to reason over is probably mangled —
  discount it / route for human attention." `radare2_understand.py` feeds
  decompiled output to the LLM (`_llm_prioritise`, `radare2_understand.py:918`)
  with no such calibration.
- **Obfuscation / anti-analysis triage.** Control-flow flattening, opaque
  predicates, and hand-written asm all produce irreducible CFGs and thus
  high higher-dimensional homology. Cyclomatic complexity *cannot* see this
  (directionless, dimension-1 only). Path homology is purpose-built for it,
  and separates "big but simple" (200-block linear parser, `β_2 = 0`) from
  "small but gnarly" (30-block jump-interleaved function, `β_2 > 0`) — the
  latter being where bugs and obfuscation hide.

Huntsman's evaluation on GNU grep binaries (NIST SARD, vulnerable vs.
benign) found the injected-vulnerability function `dfamust` was a
structural outlier in the `(cyclomatic, β_1)` plane — suggestive that
homological features track "structurally relevant" control flow that the
scalar metric misses.

## 3. Background — the reference

> Steve Huntsman. *Path homology as a stronger analogue of cyclomatic
> complexity.* arXiv:2003.00944 [cs.SE], March 2020 (v4, August 2020).
> BAE Systems FAST Labs, Arlington, VA. Work supported by the DARPA
> SafeDocs program (contract HR001119C0072).
> https://arxiv.org/abs/2003.00944

Mathematical foundations the paper builds on:

- A. Grigor'yan, Y. Lin, Yu. Muranov, S.-T. Yau. *Homologies of path
  complexes and digraphs.* arXiv:1207.2834 (2012); and related
  *Homotopy theory for digraphs*, *Path homology theory of multigraphs
  and quivers* (2014–2018) — the construction of path homology on
  directed graphs.
- S. Chowdhury, F. Mémoli. *Persistent path homology of directed
  networks.* SODA 2018 — the persistence variant (future work, §8).
- T. J. McCabe. *A complexity measure.* IEEE TSE SE-2 (1976) — cyclomatic
  complexity, the baseline this generalizes.

### Path homology in one screen

Let `D = (V, E)` be a loopless digraph. An **allowed `p`-path** is a
sequence of vertices `(v_0, …, v_p)` with `(v_{j-1}, v_j) ∈ E` for every
step (a real walk along edges). The non-regular boundary operator

```
∂(v_0, …, v_p) = Σ_j (−1)^j (v_0, …, v̂_j, …, v_p)
```

deletes each interior vertex in turn. A walk stays a walk under most
deletions, but deleting an interior vertex can produce a sequence that is
*not* a walk; the **path complex** `Ω_p` is the subspace of allowed paths
whose boundary is *also* allowed (`∂Ω_p ⊆ Ω_{p-1}`). The homology of
`(Ω_•, ∂)` is the path homology of `D`; its Betti numbers are `β_p`.

For control flow:

- `β_0` = weakly-connected components (1 for a normal function CFG).
- `β_1` = directed independent cycles. Agrees with cyclomatic complexity
  on genuine loops; *direction-aware*, so on branch/merge structure it is
  strictly smaller (`β_1 ≤ cyclomatic`) — the commutative square between
  two branches is filled. Verified in Phase 1 (`test_path_homology.py`).
- `β_2, β_3, …` = higher-dimensional "voids," nonzero only for
  unstructured / irreducible control flow. Huntsman's Figs 2–3 exhibit
  minimal digraphs with `β_2 = 1` and `β_3 = 1` that are realizable as
  assembly-level CFGs.

## 4. Where it fits in RAPTOR (and where it does not)

Confirmed by codebase survey — RAPTOR has **no** complexity metric of any
kind today (no cyclomatic, no Betti, no block/edge counts in non-test
code), but it *does* have the directed-graph substrate a homology
computation consumes.

### Fits

- **`core/inventory/dominators.py`** — the `Graph` protocol (`:57`,
  `entry` / `nodes()` / `successors()`) is the universal directed-graph
  interface; a `betti(graph, max_dim)` function is a drop-in sibling of
  `build_dom_tree` (`:263`).
- **`packages/binary_analysis/radare2_understand.py`** — the primary
  home. It already drives r2 per function (`_tag_dangerous_callers`,
  `:638`) and decompiles top functions (`_decompile_priorities`, `:807`).
  It builds only a *function-granularity call graph* today; r2's
  `afbj` / `agfj @ <addr>` returns the per-function **basic-block CFG**
  as JSON, one call away. The per-function scoring hook already exists:
  `_heuristic_prioritise._score(fn)` (`:878`) and the `fuzz_priorities`
  records (`:905`); a Betti term / field slots straight in.
- **Annotation sinks** for the computed score: `FunctionInfo` (`:92`),
  the per-function triage enrichment in
  `core/orchestration/reachability_enrichment.py` (`:204`), the inventory
  metadata in `core/inventory/binary_oracle_edges.py` (`:572`), and the
  persistent `/annotate` store (`core/annotations/storage.py`).

### Does **not** fit (scope guard)

- **Source-level Python CFGs** (`core/inventory/cfg_builder.py`).
  Structured control flow ⇒ `β_{≥2} = 0` ⇒ it merely reproduces a
  cyclomatic number on code that is essentially never irreducible. Low
  value; excluded from the arc. (C/C++ source is *in* scope — see
  Phase 6 — because `cfg_builder_cpp.py` models `goto` / `switch`
  fallthrough / `do/while`, the constructs that actually produce
  irreducible source-level control flow.)
- **The sanitizer-cut chokepoint** (`core/inventory/sanitizer_cut.py`).
  That needs *sound reachability* (vertex cut). Path homology is a fuzzy
  metric and must never gate a suppression. Hard boundary.
- **Crash analysis** (`crash_agent.py`) consumes only a linear
  disassembly window, no CFG — nothing to score.

## 5. Design

- **`core/inventory/path_homology.py`** — pure Python, no SciPy / NumPy /
  NetworkX (honors the runtime-dep rule in CLAUDE.md). Computes `β_0 … β_k`
  over `GF(2)` by Gaussian elimination on the sparse boundary matrices.
  `k` capped (default 3). Input is anything satisfying the `Graph`
  protocol; output a small `BettiVector` dataclass. Cost is bounded for
  per-function CFGs (tens of blocks, out-degree ≈ 2); a node/path budget
  with a `homology_complete: bool` flag guards pathological functions, the
  same shape as the WP-extraction cap in Project C.
- **r2 extraction** — add one `afbj @ <addr>` (basic blocks + edges) per
  prioritized function inside the existing per-function loop; adapt the
  JSON to a tiny `Graph` adapter. Cached per build-id alongside the
  existing r2 caching, since r2 invocations are the slow part.
- **Surfacing** — Betti vector becomes a field on `FunctionInfo`,
  `fuzz_priorities`, and the binary `context-map.json`; plus a derived
  boolean `decompiler_low_confidence = (β_2 > 0)` tag consumed by the LLM
  decompiler prompt as a discount hint. **Behind a flag until Phase 4
  clears.**

## 6. Phases

Sequential. Each ships independently; the scoring influence (Phase 5) is
gated on the validation in Phase 4.

| Phase | Scope | Ships | Status |
|------:|-------|-------|--------|
| 1 | **Homology core.** `core/inventory/path_homology.py`: `betti(graph, max_dim)` over `GF(2)`, dims 0–3, dep-free; `BettiVector` dataclass + per-dim path budget with `complete` flag; `cyclomatic_number` companion. | Module + 27 unit tests: the closed-form layered-digraph oracle `K_{n…}` (`β_2 = 1`, `β_3 = 1`, `β_2 = 2`), `β_0` = components, directed-cycle `β_1`, structured-CFG triviality (`β_{≥2} = 0`), the if/else `β_1 < cyclomatic` divergence, and budget truncation. No integration. | **done** |
| 2 | **Binary CFG extraction.** Per-function basic-block CFG via r2 `afbj` in `radare2_understand.py`; `Graph` adapter; per-build-id cache. | `packages/binary_analysis/function_cfg.py` (`BasicBlockCFG` adapter + `parse_afbj` + build-id cache, all r2-free/testable); `FunctionInfo.basic_block_cfg` populated under opt-in `analyse(extract_cfgs=True)` (off by default → no cost/behaviour change); 16 unit tests. No scoring change. | **done** |
| 3 | **Compute + surface (reported only).** Betti vector per function; attach to `FunctionInfo`, `fuzz_priorities`, `binary-context-map.json`; derive `decompiler_low_confidence` (β_2 > 0). Behind `--path-homology` (off by default), plumbed `analyse → analyse_binary_context → orchestrator.execute → raptor_fuzzing` CLI. | `compute_path_homology` + `homology_report` (module-level, r2-free/testable); `FunctionInfo` fields + `to_dict`/fuzz-priority surfacing; β_2>0 context note; 8 unit tests. No ranking effect (does not feed `_score`). | **done** |
| 4 | **Validation / reproduction gate.** Harness over a corpus of r2-extracted function CFGs. Measure: (a) does `β_2⁺` separate vulnerable from benign functions? (b) does `β_2 > 0` correlate with decompiler-structuring failure (`goto` in `pdc` output)? | `core/inventory/path_homology_precision.py` + `libexec/raptor-path-homology-precision` (cross-tab, risk ratio, rule-of-three, non-vacuousness guard; 11 unit tests). **Ran on 8,459 functions from 6 macOS binaries → NO-GO** (see "Phase 4 result"). | **done — NO-GO** |
| 5 | **Wire into triage (gated on Phase 4 = go).** Add a Betti term to `_score()` and an LLM decompiler-confidence discount. | — | **blocked: Phase 4 NO-GO** — does not proceed |
| 6 | **Source-level C/C++ signal.** Homology over `cfg_builder_cpp.py`'s goto/switch-aware CFG. | — | **on hold** — same β_2-vacuity risk as the binary track; re-scope to β_1 first (see Phase 4 result) |
| 7 | **Persistent path homology.** Persistent path homology (Chowdhury–Mémoli) over the nesting hierarchy. | — | **on hold** — pending arc re-scope |

**Total: 7 phases.** Phases 1–3 (the reported-only machinery) shipped and
stand. **Phase 4 — the evidence gate — returned NO-GO**, so Phases 5–7 do
not proceed as designed: the β_2 / irreducibility signal is vacuous on
real binaries (see below). This is the gate working as intended.

## Phase 4 result — NO-GO (β_2 signal vacuous on real binaries)

Ran `path_homology_precision` over **8,459 functions** from six macOS
system binaries (`grep`, `awk`, `sed`, `bash`, `perl`, `vim`), with
radare2 6.1.6.

- **Non-vacuousness fails.** Exactly **1 / 8,459** functions had
  `β_2 > 0` (a single `vim` function, β = (1, 246, 1)). Modern
  compiler output is overwhelmingly *reducible*, so the irreducibility
  signal essentially never fires. The harness's non-vacuousness guard
  returns NO-GO: "signal absent — cannot validate." Claim (a)
  (vuln separation) is unassessable at this base rate.
- **The decompiler-confidence proxy is invalidated independently.**
  Among 313 decompiled functions, **68% of *reducible* (β_2 = 0)
  functions already contain `goto`** in r2's `pdc` output (e.g.
  `/bin/ls` `main`: β = (1, 22, 0), yet 27 gotos). r2's structurer emits
  gotos liberally regardless of irreducibility, so `β_2 > 0` carries no
  predictive signal over the decompiler's baseline. Claim (b) fails on
  its own terms.

**Decision.** The binary β_2 / `decompiler_low_confidence` signal does
**not** earn a place in prioritisation. Phase 5 is cancelled. Phases 1–3
remain as *reported-only* telemetry (harmless, off by default; the
`path_betti` / `cyclomatic` fields they surface are still informative
when an operator asks for them) — but nothing feeds `_score()`.

**Constructive pivot (not in this arc).** Huntsman's actual
vulnerability result (the grep `dfamust` outlier, Fig 8–9) was a
**β_1 / cyclomatic** anomaly in *dimension 1* — not β_2. β_1 (the
direction-aware cyclomatic refinement, already computed and dense on
every function) is the signal worth testing next, against a *labelled*
corpus (NIST SARD), as a separate experiment. Phases 6–7 are on hold
behind that re-scope, since source-level β_2 faces the same vacuity.

## 7. Validation / evidence gate (Phase 4 detail)

RAPTOR's culture is corpus-earned precision (cf. the binary-oracle's
1952/1952 + rule-of-three bound). Path-homology-as-signal had *none* of
that — Huntsman's vuln result is essentially one outlier on one utility.
So Phase 5 was gated on Phase 4 demonstrating, on a real corpus, at
least one of:

1. **Vulnerability separation** — functions with `β_2 > 0` are
   over-represented among known-vulnerable functions vs. a benign base
   rate (effect size + simple interval, not just a point estimate).
2. **Decompiler-confidence validity** — `β_2 > 0` predicts decompiler-
   structuring failure (goto/duplication in `pdc`/`pdg`) better than
   cyclomatic complexity or block count alone.

**Outcome: neither held** (see "Phase 4 result" above). Per the
pre-committed rule, the arc stops at Phase 3 — Betti numbers remain a
*reported* curiosity, never a ranking input — and the negative result is
recorded. Re-run the harness anytime on a labelled corpus with
`libexec/raptor-path-homology-precision <manifest.json>` (manifest:
`{"binaries":[{"path":..,"vulnerable_functions":[..]}]}`).

## 8. Risks and open questions

- **Empirical-only theory.** The "structurally relevant" claim is
  suggestive, not proven (the paper itself says "not yet a mathematical
  proof"). Mitigation: Phase 4 gate; reported-only until then.
- **Cost on pathological functions.** Allowed-path enumeration can grow;
  capped dimension + node/path budget + `homology_complete` flag bound it.
  Open: the right default budget for real binaries (set empirically in
  Phase 2).
- **Reducibility of compiled code.** Most compiler output is reducible, so
  `β_2 > 0` may be *rare* — which is fine if rarity = signal, but Phase 4
  must check it isn't simply *absent* on the corpus (the non-vacuousness
  check, mirroring the binary-oracle held-out "live function" guard).
- **`β_1` vs. McCabe direction mismatch.** Path-homology `β_1` is
  direction-aware, so it can disagree with classic cyclomatic complexity
  even in dimension 1. Decide whether to report both (recommended) so the
  divergence is visible rather than silently substituting one for the
  other.
- **r2 dependency surface.** Extraction runs under the existing r2
  sandboxing (`core.sandbox.run`); no new trust surface, but adds r2
  calls to the per-function loop — hence the per-build-id cache.

## 9. Out of scope (explicit)

- Any use of homology to gate suppression / soundness decisions.
- Source-level **Python** homology (structured ⇒ trivial).
- Persistent path homology beyond the Phase 7 prototype (full
  birth/death persistence-diagram tooling is a later arc if the
  prototype proves out).
- Arc-crossing / drawing-complexity analysis (NP-hard; Huntsman §3 notes
  this and does not pursue it — neither do we).

## 10. References

1. S. Huntsman. *Path homology as a stronger analogue of cyclomatic
   complexity.* arXiv:2003.00944 [cs.SE], 2020.
   https://arxiv.org/abs/2003.00944
2. A. Grigor'yan, Y. Lin, Yu. Muranov, S.-T. Yau. *Homologies of path
   complexes and digraphs.* arXiv:1207.2834, 2012.
3. S. Chowdhury, F. Mémoli. *Persistent path homology of directed
   networks.* SODA, 2018.
4. T. J. McCabe. *A complexity measure.* IEEE Trans. Soft. Eng. SE-2,
   1976.
5. RAPTOR internal: `docs/design-aggregation-dominators-wp.md` (Project B
   — CFG / `Graph` / dominator substrate this arc reuses).
