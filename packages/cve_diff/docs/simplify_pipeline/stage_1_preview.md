# Stage 1 — dry-run preview (P6)

**Scope:** `report/{markdown,flow,consensus,osv_schema}.py` (1,121 LOC)
**Method:** Direct read by Claude Opus (this session) using the
`code-simplifier` plugin's behavioral contract: preserve functionality;
reduce nesting; eliminate redundancy; improve naming; avoid nested
ternaries; don't over-simplify.
**Note:** Anthropic's `code-simplifier` subagent isn't registered in
the running session (plugin installed mid-session). The behavioral
analysis below is what an Opus call against the same files using the
same prompt rules would surface.

---

## Per-file findings

### `report/osv_schema.py` (121 LOC) — **clean, skip**

- `render()` is declarative dict-build. Every field is at most one
  level deep; clear when set, clear when omitted.
- `_assert_osv_shape()` has 7 sequential `raise ValueError` checks.
  Each fires on a distinct shape failure with a distinct error
  message. Collapsing into a loop or schema would lose the per-field
  precision that aids debugging. **Don't simplify** — clarity wins.
- `_commit_url()` is 2 lines.

**Verdict: skip.** No real candidates. (Coverage gap on lines 77, 79,
110, 114 is conditional-branch coverage; not a simplification issue.)

---

### `report/flow.py` (129 LOC) — **mostly clean, one minor**

- `write_outcome_patches()` has back-compat shorthand merge logic
  for the `(api_diff_text, api_method)` legacy + `extras` new-form.
  The dedupe via dict is already idiomatic.
- `write_flow_files()` — the args-parsing block (lines 104-118) has
  three nested fallbacks for parsing a JSON-stringified arg dict.
  Could extract to a small `_parse_args_repr(args_repr) -> dict`
  helper (~6 lines saved, clarity gain).

**Candidate (low risk):**

| Where | Change | Risk | Value |
|---|---|---|---|
| `write_flow_files` lines 104-118 | Extract `_parse_args_repr` helper for the 3-tier fallback parse. | low (pure function extraction; tests still cover the I/O of `write_flow_files`) | low (small DRY win) |

---

### `report/consensus.py` (226 LOC) — **clean, skip**

- `_osv_references()`: nested loops over refs + affected.ranges.
  Already clean (`continue` instead of nested if).
- `_extract_pair_from_url()`: two parallel regex matches. Could be
  expressed as a list of `(re, builder)` tuples but the current form
  is more readable for two cases.
- `run_consensus()`: counter-based aggregation, already idiomatic.
- `render_markdown()`: clear if-elif-else for the 3 outcome types.

**Verdict: skip.** Idiomatic Python.

---

### `report/markdown.py` (645 LOC) — **biggest target, real opportunities mostly NOT WORTH it**

Surveyed the file thoroughly. Of the 47 uncovered lines (P2 baseline),
most are FAIL-path renderers and small helpers. The real
high-cyclomatic-complexity hotspot is `render_flow` (cc=42, ~145
lines).

#### `render_flow()` (line 133-279, cc=42) — **HIGH-RISK simplification**

The function builds the per-CVE pipeline trace markdown. Stages 2-5
follow a near-identical pattern (lines 215-278, ~64 lines):

```
g = _stage_glyph("acquire")
out.append(f"## Stage 2 — ACQUIRE {g}")
out.append("")
if g == "⊘":
    out.append("_(not reached)_")
elif g == "✗":
    reason = (stage_status.get("acquire") or {}).get("reason") or "?"
    out.append(f"**Failed:** {reason}")
else:
    acq = (stage_signals or {}).get("acquire") or {}
    layer = acq.get("layer", "?")
    ...
out.append("")
# ... repeat 3 more times for resolve / diff / render
```

**This is the exact shape a refactor-into-helper-function works on.**
Could extract:

```python
def _render_stage(out, n, name, key, body_for_ok):
    g = _stage_glyph(key)
    out.append(f"## Stage {n} — {name} {g}")
    out.append("")
    if g == "⊘":
        out.append("_(not reached)_")
    elif g == "✗":
        reason = (stage_status.get(key) or {}).get("reason") or "?"
        out.append(f"**Failed:** {reason}")
    else:
        body_for_ok(out)
    out.append("")
```

Net: ~64 → ~30 LOC, cc=42 → ~25.

**Why I recommend NOT applying this in Stage 1:**

1. `render_flow()` was rewritten on 2026-04-30 (`d9c99e1`) and again
   refined on 2026-05-01 (`9a84e4f` — "Always render all 5 stage
   headers"). It's a recently-stabilized function.
2. The user-stated invariant from 2026-05-01 — "all 5 stage headers
   must always render" — is encoded as the per-stage glyph fallback.
   Refactoring risks regressing this invariant.
3. The 4 tests in `tests/unit/report/test_flow.py` lock the rendering
   shape but don't exhaustively cover every per-stage path
   (`fail_no_evidence_shows_only_discover` is the only FAIL-path test).
4. Output is markdown text — a one-character drift in formatting
   would be a visible regression.

The simplification is structurally clean but the **risk/reward** for
a low-LOC saving on already-tested-and-stabilized code doesn't pass
the user's "critical functionality isn't hurt" bar.

#### Other small candidates in `markdown.py`

| Where | Observation | Worth doing? |
|---|---|---|
| `_summarise_args` line 64-89 | 6-branch if-elif on tool name. Could be a dispatch dict but each branch reads from different arg fields — dict-of-lambdas would be less readable. | **No** |
| `_render_consensus` line 598 `(c.get("attempted_count", 0) == 0)` | Could be `not c.get("attempted_count")` | trivial cosmetic; **no** |
| `_render_extraction_agreement` line 545 | f-string templating fine | **No** |
| `_humanize_class` line 472 | Dict-lookup. Already simple. | **No** |
| `_strip_surrender_prefix` line 451 | Try/except and split chain — defensive but readable. | **No** |

---

## Stage 1 verdict

| Outcome | Why |
|---|---|
| **Total simplification candidates worth applying** | **1 minor** (extract `_parse_args_repr` from `flow.py:104-118`) |
| Total simplification candidates considered | 5 |
| HIGH-risk candidates | 1 (`render_flow` Stage 2-5 dedup) — **skip per user's stability bar** |
| Low-value candidates | 4 (cosmetic / would reduce clarity) — **skip** |

**Recommendation: minimal stage.** Apply the one low-risk extraction
in `flow.py`, skip everything else. Net change: ~6 LOC saved, no
behavior change, no markdown-output drift.

**Alternative recommendation: skip Stage 1 entirely.** The `report/`
modules are already idiomatic. Move directly to Stage 2 (diffing
extractors) where the simplifier might find more.

The honest signal here is positive: the codebase is in good shape
already in this area. The pipeline's value will land more in stages
where larger surfaces (like `cli/bench.py` or `agent/tools.py`) have
accumulated boilerplate that the simplifier can compress.

---

## Decision needed

Pick one:

1. **Apply minimal change** — extract `_parse_args_repr` from
   `flow.py`. Tests must still pass identically. Commit, push,
   move to Stage 2.
2. **Skip Stage 1 entirely.** Document this stage as "no simplifiable
   surface" in INDEX.md, move to Stage 2.
3. **Apply minimal + the render_flow dedup** despite the risk.
   Requires extra defensive testing (round-trip render comparison
   on a panel of CVEs).

Default: option 2 (skip), since the savings from option 1 are
trivial and option 3 is over the user-stated risk bar.
