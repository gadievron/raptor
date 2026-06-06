"""Tests for the ``actions/*`` prefix-trust rule — any first-party
GitHub action under the ``actions/`` org is trusted to consume
secrets via its ``with:`` inputs.

Surfaced by the stress sweep against the ``django`` repo: their
``actions/first-interaction`` step received ``repo-token`` from
``${{ secrets.GITHUB_TOKEN }}`` and FP-fired before this rule
because the action wasn't explicitly enumerated in the data file.
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


def test_actions_first_interaction_trusted(tmp_path: Path) -> None:
    """``actions/first-interaction`` is not explicitly listed in
    the data file but is trusted by the ``actions/*`` prefix rule."""
    _write_wf(tmp_path, """\
on:
  issues:
    types: [opened]
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/first-interaction@v1
        with:
          repo-token: ${{ secrets.GITHUB_TOKEN }}
          issue-message: 'Welcome!'
""")
    hits = scan_target(tmp_path, [], [])
    assert hits == []


def test_actions_random_future_action_trusted(tmp_path: Path) -> None:
    """A hypothetical ``actions/some-future-thing`` consuming a
    secret is trusted by prefix without code change."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/some-future-thing@v1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
""")
    hits = scan_target(tmp_path, [], [])
    assert hits == []


def test_non_actions_org_still_untrusted(tmp_path: Path) -> None:
    """A third-party action whose owner happens to contain
    ``actions`` (eg ``my-actions/foo``) is NOT trusted by the
    prefix rule.  The prefix is anchored at the start."""
    _write_wf(tmp_path, """\
on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: my-actions/foo@v1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
""")
    hits = scan_target(tmp_path, [], [])
    untrusted = [h for h in hits if h.sink_kind == "untrusted_action"]
    assert untrusted, "my-actions/foo must NOT be trusted by prefix"
