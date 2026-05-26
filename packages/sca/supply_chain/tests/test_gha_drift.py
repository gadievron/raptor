"""Tests for ``packages.sca.supply_chain.gha_drift``."""

from __future__ import annotations

from pathlib import Path

from packages.sca.supply_chain.gha_drift import scan_target


def _write_workflow(tmp_path: Path, body: str,
                    name: str = "ci.yml") -> Path:
    wf = tmp_path / ".github" / "workflows" / name
    wf.parent.mkdir(parents=True, exist_ok=True)
    wf.write_text(body, encoding="utf-8")
    return wf


# ---------------------------------------------------------------------------
# Should flag
# ---------------------------------------------------------------------------

def test_tag_ref_flagged_low(tmp_path: Path) -> None:
    _write_workflow(tmp_path, """\
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""")
    findings = scan_target(tmp_path, [])
    assert len(findings) == 1
    f = findings[0]
    assert f.action == "actions/checkout"
    assert f.ref == "v4"
    assert f.ref_kind == "tag"
    assert f.severity == "low"


def test_branch_ref_flagged_medium(tmp_path: Path) -> None:
    _write_workflow(tmp_path, """\
jobs:
  x:
    steps:
      - uses: foo/bar@main
""")
    findings = scan_target(tmp_path, [])
    assert len(findings) == 1
    assert findings[0].ref_kind == "branch_or_other"
    assert findings[0].severity == "medium"


def test_semver_with_three_components_still_a_tag(tmp_path: Path) -> None:
    _write_workflow(tmp_path, "      - uses: actions/setup-python@v5.0.0\n")
    findings = scan_target(tmp_path, [])
    assert findings and findings[0].ref_kind == "tag"


def test_release_tag_flagged_as_tag(tmp_path: Path) -> None:
    _write_workflow(tmp_path, "      - uses: foo/bar@release-1.0\n")
    findings = scan_target(tmp_path, [])
    # `release-1.0` doesn't start with a digit / `v` — classifies as
    # branch-or-other (medium severity), which is the safer default.
    assert findings and findings[0].ref_kind == "branch_or_other"


def test_subaction_path_flagged(tmp_path: Path) -> None:
    """`uses: org/repo/sub-action@v1` is a real shape — the action
    name has a `/` inside before the `@`."""
    _write_workflow(tmp_path, "      - uses: org/repo/sub-action@v1\n")
    findings = scan_target(tmp_path, [])
    assert findings and findings[0].action == "org/repo/sub-action"


def test_yaml_extension_also_scanned(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path,
        "      - uses: foo/bar@v1\n",
        name="release.yaml",
    )
    findings = scan_target(tmp_path, [])
    assert findings


def test_multiple_workflows_all_scanned(tmp_path: Path) -> None:
    _write_workflow(tmp_path, "      - uses: a/a@v1\n", name="a.yml")
    _write_workflow(tmp_path, "      - uses: b/b@v2\n", name="b.yml")
    findings = scan_target(tmp_path, [])
    actions = sorted(f.action for f in findings)
    assert actions == ["a/a", "b/b"]


# ---------------------------------------------------------------------------
# Should NOT flag
# ---------------------------------------------------------------------------

def test_sha_pin_not_flagged(tmp_path: Path) -> None:
    """40-char commit SHA — the recommended pin shape."""
    _write_workflow(
        tmp_path,
        "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11\n",
    )
    assert scan_target(tmp_path, []) == []


def test_local_action_not_flagged(tmp_path: Path) -> None:
    """`uses: ./local-action` references a local file — different
    threat model, not external supply chain."""
    _write_workflow(tmp_path, "      - uses: ./.github/actions/local\n")
    assert scan_target(tmp_path, []) == []


def test_no_workflows_dir_returns_empty(tmp_path: Path) -> None:
    assert scan_target(tmp_path, []) == []


def test_empty_workflows_dir_returns_empty(tmp_path: Path) -> None:
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    assert scan_target(tmp_path, []) == []


def test_non_yaml_file_skipped(tmp_path: Path) -> None:
    """A `.md` file inside .github/workflows/ is not a workflow."""
    p = tmp_path / ".github" / "workflows" / "README.md"
    p.parent.mkdir(parents=True)
    p.write_text("uses: foo/bar@v1", encoding="utf-8")
    assert scan_target(tmp_path, []) == []


def test_uses_without_at_ignored(tmp_path: Path) -> None:
    """`uses: foo/bar` (no ref) means use the default branch — odd
    but the action layer would handle it; we only flag explicit refs."""
    _write_workflow(tmp_path, "      - uses: foo/bar\n")
    assert scan_target(tmp_path, []) == []


def test_finding_carries_line_number(tmp_path: Path) -> None:
    _write_workflow(tmp_path, """\
name: ci
on: push


jobs:
  x:
    steps:
      - uses: foo/bar@v1
""")
    findings = scan_target(tmp_path, [])
    assert findings and findings[0].line == 8
