"""Tests for GitHub Actions ``uses:`` extraction in
``parse_gha_workflow``."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import PinStyle
from packages.sca.parsers.inline_installs import parse_gha_workflow


def _write(tmp_path: Path, body: str, name: str = "ci.yml") -> Path:
    p = tmp_path / name
    p.write_text(body)
    return p


def test_basic_uses_extraction(tmp_path):
    p = _write(tmp_path, """\
name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
""")
    deps = parse_gha_workflow(p)
    by_name = {d.name: d for d in deps}
    assert "actions/checkout" in by_name
    assert "actions/setup-python" in by_name
    assert by_name["actions/checkout"].ecosystem == "GitHub Actions"
    assert by_name["actions/checkout"].version == "v4"
    assert by_name["actions/checkout"].pin_style == PinStyle.CARET
    assert by_name["actions/checkout"].source_kind == "gha_uses"
    assert by_name["actions/checkout"].purl == \
        "pkg:githubactions/actions/checkout@v4"


def test_sha_pin_classified_as_git(tmp_path):
    sha = "a" * 40
    p = _write(tmp_path, f"""\
jobs:
  x:
    steps:
      - uses: actions/checkout@{sha}
""")
    [d] = [d for d in parse_gha_workflow(p) if d.ecosystem == "GitHub Actions"]
    assert d.pin_style == PinStyle.GIT
    assert d.version == sha


def test_branch_ref_classified_as_unknown(tmp_path):
    p = _write(tmp_path, """\
jobs:
  x:
    steps:
      - uses: actions/checkout@main
""")
    [d] = [d for d in parse_gha_workflow(p) if d.ecosystem == "GitHub Actions"]
    assert d.pin_style == PinStyle.UNKNOWN
    assert d.version == "main"


def test_local_ref_skipped(tmp_path):
    """``./.github/workflows/foo.yml`` is an internal reusable
    workflow; not a registered third-party action."""
    p = _write(tmp_path, """\
jobs:
  x:
    uses: ./.github/workflows/inner.yml
""")
    deps = parse_gha_workflow(p)
    action_deps = [d for d in deps if d.ecosystem == "GitHub Actions"]
    assert action_deps == []


def test_docker_ref_skipped(tmp_path):
    """``docker://image@digest`` is a Dockerfile-FROM threat model;
    handled separately by the B9 scanner."""
    p = _write(tmp_path, """\
jobs:
  x:
    steps:
      - uses: docker://alpine:3.18
""")
    deps = parse_gha_workflow(p)
    action_deps = [d for d in deps if d.ecosystem == "GitHub Actions"]
    assert action_deps == []


def test_sub_action_path(tmp_path):
    """``actions/cache/restore@v4`` — sub-action path. Whole
    ``actions/cache/restore`` is the dep name."""
    p = _write(tmp_path, """\
jobs:
  x:
    steps:
      - uses: actions/cache/restore@v4
""")
    [d] = [d for d in parse_gha_workflow(p) if d.ecosystem == "GitHub Actions"]
    assert d.name == "actions/cache/restore"
    assert d.version == "v4"


def test_uses_alongside_run(tmp_path):
    """A workflow with both ``uses:`` and ``run:`` produces both
    kinds of deps in one parse_gha_workflow call."""
    p = _write(tmp_path, """\
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - run: pip install requests==2.31.0
""")
    deps = parse_gha_workflow(p)
    eco_kinds = {(d.ecosystem, d.source_kind) for d in deps}
    assert ("GitHub Actions", "gha_uses") in eco_kinds
    assert ("PyPI", "gha_workflow") in eco_kinds


def test_bare_uses_without_owner_skipped(tmp_path):
    """``uses: setup-node@v3`` (no owner) is invalid — skipped."""
    p = _write(tmp_path, """\
jobs:
  x:
    steps:
      - uses: setup-node@v3
""")
    deps = parse_gha_workflow(p)
    assert [d for d in deps if d.ecosystem == "GitHub Actions"] == []


def test_dedup_same_action_multiple_jobs(tmp_path):
    """Same action used in two jobs → two Dependency rows; the
    join layer dedups by key, but the parser emits both for
    accurate per-line provenance."""
    p = _write(tmp_path, """\
jobs:
  a:
    steps:
      - uses: actions/checkout@v4
  b:
    steps:
      - uses: actions/checkout@v4
""")
    deps = [d for d in parse_gha_workflow(p) if d.ecosystem == "GitHub Actions"]
    assert len(deps) == 2
    assert all(d.name == "actions/checkout" for d in deps)


# ---------------------------------------------------------------------------
# Composite actions — action.yml at repo root or under .github/actions/
# ---------------------------------------------------------------------------


def test_composite_action_at_github_actions_path(tmp_path):
    """``.github/actions/<name>/action.yml`` — composite action
    defined inside a regular project. The same parser extracts
    ``uses:`` from its ``runs.steps[]`` block."""
    composite = tmp_path / ".github/actions/build/action.yml"
    composite.parent.mkdir(parents=True)
    composite.write_text("""\
name: Build composite
description: Composite action
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v5
    - run: pip install -e .
      shell: bash
""")
    deps = parse_gha_workflow(composite)
    by_name = {d.name: d for d in deps if d.ecosystem == "GitHub Actions"}
    assert "actions/checkout" in by_name
    assert "actions/setup-python" in by_name


def test_action_yaml_extension_also_matched(tmp_path):
    """Both ``action.yml`` and ``action.yaml`` are valid GHA
    composite-action filenames."""
    composite = tmp_path / "action.yaml"
    composite.write_text("""\
name: my-action
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
""")
    deps = parse_gha_workflow(composite)
    assert any(
        d.name == "actions/checkout" and d.ecosystem == "GitHub Actions"
        for d in deps
    )


def test_repo_root_action_yml(tmp_path):
    """Repo-root ``action.yml`` (the repo IS an action). Composite
    runs.steps[].uses extracted; run blocks too."""
    root_action = tmp_path / "action.yml"
    root_action.write_text("""\
name: my-action
runs:
  using: composite
  steps:
    - uses: actions/setup-node@v4
    - run: npm install
      shell: bash
""")
    deps = parse_gha_workflow(root_action)
    eco_kinds = {(d.ecosystem, d.source_kind) for d in deps}
    assert ("GitHub Actions", "gha_uses") in eco_kinds


def test_is_gha_workflow_matches_composite_paths(tmp_path):
    """Predicate-level check: both workflows and action manifests
    route to ``parse_gha_workflow``."""
    from packages.sca.parsers.inline_installs import _is_gha_workflow

    # Standard workflow.
    assert _is_gha_workflow(
        tmp_path / ".github/workflows/ci.yml"
    )
    # Composite under .github/actions/.
    assert _is_gha_workflow(
        tmp_path / ".github/actions/build/action.yml"
    )
    # Repo-root action manifest.
    assert _is_gha_workflow(tmp_path / "action.yml")
    assert _is_gha_workflow(tmp_path / "action.yaml")
    # Random YAML file — not a workflow.
    assert not _is_gha_workflow(tmp_path / "config.yml")


def test_discovery_recognises_composite_action(tmp_path):
    """End-to-end: ``find_manifests`` actually picks up
    composite-action files and they reach the parser dispatch."""
    from packages.sca.discovery import find_manifests

    composite = tmp_path / ".github/actions/build/action.yml"
    composite.parent.mkdir(parents=True)
    composite.write_text(
        "runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n"
    )
    manifests = find_manifests(tmp_path)
    found = [m for m in manifests if m.path.name == "action.yml"]
    assert len(found) == 1
