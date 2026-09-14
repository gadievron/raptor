"""YAML-shape evasion tests for GHA ``uses:`` extraction.

A compromised-action reference written in any non-plain YAML shape
(block scalar, flow mapping, quoted key, anchor/alias) runs
identically in CI but never matched the historical per-line regex —
blinding gha_drift AND the workflow dep parser (so OSV matching,
sunset, freshness and the GHA+SENTINEL composite pair all went dark).
These tests pin the YAML-walk union pass in both consumers.
"""

from __future__ import annotations

from pathlib import Path

from packages.sca import _gha_uses
from packages.sca.parsers.inline_installs import parse_gha_workflow
from packages.sca.supply_chain import gha_drift


def _write_wf(tmp_path: Path, body: str, name: str = "ci.yml") -> Path:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True, exist_ok=True)
    p = wf_dir / name
    p.write_text(body, encoding="utf-8")
    return p


_BLOCK_SCALAR = """\
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: >-
          evil/action@v45
"""

_FLOW_MAP = """\
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - {uses: evil/action@v1}
"""

_QUOTED_KEY = """\
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - "uses": evil/action@main
"""

_ANCHOR_ALIAS = """\
on: push
_template: &step
  uses: evil/action@v2
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - *step
"""


def test_gha_drift_block_scalar_uses_flagged(tmp_path: Path) -> None:
    _write_wf(tmp_path, _BLOCK_SCALAR)
    findings = gha_drift.scan_target(tmp_path)
    assert [f.action for f in findings] == ["evil/action"]
    assert findings[0].ref == "v45"
    assert findings[0].ref_kind == "tag"


def test_gha_drift_flow_map_uses_flagged(tmp_path: Path) -> None:
    _write_wf(tmp_path, _FLOW_MAP)
    findings = gha_drift.scan_target(tmp_path)
    assert [f.action for f in findings] == ["evil/action"]


def test_gha_drift_quoted_key_uses_flagged(tmp_path: Path) -> None:
    _write_wf(tmp_path, _QUOTED_KEY)
    findings = gha_drift.scan_target(tmp_path)
    assert [f.action for f in findings] == ["evil/action"]
    assert findings[0].ref_kind == "branch_or_other"


def test_gha_drift_anchor_alias_uses_flagged(tmp_path: Path) -> None:
    _write_wf(tmp_path, _ANCHOR_ALIAS)
    findings = gha_drift.scan_target(tmp_path)
    assert [f.action for f in findings] == ["evil/action"]


def test_gha_drift_plain_shape_not_double_emitted(tmp_path: Path) -> None:
    """A plain ``uses:`` line is found by both passes — exactly one
    finding, with the regex pass's exact line number."""
    _write_wf(tmp_path, """\
on: push
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
""")
    findings = gha_drift.scan_target(tmp_path)
    assert len(findings) == 1
    assert findings[0].line == 5


def test_gha_drift_sha_pin_in_flow_map_not_flagged(tmp_path: Path) -> None:
    sha = "a" * 40
    _write_wf(tmp_path, f"""\
on: push
jobs:
  build:
    steps:
      - {{uses: good/action@{sha}}}
""")
    assert gha_drift.scan_target(tmp_path) == []


def test_dep_parser_block_scalar_uses_becomes_dependency(
    tmp_path: Path,
) -> None:
    wf = _write_wf(tmp_path, _BLOCK_SCALAR)
    deps = parse_gha_workflow(wf)
    gha = [d for d in deps if d.ecosystem == "GitHub Actions"]
    assert [d.name for d in gha] == ["evil/action"]
    assert gha[0].version == "v45"


def test_dep_parser_flow_map_uses_becomes_dependency(
    tmp_path: Path,
) -> None:
    wf = _write_wf(tmp_path, _FLOW_MAP)
    deps = parse_gha_workflow(wf)
    gha = [d for d in deps if d.ecosystem == "GitHub Actions"]
    assert [d.name for d in gha] == ["evil/action"]


def test_dep_parser_plain_shape_not_double_emitted(tmp_path: Path) -> None:
    wf = _write_wf(tmp_path, """\
on: push
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
""")
    deps = parse_gha_workflow(wf)
    gha = [d for d in deps if d.ecosystem == "GitHub Actions"]
    assert len(gha) == 1
    extra = gha[0].source_extra
    assert extra is not None
    assert extra["line"] == 5


def test_extract_uses_specs_parse_failure_returns_none() -> None:
    assert _gha_uses.extract_uses_specs("uses: [unclosed") is None


def test_extract_uses_specs_scalar_document_returns_none() -> None:
    assert _gha_uses.extract_uses_specs("just a string") is None


def test_extract_uses_specs_recursive_alias_terminates() -> None:
    """A self-referential anchor parses to a cyclic object graph —
    the walk must terminate, not loop."""
    doc = "a: &x\n  uses: evil/action@v1\n  self: *x\n"
    specs = _gha_uses.extract_uses_specs(doc)
    assert specs == ["evil/action@v1"]
