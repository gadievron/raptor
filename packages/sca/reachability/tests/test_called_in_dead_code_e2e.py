"""End-to-end coverage for the ``called_in_dead_code`` verdict —
crossing the per-ecosystem refinement, risk-score downgrade, and
SBOM rendering.

These tests don't touch the network or the inventory builder; they
construct the inventory dict directly so the same fixture
exercises both the Python ecosystem refinement and the
downstream consumers of the verdict.
"""

from __future__ import annotations

from typing import Any, Dict, List


from core.inventory.call_graph import extract_call_graph_python
from packages.sca.models import (
    Advisory,
    AffectedRange,
    Confidence,
    Dependency,
    PinStyle,
    Reachability,
    VulnFinding,
)


def _file(path: str, source: str) -> Dict[str, Any]:
    import ast
    cg = extract_call_graph_python(source).to_dict()
    items: List[Dict[str, Any]] = []
    try:
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                items.append({
                    "name": node.name,
                    "kind": "function",
                    "line_start": node.lineno,
                    "line_end": getattr(node, "end_lineno", None),
                })
    except SyntaxError:
        pass
    return {
        "path": path, "language": "python",
        "items": items, "call_graph": cg,
    }


def _inv(*files: Dict[str, Any]) -> Dict[str, Any]:
    return {"files": list(files)}


def _make_finding(reachability: Reachability) -> VulnFinding:
    """Construct a minimal VulnFinding with the given reachability —
    enough fields populated for the risk scorer to run."""
    from pathlib import Path
    dep = Dependency(
        ecosystem="PyPI",
        name="requests",
        version="2.30.0",
        declared_in=Path("requirements.txt"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl="pkg:pypi/requests@2.30.0",
        parser_confidence=Confidence("high", reason="t"),
    )
    adv = Advisory(
        osv_id="GHSA-test-0001",
        aliases=["CVE-2025-9999"],
        summary="Test advisory",
        details="",
        affected=[AffectedRange(
            type="ECOSYSTEM",
            events=[{"introduced": "0"}, {"fixed": "2.31.0"}],
        )],
        severity=None,
        fixed_versions=["2.31.0"],
        references=[],
    )
    return VulnFinding(
        finding_id="sca:vuln:PyPI:requests:2.30.0:GHSA-test-0001",
        dependency=dep,
        advisories=[adv],
        in_kev=False,
        epss=None,
        fixed_version="2.31.0",
        reachability=reachability,
        version_match_confidence=Confidence("high", reason="t"),
        cvss_score=7.5,
        cvss_vector=None,
        severity="high",
        exposure_factor=0.0,
        transitive_depth=0,
    )


# ---------------------------------------------------------------------------
# Refinement → verdict end-to-end
# ---------------------------------------------------------------------------


def test_refine_emits_called_in_dead_code_for_private_host():
    """A finding's call site lives in a private function with no
    callers — refinement emits the new verdict."""
    from core.inventory.reachability import function_called
    inv = _inv(_file("src/a.py",
        "import requests\n"
        "def _legacy_unzip():\n"
        "    requests.get('/')\n"
    ))
    # Direct verification via the substrate + helper to pin the
    # ecosystem-side call.
    from packages.sca.reachability._host_reachability import (
        classify_called_or_dead,
    )
    r = function_called(inv, "requests.get")
    assert r.verdict.value == "called"
    evidence_lines = [f"{p}:{ln}" for p, ln in r.evidence]
    result = classify_called_or_dead(
        inv, evidence_lines,
        likely_called_reason="should not appear",
        affected_summary="requests.get",
    )
    assert result.verdict == "called_in_dead_code"


def test_refine_emits_likely_called_for_alive_host():
    inv = _inv(_file("src/a.py",
        "import requests\n"
        "def main():\n"          # alive: entry-point name
        "    requests.get('/')\n"
    ))
    from core.inventory.reachability import function_called
    from packages.sca.reachability._host_reachability import (
        classify_called_or_dead,
    )
    r = function_called(inv, "requests.get")
    evidence_lines = [f"{p}:{ln}" for p, ln in r.evidence]
    result = classify_called_or_dead(
        inv, evidence_lines,
        likely_called_reason="main calls requests.get",
        affected_summary="requests.get",
    )
    assert result.verdict == "likely_called"


# ---------------------------------------------------------------------------
# Risk scoring — verify the downgrade is applied
# ---------------------------------------------------------------------------


def test_risk_score_downgraded_for_called_in_dead_code():
    """Compare risk for a finding with ``likely_called`` vs the same
    finding with ``called_in_dead_code``. The latter must be lower
    (downgrade applied) but higher than ``not_function_reachable``
    high-confidence (less downgrade because confidence is medium)."""
    from packages.sca.risk import compute_risk_estimate

    f_called = _make_finding(Reachability(
        verdict="likely_called",
        confidence=Confidence("high", reason="t"),
        evidence=["src/a.py:3"],
    ))
    f_dead = _make_finding(Reachability(
        verdict="called_in_dead_code",
        confidence=Confidence("medium", reason="t"),
        evidence=["src/a.py:3"],
    ))
    f_not_reach = _make_finding(Reachability(
        verdict="not_function_reachable",
        confidence=Confidence("high", reason="t"),
        evidence=[],
    ))
    score_called, _ = compute_risk_estimate(f_called, f_called.dependency)
    score_dead, _ = compute_risk_estimate(f_dead, f_dead.dependency)
    score_not_reach, _ = compute_risk_estimate(
        f_not_reach, f_not_reach.dependency,
    )
    # likely_called > called_in_dead_code > not_function_reachable
    assert score_called > score_dead
    assert score_dead > score_not_reach


# ---------------------------------------------------------------------------
# SBOM rendering — verify VEX state
# ---------------------------------------------------------------------------


def test_sbom_called_in_dead_code_renders_in_triage():
    """A finding with the new verdict should render with VEX state
    'in_triage' (not 'not_affected') in the SBOM output."""
    from packages.sca.sbom import build_bom

    f = _make_finding(Reachability(
        verdict="called_in_dead_code",
        confidence=Confidence(
            "medium",
            reason="requests.get called from dead code",
        ),
        evidence=["src/a.py:3"],
    ))
    sbom = build_bom(
        deps=[f.dependency],
        vuln_findings=[f],
        target_name="test",
    )
    vulns = sbom.get("vulnerabilities") or []
    assert vulns, "finding not in SBOM"
    v = vulns[0]
    analysis = v.get("analysis") or {}
    assert analysis.get("state") == "in_triage", (
        f"expected in_triage, got {analysis}"
    )
