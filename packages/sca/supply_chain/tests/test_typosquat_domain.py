"""Tests for the domain-typosquat detector."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import Manifest
from packages.sca.supply_chain.typosquat_domain import scan_target


def _manifests(target: Path) -> list:
    return [Manifest(
        path=target / "package.json", ecosystem="npm", is_lockfile=False,
    )]


def test_distance_1_typosquat_fires_high(tmp_path: Path) -> None:
    """Trivy attack pattern: ``aquasecurtiy.org`` (distance 1 from
    ``aquasecurity.org``) → high severity."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src.py").write_text(
        "URL = 'https://aquasecurtiy.org/payload'\n", encoding="utf-8")
    out = scan_target(tmp_path, _manifests(tmp_path))
    assert len(out) == 1
    assert out[0].suspect_host == "aquasecurtiy.org"
    assert out[0].nearest_popular == "aquasecurity.org"
    assert out[0].distance == 1
    assert out[0].severity == "high"


def test_exact_popular_host_not_flagged(tmp_path: Path) -> None:
    """``github.com`` IS the popular host — must not flag."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "config.json").write_text(
        '{"url": "https://github.com/repo"}\n', encoding="utf-8")
    out = scan_target(tmp_path, _manifests(tmp_path))
    assert out == []


def test_distance_2_medium_severity(tmp_path: Path) -> None:
    """``glthlb.com`` (two substitutions from ``github.com``,
    distance 2) → medium."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src.js").write_text(
        "fetch('https://glthlb.com/api')\n", encoding="utf-8")
    out = scan_target(tmp_path, _manifests(tmp_path))
    assert len(out) == 1
    assert out[0].distance == 2
    assert out[0].severity == "medium"


def test_far_distance_not_flagged(tmp_path: Path) -> None:
    """A genuinely-different host shouldn't false-positive."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src.py").write_text(
        "URL = 'https://example.com/api'\n", encoding="utf-8")
    out = scan_target(tmp_path, _manifests(tmp_path))
    assert out == []


def test_test_directory_excluded(tmp_path: Path) -> None:
    """URLs in ``tests/`` are usually fixtures — skip."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "fixture.py").write_text(
        "URL = 'https://aquasecurtiy.org/payload'\n", encoding="utf-8")
    out = scan_target(tmp_path, _manifests(tmp_path))
    assert out == []


def test_localhost_skipped(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src.py").write_text(
        "URL = 'http://localhost:8080/api'\n", encoding="utf-8")
    out = scan_target(tmp_path, _manifests(tmp_path))
    assert out == []


def test_orchestrator_emits_finding(tmp_path: Path) -> None:
    """End-to-end through the supply-chain orchestrator."""
    from packages.sca.models import Dependency, Confidence, PinStyle
    from packages.sca.supply_chain import evaluate

    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src.py").write_text(
        "URL = 'https://aquasecurtiy.org/p'\n", encoding="utf-8")
    deps = [Dependency(
        ecosystem="npm", name="x", version="1.0",
        declared_in=tmp_path / "package.json",
        scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=True,
        purl="pkg:npm/x@1.0",
        parser_confidence=Confidence("high", reason="t"),
    )]
    findings = evaluate(tmp_path, _manifests(tmp_path), deps)
    kinds = {f.kind for f in findings}
    assert "typosquat_domain" in kinds


# ---------------------------------------------------------------------------
# Same-registrable-domain skip (in-family variations not typosquats)
# ---------------------------------------------------------------------------

def test_same_registrable_domain_in_family_not_flagged(tmp_path: Path) -> None:
    """``registry-2.docker.io`` vs popular ``registry-1.docker.io``
    is an in-family variation (Docker's own subdomain naming) — not
    a typosquat. Surfaced as a false positive on the docker-moby
    project's own API docs during the May 2026 200-project sweep."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src.go").write_text(
        "const URL = \"https://registry-2.docker.io/v2/\"\n",
        encoding="utf-8",
    )
    out = scan_target(tmp_path, _manifests(tmp_path))
    in_family = [
        f for f in out
        if f.suspect_host == "registry-2.docker.io"
    ]
    assert in_family == [], (
        f"in-family domain flagged as typosquat: {in_family}"
    )


def test_in_family_skip_does_not_mask_real_typosquat(tmp_path: Path) -> None:
    """The in-family skip applies only when both hosts have >= 3
    labels AND identical trailing labels. ``gthub.com`` vs
    ``github.com`` both have 2 labels — must still flag."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src.py").write_text(
        "URL = 'https://gthub.com/api'\n", encoding="utf-8")
    out = scan_target(tmp_path, _manifests(tmp_path))
    matched = [f for f in out if f.suspect_host == "gthub.com"]
    assert len(matched) == 1
    assert matched[0].nearest_popular == "github.com"


def test_in_family_skip_unit() -> None:
    """Unit-level coverage of the same-registrable-domain helper
    so future maintainers can see the rule explicitly."""
    from packages.sca.supply_chain.typosquat_domain import (
        _same_registrable_domain,
    )
    # In-family: 3+ labels, identical trailing
    assert _same_registrable_domain(
        "registry-2.docker.io", "registry-1.docker.io",
    )
    assert _same_registrable_domain(
        "api.shop.example.com", "cdn.shop.example.com",
    )
    # Not in-family: only 2 labels
    assert not _same_registrable_domain("goagle.com", "google.com")
    # Not in-family: trailing labels differ
    assert not _same_registrable_domain("evil.com", "evil.io")
    # Different number of labels — can't safely declare same-owner
    assert not _same_registrable_domain(
        "deep.sub.docker.io", "registry-1.docker.io",
    )
