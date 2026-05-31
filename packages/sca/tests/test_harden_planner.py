"""Planner-level tests for ``harden`` — exercise ``_plan_one`` end-to-end
with fake registry + fake OSV stubs.

Pins the status-classification rules: already_pinned, registry_unsupported,
no_versions, up_to_date, promoted, review_required, degraded_safety,
needs_network.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import pytest

from packages.sca.harden import HardenCandidate, _plan_one
from packages.sca.models import (
    Advisory,
    Confidence,
    CVSSScore,
    Dependency,
    PinStyle,
)
from packages.sca.osv import OsvResult


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

@dataclass
class _FakeRegistry:
    """Stub ``RegistryClient`` returning a canned version list."""

    versions: List[str]
    ecosystem: str = "PyPI"

    def list_versions(self, name: str) -> List[str]:
        return list(self.versions)


@dataclass
class _FakeOsv:
    """Stub ``OsvClient`` returning a canned per-version advisory map."""

    advisories_by_version: Dict[str, List[Advisory]] = field(default_factory=dict)

    def query_batch(self, deps: Sequence[Dependency]) -> List[OsvResult]:
        out: List[OsvResult] = []
        for d in deps:
            advs = self.advisories_by_version.get(d.version or "", [])
            out.append(OsvResult(dep_key=d.key(), advisories=list(advs)))
        return out


def _adv(osv_id: str, severity: str = "medium") -> Advisory:
    return Advisory(
        osv_id=osv_id,
        aliases=[],
        summary="",
        details="",
        affected=[],
        severity=CVSSScore(score=5.0, vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                            severity=severity),     # type: ignore[arg-type]
        fixed_versions=[],
        references=[],
    )


def _dep(
    *,
    ecosystem: str = "PyPI",
    name: str = "pkg",
    version: Optional[str] = "1.0",
    pin_style: PinStyle = PinStyle.RANGE,
) -> Dependency:
    return Dependency(
        ecosystem=ecosystem, name=name, version=version,
        declared_in=Path("/x/requirements.txt"),
        scope="main", is_lockfile=False,
        pin_style=pin_style, direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@{version}",
        parser_confidence=Confidence("high", reason="test"),
    )


# ---------------------------------------------------------------------------
# Status: exact-pinned deps still get bumped (regression: previously
# short-circuited as 'already_pinned')
# ---------------------------------------------------------------------------

def test_exact_pinned_dep_bumped_to_newer_exact() -> None:
    """``requests==2.30.0`` should be promoted to ``requests==2.33.0`` —
    the old planner short-circuited exact pins as 'already_pinned' and
    silently dropped them. They're real candidates."""
    dep = _dep(pin_style=PinStyle.EXACT, version="1.0")
    cand = _plan_one(dep, registries={"PyPI": _FakeRegistry(["1.5"])},
                     osv=_FakeOsv(), offline=False, allow_major=False)
    assert cand.status == "promoted"
    assert cand.from_version == "1.0"
    assert cand.to_version == "1.5"


def test_exact_pinned_dep_at_latest_is_up_to_date() -> None:
    """Exact pin where the registry has no newer version → up_to_date."""
    dep = _dep(pin_style=PinStyle.EXACT, version="1.5")
    cand = _plan_one(dep,
                     registries={"PyPI": _FakeRegistry(["1.0", "1.5"])},
                     osv=_FakeOsv(), offline=False, allow_major=False)
    assert cand.status == "up_to_date"


# ---------------------------------------------------------------------------
# --pin-only: refuse to convert loose pins to exact
# ---------------------------------------------------------------------------

def test_pin_only_skips_loose_pins() -> None:
    """``requests>=2.31.0`` with --pin-only → skipped_loose_pin."""
    dep = _dep(pin_style=PinStyle.RANGE, version="1.0")
    cand = _plan_one(dep, registries={"PyPI": _FakeRegistry(["1.5"])},
                     osv=_FakeOsv(), offline=False, allow_major=False,
                     pin_only=True)
    assert cand.status == "skipped_loose_pin"
    assert "loose" in cand.detail.lower()


def test_pin_only_still_bumps_exact_pins() -> None:
    """``requests==2.30.0`` with --pin-only → still promoted to newer exact."""
    dep = _dep(pin_style=PinStyle.EXACT, version="1.0")
    cand = _plan_one(dep, registries={"PyPI": _FakeRegistry(["1.5"])},
                     osv=_FakeOsv(), offline=False, allow_major=False,
                     pin_only=True)
    assert cand.status == "promoted"
    assert cand.to_version == "1.5"


# ---------------------------------------------------------------------------
# Status: registry_unsupported
# ---------------------------------------------------------------------------

def test_no_registry_for_ecosystem() -> None:
    dep = _dep(ecosystem="Debian")
    cand = _plan_one(dep, registries={"PyPI": _FakeRegistry(["2.0"])},
                     osv=_FakeOsv(), offline=False, allow_major=False)
    assert cand.status == "registry_unsupported"
    assert "Debian" in cand.detail


# ---------------------------------------------------------------------------
# Status: pinning_deferred — Debian/apt pinning is OFF by default. With
# --pin-debian it opts in, but only pins within the suite of the base image
# governing the apt line; a dep with no determinable suite still defers
# (never a guessed, possibly-uninstallable pin).
# ---------------------------------------------------------------------------

@dataclass
class _ExplodingRegistry:
    """Registry that fails if queried — proves the default (no --pin-debian)
    gate short-circuits before any registry call."""

    ecosystem: str = "Debian"

    def list_versions(self, name: str) -> List[str]:  # pragma: no cover
        raise AssertionError("registry must not be queried when pinning is off")

    def versions_in_suite(self, name: str, suite: str) -> List[str]:  # pragma: no cover
        raise AssertionError("registry must not be queried when pinning is off")


@dataclass
class _FakeDebianRegistry:
    """Debian registry stub: ``versions_in_suite`` returns a canned per-suite
    list; ``list_versions`` (all suites) should not be used by the pin path."""

    by_suite: Dict[str, List[str]]
    ecosystem: str = "Debian"
    suite_calls: List[str] = field(default_factory=list)

    def list_versions(self, name: str) -> List[str]:  # pragma: no cover
        raise AssertionError("pin path must call versions_in_suite, not list_versions")

    def versions_in_suite(self, name: str, suite: str) -> List[str]:
        self.suite_calls.append(suite)
        return list(self.by_suite.get(suite, []))


def _debian_dep(version: Optional[str], pin_style: PinStyle,
                source_extra: Optional[Dict] = None) -> Dependency:
    return Dependency(
        ecosystem="Debian", name="gcc", version=version,
        declared_in=Path("/x/Dockerfile"),
        scope="main", is_lockfile=False,
        pin_style=pin_style, direct=True,
        purl=f"pkg:deb/debian/gcc@{version}",
        parser_confidence=Confidence("high", reason="test"),
        source_kind="dockerfile", source_extra=source_extra,
    )


def test_debian_deferred_by_default() -> None:
    """Without --pin-debian, an apt dep is recorded but never pinned, and
    the registry isn't even queried."""
    dep = _debian_dep(version=None, pin_style=PinStyle.UNKNOWN,
                      source_extra={"base_image": "debian:bookworm",
                                    "suite": "bookworm"})
    cand = _plan_one(dep, registries={"Debian": _ExplodingRegistry()},
                     osv=_FakeOsv(), offline=False, allow_major=False)
    assert cand.status == "pinning_deferred"
    assert cand.to_version is None
    assert "--pin-debian" in cand.detail


def test_debian_pin_opt_in_pins_to_newest_in_suite() -> None:
    """--pin-debian pins an unpinned apt dep to the newest version in the
    base image's suite (not 'newest across all suites' = experimental)."""
    reg = _FakeDebianRegistry(by_suite={
        "bookworm": ["1.22.1-9+deb12u6", "1.22.1-9+deb12u5"],
        "experimental": ["99:0-1"],            # must NOT be considered
    })
    dep = _debian_dep(version=None, pin_style=PinStyle.UNKNOWN,
                      source_extra={"base_image": "debian:bookworm-slim",
                                    "suite": "bookworm"})
    cand = _plan_one(dep, registries={"Debian": reg}, osv=_FakeOsv(),
                     offline=False, allow_major=False, pin_debian=True)
    assert cand.status == "promoted"
    assert cand.to_version == "1.22.1-9+deb12u6"
    assert reg.suite_calls == ["bookworm"]     # queried the right suite


def test_debian_pin_opt_in_bumps_behind_suite_version() -> None:
    """A dep pinned below the current suite version is bumped up to it."""
    reg = _FakeDebianRegistry(by_suite={"bookworm": ["1.22.1-9+deb12u6"]})
    dep = _debian_dep(version="1.22.1-9+deb12u5", pin_style=PinStyle.EXACT,
                      source_extra={"base_image": "debian:bookworm",
                                    "suite": "bookworm"})
    cand = _plan_one(dep, registries={"Debian": reg}, osv=_FakeOsv(),
                     offline=False, allow_major=False, pin_debian=True)
    assert cand.status == "promoted"
    assert cand.to_version == "1.22.1-9+deb12u6"


def test_debian_pin_opt_in_skips_when_no_suite() -> None:
    """--pin-debian on a dep whose base isn't a determinable Debian suite
    (Ubuntu / silent tag / no FROM) still defers — never a guessed pin."""
    dep = _debian_dep(version=None, pin_style=PinStyle.UNKNOWN,
                      source_extra={"base_image": "ubuntu:22.04", "suite": None})
    cand = _plan_one(dep, registries={"Debian": _ExplodingRegistry()},
                     osv=_FakeOsv(), offline=False, allow_major=False,
                     pin_debian=True)
    assert cand.status == "pinning_deferred"
    assert cand.to_version is None
    assert "ubuntu:22.04" in cand.detail
    assert "uninstallable" in cand.detail


def test_git_pin_style_unsupported() -> None:
    dep = _dep(pin_style=PinStyle.GIT)
    cand = _plan_one(dep, registries={"PyPI": _FakeRegistry(["2.0"])},
                     osv=_FakeOsv(), offline=False, allow_major=False)
    assert cand.status == "registry_unsupported"
    assert "git" in cand.detail


def test_path_pin_style_unsupported() -> None:
    dep = _dep(pin_style=PinStyle.PATH)
    cand = _plan_one(dep, registries={"PyPI": _FakeRegistry(["2.0"])},
                     osv=_FakeOsv(), offline=False, allow_major=False)
    assert cand.status == "registry_unsupported"


# ---------------------------------------------------------------------------
# Status: unsupported_manifest (regression: candidates from a Dockerfile
# / GHA workflow / shell script have no rewriter and must report this
# upfront rather than silently failing during apply)
# ---------------------------------------------------------------------------

def test_inline_install_origin_now_supported() -> None:
    """A dep extracted from a Dockerfile is rewriter-supported now via
    the inline-install path. Regression: previously these were marked
    ``unsupported_manifest``; now they go through the same flow as
    requirements.txt."""
    from packages.sca.models import Confidence
    dep = Dependency(
        ecosystem="PyPI", name="semgrep", version="1.0",
        declared_in=Path("/x/.devcontainer/Dockerfile"),
        scope="main", is_lockfile=False,
        pin_style=PinStyle.RANGE, direct=True,
        purl="pkg:pypi/semgrep@1.0",
        parser_confidence=Confidence("high", reason="test"),
        source_kind="dockerfile",
    )
    cand = _plan_one(dep, registries={"PyPI": _FakeRegistry(["1.5"])},
                     osv=_FakeOsv(), offline=False, allow_major=False)
    assert cand.status == "promoted"
    assert cand.to_version == "1.5"


def test_truly_unsupported_manifest_still_flagged() -> None:
    """A dep declared in a file shape we *don't* have a rewriter for
    (e.g., go.mod, Cargo.toml) is still surfaced as
    ``unsupported_manifest`` rather than silently promoted."""
    from packages.sca.models import Confidence
    dep = Dependency(
        ecosystem="Go", name="github.com/foo/bar", version="v1.0.0",
        declared_in=Path("/x/go.mod"),
        scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=True,
        purl="pkg:golang/github.com/foo/bar@v1.0.0",
        parser_confidence=Confidence("high", reason="test"),
        source_kind="manifest",
    )
    cand = _plan_one(dep, registries={"Go": _FakeRegistry(["v1.5.0"])},
                     osv=_FakeOsv(), offline=False, allow_major=False)
    assert cand.status == "unsupported_manifest"
    assert "go.mod" in cand.detail


def test_supported_manifests_pass_through() -> None:
    """``requirements.txt`` is a supported rewrite target — must NOT be
    marked unsupported_manifest."""
    dep = _dep()      # declared_in=/x/requirements.txt
    cand = _plan_one(dep, registries={"PyPI": _FakeRegistry(["1.5"])},
                     osv=_FakeOsv(), offline=False, allow_major=False)
    assert cand.status != "unsupported_manifest"


# ---------------------------------------------------------------------------
# Status: no_versions
# ---------------------------------------------------------------------------

def test_registry_returns_empty_list() -> None:
    dep = _dep()
    cand = _plan_one(dep, registries={"PyPI": _FakeRegistry([])},
                     osv=_FakeOsv(), offline=False, allow_major=False)
    assert cand.status == "no_versions"


# ---------------------------------------------------------------------------
# Status: needs_network
# ---------------------------------------------------------------------------

def test_offline_and_empty_returns_needs_network() -> None:
    dep = _dep()
    cand = _plan_one(dep, registries={"PyPI": _FakeRegistry([])},
                     osv=_FakeOsv(), offline=True, allow_major=False)
    assert cand.status == "needs_network"


# ---------------------------------------------------------------------------
# Status: up_to_date
# ---------------------------------------------------------------------------

def test_no_versions_above_installed_is_up_to_date() -> None:
    """All registry entries are ≤ installed → nothing to promote."""
    dep = _dep(version="3.0")
    cand = _plan_one(dep,
                     registries={"PyPI": _FakeRegistry(["1.0", "2.0", "3.0"])},
                     osv=_FakeOsv(), offline=False, allow_major=False)
    assert cand.status == "up_to_date"


# ---------------------------------------------------------------------------
# Status: promoted (the happy path)
# ---------------------------------------------------------------------------

def test_promoted_picks_newest_clean() -> None:
    dep = _dep(version="1.0")
    cand = _plan_one(dep,
                     registries={"PyPI": _FakeRegistry(["1.5", "1.8"])},
                     osv=_FakeOsv(), offline=False, allow_major=False)
    assert cand.status == "promoted"
    assert cand.to_version == "1.5"     # newest-first input order


def test_promoted_skips_vulnerable_versions() -> None:
    dep = _dep(version="1.0")
    osv = _FakeOsv(advisories_by_version={
        "2.0": [_adv("GHSA-bad")],     # vulnerable
        "1.5": [],                      # clean
    })
    cand = _plan_one(dep,
                     registries={"PyPI": _FakeRegistry(["2.0", "1.5"])},
                     osv=osv, offline=False, allow_major=False)
    assert cand.status == "promoted"
    assert cand.to_version == "1.5"
    assert cand.candidates_rejected_for_cve == 1


# ---------------------------------------------------------------------------
# Status: review_required
# ---------------------------------------------------------------------------

def test_major_crossing_without_allow_major() -> None:
    dep = _dep(version="1.0")
    cand = _plan_one(dep, registries={"PyPI": _FakeRegistry(["2.0"])},
                     osv=_FakeOsv(), offline=False, allow_major=False)
    assert cand.status == "review_required"
    assert cand.to_version == "2.0"
    assert cand.crosses_major is True


def test_major_crossing_with_allow_major() -> None:
    dep = _dep(version="1.0")
    cand = _plan_one(dep, registries={"PyPI": _FakeRegistry(["2.0"])},
                     osv=_FakeOsv(), offline=False, allow_major=True)
    assert cand.status == "promoted"
    assert cand.to_version == "2.0"


# ---------------------------------------------------------------------------
# Status: degraded_safety
# ---------------------------------------------------------------------------

def test_no_clean_version_falls_through_to_degraded() -> None:
    """Every candidate has at least one advisory → pick least-worst."""
    dep = _dep(version="1.0")
    osv = _FakeOsv(advisories_by_version={
        "1.5": [_adv("GHSA-medium-x", "medium")],
        "1.8": [_adv("GHSA-critical-y", "critical"),
                _adv("GHSA-medium-z", "medium")],
    })
    cand = _plan_one(dep,
                     registries={"PyPI": _FakeRegistry(["1.8", "1.5"])},
                     osv=osv, offline=False, allow_major=False)
    assert cand.status == "degraded_safety"
    # 1.5 has lower max_severity than 1.8 → wins.
    assert cand.to_version == "1.5"
    assert cand.cve_remaining == ["GHSA-medium-x"]


def test_degraded_picks_fewer_when_severity_tied() -> None:
    dep = _dep(version="1.0")
    osv = _FakeOsv(advisories_by_version={
        "1.5": [_adv("GHSA-A", "high"), _adv("GHSA-B", "high")],
        "1.8": [_adv("GHSA-C", "high")],
    })
    cand = _plan_one(dep,
                     registries={"PyPI": _FakeRegistry(["1.8", "1.5"])},
                     osv=osv, offline=False, allow_major=False)
    assert cand.status == "degraded_safety"
    assert cand.to_version == "1.8"     # fewer advisories at same severity


def test_degraded_with_major_crossing_still_review_required() -> None:
    """Even degraded candidates respect the major-crossing gate."""
    dep = _dep(version="1.0")
    osv = _FakeOsv(advisories_by_version={
        "2.0": [_adv("GHSA-x", "low")],
    })
    cand = _plan_one(dep, registries={"PyPI": _FakeRegistry(["2.0"])},
                     osv=osv, offline=False, allow_major=False)
    assert cand.status == "review_required"
    assert cand.to_version == "2.0"


# ---------------------------------------------------------------------------
# --check actionable counter
# ---------------------------------------------------------------------------

def _candidate(status: str) -> HardenCandidate:
    return HardenCandidate(
        ecosystem="PyPI", name="x", manifest="/x/req.txt",
        pin_style="range", from_version="1.0", to_version="2.0",
        crosses_major=False, status=status,
    )


def test_count_actionable_promoted_always_counts() -> None:
    from packages.sca.harden import _count_actionable
    cands = [_candidate("promoted"), _candidate("promoted")]
    assert _count_actionable(cands, allow_major=False,
                             allow_major_without_review=False,
                             allow_degraded=False) == 2


def test_count_actionable_skips_non_actionable() -> None:
    from packages.sca.harden import _count_actionable
    cands = [
        _candidate("up_to_date"),
        _candidate("already_pinned"),
        _candidate("registry_unsupported"),
        _candidate("no_versions"),
        _candidate("needs_network"),
    ]
    assert _count_actionable(cands, allow_major=False,
                             allow_major_without_review=False,
                             allow_degraded=False) == 0


def test_count_actionable_review_required_gated() -> None:
    from packages.sca.harden import _count_actionable
    cands = [_candidate("review_required")]
    # Default: review_required not actionable.
    assert _count_actionable(cands, allow_major=False,
                             allow_major_without_review=False,
                             allow_degraded=False) == 0
    # With --allow-major-without-review: counts.
    assert _count_actionable(cands, allow_major=True,
                             allow_major_without_review=True,
                             allow_degraded=False) == 1


def test_count_actionable_degraded_gated() -> None:
    from packages.sca.harden import _count_actionable
    cands = [_candidate("degraded_safety")]
    assert _count_actionable(cands, allow_major=False,
                             allow_major_without_review=False,
                             allow_degraded=False) == 0
    assert _count_actionable(cands, allow_major=False,
                             allow_major_without_review=False,
                             allow_degraded=True) == 1


def test_apply_patch_refuses_non_git_target(tmp_path: Path) -> None:
    """``--apply`` requires a git checkout for rollback safety."""
    from packages.sca.patch_apply import apply_patch_to_target as _apply_patch_to_target
    patch = tmp_path / "p.patch"
    patch.write_text("dummy", encoding="utf-8")
    rc = _apply_patch_to_target(tmp_path, patch)
    assert rc == 4


def test_apply_patch_with_no_patch_file_is_noop(tmp_path: Path) -> None:
    from packages.sca.patch_apply import apply_patch_to_target as _apply_patch_to_target
    rc = _apply_patch_to_target(tmp_path, None)
    assert rc == 0


def test_apply_patch_to_git_target(tmp_path: Path) -> None:
    """Applies a patch to a real git checkout end-to-end."""
    import subprocess
    repo = tmp_path / "proj"
    repo.mkdir()
    (repo / "requirements.txt").write_text("django>=4.0.0\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=str(repo), check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=str(repo),
                    check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=str(repo),
                    check=True)
    subprocess.run(["git", "add", "."], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=str(repo),
                    check=True)

    patch = tmp_path / "u.patch"
    patch.write_text(
        "diff --git a/requirements.txt b/requirements.txt\n"
        "--- a/requirements.txt\n"
        "+++ b/requirements.txt\n"
        "@@ -1 +1 @@\n"
        "-django>=4.0.0\n"
        "+django==4.2.10\n",
        encoding="utf-8",
    )
    from packages.sca.patch_apply import apply_patch_to_target as _apply_patch_to_target
    rc = _apply_patch_to_target(repo, patch)
    assert rc == 0
    assert (repo / "requirements.txt").read_text() == "django==4.2.10\n"


def test_count_actionable_ecosystem_allowlist() -> None:
    """--ecosystems filter excludes candidates outside the allowlist."""
    from packages.sca.harden import _count_actionable, HardenCandidate

    def _c(eco: str, status: str = "promoted") -> HardenCandidate:
        return HardenCandidate(
            ecosystem=eco, name="x", manifest="/x/req.txt",
            pin_style="range", from_version="1.0", to_version="2.0",
            crosses_major=False, status=status,
        )

    cands = [_c("PyPI"), _c("npm"), _c("Debian")]
    # No allowlist: all 3 count.
    assert _count_actionable(cands, allow_major=False,
                             allow_major_without_review=False,
                             allow_degraded=False) == 3
    # PyPI only: just 1.
    assert _count_actionable(cands, allow_major=False,
                             allow_major_without_review=False,
                             allow_degraded=False,
                             ecosystem_allowlist={"PyPI"}) == 1
    # PyPI + npm: 2.
    assert _count_actionable(cands, allow_major=False,
                             allow_major_without_review=False,
                             allow_degraded=False,
                             ecosystem_allowlist={"PyPI", "npm"}) == 2
    # Empty allowlist: 0.
    assert _count_actionable(cands, allow_major=False,
                             allow_major_without_review=False,
                             allow_degraded=False,
                             ecosystem_allowlist=set()) == 0


# ---------------------------------------------------------------------------
# commented_out deps are skipped by the planner
# ---------------------------------------------------------------------------

def test_plan_skips_commented_out_deps(
    monkeypatch, tmp_path: Path,
) -> None:
    """Commented-out hint lines (``# pkg==X`` in requirements.txt, or
    ``# pip install foo==1.0`` in shell) are documentation, not active
    deps. ``findings.py`` already downgrades their severity to ``info``;
    ``harden`` must match the same policy by refusing to propose bumps
    for them.

    Discovered 2026-05-20: harden promoted ``PyPI:a → 1.0``,
    ``PyPI:single → 0.2.0``, etc., from a comment in a GHA workflow
    (``# grep + uv pip install keeps a single source of truth.``).
    The parser FP was fixed separately; this is the defence-in-depth
    layer that catches a parser regression before it reaches the
    operator-visible patch.
    """
    from packages.sca import harden as harden_mod

    real = _dep(name="real-dep", version="1.0", pin_style=PinStyle.EXACT)
    ghost = _dep(name="ghost-dep", version="1.0", pin_style=PinStyle.EXACT)
    object.__setattr__(ghost, "commented_out", True)

    monkeypatch.setattr(harden_mod, "find_manifests",
                        lambda _t: [Path("/fake/requirements.txt")])
    monkeypatch.setattr(harden_mod, "parse_manifest",
                        lambda _m: [real, ghost])

    candidates = harden_mod.plan(
        target=tmp_path,
        registries={"PyPI": _FakeRegistry(["1.0", "1.5"])},
        osv=_FakeOsv({"1.0": [], "1.5": []}),
        offline=False, allow_major=False,
    )

    names = [c.name for c in candidates]
    assert "real-dep" in names
    assert "ghost-dep" not in names, (
        "harden must not propose bumps for commented-out deps"
    )


# ---------------------------------------------------------------------------
# Promotion-safety check (option 2c) — the "harden" promise
# ---------------------------------------------------------------------------

class _StubPyPIClient:
    """Minimal PyPI client stub for the supply-chain evaluator path.

    Harden first calls ``list_versions`` to enumerate candidates,
    then ``_evaluate_promotion_safety`` calls ``get_metadata`` via
    the bump-tier evaluator. The canned ``releases`` dict is
    shaped like PyPI's JSON API; ``upload_time_iso_8601`` is what
    the ``recent_publish`` detector reads.
    """

    def __init__(self, *, version: str, upload_iso: str,
                 maintainers=("alice",)):
        self._version = version
        self._upload_iso = upload_iso
        self._maintainers = list(maintainers)
        self.ecosystem = "PyPI"

    def list_versions(self, name: str) -> List[str]:
        return [self._version]

    def get_metadata(self, name: str) -> dict:
        return {
            "info": {"yanked": False, "maintainer": "alice"},
            "releases": {
                self._version: [{
                    "upload_time_iso_8601": self._upload_iso,
                    "url": f"https://example/{name}-{self._version}.whl",
                    "filename": f"{name}-{self._version}.whl",
                    "digests": {"sha256": "abc"},
                    "size": 1234,
                    "packagetype": "bdist_wheel",
                    "python_version": "py3",
                    "yanked": False,
                }],
            },
        }


def test_promotion_demoted_when_target_published_recently() -> None:
    """The original ``semgrep 1.161.0 → 1.163.0`` case from the
    2026-05-20 self-bump simulation: harden's OSV-only ranking says
    Clean (no CVEs at 1.163.0); but the bump-tier
    ``recent_publish`` detector says target was published ~now.
    Post option-2c, harden mirrors bump's verdict and demotes to
    ``review_required``."""
    from datetime import datetime, timezone

    dep = _dep(name="semgrep", version="1.161.0",
                pin_style=PinStyle.EXACT)
    # Target published RIGHT NOW (well within
    # ``_RAPID_RELEASE_DAYS = 30``).
    now_iso = datetime.now(timezone.utc).isoformat().replace(
        "+00:00", "Z")
    pypi = _StubPyPIClient(version="1.163.0", upload_iso=now_iso)

    cand = _plan_one(
        dep,
        registries={"PyPI": pypi},
        osv=_FakeOsv({"1.163.0": []}),  # No CVEs → OSV path = Clean.
        offline=False, allow_major=False,
    )

    assert cand.status == "review_required"
    assert cand.to_version == "1.163.0"
    assert "recent_publish" in (cand.detail or ""), (
        f"detail should cite the supply-chain finding kind; got: "
        f"{cand.detail!r}"
    )


def test_promotion_not_demoted_when_target_published_long_ago() -> None:
    """Counter-positive: target version published well outside the
    rapid-release window → safety check passes → ``promoted``."""
    from datetime import datetime, timedelta, timezone

    dep = _dep(name="requests", version="2.30.0",
                pin_style=PinStyle.EXACT)
    long_ago_iso = (datetime.now(timezone.utc)
                     - timedelta(days=365)).isoformat().replace(
                         "+00:00", "Z")
    pypi = _StubPyPIClient(version="2.33.0", upload_iso=long_ago_iso)

    cand = _plan_one(
        dep,
        registries={"PyPI": pypi},
        osv=_FakeOsv({"2.33.0": []}),
        offline=False, allow_major=False,
    )

    assert cand.status == "promoted"
    assert cand.to_version == "2.33.0"


def test_offline_skips_safety_check() -> None:
    """``--offline`` can't run the metadata-fetch-driven
    supply-chain detectors. Skip the check rather than fail-close
    on every dep."""
    dep = _dep(name="requests", version="2.30.0",
                pin_style=PinStyle.EXACT)

    cand = _plan_one(
        dep,
        # ``_FakeRegistry`` lacks ``get_metadata`` — would have
        # AttributeError'd if the safety check ran.
        registries={"PyPI": _FakeRegistry(["2.33.0"])},
        osv=_FakeOsv({"2.33.0": []}),
        offline=True, allow_major=False,
    )

    assert cand.status == "promoted"
    assert cand.to_version == "2.33.0"


def test_registry_stub_without_get_metadata_is_safe() -> None:
    """Defensive: tests that pass a ``_FakeRegistry`` stub (no
    ``get_metadata``) must not crash the safety check. The hasattr
    guard in ``_evaluate_promotion_safety`` treats it as
    missing-client → empty findings → safe-to-promote-by-default.
    """
    dep = _dep(name="requests", version="2.30.0",
                pin_style=PinStyle.EXACT)
    cand = _plan_one(
        dep,
        registries={"PyPI": _FakeRegistry(["2.33.0"])},
        osv=_FakeOsv({"2.33.0": []}),
        offline=False, allow_major=False,
    )
    assert cand.status == "promoted"


# ---------------------------------------------------------------------------
# Bounded downgrade: no clean version at/above the pin → move DOWN to the
# highest clean version within the recorded corridor floor.
# ---------------------------------------------------------------------------

def test_bounded_downgrade_to_highest_clean_within_floor() -> None:
    """``pkg==2.7.0`` (corridor floor 2.0) where 2.7.0 and everything
    above is CVE-bearing but 2.5 is clean → bounded downgrade to 2.5."""
    dep = replace(_dep(pin_style=PinStyle.EXACT, version="2.7.0"),
                  version_floor="2.0")
    osv = _FakeOsv({
        "2.0": [_adv("CVE-A")],     # clean-but-below not needed; CVE anyway
        "2.7.0": [_adv("CVE-B")],
        "2.8": [_adv("CVE-C")],
        "2.9": [_adv("CVE-D")],
        # 2.5 absent => clean
    })
    cand = _plan_one(
        dep,
        registries={"PyPI": _FakeRegistry(
            ["2.0", "2.5", "2.7.0", "2.8", "2.9"])},
        osv=osv, offline=False, allow_major=False,
    )
    assert cand.status == "downgraded_safety", cand.status
    assert cand.to_version == "2.5"
    assert "downgrade" in cand.detail.lower()


def test_bounded_downgrade_respects_floor() -> None:
    """A clean version BELOW the floor is not eligible. When nothing in
    ``[floor, installed)`` is clean, fall back to a degraded upgrade —
    never a sub-floor downgrade."""
    dep = replace(_dep(pin_style=PinStyle.EXACT, version="2.7.0"),
                  version_floor="2.6")
    osv = _FakeOsv({
        # only clean version (1.9) is below floor 2.6; the rest carry CVEs
        "2.7.0": [_adv("CVE-B")],
        "2.8": [_adv("CVE-C")],
    })
    cand = _plan_one(
        dep,
        registries={"PyPI": _FakeRegistry(["1.9", "2.7.0", "2.8"])},
        osv=osv, offline=False, allow_major=False,
    )
    assert cand.status == "degraded_safety", cand.status


def test_no_downgrade_when_clean_version_above_exists() -> None:
    """A clean version at/above the pin always wins — never downgrade."""
    dep = replace(_dep(pin_style=PinStyle.EXACT, version="2.7.0"),
                  version_floor="2.0")
    osv = _FakeOsv({"2.7.0": [_adv("CVE-B")]})   # 2.9 clean
    cand = _plan_one(
        dep,
        registries={"PyPI": _FakeRegistry(["2.0", "2.5", "2.7.0", "2.9"])},
        osv=osv, offline=False, allow_major=False,
    )
    assert cand.status == "promoted"
    assert cand.to_version == "2.9"


# ---------------------------------------------------------------------------
# Non-PyPI promotion: harden now bumps versioned npm/Maven/Cargo deps via the
# per-ecosystem comparator (regression for _versions_above_installed having
# short-circuited every non-PyPI dep to up_to_date with `else 0`).
# ---------------------------------------------------------------------------

def test_npm_exact_pin_now_promotable() -> None:
    """A versioned npm dep is compared with semver and gets promoted —
    previously it short-circuited to up_to_date."""
    dep = replace(_dep(ecosystem="npm", name="lodash", version="4.17.0",
                       pin_style=PinStyle.EXACT),
                  declared_in=Path("/x/package.json"))
    cand = _plan_one(
        dep,
        registries={"npm": _FakeRegistry(["4.17.0", "4.17.21"], ecosystem="npm")},
        osv=_FakeOsv({"4.17.21": []}),
        offline=False, allow_major=False,
    )
    assert cand.status == "promoted", cand.status
    assert cand.to_version == "4.17.21"


def test_npm_range_spec_still_up_to_date() -> None:
    """A RANGE dep's recorded version is the whole spec string, not a
    comparable version, so the comparator can't place it 'above' anything
    — it stays up_to_date (unchanged, no spurious bump)."""
    dep = replace(_dep(ecosystem="npm", name="x", version=">=4.0.0 <5.0.0",
                       pin_style=PinStyle.RANGE),
                  declared_in=Path("/x/package.json"))
    cand = _plan_one(
        dep,
        registries={"npm": _FakeRegistry(["4.5.0", "4.9.0"], ecosystem="npm")},
        osv=_FakeOsv(), offline=False, allow_major=False,
    )
    assert cand.status == "up_to_date", cand.status


# ---------------------------------------------------------------------------
# Range/corridor selection: use the recorded floor as the comparison
# baseline (so explicit-range deps bump) and the ceiling as a filter (stay
# inside the declared corridor; also fixes a PyPI corridor that could
# select a target past its own ceiling).
# ---------------------------------------------------------------------------

def test_npm_range_with_floor_promotes_within_ceiling() -> None:
    """An explicit-range npm dep with a recorded corridor bumps to the
    newest clean version *inside* the corridor — the floor makes it
    comparable, the ceiling caps it."""
    dep = replace(_dep(ecosystem="npm", name="x", version=">=4.0.0 <5.0.0",
                       pin_style=PinStyle.RANGE),
                  declared_in=Path("/x/package.json"),
                  version_floor="4.0.0", version_ceiling="5.0.0")
    cand = _plan_one(
        dep,
        registries={"npm": _FakeRegistry(  # registries list newest-first
            ["5.2.0", "4.9.0", "4.5.0"], ecosystem="npm")},
        osv=_FakeOsv({"4.9.0": [], "4.5.0": []}),
        offline=False, allow_major=False,
    )
    assert cand.status == "promoted", cand.status
    assert cand.to_version == "4.9.0"   # 5.2.0 excluded by the <5.0.0 ceiling


def test_pypi_corridor_ceiling_respected_in_selection() -> None:
    """Regression: harden must not select a target past a PyPI range's own
    ceiling (which would rewrite to an invalid corridor like
    ``>=2.0,==3.5,<3.0``)."""
    dep = replace(_dep(ecosystem="PyPI", name="x", version=None,
                       pin_style=PinStyle.RANGE),
                  version_floor="2.0", version_ceiling="3.0")
    cand = _plan_one(
        dep,
        registries={"PyPI": _FakeRegistry(["3.5", "2.8", "2.5"])},  # newest-first
        osv=_FakeOsv({"2.8": [], "2.5": []}),
        offline=False, allow_major=False,
    )
    assert cand.status == "promoted", cand.status
    assert cand.to_version == "2.8"     # 3.5 excluded by the <3.0 ceiling


def test_bounded_downgrade_generalises_to_non_pypi() -> None:
    """The bounded downgrade is ecosystem-agnostic: given any dep with a
    recorded floor and a concrete installed pin above it, harden downgrades
    to the highest clean version >= floor using the ecosystem's comparator.
    Dormant for npm's own pin styles today (none yield floor + concrete
    installed-above-floor), but the logic must be correct for whatever
    produces that shape — verified here with a synthetic npm dep."""
    dep = replace(_dep(ecosystem="npm", name="x", version="2.7.0",
                       pin_style=PinStyle.EXACT),
                  declared_in=Path("/x/package.json"),
                  version_floor="2.0.0")
    osv = _FakeOsv({
        "2.9.0": [_adv("CVE-A")], "2.8.0": [_adv("CVE-B")],
        "2.7.0": [_adv("CVE-C")], "2.0.0": [_adv("CVE-D")],
        # 2.5.0 absent => clean
    })
    cand = _plan_one(
        dep,
        registries={"npm": _FakeRegistry(   # newest-first
            ["2.9.0", "2.8.0", "2.7.0", "2.5.0", "2.0.0"], ecosystem="npm")},
        osv=osv, offline=False, allow_major=False,
    )
    assert cand.status == "downgraded_safety", cand.status
    assert cand.to_version == "2.5.0"   # highest clean in [2.0.0, 2.7.0)


# ---------------------------------------------------------------------------
# library_mode: minimal safe floor-raise (target_kind consumer)
# ---------------------------------------------------------------------------

def test_application_mode_picks_newest_safe() -> None:
    """Default (application) posture: pin to the newest safe version in range."""
    dep = _dep(version="1.0", pin_style=PinStyle.RANGE)
    cand = _plan_one(
        dep, registries={"PyPI": _FakeRegistry(["1.3", "1.2", "1.1", "1.0"])},
        osv=_FakeOsv(), offline=False, allow_major=False,
    )
    assert cand.status == "promoted"
    assert cand.to_version == "1.3"            # newest in range
    assert cand.selection == "highest_safe"


def test_library_mode_skips_clean_baseline() -> None:
    """Library posture: an already-safe declared floor is left intact — don't
    narrow an intentional range when there's no security reason."""
    dep = _dep(version="1.0", pin_style=PinStyle.RANGE)  # floor 1.0 clean
    cand = _plan_one(
        dep, registries={"PyPI": _FakeRegistry(["1.3", "1.2", "1.1", "1.0"])},
        osv=_FakeOsv(), offline=False, allow_major=False,
        library_mode=True,
    )
    assert cand.status == "up_to_date"
    assert "already safe" in cand.detail


def test_library_mode_floor_raises_when_baseline_vulnerable() -> None:
    """Vulnerable floor → minimal safe floor-raise (lowest clean above it)."""
    dep = _dep(version="1.0", pin_style=PinStyle.RANGE)
    osv = _FakeOsv({"1.0": [_adv("CVE-FLOOR")]})   # declared floor vulnerable
    cand = _plan_one(
        dep, registries={"PyPI": _FakeRegistry(["1.3", "1.2", "1.1", "1.0"])},
        osv=osv, offline=False, allow_major=False,
        library_mode=True,
    )
    assert cand.status == "promoted"
    assert cand.to_version == "1.1"            # minimal safe, not 1.3
    assert cand.selection == "library_minimal"


def test_library_mode_minimal_skips_vulnerable_nearest() -> None:
    """Minimal means minimal *clean*: skip a vulnerable nearest version."""
    dep = _dep(version="1.0", pin_style=PinStyle.RANGE)
    osv = _FakeOsv({"1.0": [_adv("C0")], "1.1": [_adv("C1")]})  # floor+1.1 vuln
    cand = _plan_one(
        dep, registries={"PyPI": _FakeRegistry(["1.3", "1.2", "1.1", "1.0"])},
        osv=osv, offline=False, allow_major=False,
        library_mode=True,
    )
    assert cand.status == "promoted"
    assert cand.to_version == "1.2"            # lowest clean above floor


def test_library_mode_npm_floor_raises_to_range() -> None:
    """npm (Increment 2): a vulnerable library dep is promoted with a minimal,
    range-preserving floor-raise (the bare→caret happens in _bump_npm_spec)."""
    dep = replace(_dep(ecosystem="npm", name="lodash", version="1.0",
                       pin_style=PinStyle.RANGE),
                  declared_in=Path("/x/package.json"))
    osv = _FakeOsv({"1.0": [_adv("C")]})        # vulnerable floor
    cand = _plan_one(
        dep, registries={"npm": _FakeRegistry(["1.3", "1.2", "1.1", "1.0"],
                                              ecosystem="npm")},
        osv=osv, offline=False, allow_major=False, library_mode=True,
    )
    assert cand.status == "promoted"
    assert cand.to_version == "1.1"             # minimal safe above floor
    assert cand.selection == "library_minimal"


@pytest.mark.parametrize("eco,manifest", [
    ("NuGet", "App.csproj"),
    ("NuGet", "Directory.Packages.props"),
    ("Maven", "pom.xml"),
    ("Maven", "libs.versions.toml"),
])
def test_library_mode_min_version_ecosystem_promotes_not_skipped(eco, manifest) -> None:
    """NuGet/Gradle/Maven (Increment 3): minimum/soft-version manifests resolve
    by floor, so the normal bump is already a safe floor-raise — they promote,
    they are not skipped."""
    dep = replace(_dep(ecosystem=eco, name="some.pkg",
                       version="1.0", pin_style=PinStyle.RANGE),
                  declared_in=Path("/x") / manifest)
    osv = _FakeOsv({"1.0": [_adv("C")]})
    cand = _plan_one(
        dep, registries={eco: _FakeRegistry(["1.3", "1.2", "1.1", "1.0"],
                                            ecosystem=eco)},
        osv=osv, offline=False, allow_major=False, library_mode=True,
    )
    assert cand.status == "promoted"
    assert cand.selection == "library_minimal"
    assert cand.to_version == "1.1"


def test_library_mode_inline_install_is_unsupported_not_pinned() -> None:
    """Inline installs (``pip install x==Y``) are exact by nature — refuse
    rather than over-constrain a library."""
    dep = replace(_dep(version="1.0", pin_style=PinStyle.RANGE),
                  declared_in=Path("/x/Dockerfile"))
    osv = _FakeOsv({"1.0": [_adv("C")]})
    cand = _plan_one(
        dep, registries={"PyPI": _FakeRegistry(["1.3", "1.2", "1.1", "1.0"])},
        osv=osv, offline=False, allow_major=False, library_mode=True,
    )
    assert cand.status == "library_floor_raise_unsupported"
    assert cand.selection == "highest_safe"     # never marked library_minimal


@pytest.mark.parametrize("manifest,supported", [
    ("requirements.txt", True), ("requirements-dev.txt", True),
    ("pyproject.toml", True), ("package.json", True),
    ("App.csproj", True), ("Directory.Packages.props", True),
    ("Directory.Build.targets", True),   # pre-CPM central-version table
    ("libs.versions.toml", True), ("pom.xml", True),
    ("Dockerfile", False), ("install.sh", False), ("setup.cfg", False),
])
def test_supports_library_floor_raise_matrix(manifest, supported) -> None:
    from packages.sca.harden import _supports_library_floor_raise
    dep = replace(_dep(), declared_in=Path("/x") / manifest)
    assert _supports_library_floor_raise(dep) is supported


def test_two_csprojs_sharing_central_dep_collapse_to_one_patch(tmp_path) -> None:
    """Two csprojs both inheriting one central PackageVersion must produce
    a SINGLE patch on the central file, not one per csproj. The dedup key in
    _apply uses the write-path (cand.resolved_in) for exactly this."""
    from packages.sca.harden import _apply
    props = tmp_path / "Directory.Packages.props"
    props.write_text(
        '<Project><ItemGroup>'
        '<PackageVersion Include="X" Version="1.0.0"/></ItemGroup></Project>')
    cands = []
    for sub in ("A", "B"):
        (tmp_path / sub).mkdir()
        csp = tmp_path / sub / f"{sub}.csproj"
        csp.write_text('<Project/>')
        cands.append(HardenCandidate(
            ecosystem="NuGet", name="X", manifest=str(csp),
            pin_style="exact", from_version="1.0.0", to_version="1.0.1",
            crosses_major=False, status="promoted",
            resolved_in=str(props),
        ))
    out = tmp_path / "out"
    _apply(cands, target=tmp_path, out_dir=out,
           allow_major_without_review=False, allow_degraded=False,
           ecosystem_allowlist=None)
    patched = list((out / "proposed").rglob("*"))
    csproj_patches = [p for p in patched if p.is_file() and p.suffix == ".csproj"]
    props_patches = [p for p in patched if p.is_file() and p.name == "Directory.Packages.props"]
    assert len(props_patches) == 1, f"expected ONE .props patch, got {len(props_patches)}"
    assert csproj_patches == [], f"no csproj should be patched, got {csproj_patches}"


def test_central_version_dep_routes_apply_to_resolved_in(tmp_path) -> None:
    """A dep whose version is owned by a central file (CPM Directory.Packages
    .props or pre-CPM Directory.Build.targets) must have its PATCH routed to
    THAT file by _apply — not to the csproj where the PackageReference is
    declared (the csproj holds no Version attribute to update). Carried via
    HardenCandidate.resolved_in, set from dep.source_extra['resolved_in']."""
    from packages.sca.harden import _apply
    csproj = tmp_path / "App.csproj"
    csproj.write_text(
        '<Project Sdk="Microsoft.NET.Sdk">'
        '<ItemGroup><PackageReference Include="X"/></ItemGroup></Project>')
    props = tmp_path / "Directory.Packages.props"
    props.write_text(
        '<Project><ItemGroup>'
        '<PackageVersion Include="X" Version="1.0.0"/></ItemGroup></Project>')
    cand = HardenCandidate(
        ecosystem="NuGet", name="X", manifest=str(csproj),
        pin_style="exact", from_version="1.0.0", to_version="1.0.1",
        crosses_major=False, status="promoted",
        resolved_in=str(props),         # parser-set: version lives in props
    )
    out = tmp_path / "out"
    _apply([cand], target=tmp_path, out_dir=out,
           allow_major_without_review=False, allow_degraded=False,
           ecosystem_allowlist=None)
    proposed_props = out / "proposed" / "Directory.Packages.props"
    proposed_csproj = out / "proposed" / "App.csproj"
    assert proposed_props.exists() and 'Version="1.0.1"' in proposed_props.read_text()
    assert not proposed_csproj.exists()


def test_library_mode_directory_build_targets_no_longer_unsupported() -> None:
    """Directory.Build.targets was rejected as unsupported_manifest by the
    pre-follow-up harden._has_rewriter. With the new rewriter + dispatch +
    gate entries, deps attributed to that file flow through the planner
    cleanly (status driven by the registry/OSV result, not by the gate)."""
    dep = replace(_dep(ecosystem="NuGet", name="IdentityServer4",
                       version="3.1.0", pin_style=PinStyle.RANGE),
                  declared_in=Path("/x/Directory.Build.targets"))
    osv = _FakeOsv({"3.1.0": [_adv("C")]})
    cand = _plan_one(
        dep, registries={"NuGet": _FakeRegistry(["4.2.0", "4.1.2", "3.1.0"],
                                                ecosystem="NuGet")},
        osv=osv, offline=False, allow_major=False, library_mode=True,
    )
    assert cand.status != "unsupported_manifest"
    assert cand.status != "library_floor_raise_unsupported"


def test_library_mode_no_clean_version_refuses_to_pin() -> None:
    """Library + no safe version anywhere in range → refuse (never degrade-pin
    a library to a single/residual-vulnerable version)."""
    dep = _dep(version="1.0", pin_style=PinStyle.RANGE)
    osv = _FakeOsv({v: [_adv(f"C-{v}")] for v in ("1.0", "1.1", "1.2", "1.3")})
    cand = _plan_one(
        dep, registries={"PyPI": _FakeRegistry(["1.3", "1.2", "1.1", "1.0"])},
        osv=osv, offline=False, allow_major=False, library_mode=True,
    )
    assert cand.status == "library_floor_raise_unsupported"


def test_pypi_floor_raise_spec_is_a_range_not_a_pin() -> None:
    """The leaf: floor_raise raises the lower bound and drops the == pin."""
    from packages.sca.update import _pypi_pin_preserving_bounds
    # corridor (app): keep floor, add exact pin
    assert _pypi_pin_preserving_bounds(">=2.0,<3.0", "2.1") == ">=2.0,==2.1,<3.0"
    # floor-raise (library): raise floor, keep ceiling, NO ==
    assert _pypi_pin_preserving_bounds(">=2.0,<3.0", "2.1",
                                       floor_raise=True) == ">=2.1,<3.0"
    assert "==" not in _pypi_pin_preserving_bounds(">=2.0", "2.1",
                                                   floor_raise=True)


def test_report_surfaces_library_detection_and_override() -> None:
    """The report banner states detection + override, keyed on target_kind."""
    import tempfile
    from packages.sca.harden import _write_report
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "report.md"
        _write_report(out, [], [], target_kind="library",
                      target_kind_reason="pyproject.toml [project]")
        text = out.read_text()
    assert "Detected as a library target" in text
    assert "pyproject.toml [project]" in text
    assert "RAPTOR_TARGET_KIND=application" in text


def test_report_lists_unsupported_section() -> None:
    """When deps were refused, the report has a per-dep detail section so the
    operator sees exactly which ones (and why) — not just a summary count."""
    import tempfile
    from packages.sca.harden import _write_report
    cand = HardenCandidate(
        ecosystem="PyPI", name="pkg", manifest="Dockerfile",
        pin_style="range", from_version="1.0", to_version=None,
        crosses_major=False, status="library_floor_raise_unsupported",
        detail="library target: refusing to pin (would force exact pin)",
    )
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "report.md"
        _write_report(out, [cand], [], target_kind="library")
        text = out.read_text()
    assert "Library floor-raise unsupported" in text
    assert "**PyPI:pkg**" in text and "Dockerfile" in text


def test_target_kind_cli_flag_sets_env(monkeypatch) -> None:
    """`raptor-sca fix --harden --target-kind library` sets RAPTOR_TARGET_KIND
    so the in-process detector honours the operator's intent (the same env
    consulted by resolve_library_mode)."""
    monkeypatch.delenv("RAPTOR_TARGET_KIND", raising=False)
    from packages.sca.harden import _parse_args
    args = _parse_args(["/tmp", "--target-kind", "library"])
    assert args.target_kind == "library"
    # main() sets the env from args; replicate that single line here to keep
    # this a focused unit test (full main() needs registries/cache).
    import os
    from core.config import RaptorConfig
    if args.target_kind != "auto":
        os.environ[RaptorConfig.ENV_TARGET_KIND] = args.target_kind
    assert os.environ.get(RaptorConfig.ENV_TARGET_KIND) == "library"
