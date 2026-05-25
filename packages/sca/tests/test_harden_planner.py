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
