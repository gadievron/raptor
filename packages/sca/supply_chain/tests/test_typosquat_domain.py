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
    """Distinct registrable domains must still flag as near misses."""
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
    # In-family: same registrable domain
    assert _same_registrable_domain(
        "registry-2.docker.io", "registry-1.docker.io",
    )
    assert _same_registrable_domain(
        "api.shop.example.com", "cdn.shop.example.com",
    )
    # Not in-family: different registrable domains
    assert not _same_registrable_domain("goagle.com", "google.com")
    # Not in-family: trailing labels differ
    assert not _same_registrable_domain("evil.com", "evil.io")
    # Different depths still share the same registrable domain.
    assert _same_registrable_domain(
        "deep.sub.docker.io", "registry-1.docker.io",
    )


# ---------------------------------------------------------------------------
# Userinfo decoys — the host is what the runtime connects to
# ---------------------------------------------------------------------------

def test_userinfo_decoy_flags_the_real_host(tmp_path: Path) -> None:
    """``https://github.com@glthlb.com/x`` connects to ``glthlb.com``
    — everything before ``@`` is userinfo the server never sees.  The
    URL parser must evaluate the REAL host, not the popular decoy in
    the userinfo position (which would read as an exact popular match
    and skip)."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src.js").write_text(
        "fetch('https://github.com@glthlb.com/api')\n", encoding="utf-8")
    out = scan_target(tmp_path, _manifests(tmp_path))
    assert len(out) == 1
    assert out[0].suspect_host == "glthlb.com"
    assert out[0].nearest_popular == "github.com"


def test_userinfo_on_popular_host_not_flagged(tmp_path: Path) -> None:
    """Credentials on the genuinely-popular host stay quiet — the
    userinfo skip must not distort which host gets evaluated."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src.js").write_text(
        "fetch('https://user:tok@github.com/api')\n", encoding="utf-8")
    out = scan_target(tmp_path, _manifests(tmp_path))
    assert out == []


# ---------------------------------------------------------------------------
# Distance-convention boundary — this module returns cap+1 on overflow
# ---------------------------------------------------------------------------

def test_distance_convention_exact_at_cap_and_cap_plus_one_beyond() -> None:
    from packages.sca.supply_chain.typosquat_domain import (
        _damerau_levenshtein,
    )
    # Exact distances up to and INCLUDING the cap.
    assert _damerau_levenshtein("abcd", "abXY", 2) == 2
    assert _damerau_levenshtein("abc", "abd", 2) == 1
    assert _damerau_levenshtein("ab", "ba", 2) == 1     # transposition
    assert _damerau_levenshtein("same", "same", 2) == 0
    # Beyond the cap: cap + 1, regardless of how far beyond.
    assert _damerau_levenshtein("abcd", "wxyz", 2) == 3
    assert _damerau_levenshtein("a" * 20, "b" * 20, 2) == 3
    # The shared implementation's base-row initialisation carries
    # over (a zeroed base row made DL("a", "cma") come out 0).
    assert _damerau_levenshtein("a", "cma", 98) == 2


def test_subdomain_hosted_squat_flagged(tmp_path: Path) -> None:
    """The module's own motivating shape (CVE-2026-33634):
    ``scan.aquasecurtiy.org`` is distance ≥5 from any popular entry
    as a whole host, but its registrable suffix is distance 1 from
    ``aquasecurity.org`` — the suffix pass must catch it."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src.py").write_text(
        "URL = 'https://scan.aquasecurtiy.org/payload'\n",
        encoding="utf-8")
    out = scan_target(tmp_path, _manifests(tmp_path))
    assert len(out) == 1
    assert out[0].suspect_host == "scan.aquasecurtiy.org"
    assert out[0].nearest_popular == "aquasecurity.org"
    assert out[0].distance == 1
    assert out[0].severity == "high"


def test_subdomain_of_popular_domain_not_flagged(tmp_path: Path) -> None:
    """An exact suffix match means the host is a subdomain of the
    popular domain itself — only that owner can serve it."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src.py").write_text(
        "URL = 'https://scan.aquasecurity.org/x'\n", encoding="utf-8")
    out = scan_target(tmp_path, _manifests(tmp_path))
    assert out == []


def test_uppercase_scheme_still_detected(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "src.py").write_text(
        "URL = 'HTTPS://aquasecurtiy.org/payload'\n", encoding="utf-8")
    out = scan_target(tmp_path, _manifests(tmp_path))
    assert len(out) == 1
    assert out[0].suspect_host == "aquasecurtiy.org"


def test_esm_extension_scanned(tmp_path: Path) -> None:
    """.mjs / .cjs / .jsx / .tsx are the primary npm hook-payload
    extensions — the walker must not skip them."""
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "hook.mjs").write_text(
        "const u = 'https://aquasecurtiy.org/x';\n", encoding="utf-8")
    out = scan_target(tmp_path, _manifests(tmp_path))
    assert len(out) == 1
    assert out[0].path.name == "hook.mjs"


def test_anchor_matches_sibling_detectors(tmp_path: Path) -> None:
    """typosquat_domain must resolve its host dep through the shared
    dominance-based resolver like every other tree-walking detector:
    the same flagged file must yield the same composite ``_dep_key``
    a sibling anchor consumer produces, or SQUAT-family conjunctions
    can never co-fire. Also pins the multi-manifest anchor — the
    DOMINATING manifest wins, not the first discovered one."""
    from packages.sca.supply_chain._closest_manifest import (
        project_host_dep,
    )
    from packages.sca.supply_chain.composite import _dep_key

    (tmp_path / "package.json").write_text(
        '{"name": "rootapp"}', encoding="utf-8")
    sub = tmp_path / "svc"
    sub.mkdir()
    (sub / "package.json").write_text(
        '{"name": "subapp"}', encoding="utf-8")
    (sub / "src.py").write_text(
        "URL = 'https://aquasecurtiy.org/x'\n", encoding="utf-8")

    manifests = [
        Manifest(path=tmp_path / "package.json", ecosystem="npm",
                 is_lockfile=False),
        Manifest(path=sub / "package.json", ecosystem="npm",
                 is_lockfile=False),
    ]
    out = scan_target(tmp_path, manifests)
    assert len(out) == 1
    dep = out[0].dependency
    sibling = project_host_dep(
        manifests, sub / "src.py", tmp_path, reason="sibling walker",
    )
    assert _dep_key(dep) == _dep_key(sibling)
    # Dominance anchor + own-name resolution (not "<project>" pinned
    # to the first-discovered manifest).
    assert dep.declared_in == sub / "package.json"
    assert dep.name == "subapp"


def test_private_and_country_suffixes_do_not_suppress_typosquats() -> None:
    from packages.sca.supply_chain.typosquat_domain import _nearest_popular

    for suffix in ('github.io', 'surge.sh', 'up.railway.app',
                   's3.amazonaws.com', 'co.uk', 'com.sg', 'foo.ck'):
        popular = 'victim.' + suffix
        suspect = 'vicitm.' + suffix
        assert _nearest_popular(suspect, {popular}) == (1, popular)
        # The tenant boundary can be deeper than three labels.
        assert _nearest_popular('scan.' + suspect, {popular}) == (1, popular)
        assert _nearest_popular('scan.' + popular, {popular}) is None


def test_psl_same_owner_handles_public_suffixes_and_exceptions() -> None:
    from packages.sca.supply_chain.typosquat_domain import _same_registrable_domain

    assert not _same_registrable_domain('co.uk', 'github.io')
    assert not _same_registrable_domain('github.io', 'github.io')
    assert not _same_registrable_domain('victim.foo.ck', 'attacker.foo.ck')
    assert _same_registrable_domain('www.ck', 'sub.www.ck')
    assert _same_registrable_domain('victim.github.io', 'sub.victim.github.io')


def test_psl_failure_does_not_silently_suppress_findings(monkeypatch) -> None:
    import pytest
    from packages.sca.supply_chain import typosquat_domain as module

    def unavailable(host, **kwargs):
        raise OSError('missing PSL')

    monkeypatch.setattr(module, 'domain_boundary', unavailable)
    with pytest.raises(OSError, match='missing PSL'):
        module._nearest_popular('vicitm.github.io', {'victim.github.io'})


def test_unavailable_psl_fails_scan_and_orchestrator(tmp_path, monkeypatch) -> None:
    import pytest
    from core.domains import public_suffix as psl
    from packages.sca.supply_chain import evaluate

    snapshot = tmp_path / 'psl.dat'
    monkeypatch.setattr(psl, 'PSL_PATH', snapshot)
    (tmp_path / 'package.json').write_text('{}')
    # Empty projects and exact popular hosts must not bypass the preflight.
    for source in ('', "URL = 'https://github.com/'"):
        (tmp_path / 'source.py').write_text(source)
        for state in ('missing', 'invalid', 'unreadable'):
            if snapshot.is_file():
                snapshot.unlink()
            elif snapshot.is_dir():
                snapshot.rmdir()
            if state == 'invalid':
                snapshot.write_bytes(b'\xff')
            elif state == 'unreadable':
                snapshot.mkdir()  # Reading a directory raises OSError even as root.
            psl.load_suffix_rules.cache_clear()
            try:
                for scan in (lambda: scan_target(tmp_path, _manifests(tmp_path)),
                             lambda: evaluate(tmp_path, _manifests(tmp_path), [])):
                    with pytest.raises(RuntimeError, match='Public Suffix List') as err:
                        scan()
                    assert isinstance(err.value.__cause__, (OSError, ValueError))
            finally:
                psl.load_suffix_rules.cache_clear()


def test_nested_popular_host_typosquats_retain_detection(tmp_path) -> None:
    (tmp_path / 'package.json').write_text('{}')
    hosts = {
        'scan.files.pythonhostde.org': 'files.pythonhosted.org',
        'cdn.raw.githubuserconten.com': 'raw.githubusercontent.com',
        'nested.registry.npmjs.rog': 'registry.npmjs.org',
    }
    (tmp_path / 'source.py').write_text('\n'.join(
        f"URL = 'https://{host}/payload'" for host in hosts))
    findings = scan_target(tmp_path, _manifests(tmp_path))
    assert {f.suspect_host: f.nearest_popular for f in findings} == hosts
    assert all(f.distance == 1 for f in findings)


def test_overlong_host_does_not_abort_or_hide_other_findings(tmp_path) -> None:
    (tmp_path / 'package.json').write_text('{}')
    huge = 'a.' * 16000 + 'example.com'
    (tmp_path / 'source.py').write_text(
        f"URL = 'https://{huge}/'\nURL2 = 'https://aquasecurtiy.org/'\n")
    findings = scan_target(tmp_path, _manifests(tmp_path))
    assert [(f.suspect_host, f.nearest_popular) for f in findings] == [
        ('aquasecurtiy.org', 'aquasecurity.org')]


def test_default_suffix_does_not_establish_shared_ownership() -> None:
    from packages.sca.supply_chain.typosquat_domain import (
        _nearest_popular, _same_registrable_domain,
    )

    for suffix in ('office.local', 'team.internal', 'service_name.corp'):
        assert not _same_registrable_domain('api.' + suffix, 'apj.' + suffix)
        assert _nearest_popular('apj.' + suffix, {'api.' + suffix}) == (
            1, 'api.' + suffix)
    assert _same_registrable_domain('api.example.com', 'apj.example.com')


def test_internal_underscore_url_does_not_abort_scan(tmp_path) -> None:
    (tmp_path / 'package.json').write_text('{}')
    (tmp_path / 'source.py').write_text(
        "URL = 'https://api.service_name.internal/'\n"
        "URL2 = 'https://aquasecurtiy.org/'\n")
    findings = scan_target(tmp_path, _manifests(tmp_path))
    assert any(f.suspect_host == 'aquasecurtiy.org' for f in findings)
