"""Tests for the license-policy module."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import pytest

from packages.sca.license import (
    DEFAULT_POLICY,
    LicensePolicy,
    _spdx_from_npm,
    _spdx_from_pypi,
    enrich_licenses,
    evaluate,
    load_policy,
)
from packages.sca.models import Confidence, Dependency, PinStyle


def _dep(
    name: str = "foo",
    version: str = "1.0.0",
    ecosystem: str = "PyPI",
    license: Optional[str] = None,
) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=Path("/repo/manifest"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
        declared_license=license,
    )


# ---------------------------------------------------------------------------
# evaluate — classification
# ---------------------------------------------------------------------------


def test_non_spdx_ecosystems_skipped() -> None:
    """GitHub Actions / Debian / OCI / Inline deps don't carry
    package-level SPDX metadata. Pre-fix the evaluator emitted
    ``license_unknown`` info findings for every such dep — 295 on
    one Cargo project (mostly GHA actions + Debian apt installs).
    These aren't license policy issues; they're metadata gaps.
    Skip the whole ecosystem rather than flooding the report."""
    deps = [
        _dep(ecosystem="GitHub Actions", license=None),
        _dep(ecosystem="Debian", license=None),
        _dep(ecosystem="OCI", license=None),
        _dep(ecosystem="Inline", license=None),
    ]
    # Use a strict policy to prove the skip path takes effect even
    # when default=deny would otherwise fire on unknown.
    policy = LicensePolicy(allow={"MIT"}, default="deny",
                            on_unknown="deny")
    findings = evaluate(deps, policy)
    assert findings == [], (
        "non-SPDX ecosystems must be skipped; got "
        f"{[(f.dependency.ecosystem, f.kind) for f in findings]}"
    )


def test_spdx_ecosystems_still_evaluated() -> None:
    """The skip list is allowlist-shaped — PyPI / npm / Maven /
    Cargo / etc. must still flow through ``evaluate``."""
    deps = [
        _dep(ecosystem="PyPI", license=None),
        _dep(ecosystem="npm", license=None),
        _dep(ecosystem="Maven", license=None),
        _dep(ecosystem="Cargo", license=None),
    ]
    policy = LicensePolicy(allow={"MIT"}, default="warn",
                            on_unknown="warn")
    findings = evaluate(deps, policy)
    assert len(findings) == 4
    assert all(f.kind == "license_unknown" for f in findings)


def test_go_currently_skipped_pending_enrichment() -> None:
    """Go modules don't have a centralized SPDX feed; until an
    enrich_go() implementation ships, treat Go like the other
    non-SPDX ecosystems and skip license evaluation. Pre-fix,
    Go's presence in the allowlist produced 977 ``license_unknown``
    info findings on Helm-3.5 (every Go module in the dep graph)."""
    deps = [_dep(ecosystem="Go", license=None)]
    policy = LicensePolicy(allow=set(), default="deny",
                            on_unknown="deny")
    findings = evaluate(deps, policy)
    assert findings == []


def test_allowed_license_emits_no_finding():
    deps = [_dep(license="MIT")]
    policy = LicensePolicy(allow={"MIT"}, default="deny")
    findings = evaluate(deps, policy)
    assert findings == []


def test_denied_license_emits_high_severity():
    deps = [_dep(license="AGPL-3.0")]
    findings = evaluate(deps, DEFAULT_POLICY)
    assert len(findings) == 1
    assert findings[0].kind == "license_denied"
    assert findings[0].severity == "high"
    assert findings[0].spdx == "AGPL-3.0"


def test_warned_license_emits_medium_severity():
    deps = [_dep(license="GPL-3.0")]
    findings = evaluate(deps, DEFAULT_POLICY)
    assert len(findings) == 1
    assert findings[0].kind == "license_warned"
    assert findings[0].severity == "medium"


def test_unknown_license_with_warn_policy_emits_info():
    deps = [_dep(license=None)]
    findings = evaluate(deps, DEFAULT_POLICY)  # on_unknown="warn"
    assert len(findings) == 1
    assert findings[0].kind == "license_unknown"
    assert findings[0].severity == "info"
    assert findings[0].spdx is None


def test_unknown_license_with_deny_policy_emits_high():
    policy = LicensePolicy(on_unknown="deny")
    findings = evaluate([_dep(license=None)], policy)
    assert findings[0].severity == "high"


def test_unknown_license_with_allow_policy_no_finding():
    policy = LicensePolicy(on_unknown="allow")
    findings = evaluate([_dep(license=None)], policy)
    assert findings == []


def test_default_action_deny_for_unmatched_license():
    """When ``default=deny``, a license not in any list (and not
    AGPL/etc.) gets denied. Strict policy."""
    policy = LicensePolicy(default="deny")
    findings = evaluate([_dep(license="WTFPL")], policy)
    assert findings[0].kind == "license_denied"


def test_default_action_warn_for_unmatched_license():
    policy = LicensePolicy(default="warn")
    findings = evaluate([_dep(license="WTFPL")], policy)
    assert findings[0].kind == "license_warned"


def test_default_action_allow_silent():
    policy = LicensePolicy(default="allow")
    findings = evaluate([_dep(license="WTFPL")], policy)
    assert findings == []


def test_dedup_same_dep_across_manifests():
    """Same dep declared in two manifests doesn't emit two findings."""
    d1 = _dep(name="bad", license="AGPL-3.0")
    d2 = _dep(name="bad", license="AGPL-3.0")
    findings = evaluate([d1, d2], DEFAULT_POLICY)
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# evaluate — multi-license expressions
# ---------------------------------------------------------------------------


def test_or_expression_satisfied_by_any_allowed_choice():
    """``MIT OR Apache-2.0`` — operator only needs ONE choice in
    policy.allow. Common dual-license shape in OSS."""
    policy = LicensePolicy(allow={"MIT"}, deny={"AGPL-3.0"})
    findings = evaluate(
        [_dep(license="MIT OR Apache-2.0")], policy,
    )
    assert findings == []


def test_or_expression_all_denied_emits_denied():
    policy = LicensePolicy(deny={"AGPL-3.0", "SSPL-1.0"})
    findings = evaluate(
        [_dep(license="AGPL-3.0 OR SSPL-1.0")], policy,
    )
    assert findings[0].kind == "license_denied"


def test_or_expression_passes_when_any_choice_default_allowed():
    """OR expression with ``default="allow"`` (the baseline policy):
    if neither MIT nor Apache-2.0 is in the deny-list, BOTH pass
    individually via the default — so the OR is satisfied. Pre-fix
    the OR-handler required at least one choice in ``policy.allow``
    explicitly and over-flagged this canonical permissive
    dual-license declaration as ``license_incompatible``."""
    policy = LicensePolicy(allow={"BSD-3-Clause"}, deny={"GPL-3.0"})
    findings = evaluate(
        [_dep(license="MIT OR Apache-2.0")], policy,
    )
    assert not findings, (
        f"expected no finding for MIT OR Apache-2.0 under "
        f"default=allow policy; got {findings}"
    )


def test_or_expression_mixed_warn_deny_emits_incompatible():
    """OR with one choice ``warn`` + one ``deny`` (no policy-satisfying
    choice but not all-deny either): operator must pick / configure.
    Emits incompatible (medium)."""
    policy = LicensePolicy(
        warn={"GPL-3.0"}, deny={"AGPL-3.0"},
        default="deny",  # unmatched → deny so the OR can't slip
    )
    findings = evaluate(
        [_dep(license="GPL-3.0 OR AGPL-3.0")], policy,
    )
    assert len(findings) == 1
    assert findings[0].kind == "license_incompatible"


def test_or_expression_explicit_allow_choice_passes():
    """OR where one choice IS in ``policy.allow``: passes regardless
    of what the other choice is (operator has accepted that path)."""
    policy = LicensePolicy(
        allow={"MIT"}, default="deny",
    )
    findings = evaluate(
        [_dep(license="MIT OR GPL-3.0")], policy,
    )
    assert not findings


def test_and_expression_first_violation_terminates():
    """AND expression: the first denied/warned term emits the
    finding. ``GPL-3.0 AND BSD-3-Clause`` against deny={GPL-3.0}
    surfaces the denial."""
    policy = LicensePolicy(deny={"GPL-3.0"}, allow={"BSD-3-Clause"})
    findings = evaluate(
        [_dep(license="GPL-3.0 AND BSD-3-Clause")], policy,
    )
    assert findings[0].kind == "license_denied"


def test_with_expression_evaluates_base_license():
    """``GPL-2.0 WITH Classpath-exception-2.0`` is a license-with-
    exception. Today we evaluate only the base license (left side).
    Per-exception policy is a future refinement."""
    # Base allowed (via default) → pass.
    policy = LicensePolicy(allow=set(), deny={"AGPL-3.0"})
    findings = evaluate(
        [_dep(license="GPL-2.0 WITH Classpath-exception-2.0")], policy,
    )
    assert not findings
    # Base denied → deny finding (exception ignored).
    policy = LicensePolicy(deny={"GPL-2.0"}, default="allow")
    findings = evaluate(
        [_dep(license="GPL-2.0 WITH Classpath-exception-2.0")], policy,
    )
    assert findings and findings[0].kind == "license_denied"


# ---------------------------------------------------------------------------
# load_policy
# ---------------------------------------------------------------------------


def test_load_policy_no_file_returns_default(tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    policy = load_policy(target)
    assert policy is DEFAULT_POLICY


def test_load_policy_from_yaml(tmp_path):
    pytest.importorskip("yaml")
    target = tmp_path / "repo"
    target.mkdir()
    (target / ".raptor-sca-license-policy.yml").write_text(
        "allow:\n  - MIT\n  - Apache-2.0\n"
        "deny:\n  - AGPL-3.0\n"
        "warn:\n  - GPL-3.0\n"
        "default: warn\n"
        "on_unknown: deny\n"
    )
    policy = load_policy(target)
    assert policy.allow == {"MIT", "Apache-2.0"}
    assert policy.deny == {"AGPL-3.0"}
    assert policy.warn == {"GPL-3.0"}
    assert policy.default == "warn"
    assert policy.on_unknown == "deny"


def test_load_policy_malformed_yaml_falls_back(tmp_path):
    pytest.importorskip("yaml")
    target = tmp_path / "repo"
    target.mkdir()
    (target / ".raptor-sca-license-policy.yml").write_text("not: valid: yaml: [")
    policy = load_policy(target)
    assert policy is DEFAULT_POLICY


def test_load_policy_invalid_action_falls_back_to_default(tmp_path):
    pytest.importorskip("yaml")
    target = tmp_path / "repo"
    target.mkdir()
    (target / ".raptor-sca-license-policy.yml").write_text(
        "default: nonsense\non_unknown: also-bad\n"
    )
    policy = load_policy(target)
    # Action invalid -> default fallback ("allow"/"warn").
    assert policy.default == "allow"
    assert policy.on_unknown == "warn"


# ---------------------------------------------------------------------------
# enrich_licenses — registry-metadata extraction
# ---------------------------------------------------------------------------


def test_spdx_from_pypi_explicit_field():
    meta = {"info": {"license": "MIT"}}
    assert _spdx_from_pypi(meta) == "MIT"


def test_spdx_from_pypi_pep639_expression_wins():
    meta = {
        "info": {
            "license_expression": "Apache-2.0",
            "license": "free-text fallback",
        },
    }
    assert _spdx_from_pypi(meta) == "Apache-2.0"


def test_spdx_from_pypi_freetext_skipped():
    """Long free-text descriptions like 'see LICENSE file' aren't
    SPDX ids and shouldn't be returned."""
    meta = {"info": {"license": "see the LICENSE file in the source tree"}}
    assert _spdx_from_pypi(meta) is None


def test_spdx_from_pypi_trove_classifier_fallback():
    meta = {
        "info": {
            "license": "",
            "classifiers": [
                "Operating System :: POSIX",
                "License :: OSI Approved :: MIT License",
                "Programming Language :: Python :: 3",
            ],
        },
    }
    assert _spdx_from_pypi(meta) == "MIT"


def test_spdx_from_npm_top_level_string():
    meta = {"license": "ISC"}
    assert _spdx_from_npm(meta, version=None) == "ISC"


def test_spdx_from_npm_legacy_object_form():
    meta = {"license": {"type": "MIT", "url": "https://..."}}
    assert _spdx_from_npm(meta, version=None) == "MIT"


def test_spdx_from_npm_per_version_wins():
    meta = {
        "license": "MIT",
        "versions": {
            "1.0.0": {"license": "Apache-2.0"},
        },
    }
    # Per-version override beats top-level default.
    assert _spdx_from_npm(meta, version="1.0.0") == "Apache-2.0"


def test_spdx_from_npm_legacy_list_form():
    """Very old npm packages used ``licenses: [{type: ...}]``."""
    meta = {"licenses": [{"type": "MIT", "url": "..."}]}
    assert _spdx_from_npm(meta, version=None) == "MIT"


def test_enrich_licenses_no_http_skips():
    deps = [_dep(license=None)]
    enriched = enrich_licenses(deps, http=None)
    assert enriched == 0
    assert deps[0].declared_license is None


def test_enrich_licenses_skips_already_populated(monkeypatch):
    """A dep that already has declared_license isn't re-fetched."""
    deps = [_dep(license="MIT")]

    class _StubHttp:
        def get_json(self, *a, **kw):
            raise AssertionError("should not be called")

    enriched = enrich_licenses(deps, http=_StubHttp())
    assert enriched == 0
    assert deps[0].declared_license == "MIT"


def test_enrich_licenses_propagates_to_duplicates(monkeypatch):
    """A dep declared in multiple manifests (same ecosystem + name,
    possibly different versions / paths) creates multiple
    ``Dependency`` objects. ``enrich_licenses`` deduplicates the
    fetch-loop by ``(ecosystem, name)`` to avoid thundering-herd
    registry calls — but historically only set ``declared_license``
    on the single representative chosen for the fetch.

    The remaining duplicates kept ``declared_license=None``,
    triggering spurious ``license_unknown`` findings during
    evaluation. Surfaced 2026-05-21 by the dogfood scan: ``urllib3``
    declared in both ``requirements.txt`` AND a GHA workflow's
    ``pip install``, plus ``pytest`` / ``openai`` declared in
    multiple Python manifests — all flagged as ``license_unknown``
    despite at least one of their representatives having been
    enriched correctly.

    Fix: after the fetch loop, propagate ``declared_license`` by
    ``(ecosystem, name)`` to every Dependency in the input list."""

    from packages.sca.license import enrich_licenses

    # Three duplicates of urllib3 — different declared_in paths.
    d1 = _dep(name="urllib3", version="2.7.0")
    d2 = _dep(name="urllib3", version="2.7.0")
    d3 = _dep(name="urllib3", version=None)  # unpinned in a workflow
    deps = [d1, d2, d3]

    # Stub the http path so only the first urllib3 fetch returns
    # a valid SPDX. We verify all three end up with declared_license.
    class _StubPyPIMeta:
        def __init__(self):
            self.calls = 0

        def __call__(self, url, *a, **kw):
            self.calls += 1
            return {"info": {"license_expression": "MIT"},
                    "releases": {}}

    fetcher = _StubPyPIMeta()

    class _StubHttp:
        def get_json(self, url, *a, **kw):
            return fetcher(url, *a, **kw)

    enriched = enrich_licenses(deps, http=_StubHttp())

    # Three deps enriched (1 via fetch + 2 via propagation).
    assert enriched == 3, f"expected 3 enrichments, got {enriched}"
    assert d1.declared_license == "MIT"
    assert d2.declared_license == "MIT"
    assert d3.declared_license == "MIT"
    # Critically: only ONE registry round-trip — dedup still works.
    assert fetcher.calls == 1, (
        f"expected 1 registry fetch (dedup), got {fetcher.calls}"
    )


# ---------------------------------------------------------------------------
# Cargo enrichment via crates.io
# ---------------------------------------------------------------------------


def test_enrich_cargo_via_crates_api():
    from packages.sca.license import _fetch_crates_license

    class _StubHttp:
        def get_json(self, url):
            assert url == "https://crates.io/api/v1/crates/serde"
            return {
                "crate": {"name": "serde", "license": "MIT OR Apache-2.0"},
            }

    spdx = _fetch_crates_license("serde", http=_StubHttp(), cache=None)
    assert spdx == "MIT OR Apache-2.0"


def test_enrich_cargo_handles_missing_license_field():
    from packages.sca.license import _fetch_crates_license

    class _StubHttp:
        def get_json(self, url):
            return {"crate": {"name": "x"}}

    assert _fetch_crates_license("x", http=_StubHttp(), cache=None) is None


def test_enrich_cargo_caches_result():
    """Second lookup hits cache, not network."""
    from packages.sca.license import _fetch_crates_license

    calls = []

    class _StubHttp:
        def get_json(self, url):
            calls.append(url)
            return {"crate": {"license": "MIT"}}

    class _Cache:
        def __init__(self):
            self._d = {}
        def get(self, key, ttl_seconds=0):
            return self._d.get(key)
        def put(self, key, value, ttl_seconds=0):
            self._d[key] = value

    cache = _Cache()
    _fetch_crates_license("serde", http=_StubHttp(), cache=cache)
    _fetch_crates_license("serde", http=_StubHttp(), cache=cache)
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# Maven enrichment via POM XML
# ---------------------------------------------------------------------------


def test_spdx_from_pom_apache():
    from packages.sca.license import _spdx_from_pom

    pom = b"""<?xml version="1.0"?>
    <project xmlns="http://maven.apache.org/POM/4.0.0">
      <licenses>
        <license>
          <name>The Apache Software License, Version 2.0</name>
        </license>
      </licenses>
    </project>"""
    assert _spdx_from_pom(pom) == "Apache-2.0"


def test_spdx_from_pom_mit():
    from packages.sca.license import _spdx_from_pom

    pom = b"""<project>
      <licenses>
        <license><name>MIT License</name></license>
      </licenses>
    </project>"""
    assert _spdx_from_pom(pom) == "MIT"


def test_spdx_from_pom_unknown_name_returns_none():
    from packages.sca.license import _spdx_from_pom

    pom = b"""<project>
      <licenses>
        <license><name>Some weird custom license name</name></license>
      </licenses>
    </project>"""
    # Long unknown free-text isn't accepted as SPDX; returns None.
    assert _spdx_from_pom(pom) is None


def test_spdx_from_pom_no_license_element():
    from packages.sca.license import _spdx_from_pom

    pom = b"<project><groupId>x</groupId></project>"
    assert _spdx_from_pom(pom) is None


def test_spdx_from_pom_malformed_xml():
    from packages.sca.license import _spdx_from_pom

    assert _spdx_from_pom(b"not xml at all") is None


def test_fetch_maven_license_constructs_pom_url():
    from packages.sca.license import _fetch_maven_license

    captured_url = []

    class _StubHttp:
        def get_bytes(self, url, max_bytes):
            captured_url.append(url)
            return b"""<project><licenses><license>
                <name>MIT License</name>
            </license></licenses></project>"""

    spdx = _fetch_maven_license(
        "com.fasterxml.jackson.core:jackson-databind",
        "2.15.0", http=_StubHttp(), cache=None,
    )
    assert spdx == "MIT"
    # URL should follow Maven Central layout: groupId-as-path.
    assert captured_url[0] == (
        "https://repo.maven.apache.org/maven2/com/fasterxml/jackson/core/"
        "jackson-databind/2.15.0/jackson-databind-2.15.0.pom"
    )


def test_fetch_maven_license_malformed_coord_returns_none():
    from packages.sca.license import _fetch_maven_license

    class _StubHttp:
        def get_bytes(self, *a, **kw):
            raise AssertionError("should not be called")

    assert _fetch_maven_license(
        "no-colon-in-name", "1.0", http=_StubHttp(), cache=None,
    ) is None


def test_enrich_licenses_dispatches_to_cargo():
    """Integration: enrich_licenses calls the Cargo path for
    Cargo deps."""
    deps = [_dep(name="serde", version="1.0", ecosystem="Cargo")]

    class _StubHttp:
        def get_json(self, url):
            return {"crate": {"license": "MIT OR Apache-2.0"}}

    n = enrich_licenses(deps, http=_StubHttp())
    assert n == 1
    assert deps[0].declared_license == "MIT OR Apache-2.0"


def test_enrich_licenses_dispatches_to_maven():
    deps = [_dep(
        name="org.springframework:spring-core",
        version="5.3.0", ecosystem="Maven",
    )]

    class _StubHttp:
        def get_bytes(self, url, max_bytes):
            return b"""<project><licenses><license>
                <name>Apache License, Version 2.0</name>
            </license></licenses></project>"""

    n = enrich_licenses(deps, http=_StubHttp())
    assert n == 1
    assert deps[0].declared_license == "Apache-2.0"


# ---------------------------------------------------------------------------
# RubyGems / NuGet / Packagist enrichment
# ---------------------------------------------------------------------------


def test_enrich_rubygems_first_license_in_array():
    from packages.sca.license import _fetch_rubygems_license

    class _StubHttp:
        def get_json(self, url):
            assert url == "https://rubygems.org/api/v1/gems/rails.json"
            return {"licenses": ["MIT"]}

    spdx = _fetch_rubygems_license("rails", http=_StubHttp(), cache=None)
    assert spdx == "MIT"


def test_enrich_rubygems_empty_array_returns_none():
    from packages.sca.license import _fetch_rubygems_license

    class _StubHttp:
        def get_json(self, url):
            return {"licenses": []}

    assert _fetch_rubygems_license("x", http=_StubHttp(), cache=None) is None


def test_enrich_nuget_uses_license_expression():
    from packages.sca.license import _fetch_nuget_license

    class _StubHttp:
        def get_json(self, url):
            assert "newtonsoft.json" in url and "13.0.1" in url
            return {"catalogEntry": {"licenseExpression": "MIT"}}

    spdx = _fetch_nuget_license(
        "Newtonsoft.Json", "13.0.1", http=_StubHttp(), cache=None,
    )
    assert spdx == "MIT"


def test_enrich_nuget_no_license_expression_returns_none():
    from packages.sca.license import _fetch_nuget_license

    class _StubHttp:
        def get_json(self, url):
            return {"catalogEntry": {"licenseUrl": "https://..."}}

    assert _fetch_nuget_license(
        "X", "1.0", http=_StubHttp(), cache=None,
    ) is None


def test_enrich_packagist_per_version_match():
    from packages.sca.license import _fetch_packagist_license

    class _StubHttp:
        def get_json(self, url):
            assert "symfony/http-foundation" in url
            return {
                "packages": {
                    "symfony/http-foundation": [
                        {"version": "v5.4.0", "license": ["MIT"]},
                        {"version": "v6.0.0", "license": ["BSD-3-Clause"]},
                    ],
                },
            }

    spdx = _fetch_packagist_license(
        "symfony/http-foundation", "v6.0.0",
        http=_StubHttp(), cache=None,
    )
    assert spdx == "BSD-3-Clause"


def test_enrich_packagist_falls_back_to_first_when_version_missing():
    from packages.sca.license import _fetch_packagist_license

    class _StubHttp:
        def get_json(self, url):
            return {
                "packages": {
                    "vendor/pkg": [
                        {"version": "1.0", "license": ["MIT"]},
                    ],
                },
            }

    spdx = _fetch_packagist_license(
        "vendor/pkg", None, http=_StubHttp(), cache=None,
    )
    assert spdx == "MIT"


def test_enrich_packagist_invalid_name_returns_none():
    """Packagist names are ``vendor/package``; no slash -> not a
    valid Packagist coord."""
    from packages.sca.license import _fetch_packagist_license

    class _StubHttp:
        def get_json(self, *a, **kw):
            raise AssertionError("should not be called")

    assert _fetch_packagist_license(
        "no-slash", "1.0", http=_StubHttp(), cache=None,
    ) is None


def test_enrich_dispatches_to_rubygems():
    deps = [_dep(name="rails", version="7.1", ecosystem="RubyGems")]

    class _StubHttp:
        def get_json(self, url):
            return {"licenses": ["MIT"]}

    n = enrich_licenses(deps, http=_StubHttp())
    assert n == 1
    assert deps[0].declared_license == "MIT"


def test_enrich_dispatches_to_nuget():
    deps = [_dep(name="X", version="1.0", ecosystem="NuGet")]

    class _StubHttp:
        def get_json(self, url):
            return {"catalogEntry": {"licenseExpression": "Apache-2.0"}}

    n = enrich_licenses(deps, http=_StubHttp())
    assert n == 1
    assert deps[0].declared_license == "Apache-2.0"


def test_enrich_dispatches_to_packagist():
    deps = [_dep(
        name="symfony/console", version="5.4", ecosystem="Packagist",
    )]

    class _StubHttp:
        def get_json(self, url):
            return {
                "packages": {
                    "symfony/console": [
                        {"version": "5.4", "license": ["MIT"]},
                    ],
                },
            }

    n = enrich_licenses(deps, http=_StubHttp())
    assert n == 1
    assert deps[0].declared_license == "MIT"


def test_enrich_licenses_skips_maven_without_version():
    """Maven enrichment requires a concrete version (POM URL
    needs it). Unpinned deps fall through."""
    deps = [_dep(
        name="org.x:y", version=None, ecosystem="Maven",
    )]

    class _StubHttp:
        def get_bytes(self, *a, **kw):
            raise AssertionError("should not be called")

    n = enrich_licenses(deps, http=_StubHttp())
    assert n == 0
