"""Tests for the GHA freshness (major-version-behind) detector."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from packages.sca.models import Confidence, Dependency, PinStyle
from packages.sca.supply_chain.gha_freshness import (
    _extract_major,
    scan_dependencies,
)


def _action(name: str, version: str) -> Dependency:
    return Dependency(
        ecosystem="GitHub Actions",
        name=name,
        version=version,
        declared_in=Path(".github/workflows/ci.yml"),
        scope="build",
        is_lockfile=False,
        pin_style=PinStyle.CARET,
        direct=True,
        purl=f"pkg:githubactions/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
        source_kind="gha_uses",
    )


def _stub_client(latest_tag_by_action):
    client = MagicMock()
    client.get_latest_tag.side_effect = (
        lambda name: latest_tag_by_action.get(name)
    )
    return client


# ---------------------------------------------------------------------------
# _extract_major
# ---------------------------------------------------------------------------


def test_extract_major_simple():
    assert _extract_major("v1") == 1
    assert _extract_major("v2.3.4") == 2
    assert _extract_major("v10.0") == 10


def test_extract_major_no_v_prefix():
    assert _extract_major("3") == 3
    assert _extract_major("3.5.7") == 3


def test_extract_major_release_prefix():
    assert _extract_major("release-1.0") == 1


def test_extract_major_calver_returns_none():
    """Calendar-versioned tags — out of scope."""
    assert _extract_major("2024.05.01") is None


def test_extract_major_sha_returns_none():
    assert _extract_major("a" * 40) is None


def test_extract_major_branch_returns_none():
    assert _extract_major("main") is None
    assert _extract_major("master") is None


def test_extract_major_empty_returns_none():
    assert _extract_major("") is None


# ---------------------------------------------------------------------------
# scan_dependencies — gap classification
# ---------------------------------------------------------------------------


def test_one_major_behind_emits_info():
    deps = [_action("actions/checkout", "v3")]
    client = _stub_client({"actions/checkout": "v4"})
    [f] = scan_dependencies(deps, client=client)
    assert f.severity == "info"
    assert f.evidence["majors_behind"] == 1
    assert f.evidence["pinned_major"] == 3
    assert f.evidence["latest_major"] == 4


def test_two_majors_behind_emits_low():
    deps = [_action("actions/checkout", "v2")]
    client = _stub_client({"actions/checkout": "v4"})
    [f] = scan_dependencies(deps, client=client)
    assert f.severity == "low"


def test_three_majors_behind_emits_medium():
    deps = [_action("actions/checkout", "v1")]
    client = _stub_client({"actions/checkout": "v4"})
    [f] = scan_dependencies(deps, client=client)
    assert f.severity == "medium"


def test_four_or_more_majors_behind_emits_high():
    deps = [_action("actions/checkout", "v1")]
    client = _stub_client({"actions/checkout": "v6"})
    [f] = scan_dependencies(deps, client=client)
    assert f.severity == "high"

    deps = [_action("actions/checkout", "v1")]
    client = _stub_client({"actions/checkout": "v10"})
    [f] = scan_dependencies(deps, client=client)
    assert f.severity == "high"     # clamped


def test_current_major_emits_nothing():
    deps = [_action("actions/checkout", "v6")]
    client = _stub_client({"actions/checkout": "v6"})
    assert scan_dependencies(deps, client=client) == []


def test_pinned_ahead_of_latest_emits_nothing():
    """Should not happen in practice (operator pinning to a newer
    release than ``releases/latest`` reports), but defensive: don't
    misclassify."""
    deps = [_action("actions/checkout", "v7")]
    client = _stub_client({"actions/checkout": "v6"})
    assert scan_dependencies(deps, client=client) == []


def test_minor_version_match_in_pinned_doesnt_affect_classification():
    deps = [_action("actions/checkout", "v3.6.0")]
    client = _stub_client({"actions/checkout": "v6.0.0"})
    [f] = scan_dependencies(deps, client=client)
    assert f.evidence["majors_behind"] == 3
    assert f.evidence["pinned_major"] == 3


# ---------------------------------------------------------------------------
# Skip conditions
# ---------------------------------------------------------------------------


def test_sha_pinned_dep_skipped():
    """Can't extract a major from a SHA — skip silently."""
    sha = "a" * 40
    deps = [_action("actions/checkout", sha)]
    client = _stub_client({"actions/checkout": "v6"})
    assert scan_dependencies(deps, client=client) == []


def test_branch_pinned_dep_skipped():
    deps = [_action("actions/checkout", "main")]
    client = _stub_client({"actions/checkout": "v6"})
    assert scan_dependencies(deps, client=client) == []


def test_calver_pinned_dep_skipped():
    deps = [_action("custom-org/calver-action", "2024.05.01")]
    client = _stub_client(
        {"custom-org/calver-action": "2024.06.01"},
    )
    assert scan_dependencies(deps, client=client) == []


def test_non_gha_dep_skipped():
    """A PyPI dep with a v-prefixed version isn't matched."""
    pypi_dep = Dependency(
        ecosystem="PyPI",
        name="pkg",
        version="v1",
        declared_in=Path("requirements.txt"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl="pkg:pypi/pkg@v1",
        parser_confidence=Confidence("high", reason="t"),
    )
    client = _stub_client({"pkg": "v6"})
    assert scan_dependencies([pypi_dep], client=client) == []


def test_dep_without_version_skipped():
    deps = [_action("actions/checkout", "")]
    client = _stub_client({"actions/checkout": "v6"})
    assert scan_dependencies(deps, client=client) == []


def test_client_returns_none_skip():
    """No latest-version data → no finding emitted."""
    deps = [_action("actions/checkout", "v3")]
    client = _stub_client({})            # empty — get_latest_tag → None
    assert scan_dependencies(deps, client=client) == []


def test_no_client_no_findings():
    deps = [_action("actions/checkout", "v3")]
    assert scan_dependencies(deps, client=None) == []


# ---------------------------------------------------------------------------
# Multi-dep + sub-action
# ---------------------------------------------------------------------------


def test_multiple_deps_independent_evaluation():
    deps = [
        _action("actions/checkout", "v3"),
        _action("actions/setup-python", "v6"),       # current
        _action("actions/upload-artifact", "v3"),    # 1 behind
    ]
    client = _stub_client({
        "actions/checkout": "v6",                    # 3 behind
        "actions/setup-python": "v6",                # current
        "actions/upload-artifact": "v4",             # 1 behind
    })
    findings = scan_dependencies(deps, client=client)
    by_action = {f.evidence["action"]: f for f in findings}
    assert "actions/checkout" in by_action
    assert "actions/upload-artifact" in by_action
    assert "actions/setup-python" not in by_action
    assert by_action["actions/checkout"].severity == "medium"   # 3 behind
    assert by_action["actions/upload-artifact"].severity == "info"


def test_sub_action_passes_full_name_to_client():
    """Client is responsible for parent-repo resolution; the
    detector passes the full sub-action name."""
    deps = [_action("actions/cache/restore", "v2")]
    client = MagicMock()
    client.get_latest_tag.return_value = "v4"
    scan_dependencies(deps, client=client)
    client.get_latest_tag.assert_called_once_with("actions/cache/restore")


# ---------------------------------------------------------------------------
# Detail formatting
# ---------------------------------------------------------------------------


def test_finding_detail_includes_pinned_and_latest():
    deps = [_action("actions/checkout", "v3")]
    client = _stub_client({"actions/checkout": "v6.0.1"})
    [f] = scan_dependencies(deps, client=client)
    assert "actions/checkout@v3" in f.detail
    assert "v6.0.1" in f.detail
    assert "3 major" in f.detail


def test_finding_detail_singular_for_one_major():
    deps = [_action("actions/checkout", "v3")]
    client = _stub_client({"actions/checkout": "v4"})
    [f] = scan_dependencies(deps, client=client)
    assert "1 major version " in f.detail
    assert "1 major versions" not in f.detail
