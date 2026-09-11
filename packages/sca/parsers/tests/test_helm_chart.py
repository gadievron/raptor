"""Tests for the Helm Chart parsers (Chart.yaml + Chart.lock)."""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.sca.models import PinStyle
from packages.sca.parsers.helm_chart import _classify_version, parse


pytest.importorskip("yaml")


def _write(tmp_path: Path, content: str, name: str = "Chart.yaml") -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# Chart.yaml — manifest mode
# ---------------------------------------------------------------------------


def test_simple_chart_dependencies(tmp_path):
    p = _write(tmp_path, """\
apiVersion: v2
name: myapp
version: 1.0.0
dependencies:
  - name: postgresql
    version: 13.4.2
    repository: https://charts.bitnami.com/bitnami
  - name: redis
    version: 18.0.0
    repository: oci://registry-1.docker.io/bitnamicharts
""")
    deps = parse(p)
    by_name = {d.name: d for d in deps}
    assert "postgresql" in by_name
    assert "redis" in by_name
    assert by_name["postgresql"].version == "13.4.2"
    assert by_name["postgresql"].ecosystem == "Helm"
    assert by_name["postgresql"].purl == "pkg:helm/postgresql@13.4.2"
    assert by_name["postgresql"].source_kind == "helm_chart"
    assert "bitnami" in by_name["postgresql"].source_extra["repository"]


def test_chart_yaml_no_dependencies(tmp_path):
    """A chart that doesn't import anything — empty deps list."""
    p = _write(tmp_path, """\
apiVersion: v2
name: standalone
version: 1.0.0
""")
    assert parse(p) == []


def test_pin_style_classification(tmp_path):
    p = _write(tmp_path, """\
dependencies:
  - name: exact
    version: 1.2.3
    repository: https://example.com
  - name: caret
    version: ^1.2.3
    repository: https://example.com
  - name: tilde
    version: ~1.2.3
    repository: https://example.com
  - name: range
    version: '>=1.0 <2.0'
    repository: https://example.com
  - name: wildcard
    version: '*'
    repository: https://example.com
""")
    by_name = {d.name: d for d in parse(p)}
    assert by_name["exact"].pin_style == PinStyle.EXACT
    assert by_name["caret"].pin_style == PinStyle.CARET
    assert by_name["tilde"].pin_style == PinStyle.TILDE
    assert by_name["range"].pin_style == PinStyle.RANGE
    assert by_name["wildcard"].pin_style == PinStyle.WILDCARD


def test_classify_version_helper():
    assert _classify_version("1.2.3") == PinStyle.EXACT
    assert _classify_version("^1.2.3") == PinStyle.CARET
    assert _classify_version("~1.2") == PinStyle.TILDE
    assert _classify_version(">=1.0") == PinStyle.RANGE
    assert _classify_version("*") == PinStyle.WILDCARD


def test_classify_version_wildcard_segment_not_substring():
    assert _classify_version("1.x") == PinStyle.WILDCARD
    assert _classify_version("1.x.x") == PinStyle.WILDCARD
    assert _classify_version("1.*") == PinStyle.WILDCARD
    assert _classify_version("1.2.3-extra") == PinStyle.EXACT
    assert _classify_version("1.0.0-next") == PinStyle.EXACT
    assert _classify_version("10.0.0-proxy") == PinStyle.EXACT


def test_chart_with_missing_version_skipped(tmp_path):
    """Entry without a ``version:`` field — not a meaningful pin."""
    p = _write(tmp_path, """\
dependencies:
  - name: ok
    version: 1.0.0
    repository: https://example.com
  - name: bad
    repository: https://example.com
""")
    deps = parse(p)
    assert {d.name for d in deps} == {"ok"}


def test_malformed_yaml(tmp_path):
    p = _write(tmp_path, ":\n  garbage")
    assert parse(p) == []


# ---------------------------------------------------------------------------
# Chart.lock
# ---------------------------------------------------------------------------


def test_chart_lock_marks_lockfile_true(tmp_path):
    p = _write(tmp_path, """\
dependencies:
  - name: postgresql
    version: 13.4.2
    repository: https://charts.bitnami.com/bitnami
""", name="Chart.lock")
    [d] = parse(p)
    assert d.is_lockfile is True
    assert d.direct is False
    assert d.parser_confidence.level == "high"


# ---------------------------------------------------------------------------
# End-to-end via discovery + parser dispatch
# ---------------------------------------------------------------------------


def test_discovery_finds_chart_yaml(tmp_path):
    from packages.sca.discovery import find_manifests
    _write(tmp_path, """\
apiVersion: v2
name: x
version: 1.0
dependencies:
  - name: postgresql
    version: 13.4.2
    repository: https://example.com
""")
    manifests = find_manifests(tmp_path)
    chart = [m for m in manifests if m.path.name == "Chart.yaml"]
    assert len(chart) == 1
    assert chart[0].ecosystem == "Helm"


# ---------------------------------------------------------------------------
# chart_repository_hosts — proxy-allowlist helper
# ---------------------------------------------------------------------------


def _write_chart(dir_path: Path, content: str) -> None:
    dir_path.mkdir(parents=True, exist_ok=True)
    (dir_path / "Chart.yaml").write_text(content)


def test_chart_repository_hosts_extracts_https_only(tmp_path: Path):
    """HTTPS Helm repos contribute their hostname; OCI repos are
    skipped (they route through the OCI client's existing host
    discovery in ``image_source_registry_hosts``)."""
    from packages.sca.parsers.helm_chart import chart_repository_hosts

    _write_chart(tmp_path / "a", """\
apiVersion: v2
name: a
version: 1.0
dependencies:
  - name: postgresql
    version: 13.4.2
    repository: https://charts.bitnami.com/bitnami
  - name: redis
    version: 18.0.0
    repository: oci://registry-1.docker.io/bitnamicharts
""")
    _write_chart(tmp_path / "b", """\
apiVersion: v2
name: b
version: 1.0
dependencies:
  - name: ingress-nginx
    version: 4.9.0
    repository: https://kubernetes.github.io/ingress-nginx
""")
    hosts = chart_repository_hosts(tmp_path)
    assert hosts == [
        "charts.bitnami.com",
        "kubernetes.github.io",
    ]


def test_chart_repository_hosts_handles_malformed(tmp_path: Path):
    """A malformed Chart.yaml is skipped silently — other charts
    in the tree still contribute their hosts."""
    from packages.sca.parsers.helm_chart import chart_repository_hosts

    _write_chart(tmp_path / "bad",
                  "not: [valid: yaml:\n  - unbalanced")
    _write_chart(tmp_path / "good", """\
apiVersion: v2
name: g
version: 1.0
dependencies:
  - name: x
    version: 1.0.0
    repository: https://example.com
""")
    assert chart_repository_hosts(tmp_path) == ["example.com"]


def test_chart_repository_hosts_empty_tree(tmp_path: Path):
    """No Chart.yaml under target → empty list (not a crash)."""
    from packages.sca.parsers.helm_chart import chart_repository_hosts

    assert chart_repository_hosts(tmp_path) == []


def test_chart_repository_hosts_no_dependencies_field(tmp_path: Path):
    """A Chart.yaml without a ``dependencies:`` array is the
    library / single-chart shape — no repos to add."""
    from packages.sca.parsers.helm_chart import chart_repository_hosts

    _write(tmp_path, """\
apiVersion: v2
name: solo
version: 1.0
""")
    assert chart_repository_hosts(tmp_path) == []


def test_broken_chart_in_fixture_tree_logs_debug_not_warning(
    tmp_path, caplog,
):
    """A deliberately-broken chart in a test/fixture tree (helm's own
    testdata/testcharts is the canonical case) is a test assertion —
    it must not warn at operator level. The same breakage in a
    production path stays a WARNING (real deps silently missing)."""
    import logging

    from packages.sca.parsers._safe_read import scan_root_context
    from packages.sca.parsers.helm_chart import parse

    bad_yaml = "dependencies:\n  - name: a\n   oops: [\n"
    fixture = tmp_path / "cmd" / "helm" / "testdata" / "testcharts" \
        / "chart-bad-requirements" / "Chart.yaml"
    fixture.parent.mkdir(parents=True)
    fixture.write_text(bad_yaml)
    prod = tmp_path / "deploy" / "Chart.yaml"
    prod.parent.mkdir(parents=True)
    prod.write_text(bad_yaml)

    with scan_root_context(tmp_path):
        with caplog.at_level(logging.DEBUG, logger="packages.sca.parsers.helm_chart"):
            assert parse(fixture) == []
            assert parse(prod) == []

    records = [r for r in caplog.records if "YAML parse failed" in r.message]
    fixture_recs = [r for r in records if "testcharts" in str(r.args[0])]
    prod_recs = [r for r in records if "deploy" in str(r.args[0])]
    assert fixture_recs and all(r.levelname == "DEBUG" for r in fixture_recs)
    assert prod_recs and all(r.levelname == "WARNING" for r in prod_recs)


# ---------------------------------------------------------------------------
# Repository-host vetting for the egress allowlist
# ---------------------------------------------------------------------------

def _write_repo_chart(tmp_path: Path, repository: str) -> None:
    (tmp_path / "Chart.yaml").write_text(
        "apiVersion: v2\n"
        "name: x\n"
        "version: 1.0.0\n"
        "dependencies:\n"
        "  - name: dep\n"
        "    version: 1.0.0\n"
        f'    repository: "{repository}"\n',
        encoding="utf-8",
    )


def test_repository_hosts_reject_userinfo(tmp_path: Path) -> None:
    # Chart.yaml is target-controlled and this list feeds the egress
    # proxy allowlist — credential-bearing URLs must not widen egress.
    from packages.sca.parsers.helm_chart import chart_repository_hosts
    _write_repo_chart(tmp_path, "https://user:pw@repo.example.com/charts")
    assert chart_repository_hosts(tmp_path) == []


def test_repository_hosts_reject_malformed_host(tmp_path: Path) -> None:
    from packages.sca.parsers.helm_chart import chart_repository_hosts
    _write_repo_chart(tmp_path, "https://bad host/charts")
    assert chart_repository_hosts(tmp_path) == []


def test_repository_hosts_accept_clean_dns_names(tmp_path: Path) -> None:
    # Other direction: well-formed hosts still flow through.
    from packages.sca.parsers.helm_chart import chart_repository_hosts
    _write_repo_chart(tmp_path, "https://charts.bitnami.com/bitnami")
    assert chart_repository_hosts(tmp_path) == ["charts.bitnami.com"]
