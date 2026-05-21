"""Tests for ``packages.sca.rewriters.helm_chart``."""

from __future__ import annotations

from pathlib import Path


from packages.sca.rewriters import RewriteEdit, rewrite
from packages.sca.rewriters.helm_chart import rewrite_chart_yaml


def test_chart_yaml_name_first_shape(tmp_path: Path) -> None:
    """Canonical ``- name: <X>`` then ``version: <Y>`` shape."""
    chart = tmp_path / "Chart.yaml"
    chart.write_text(
        "apiVersion: v2\n"
        "name: my-chart\n"
        "version: 1.0.0\n"
        "dependencies:\n"
        "  - name: postgresql\n"
        "    version: 13.4.4\n"
        "    repository: https://charts.bitnami.com/bitnami\n"
    )
    edits = [RewriteEdit(
        locator="postgresql", old_value="13.4.4", new_value="14.0.0",
    )]
    results = rewrite_chart_yaml(chart, edits)
    assert results[0].applied
    assert "version: 14.0.0" in chart.read_text()


def test_chart_yaml_version_first_shape(tmp_path: Path) -> None:
    """``- version: X`` then ``name: Y`` (less common but legal
    YAML order)."""
    chart = tmp_path / "Chart.yaml"
    chart.write_text(
        "dependencies:\n"
        "  - version: 13.4.4\n"
        "    name: postgresql\n"
        "    repository: https://charts.bitnami.com/bitnami\n"
    )
    edits = [RewriteEdit(
        locator="postgresql", old_value="13.4.4", new_value="14.0.0",
    )]
    results = rewrite_chart_yaml(chart, edits)
    assert results[0].applied
    assert "version: 14.0.0" in chart.read_text()


def test_chart_yaml_multiple_dependencies(tmp_path: Path) -> None:
    """Only the matching dep's version gets rewritten — siblings
    stay intact."""
    chart = tmp_path / "Chart.yaml"
    chart.write_text(
        "dependencies:\n"
        "  - name: redis\n"
        "    version: 17.0.0\n"
        "    repository: https://charts.bitnami.com/bitnami\n"
        "  - name: postgresql\n"
        "    version: 13.4.4\n"
        "    repository: https://charts.bitnami.com/bitnami\n"
    )
    edits = [RewriteEdit(
        locator="postgresql", old_value="13.4.4", new_value="14.0.0",
    )]
    rewrite_chart_yaml(chart, edits)
    text = chart.read_text()
    assert "version: 14.0.0" in text         # bumped
    assert "version: 17.0.0" in text         # untouched
    assert "version: 13.4.4" not in text


def test_chart_yaml_value_mismatch(tmp_path: Path) -> None:
    """File has different version than plan expects — refuse."""
    chart = tmp_path / "Chart.yaml"
    chart.write_text(
        "dependencies:\n"
        "  - name: postgresql\n"
        "    version: 12.0.0\n"
    )
    edits = [RewriteEdit(
        locator="postgresql", old_value="13.4.4", new_value="14.0.0",
    )]
    results = rewrite_chart_yaml(chart, edits)
    assert not results[0].applied
    assert "value_mismatch" in results[0].reason


def test_chart_yaml_no_change(tmp_path: Path) -> None:
    """Already at target → no_change, file untouched."""
    chart = tmp_path / "Chart.yaml"
    chart.write_text(
        "dependencies:\n"
        "  - name: postgresql\n"
        "    version: 14.0.0\n"
    )
    orig_mtime = chart.stat().st_mtime
    edits = [RewriteEdit(
        locator="postgresql", old_value="13.4.4", new_value="14.0.0",
    )]
    results = rewrite_chart_yaml(chart, edits)
    assert not results[0].applied
    assert results[0].reason == "no_change"
    assert chart.stat().st_mtime == orig_mtime


def test_chart_yaml_not_found(tmp_path: Path) -> None:
    """Locator absent → not_found."""
    chart = tmp_path / "Chart.yaml"
    chart.write_text(
        "dependencies:\n"
        "  - name: redis\n"
        "    version: 17.0.0\n"
    )
    edits = [RewriteEdit(
        locator="postgresql", old_value="13.4.4", new_value="14.0.0",
    )]
    results = rewrite_chart_yaml(chart, edits)
    assert not results[0].applied
    assert results[0].reason == "not_found"


def test_chart_yaml_quoted_version_handled(tmp_path: Path) -> None:
    """``version: "13.4.4"`` (quoted scalar) rewrites — common in
    Helm charts where versions look numeric to YAML."""
    chart = tmp_path / "Chart.yaml"
    chart.write_text(
        "dependencies:\n"
        "  - name: postgresql\n"
        '    version: "13.4.4"\n'
    )
    edits = [RewriteEdit(
        locator="postgresql", old_value="13.4.4", new_value="14.0.0",
    )]
    results = rewrite_chart_yaml(chart, edits)
    assert results[0].applied
    assert "14.0.0" in chart.read_text()


def test_chart_yaml_with_inline_comment_preserved(tmp_path: Path) -> None:
    """Operator comments on the version line survive the
    rewrite."""
    chart = tmp_path / "Chart.yaml"
    chart.write_text(
        "dependencies:\n"
        "  - name: postgresql\n"
        "    version: 13.4.4   # frozen pre-Q3 upgrade\n"
    )
    edits = [RewriteEdit(
        locator="postgresql", old_value="13.4.4", new_value="14.0.0",
    )]
    results = rewrite_chart_yaml(chart, edits)
    assert results[0].applied
    text = chart.read_text()
    assert "14.0.0" in text
    assert "# frozen pre-Q3 upgrade" in text


def test_registry_dispatch_chart_yaml(tmp_path: Path) -> None:
    """``rewriters.rewrite(path, edits)`` with Chart.yaml dispatches
    here."""
    chart = tmp_path / "Chart.yaml"
    chart.write_text(
        "dependencies:\n"
        "  - name: postgresql\n"
        "    version: 13.4.4\n"
    )
    edits = [RewriteEdit(
        locator="postgresql", old_value="13.4.4", new_value="14.0.0",
    )]
    results = rewrite(chart, edits)
    assert len(results) == 1
    assert results[0].applied


def test_chart_lock_NOT_routed_to_chart_yaml_rewriter(
    tmp_path: Path,
) -> None:
    """Chart.lock gets regenerated by ``helm dep update``; we
    don't rewrite it directly."""
    lock = tmp_path / "Chart.lock"
    lock.write_text(
        "dependencies:\n"
        "  - name: postgresql\n"
        "    version: 13.4.4\n"
    )
    edits = [RewriteEdit(
        locator="postgresql", old_value="13.4.4", new_value="14.0.0",
    )]
    results = rewrite(lock, edits)
    # No rewriter matches Chart.lock → empty result list.
    assert results == []
    # File untouched.
    assert "13.4.4" in lock.read_text()
