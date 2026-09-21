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


def test_chart_yaml_aliased_twin_entries_both_bumped(
    tmp_path: Path,
) -> None:
    """Two aliased entries of the SAME chart at the same vulnerable
    version: both must be bumped — a first-match count=1 substitution
    bumped one alias and left its twin vulnerable while the run
    reported applied."""
    chart = tmp_path / "Chart.yaml"
    chart.write_text(
        "apiVersion: v2\n"
        "name: my-chart\n"
        "version: 1.0.0\n"
        "dependencies:\n"
        "  - name: redis\n"
        "    alias: cache\n"
        "    version: 17.0.0\n"
        "  - name: redis\n"
        "    alias: queue\n"
        "    version: 17.0.0\n",
        encoding="utf-8",
    )
    edits = [RewriteEdit(
        locator="redis", old_value="17.0.0", new_value="18.1.0",
    )]
    results = rewrite_chart_yaml(chart, edits)
    assert results[0].applied
    text = chart.read_text()
    assert text.count("version: 18.1.0") == 2
    assert "17.0.0" not in text


def test_chart_yaml_mixed_versions_partial_reported(
    tmp_path: Path,
) -> None:
    chart = tmp_path / "Chart.yaml"
    chart.write_text(
        "apiVersion: v2\n"
        "name: my-chart\n"
        "version: 1.0.0\n"
        "dependencies:\n"
        "  - name: redis\n"
        "    version: 17.0.0\n"
        "  - name: redis\n"
        "    version: 16.5.0\n",
        encoding="utf-8",
    )
    edits = [RewriteEdit(
        locator="redis", old_value="17.0.0", new_value="18.1.0",
    )]
    results = rewrite_chart_yaml(chart, edits)
    assert results[0].applied
    assert results[0].reason.startswith("partial:")
    text = chart.read_text()
    assert "version: 18.1.0" in text
    assert "version: 16.5.0" in text


def test_pathological_chart_yaml_is_fast(tmp_path: Path) -> None:
    """Hostile Chart.yaml: a matching ``- name:`` block padded with
    filler lines and NO same-indent ``version:`` line. The previous
    between-lines group backtracked exponentially on the overall-match
    failure (~x16 per two filler lines; 30 lines hung the harden/bump
    run) — the attacker controls both the dep name (their Chart.yaml
    produced the plan) and the filler. Both-direction bound: fast AND
    still a clean not_found."""
    import time

    chart = tmp_path / "Chart.yaml"
    chart.write_text(
        "dependencies:\n"
        "  - name: postgresql\n"
        + "    key: value\n" * 40
        + "  - name: other\n"
        "    version: 1.0.0\n"
    )
    edits = [RewriteEdit(
        locator="postgresql", old_value="13.4.4", new_value="14.0.0",
    )]
    start = time.monotonic()
    results = rewrite_chart_yaml(chart, edits)
    assert time.monotonic() - start < 5.0
    assert not results[0].applied
    assert results[0].reason == "not_found"


def test_version_first_pathological_is_fast(tmp_path: Path) -> None:
    """Same bound for the version-then-name shape."""
    import time

    chart = tmp_path / "Chart.yaml"
    chart.write_text(
        "dependencies:\n"
        "  - version: 13.4.4\n"
        + "    key: value\n" * 40
        + "  - version: 1.0.0\n"
        "    name: other\n"
    )
    edits = [RewriteEdit(
        locator="postgresql", old_value="13.4.4", new_value="14.0.0",
    )]
    start = time.monotonic()
    results = rewrite_chart_yaml(chart, edits)
    assert time.monotonic() - start < 5.0
    assert not results[0].applied


def test_nested_list_between_anchors_declines(tmp_path: Path) -> None:
    """Boundary is STRICTER than the pre-fix pattern: a nested list
    (tags:/condition: blocks) between name and version hard-stops the
    window at the first `-` line, so the edit declines with not_found
    (visible, refusal direction) instead of the old accidental
    cross-line match. Documented capability regression."""
    chart = tmp_path / "Chart.yaml"
    chart.write_text(
        "dependencies:\n"
        "  - name: postgresql\n"
        "    tags:\n"
        "      - database\n"
        "    version: 13.4.4\n"
    )
    edits = [RewriteEdit(
        locator="postgresql", old_value="13.4.4", new_value="14.0.0",
    )]
    results = rewrite_chart_yaml(chart, edits)
    assert not results[0].applied
    assert results[0].reason == "not_found"


def test_blank_line_run_is_fast(tmp_path: Path) -> None:
    """Hostile Chart.yaml made of a blank-line RUN: under the
    MULTILINE ``^`` anchor a ``\\s+`` indent group matched at every
    line start inside the run and backtracked per character —
    quadratic (a 64KB file of newlines took ~30s end-to-end while the
    filler-line exponential class above stayed green). Horizontal-only
    indent is linear. Both-direction bound: fast AND the dep after
    the run still bumps."""
    import time

    chart = tmp_path / "Chart.yaml"
    chart.write_text(
        "dependencies:\n"
        + "\n" * 65536
        + "  - name: redis\n"
        "    version: 1.0.0\n"
    )
    edits = [RewriteEdit(
        locator="redis", old_value="1.0.0", new_value="2.0.0",
    )]
    start = time.monotonic()
    results = rewrite_chart_yaml(chart, edits)
    assert time.monotonic() - start < 5.0
    assert results[0].applied
    assert "version: 2.0.0" in chart.read_text()


def test_indent_never_captures_across_blank_line(tmp_path: Path) -> None:
    """The indent group is horizontal-only: a blank line between two
    deps must hard-stop the window (the ``\\s+`` spelling silently
    captured across it, contradicting the documented hard-stop
    contract). The version separated from its name by a blank line
    declines not_found instead of splicing."""
    chart = tmp_path / "Chart.yaml"
    chart.write_text(
        "dependencies:\n"
        "  - name: postgresql\n"
        "\n"
        "    version: 13.4.4\n"
    )
    edits = [RewriteEdit(
        locator="postgresql", old_value="13.4.4", new_value="14.0.0",
    )]
    results = rewrite_chart_yaml(chart, edits)
    assert not results[0].applied
    assert results[0].reason == "not_found"
