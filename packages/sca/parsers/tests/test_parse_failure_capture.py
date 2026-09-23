"""Tests for the parser-warning capture mechanism.

Parsers swallow malformed-input errors and return ``[]`` so a
single bad manifest doesn't abort the pipeline. ``capture_parse_failures``
attaches a logging handler that lifts those warnings into structured
``ParseFailure`` records the runner can render in ``report.md`` —
operators otherwise see "0 deps analysed" with no indication the
manifest was unparseable.

Tier-4 dev E2E surfaced this gap: a malformed pom.xml produced an
identical report to a project with zero dependencies.
"""

from __future__ import annotations

import logging
from pathlib import Path

from packages.sca.models import Manifest
from packages.sca.parsers import (
    ParseFailure,
    capture_parse_failures,
    parse_manifest,
)


def _manifest(path: Path, ecosystem: str = "Maven") -> Manifest:
    return Manifest(path=path, ecosystem=ecosystem, is_lockfile=False)


def test_capture_captures_pom_parse_failure(tmp_path: Path) -> None:
    """A malformed pom.xml emits a WARNING via the canonical
    ``sca.parsers.pom: XML parse failed for <path>: <reason>``
    format; the capture handler should lift it into a structured
    ``ParseFailure`` record."""
    pom = tmp_path / "pom.xml"
    pom.write_text("""\
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies><dependency>
    <groupId>broken
    <!-- unbalanced tags below -->
  </dependency></dependencies>
""")

    with capture_parse_failures() as failures:
        parse_manifest(_manifest(pom))

    assert len(failures) == 1
    f = failures[0]
    assert isinstance(f, ParseFailure)
    assert f.path == pom
    assert "mismatched" in f.reason.lower() or "parse" in f.reason.lower()


def test_capture_captures_pipfile_lock_failure(tmp_path: Path) -> None:
    """``packages.sca.parsers.pipfile_lock`` emits the same
    canonical format; capture should work across parsers."""
    pl = tmp_path / "Pipfile.lock"
    pl.write_text('{ "_meta": broken json }')

    with capture_parse_failures() as failures:
        parse_manifest(_manifest(pl, ecosystem="PyPI"))

    assert len(failures) == 1
    assert failures[0].path == pl


def test_capture_ignores_unrelated_warnings(tmp_path: Path) -> None:
    """Unrelated WARNING-level log lines (anything that doesn't
    match the canonical ``sca.parsers.X: <kind> parse failed for
    <path>: <reason>`` shape) should not produce ``ParseFailure``
    records. Otherwise a noisy module would poison the report."""
    log = logging.getLogger("packages.sca.parsers.test_unrelated")
    with capture_parse_failures() as failures:
        log.warning("sca.parsers.test_unrelated: something unrelated")
        log.warning("nothing to do with parsers at all")

    assert failures == []


def test_capture_detaches_handler_on_exit(tmp_path: Path) -> None:
    """The handler must come off the parsers logger when the
    context exits — otherwise a long-lived process (pytest run,
    embedded SCA) would leak a handler per scan."""
    parsers_logger = logging.getLogger("packages.sca.parsers")
    before = len(parsers_logger.handlers)
    with capture_parse_failures():
        pass
    after = len(parsers_logger.handlers)
    assert before == after


def test_capture_isolates_between_runs(tmp_path: Path) -> None:
    """Two independent ``capture_parse_failures`` contexts must
    not see each other's failures — the runner reuses the same
    process for multiple SCA runs (e.g. when invoked from a
    long-running orchestrator) and run N+1's report would be
    polluted otherwise."""
    pom = tmp_path / "pom.xml"
    pom.write_text("<unclosed")

    with capture_parse_failures() as failures_a:
        parse_manifest(_manifest(pom))

    with capture_parse_failures() as failures_b:
        pass  # no parsing happens here

    assert len(failures_a) == 1
    assert failures_b == []


def test_capture_captures_oversize_manifest_refusal(tmp_path: Path) -> None:
    """``read_bounded``'s oversize refusal must reach the structured
    ``parse_failures`` like a malformed manifest does — otherwise an
    over-cap manifest is skipped with only a log-stream warning and
    the run report shows no trace of the lost coverage. Sparse
    truncate: the stat gate fires before any read, so no 50 MB of
    data is materialised."""
    import os

    from packages.sca.parsers._safe_read import _MAX_PARSER_BYTES

    lock = tmp_path / "package-lock.json"
    lock.write_text('{"packages": {}}', encoding="utf-8")
    os.truncate(lock, _MAX_PARSER_BYTES + 1)

    with capture_parse_failures() as failures:
        parse_manifest(_manifest(lock, ecosystem="npm"))

    assert len(failures) == 1
    f = failures[0]
    assert isinstance(f, ParseFailure)
    assert f.path == lock
    assert "size=" in f.reason


# ---------------------------------------------------------------------------
# Every ecosystem's parse failure must reach the collector — cargo,
# composer, and the NuGet XML/JSON parsers previously logged shapes
# that missed the canonical format, so whole ecosystems' failures
# never surfaced in report.md.
# ---------------------------------------------------------------------------

def test_capture_captures_cargo_manifest_failure(tmp_path: Path) -> None:
    m = tmp_path / "Cargo.toml"
    m.write_text("[package\nname = broken toml", encoding="utf-8")
    with capture_parse_failures() as failures:
        parse_manifest(_manifest(m, ecosystem="Cargo"))
    assert len(failures) == 1
    assert failures[0].path == m


def test_capture_captures_cargo_lockfile_failure(tmp_path: Path) -> None:
    lock = tmp_path / "Cargo.lock"
    lock.write_text("[[package\nbroken", encoding="utf-8")
    with capture_parse_failures() as failures:
        parse_manifest(_manifest(lock, ecosystem="Cargo"))
    assert len(failures) == 1
    assert failures[0].path == lock


def test_capture_captures_composer_manifest_failure(tmp_path: Path) -> None:
    cj = tmp_path / "composer.json"
    cj.write_text('{ "require": broken }', encoding="utf-8")
    with capture_parse_failures() as failures:
        parse_manifest(_manifest(cj, ecosystem="Composer"))
    assert len(failures) == 1
    assert failures[0].path == cj


def test_capture_captures_composer_lockfile_failure(tmp_path: Path) -> None:
    cl = tmp_path / "composer.lock"
    cl.write_text('{ "packages": [ broken ] }', encoding="utf-8")
    with capture_parse_failures() as failures:
        parse_manifest(_manifest(cl, ecosystem="Composer"))
    assert len(failures) == 1
    assert failures[0].path == cl


def test_capture_captures_nuget_csproj_xml_failure(tmp_path: Path) -> None:
    import pytest
    from packages.sca.parsers import nuget
    if not nuget._AVAILABLE:
        pytest.skip("defusedxml not installed")
    csproj = tmp_path / "app.csproj"
    csproj.write_text("<Project><ItemGroup></Project>", encoding="utf-8")
    with capture_parse_failures() as failures:
        parse_manifest(_manifest(csproj, ecosystem="NuGet"))
    assert len(failures) == 1
    assert failures[0].path == csproj


def test_capture_captures_nuget_lockfile_json_failure(tmp_path: Path) -> None:
    lock = tmp_path / "packages.lock.json"
    lock.write_text('{ "dependencies": broken }', encoding="utf-8")
    with capture_parse_failures() as failures:
        parse_manifest(_manifest(lock, ecosystem="NuGet"))
    assert len(failures) == 1
    assert failures[0].path == lock


def test_capture_captures_directory_packages_props_failure(
    tmp_path: Path,
) -> None:
    import pytest
    from packages.sca.parsers import directory_packages_props as dpp
    if not dpp._AVAILABLE:
        pytest.skip("defusedxml not installed")
    dpp.reset_cache()
    props = tmp_path / "Directory.Packages.props"
    props.write_text("<Project><ItemGroup></Project>", encoding="utf-8")
    with capture_parse_failures() as failures:
        dpp.parse_directory_packages_props(props)
    assert len(failures) == 1
    # The dpp warning escapes the path for log hygiene; the captured
    # record still points at the file.
    assert str(props.resolve()) in str(failures[0].path)


# ---------------------------------------------------------------------------
# Whole-file failure / refusal shapes that once bypassed the collector
# ---------------------------------------------------------------------------
# Each of these produced only a free-form log line — the run report's
# structured parse_failures stayed empty, so a repo full of such files
# read as a clean "0 deps analysed".

def test_capture_captures_package_json_non_object_root(
    tmp_path: Path,
) -> None:
    pj = tmp_path / "package.json"
    pj.write_text('["not", "an", "object"]', encoding="utf-8")
    with capture_parse_failures() as failures:
        parse_manifest(_manifest(pj, ecosystem="npm"))
    assert len(failures) == 1
    assert failures[0].path == pj
    assert "not an object" in failures[0].reason


def test_capture_captures_devcontainer_jsonc_failure(
    tmp_path: Path,
) -> None:
    from packages.sca.parsers.inline_installs import parse_devcontainer_json
    dc = tmp_path / "devcontainer.json"
    dc.write_text('{"postCreateCommand": [[[', encoding="utf-8")
    with capture_parse_failures() as failures:
        parse_devcontainer_json(dc)
    assert len(failures) == 1
    assert failures[0].path == dc


def test_capture_captures_pnpm_catalog_yaml_failure(
    tmp_path: Path,
) -> None:
    from packages.sca.parsers._pnpm_catalog import get_catalogs
    ws = tmp_path / "pnpm-workspace.yaml"
    ws.write_text("catalog:\n  foo: [unclosed\n", encoding="utf-8")
    with capture_parse_failures() as failures:
        get_catalogs(tmp_path)
    assert len(failures) == 1
    assert failures[0].path == ws


def test_capture_captures_pom_defusedxml_rejection(tmp_path: Path) -> None:
    """A hostile pom rejected by defusedxml (XXE / entity expansion)
    is a refusal the operator must see in parse_failures — the code's
    own comment promises the file's rejection is surfaced."""
    import pytest
    from packages.sca.parsers import pom
    if not pom._AVAILABLE:
        pytest.skip("defusedxml not installed")
    hostile = tmp_path / "pom.xml"
    hostile.write_text(
        '<?xml version="1.0"?>\n'
        "<!DOCTYPE project [<!ENTITY x \"boom\">]>\n"
        "<project><dependencies/></project>\n",
        encoding="utf-8",
    )
    with capture_parse_failures() as failures:
        parse_manifest(_manifest(hostile))
    assert len(failures) == 1
    assert failures[0].path == hostile
    assert "defused" in failures[0].reason.lower()


def test_capture_captures_cannot_stat_refusal(tmp_path: Path) -> None:
    from packages.sca.parsers import _safe_read
    missing = tmp_path / "vanished" / "pom.xml"
    with capture_parse_failures() as failures:
        assert _safe_read.read_bounded(missing) is None
    assert len(failures) == 1
    assert failures[0].path == missing
    assert "cannot stat" in failures[0].reason


def test_capture_captures_symlink_escape_refusal(tmp_path: Path) -> None:
    from packages.sca.parsers import _safe_read
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "real.xml").write_text("<project/>", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    link = root / "pom.xml"
    link.symlink_to(outside / "real.xml")
    token = _safe_read._SCAN_ROOT.set(root.resolve())
    try:
        with capture_parse_failures() as failures:
            assert _safe_read.read_bounded(
                link, follow_symlinks=False) is None
    finally:
        _safe_read._SCAN_ROOT.reset(token)
    assert len(failures) == 1
    assert failures[0].path == link
    assert "outside the scan root" in failures[0].reason


def test_capture_captures_grew_past_max_refusal(tmp_path: Path) -> None:
    """The stat-vs-read race arm: size passes the cap but the read
    returns more bytes. Simulated with a stub path object (the race
    itself is not reproducible deterministically)."""
    import os
    import stat as _stat_mod
    from packages.sca.parsers import _safe_read

    real = tmp_path / "grown.xml"
    real.write_bytes(b"x" * 64)

    class _GrowingPath:
        def __str__(self) -> str:
            return str(real)

        def stat(self):
            st = os.stat(real)
            # Lie: report a size under the cap.
            return os.stat_result(
                (st.st_mode, st.st_ino, st.st_dev, st.st_nlink,
                 st.st_uid, st.st_gid, 8, st.st_atime, st.st_mtime,
                 st.st_ctime))

        def open(self, mode="rb"):
            return open(real, mode)

    stub = _GrowingPath()
    assert _stat_mod.S_ISREG(stub.stat().st_mode)
    with capture_parse_failures() as failures:
        assert _safe_read.read_bounded(
            stub, max_bytes=8, follow_symlinks=True) is None
    assert len(failures) == 1
    assert "grew past max" in failures[0].reason


def test_capture_captures_cannot_read_refusal(tmp_path: Path) -> None:
    import os
    import pytest
    if os.geteuid() == 0:
        pytest.skip("chmod 0o000 does not block root")
    from packages.sca.parsers import _safe_read
    blocked = tmp_path / "blocked.xml"
    blocked.write_text("<project/>", encoding="utf-8")
    blocked.chmod(0o000)
    try:
        with capture_parse_failures() as failures:
            assert _safe_read.read_bounded(blocked) is None
    finally:
        blocked.chmod(0o644)
    assert len(failures) == 1
    assert failures[0].path == blocked
    assert "cannot" in failures[0].reason


def test_nested_capture_restores_outer_collector(tmp_path: Path) -> None:
    """A nested capture must restore the OUTER collector on exit, not
    clear the slot — clearing silently dropped every failure logged
    after the inner block."""
    bad = tmp_path / "pom.xml"
    bad.write_text("<project><unclosed>", encoding="utf-8")
    from packages.sca.parsers import pom

    with capture_parse_failures() as outer:
        with capture_parse_failures() as inner:
            pom.parse(bad)
        # After the inner block, failures must still route to OUTER.
        pom.parse(bad)
    assert len(inner) == 1
    assert len(outer) >= 1
