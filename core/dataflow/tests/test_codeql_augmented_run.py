"""Tests for ``core.dataflow.codeql_augmented_run``.

Subprocess invocation is mocked — these tests verify the CLI
construction and error propagation; they do NOT run real CodeQL.
PR2c's corpus measurement is the real-CodeQL integration test.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import List

import pytest

from core.dataflow.codeql_augmented_run import (
    AnalysisResult,
    CodeQLRunError,
    DEFAULT_CODEQL_BIN,
    DEFAULT_TIMEOUT_SECONDS,
    analyze,
    run_baseline_and_augmented,
)


# ---------------------------------------------------------------------
# Fake runner
# ---------------------------------------------------------------------


def _make_runner(returncode: int = 0, stderr: str = "", raise_timeout: bool = False):
    """Build a fake subprocess runner. Records each call's args."""
    calls: List[List[str]] = []

    def _runner(args, *, capture_output=True, text=True, timeout=None, check=False, env=None):
        calls.append(list(args))
        if raise_timeout:
            raise subprocess.TimeoutExpired(cmd=args, timeout=timeout)
        return SimpleNamespace(
            returncode=returncode,
            stdout="",
            stderr=stderr,
        )

    return _runner, calls


# ---------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------


def test_analyze_builds_expected_cli(tmp_path: Path):
    runner, calls = _make_runner()
    db = tmp_path / "db"
    out = tmp_path / "result.sarif"
    analyze(
        db,
        ["codeql/python-queries:Security/CWE/CWE-078"],
        out,
        runner=runner,
    )
    assert len(calls) == 1
    cmd = calls[0]
    assert cmd[0] == DEFAULT_CODEQL_BIN
    assert cmd[1:4] == ["database", "analyze", str(db)]
    assert "codeql/python-queries:Security/CWE/CWE-078" in cmd
    assert "--format=sarif-latest" in cmd
    assert f"--output={out}" in cmd


def test_analyze_omits_additional_packs_when_no_extension(tmp_path: Path):
    runner, calls = _make_runner()
    analyze(
        tmp_path / "db",
        ["q.ql"],
        tmp_path / "out.sarif",
        runner=runner,
    )
    assert "--additional-packs" not in calls[0]


def _mk_pack(tmp_path: Path, name: str = "raptor/test-models") -> Path:
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "codeql-pack.yml").write_text(
        f"name: {name}\nversion: 0.0.1\nlibrary: true\n",
        encoding="utf-8",
    )
    return pack


def test_analyze_adds_additional_packs_when_extension_supplied(tmp_path: Path):
    runner, calls = _make_runner()
    pack = _mk_pack(tmp_path)
    analyze(
        tmp_path / "db",
        ["q.ql"],
        tmp_path / "out.sarif",
        extension_pack=pack,
        runner=runner,
    )
    cmd = calls[0]
    assert "--additional-packs" in cmd
    assert str(pack) in cmd
    # `--additional-packs` immediately followed by the pack path
    idx = cmd.index("--additional-packs")
    assert cmd[idx + 1] == str(pack)


def test_analyze_applies_models_and_forces_rerun(tmp_path: Path):
    """--additional-packs only resolves; the extension must ALSO be
    named via --model-packs and cached results must be discarded —
    without both, the augmented run is byte-identical to the baseline
    (the vacuous zero-delta bug, verified live)."""
    runner, calls = _make_runner()
    pack = _mk_pack(tmp_path, name="raptor/learned-models-java")
    analyze(
        tmp_path / "db",
        ["q.ql"],
        tmp_path / "out.sarif",
        extension_pack=pack,
        runner=runner,
    )
    cmd = calls[0]
    idx = cmd.index("--model-packs")
    assert cmd[idx + 1] == "raptor/learned-models-java"
    assert "--rerun" in cmd


def test_analyze_refuses_pack_without_name(tmp_path: Path):
    runner, _calls = _make_runner()
    pack = _mk_pack(tmp_path)
    (pack / "codeql-pack.yml").write_text("version: 0.0.1\n",
                                          encoding="utf-8")
    with pytest.raises(CodeQLRunError, match="no parseable name"):
        analyze(
            tmp_path / "db",
            ["q.ql"],
            tmp_path / "out.sarif",
            extension_pack=pack,
            runner=runner,
        )


def test_analyze_creates_output_parent_dir(tmp_path: Path):
    runner, _ = _make_runner()
    deep_out = tmp_path / "a" / "b" / "c" / "result.sarif"
    assert not deep_out.parent.exists()
    analyze(tmp_path / "db", ["q.ql"], deep_out, runner=runner)
    assert deep_out.parent.is_dir()


def test_analyze_returns_analysis_result(tmp_path: Path):
    runner, _ = _make_runner()
    out = tmp_path / "out.sarif"
    pack = _mk_pack(tmp_path)
    result = analyze(
        tmp_path / "db",
        ["a.ql", "b.ql"],
        out,
        extension_pack=pack,
        runner=runner,
    )
    assert isinstance(result, AnalysisResult)
    assert result.sarif_path == out
    assert result.queries == ("a.ql", "b.ql")
    assert result.extension_pack == pack
    assert result.elapsed_seconds >= 0


def test_analyze_forwards_extra_args(tmp_path: Path):
    """Operator escape hatch: --threads=8 etc. should reach the CLI."""
    runner, calls = _make_runner()
    analyze(
        tmp_path / "db",
        ["q.ql"],
        tmp_path / "out.sarif",
        runner=runner,
        extra_args=("--threads=8", "--ram=8192"),
    )
    cmd = calls[0]
    assert "--threads=8" in cmd
    assert "--ram=8192" in cmd


def test_analyze_uses_custom_codeql_binary_path(tmp_path: Path):
    runner, calls = _make_runner()
    analyze(
        tmp_path / "db",
        ["q.ql"],
        tmp_path / "out.sarif",
        codeql_bin="/opt/codeql/bin/codeql",
        runner=runner,
    )
    assert calls[0][0] == "/opt/codeql/bin/codeql"


def test_analyze_passes_timeout_to_runner(tmp_path: Path):
    captured = {}

    def _runner(args, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    analyze(
        tmp_path / "db",
        ["q.ql"],
        tmp_path / "out.sarif",
        timeout_seconds=42,
        runner=_runner,
    )
    assert captured["timeout"] == 42


def test_default_timeout_is_reasonable_for_a_real_codeql_run():
    """Sanity guard against shipping a 1-second timeout. CodeQL
    analyses take minutes on real targets."""
    assert DEFAULT_TIMEOUT_SECONDS >= 60


# ---------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------


def test_analyze_raises_codeqlrunerror_on_non_zero_exit(tmp_path: Path):
    runner, _ = _make_runner(returncode=1, stderr="some error happened")
    with pytest.raises(CodeQLRunError) as ei:
        analyze(tmp_path / "db", ["q.ql"], tmp_path / "out.sarif", runner=runner)
    assert "exited 1" in str(ei.value)
    assert "some error happened" in str(ei.value)


def test_analyze_trims_very_long_stderr_in_error_message(tmp_path: Path):
    long_err = "x" * 5000
    runner, _ = _make_runner(returncode=2, stderr=long_err)
    with pytest.raises(CodeQLRunError) as ei:
        analyze(tmp_path / "db", ["q.ql"], tmp_path / "out.sarif", runner=runner)
    msg = str(ei.value)
    # Last 2000 chars trimmed, so the message can be read without
    # flooding the operator's terminal.
    assert msg.count("x") <= 2100  # 2000 + headers


def test_analyze_raises_on_timeout(tmp_path: Path):
    runner, _ = _make_runner(raise_timeout=True)
    with pytest.raises(CodeQLRunError) as ei:
        analyze(
            tmp_path / "db",
            ["q.ql"],
            tmp_path / "out.sarif",
            timeout_seconds=5,
            runner=runner,
        )
    assert "timed out" in str(ei.value)
    assert "5s" in str(ei.value)


def test_analyze_rejects_empty_queries(tmp_path: Path):
    """No queries = no work; this is operator error, surface loudly."""
    runner, _ = _make_runner()
    with pytest.raises(ValueError, match="at least one query"):
        analyze(tmp_path / "db", [], tmp_path / "out.sarif", runner=runner)


# ---------------------------------------------------------------------
# run_baseline_and_augmented
# ---------------------------------------------------------------------


def test_baseline_and_augmented_runs_twice(tmp_path: Path):
    runner, calls = _make_runner()
    pack = _mk_pack(tmp_path)
    out_dir = tmp_path / "results"
    run_baseline_and_augmented(
        tmp_path / "db",
        ["q.ql"],
        pack,
        out_dir,
        runner=runner,
    )
    assert len(calls) == 2


def test_baseline_first_call_has_no_extension_pack(tmp_path: Path):
    runner, calls = _make_runner()
    pack = _mk_pack(tmp_path)
    run_baseline_and_augmented(
        tmp_path / "db",
        ["q.ql"],
        pack,
        tmp_path / "results",
        runner=runner,
    )
    assert "--additional-packs" not in calls[0]


def test_augmented_second_call_has_extension_pack(tmp_path: Path):
    runner, calls = _make_runner()
    pack = _mk_pack(tmp_path)
    run_baseline_and_augmented(
        tmp_path / "db",
        ["q.ql"],
        pack,
        tmp_path / "results",
        runner=runner,
    )
    assert "--additional-packs" in calls[1]
    assert str(pack) in calls[1]


def test_baseline_and_augmented_writes_to_distinct_paths(tmp_path: Path):
    runner, _ = _make_runner()
    out_dir = tmp_path / "results"
    _mk_pack(tmp_path)
    baseline, augmented = run_baseline_and_augmented(
        tmp_path / "db",
        ["q.ql"],
        tmp_path / "pack",
        out_dir,
        runner=runner,
    )
    assert baseline.sarif_path != augmented.sarif_path
    assert baseline.sarif_path == out_dir / "baseline.sarif"
    assert augmented.sarif_path == out_dir / "augmented.sarif"


def test_baseline_and_augmented_propagates_runner_failure(tmp_path: Path):
    """If baseline fails, augmented isn't run — fail loudly so the
    operator sees the first error rather than two."""
    runner, calls = _make_runner(returncode=1, stderr="boom")
    (tmp_path / "pack").mkdir()
    with pytest.raises(CodeQLRunError):
        run_baseline_and_augmented(
            tmp_path / "db",
            ["q.ql"],
            tmp_path / "pack",
            tmp_path / "results",
            runner=runner,
        )
    assert len(calls) == 1  # augmented never reached


class TestDataOnlyPackGate:
    """The extension pack is loaded with pack-trust disabled, so it
    must be declarative data only — query content is refused."""

    def test_pack_with_ql_refused(self, tmp_path: Path):
        runner, calls = _make_runner()
        pack = tmp_path / "pack"
        pack.mkdir()
        (pack / "evil.ql").write_text("select 1")
        with pytest.raises(ValueError, match="data extensions only"):
            analyze(
                tmp_path / "db", ["q.ql"], tmp_path / "out.sarif",
                extension_pack=pack, runner=runner,
            )
        assert calls == []  # refused before any subprocess ran

    def test_pack_with_qll_in_subdir_refused(self, tmp_path: Path):
        runner, calls = _make_runner()
        pack = tmp_path / "pack"
        (pack / "lib").mkdir(parents=True)
        (pack / "lib" / "helper.qll").write_text("")
        with pytest.raises(ValueError, match="data extensions only"):
            analyze(
                tmp_path / "db", ["q.ql"], tmp_path / "out.sarif",
                extension_pack=pack, runner=runner,
            )
        assert calls == []

    def test_missing_pack_dir_refused(self, tmp_path: Path):
        runner, calls = _make_runner()
        with pytest.raises(ValueError, match="not a directory"):
            analyze(
                tmp_path / "db", ["q.ql"], tmp_path / "out.sarif",
                extension_pack=tmp_path / "absent", runner=runner,
            )
        assert calls == []

    def test_data_only_pack_accepted(self, tmp_path: Path):
        runner, calls = _make_runner()
        pack = tmp_path / "pack"
        pack.mkdir()
        (pack / "codeql-pack.yml").write_text("name: x/y\n")
        (pack / "models.yml").write_text("extensions: []\n")
        analyze(
            tmp_path / "db", ["q.ql"], tmp_path / "out.sarif",
            extension_pack=pack, runner=runner,
        )
        assert len(calls) == 1
