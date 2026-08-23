"""synthesise_build_command must keep the script that measured best.

Regression: after the CC-suggest retry, the build script was
unconditionally rewritten back to heuristic-only flags — discarding the
CC improvement while build_type still claimed "synthesised-cc" — and
the cc_failures-is-None branch ("keeping heuristic") left the
unmeasured CC flags on disk.
"""

from pathlib import Path
from unittest import mock

from core.build.build_detector import BuildDetector


def _detector(tmp_path: Path) -> BuildDetector:
    return BuildDetector(tmp_path)


def _run(tmp_path, dry_run_results, cc_flags):
    """Drive synthesise_build_command with mocked probes.

    Returns (BuildSystem, list of _write_build_script call kwargs-tuples).
    """
    sources = [tmp_path / "a.c", tmp_path / "b.c", tmp_path / "c.c"]
    writes = []

    def record_write(script_path, build_dir, source_files, compiler,
                     include_flags, define_flags):
        writes.append((list(include_flags), list(define_flags)))

    with mock.patch.object(
            BuildDetector, "_detect_build_params",
            return_value=(sources, "gcc", ["-I."], ["-DH"])), \
         mock.patch.object(
            BuildDetector, "detect_missing_config_headers", return_value=[]), \
         mock.patch.object(
            BuildDetector, "_write_build_script", side_effect=record_write), \
         mock.patch.object(
            BuildDetector, "_dry_run", side_effect=dry_run_results), \
         mock.patch.object(
            BuildDetector, "_cc_suggest_flags", return_value=cc_flags):
        detector = _detector(tmp_path)
        result = detector.synthesise_build_command("cpp")

    # Clean the mkdtemp/mkstemp artifacts the method created in the repo.
    if result:
        for p in result.cleanup_paths:
            if p.is_dir():
                import shutil
                shutil.rmtree(p, ignore_errors=True)
            else:
                p.unlink(missing_ok=True)
    return result, writes


_CC = {"includes": ["-Igen"], "defines": ["-DCC"]}
_HEURISTIC_WRITE = (["-I."], ["-DH"])
_CC_WRITE = (["-I.", "-Igen"], ["-DH", "-DCC"])


def test_cc_improvement_keeps_cc_script(tmp_path):
    result, writes = _run(
        tmp_path,
        dry_run_results=[["a.c: error", "b.c: error"], []],  # 1/3 → 3/3
        cc_flags=_CC,
    )
    assert result.type == "synthesised-cc"
    # Last script on disk must be the CC-flag one that measured better.
    assert writes[-1] == _CC_WRITE


def test_cc_no_improvement_restores_heuristic_script(tmp_path):
    result, writes = _run(
        tmp_path,
        dry_run_results=[["a.c: error"], ["a.c: error"]],  # 2/3 → 2/3
        cc_flags=_CC,
    )
    assert result.type == "synthesised"
    assert writes[-1] == _HEURISTIC_WRITE


def test_cc_retry_not_run_restores_heuristic_script(tmp_path):
    result, writes = _run(
        tmp_path,
        dry_run_results=[["a.c: error"], None],  # retry never executed
        cc_flags=_CC,
    )
    assert result.type == "synthesised"
    # "keeping heuristic" must mean the heuristic script is on disk,
    # not the unmeasured CC-flag one.
    assert writes[-1] == _HEURISTIC_WRITE
