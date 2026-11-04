"""The composed pass must add overlap findings without losing baseline evidence."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from core.detectors import memcpy_overlap

_spec = importlib.util.spec_from_file_location(
    "static_analysis_overlap", Path(__file__).parents[1] / "compiler_scan.py",
)
cs = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = cs
_spec.loader.exec_module(cs)


@pytest.fixture
def harness(tmp_path, monkeypatch):
    for name in ("a.c", "b.c", "extra.c"):
        (tmp_path / name).write_text("void f(void) { memcpy(d,s,n); }\n")
    monkeypatch.setattr(memcpy_overlap, "_expanded_candidates", lambda *args: False)
    monkeypatch.setattr(cs, "_gcc_analyzer", lambda: ("/trusted/gcc", "json"))
    monkeypatch.setattr(cs, "_clang_path", lambda: None)
    monkeypatch.setattr(cs, "_suppression_vet", lambda *a: ("", ""))
    monkeypatch.setattr("packages.semgrep.runner.is_available", lambda: True)
    state = {"calls": [], "candidate_calls": [], "probe_rc": 0, "extra_rc": 0,
             "extra_raises": None, "candidate_errors": [], "candidate_available": True}

    def candidates(target, config, **kw):
        state["candidate_calls"].append((target, config, kw))
        return SimpleNamespace(errors=state["candidate_errors"], findings=[
            SimpleNamespace(file=str(tmp_path / name))
            for name in ("a.c", "b.c", "extra.c", "../outside.c")
        ])

    monkeypatch.setattr("packages.semgrep.runner.run_rule", candidates)

    def run(cmd, **kwargs):
        state["calls"].append((cmd, kwargs))
        if "-fsyntax-only" in cmd:
            return SimpleNamespace(returncode=state["probe_rc"], stderr="[]")
        extra = "-fno-builtin-memcpy" in cmd
        if extra and state["extra_raises"]:
            raise state["extra_raises"]
        source = cmd[cmd.index("-c") + 1]
        ids = [memcpy_overlap.OVERLAP_ID, "-Wanalyzer-null-dereference"] if extra else ["-Wanalyzer-use-after-free"]
        diags = [{"kind": "warning", "option": ident, "message": ident,
                  "locations": [{"caret": {"file": source, "line": 1}}]} for ident in ids]
        return SimpleNamespace(returncode=state["extra_rc"] if extra else 0, stderr=json.dumps(diags))

    monkeypatch.setattr(cs, "_sandbox_runner", lambda: run)
    return state


def test_adds_overlap_preserves_baseline_and_cap(tmp_path, harness):
    result = cs.scan_target(tmp_path, max_tus=1)
    assert result.tus_analyzed == 1 and result.tus_skipped_cap == 2
    assert {(d["file"], d["rule_id"]) for d in result.findings} == {
        ("a.c", "-Wanalyzer-use-after-free"), ("a.c", memcpy_overlap.OVERLAP_ID),
    }
    assert not result.detector_limitations
    assert len(harness["candidate_calls"]) == 1
    assert len(harness["calls"]) == 3  # ordinary compile, capability probe, supplemental compile
    first = harness["calls"][0][0]
    assert "-fno-builtin-memcpy" not in first
    for cmd, kw in harness["calls"]:
        assert kw["block_network"] and kw["target"] == str(tmp_path)
        assert kw["cwd"] == kw["output"] and not Path(kw["output"]).exists()
    assert len(cs.to_sarif(result)["runs"][0]["results"]) == 2


@pytest.mark.parametrize("failure", ["probe", "compile", "timeout", "candidates"])
def test_supplemental_failures_leave_baseline_evidence(tmp_path, harness, failure):
    if failure == "probe": harness["probe_rc"] = 1
    if failure == "compile": harness["extra_rc"] = 1
    if failure == "timeout": harness["extra_raises"] = subprocess.TimeoutExpired("gcc", 120)
    if failure == "candidates": harness["candidate_errors"] = ["partial scan"]
    result = cs.scan_target(tmp_path, max_tus=1)
    assert result.ok and result.tus_analyzed == 1 and result.tus_failed == 0
    assert any(d["rule_id"] == "-Wanalyzer-use-after-free" for d in result.findings)
    if failure != "candidates":
        assert not any(d["rule_id"] == memcpy_overlap.OVERLAP_ID for d in result.findings)
    assert result.detector_limitations
    sarif = cs.to_sarif(result)
    notes = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert notes
    if failure in ("probe", "candidates"):
        assert "locations" not in notes[0]  # Global failures have no source location.
    assert "additional analyzer limitation" in result.summary_line()


def test_failed_baseline_never_runs_supplement(tmp_path, harness, monkeypatch):
    monkeypatch.setattr(cs, "analyze_tu", lambda *a, **kw: cs.TuDiagnostics("a.c", ok=False))
    result = cs.scan_target(tmp_path, max_tus=1)
    assert result.tus_failed == 1 and not result.findings
    assert not harness["calls"] and not harness["candidate_calls"]


def test_candidate_failure_does_not_export_candidate_matches(tmp_path, harness, monkeypatch):
    monkeypatch.setattr("packages.semgrep.runner.run_rule", lambda *a, **kw: SimpleNamespace(
        errors=["bad rule"], findings=[],
    ))
    result = cs.scan_target(tmp_path, max_tus=1)
    assert [d["rule_id"] for d in result.findings] == ["-Wanalyzer-use-after-free"]
    assert result.detector_limitations
    assert len(harness["calls"]) == 1


def test_semgrep_absent_only_skips_overlap_pass(tmp_path, harness, monkeypatch):
    monkeypatch.setattr("packages.semgrep.runner.is_available", lambda: False)
    result = cs.scan_target(tmp_path, max_tus=1)
    assert [d["rule_id"] for d in result.findings] == ["-Wanalyzer-use-after-free"]
    assert result.detector_limitations and len(harness["calls"]) == 1


@pytest.mark.slow
def test_native_overlap_added_and_use_after_free_retained(tmp_path, monkeypatch):
    import shutil
    from core.audit import compiler_sweep

    compiler_sweep._reset_probe_cache()
    gcc = cs._gcc_analyzer()
    if gcc is None or shutil.which("semgrep") is None:
        pytest.skip("requires GCC analyzer and Semgrep")
    options = subprocess.run([gcc[0], "-Q", "--help=warnings"], capture_output=True, text=True, timeout=30)
    if memcpy_overlap.OVERLAP_ID not in options.stdout:
        pytest.skip("requires GCC overlap warning (GCC 14+)")
    repo = tmp_path / "repo"
    repo.mkdir()
    source = (
        "#include <stdlib.h>\n#include <string.h>\n"
        "void alias_copy(void) { char b[64]={0}; char *p=b+4; memcpy(p,b,16); }\n"
        "void adjacent(void) { char b[64]={0}; memcpy(b+16,b,16); }\n"
        "void move(void) { char b[64]={0}; memmove(b+4,b,16); }\n"
        "void uaf(const char *s) { char *d=malloc(16); if(!d)return; free(d); memcpy(d,s,16); }\n"
    )
    (repo / "cases.c").write_text(source)
    calls = []

    def run(cmd, **kw):
        calls.append((cmd, kw))
        return subprocess.run(cmd, check=False, **{
            k: kw[k] for k in ("capture_output", "text", "timeout", "cwd") if k in kw
        })

    monkeypatch.setattr(cs, "_sandbox_runner", lambda: run)
    result = cs.scan_target(repo, out_dir=tmp_path / "out")
    assert result.ok and result.tus_analyzed == 1 and result.tus_failed == 0
    assert not result.detector_limitations, result.detector_limitations
    overlaps = [d for d in result.findings if d["rule_id"] == memcpy_overlap.OVERLAP_ID]
    assert len(overlaps) == 1
    assert "alias_copy" in source.splitlines()[overlaps[0]["line"] - 1]
    assert any(d["rule_id"] == "-Wanalyzer-use-after-free" for d in result.findings)
    assert sum("-fno-builtin-memcpy" in cmd for cmd, _ in calls) == 1
    assert all(kw["block_network"] for _, kw in calls)
    assert all(not Path(kw["output"]).exists() for _, kw in calls)


def test_no_candidates_adds_no_compile_or_limitation(tmp_path, harness, monkeypatch):
    monkeypatch.setattr("packages.semgrep.runner.run_rule", lambda *a, **kw: SimpleNamespace(
        errors=[], findings=[],
    ))
    result = cs.scan_target(tmp_path, max_tus=1)
    assert not result.detector_limitations
    assert len(harness["calls"]) == 1
    assert [d["rule_id"] for d in result.findings] == ["-Wanalyzer-use-after-free"]


def test_cpp_files_never_start_candidate_scan(tmp_path, harness, monkeypatch):
    monkeypatch.setattr(cs, "enumerate_tus", lambda path: ["x.cpp"])
    monkeypatch.setattr(cs, "analyze_tu", lambda *a, **kw: cs.TuDiagnostics("x.cpp", ok=True, compiler="clang"))
    result = cs.scan_target(tmp_path)
    assert result.tus_analyzed == 1
    assert not harness["calls"] and not harness["candidate_calls"]
    assert not result.detector_limitations


def test_gcc_absent_preserves_clang_findings(tmp_path, harness, monkeypatch):
    monkeypatch.setattr(cs, "_gcc_analyzer", lambda: None)
    monkeypatch.setattr(cs, "_clang_path", lambda: "/trusted/clang")
    monkeypatch.setattr(cs, "analyze_tu", lambda target, rel, **kw: cs.TuDiagnostics(
        rel, ok=True, compiler="clang", diagnostics=[{
            "file": rel, "line": 1, "rule_id": "core.NullDereference", "message": "null",
        }],
    ))
    result = cs.scan_target(tmp_path, max_tus=1)
    assert result.tus_analyzed == 1 and len(result.findings) == 1
    assert result.detector_limitations
    assert not harness["candidate_calls"] and not harness["calls"]


def test_one_supplemental_failure_does_not_cost_other_tus(tmp_path, harness, monkeypatch):
    ordinary = cs._sandbox_runner()

    def run(cmd, **kw):
        if "-fno-builtin-memcpy" in cmd and str(tmp_path / "b.c") in cmd:
            return SimpleNamespace(returncode=1, stderr="[]")
        return ordinary(cmd, **kw)

    monkeypatch.setattr(cs, "_sandbox_runner", lambda: run)
    result = cs.scan_target(tmp_path, max_tus=2)
    assert result.tus_analyzed == 2 and result.tus_failed == 0
    assert {(d["file"], d["rule_id"]) for d in result.findings} == {
        ("a.c", "-Wanalyzer-use-after-free"), ("b.c", "-Wanalyzer-use-after-free"),
        ("a.c", memcpy_overlap.OVERLAP_ID),
    }
    assert [item["tu"] for item in result.detector_limitations] == ["b.c"]


def test_overlap_already_found_by_baseline_is_deduplicated(tmp_path, harness, monkeypatch):
    ordinary = cs._sandbox_runner()

    def run(cmd, **kw):
        result = ordinary(cmd, **kw)
        if "-c" in cmd and "-fno-builtin-memcpy" not in cmd:
            diags = json.loads(result.stderr)
            extra = dict(diags[0], option=memcpy_overlap.OVERLAP_ID)
            result.stderr = json.dumps([*diags, extra])
        return result

    monkeypatch.setattr(cs, "_sandbox_runner", lambda: run)
    result = cs.scan_target(tmp_path, max_tus=1)
    assert sum(d["rule_id"] == memcpy_overlap.OVERLAP_ID for d in result.findings) == 1


def test_candidate_filter_only_receives_successful_capped_tus(tmp_path, harness, monkeypatch):
    def base(target, rel, **kw):
        return cs.TuDiagnostics(rel, ok=rel == "a.c")

    monkeypatch.setattr(cs, "analyze_tu", base)
    result = cs.scan_target(tmp_path, max_tus=2)
    assert result.tus_analyzed == result.tus_failed == 1
    assert {d["file"] for d in result.findings} == {"a.c"}
    compiles = [cmd for cmd, _ in harness["calls"] if "-c" in cmd]
    assert len(compiles) == 1 and str(tmp_path / "a.c") in compiles[0]


@pytest.mark.slow
def test_native_header_macros_reach_compiler_without_exporting_candidates(tmp_path, monkeypatch):
    import shutil
    from core.audit import compiler_sweep

    compiler_sweep._reset_probe_cache()
    gcc = cs._gcc_analyzer()
    if gcc is None or shutil.which('semgrep') is None:
        pytest.skip('requires GCC analyzer and Semgrep')
    options = subprocess.run([gcc[0], '-Q', '--help=warnings'], capture_output=True, text=True, timeout=30)
    if memcpy_overlap.OVERLAP_ID not in options.stdout:
        pytest.skip('requires GCC overlap warning (GCC 14+)')
    repo = tmp_path / 'repo'
    repo.mkdir()
    (repo / 'copy.h').write_text(
        '#include <stddef.h>\n#include <string.h>\n#define alias memcpy\n'
        "#if __STDC_VERSION__ >= 202311L\n#define COPY_BYTES 1'6\n#else\n#define COPY_BYTES 16\n#endif\n"
        '#define lower_copy(d,s,n) alias(d,s,n)\n'
        'static inline void header_only(char *p) { memcpy(p+1,p,8); }\n'
    )
    source = (
        '#include "copy.h"\n'
        'void overlap(void) { char b[64]={0}; char *p=b+4; int n=COPY_BYTES; lower_copy(p,b,n); }\n'
        'void adjacent(void) { char b[64]={0}; lower_copy(b+16,b,16); }\n'
        'void move(void) { char b[64]={0}; memmove(b+4,b,16); }\n'
        '#if 0\nvoid dead(void) { char b[64]; lower_copy(b+4,b,16); }\n#endif\n'
    )
    (repo / 'macro.c').write_text(source)
    (repo / 'safe.c').write_text('#include "copy.h"\nvoid safe(void) { char b[64]={0}; lower_copy(b+16,b,16); }\n')
    (repo / 'header_only.c').write_text('#include "copy.h"\nvoid plain(void) {}\n')
    calls = []

    def run(cmd, **kw):
        calls.append((cmd, kw))
        return subprocess.run(cmd, check=False, **{
            k: kw[k] for k in ('capture_output', 'text', 'timeout', 'cwd', 'env') if k in kw
        })


    monkeypatch.setattr(cs, '_sandbox_runner', lambda: run)
    monkeypatch.setattr('core.sandbox.context.run', run)
    executions = []
    original = cs.run_memcpy_overlap

    def detector(*args, **kw):
        execution = original(*args, **kw)
        executions.append(execution)
        return execution

    monkeypatch.setattr(cs, 'run_memcpy_overlap', detector)
    result = cs.scan_target(repo, out_dir=tmp_path / 'out')
    assert result.ok and result.tus_analyzed == 3 and result.tus_failed == 0
    # A raw-parser/version limitation must not disable macro discovery.
    # Preparation and the compiler-confirmed result below still have to succeed.
    assert not any('macro' in item['reason'] for item in result.detector_limitations), result.detector_limitations
    assert executions[0].value.candidates == {'macro.c', 'safe.c'}, executions[0]
    overlaps = [d for d in result.findings if d['rule_id'] == memcpy_overlap.OVERLAP_ID]
    assert len(overlaps) == 1, overlaps
    assert overlaps[0]['file'] == 'macro.c'
    assert 'void overlap' in source.splitlines()[overlaps[0]['line'] - 1]
    extra = [cmd for cmd, _ in calls if '-fno-builtin-memcpy' in cmd]
    assert len(extra) == 2
    assert {Path(cmd[cmd.index('-c') + 1]).name for cmd in extra} == {'macro.c', 'safe.c'}
    preprocessed = [cmd for cmd, kw in calls if kw.get('caller_label') == 'audit-preprocessor-view']
    assert len(preprocessed) == 3 and all(cmd[0] == gcc[0] for cmd in preprocessed)
    semgrep = [cmd for cmd, _ in calls if 'scan' in cmd]
    assert len(semgrep) == 1  # Expanded candidates do not depend on Semgrep's C parser.
    assert all(kw['block_network'] for _, kw in calls)


def test_include_discovery_shared_across_baseline_and_overlap_and_fresh_next_scan(
    tmp_path, harness, monkeypatch,
):
    from core.audit import compiler_sweep
    walks = []
    derive = compiler_sweep._derive_include_dirs
    def count(target, directory):
        walks.append((target, directory))
        return derive(target, directory)
    monkeypatch.setattr(compiler_sweep, '_derive_include_dirs', count)
    monkeypatch.setattr(cs, '_derive_include_dirs', count)
    first = cs.scan_target(tmp_path)
    assert first.tus_analyzed == 3 and len(first.findings) == 6
    # Concurrent baseline TUs and repeated supplementary request construction
    # all refer to the same directory, so they share one bounded tree walk.
    assert walks == [(tmp_path, tmp_path)]
    first_commands = [cmd for cmd, _ in harness['calls'] if '-c' in cmd]
    assert len(first_commands) == 6  # sharing paths must not skip an analysis
    assert all([arg for arg in cmd if arg.startswith('-I')] == [f'-I{tmp_path}']
               for cmd in first_commands)
    harness['calls'].clear()
    added = tmp_path / 'generated' / 'include'
    added.mkdir(parents=True)
    second = cs.scan_target(tmp_path)
    assert len(walks) == 2  # no stale directory inventory across scans
    assert first.findings == second.findings
    commands = [cmd for cmd, _ in harness['calls'] if '-c' in cmd]
    assert len(commands) == 6
    assert all([arg for arg in cmd if arg.startswith('-I')] == [f'-I{tmp_path}', f'-I{added}']
               for cmd in commands)


def test_include_memo_keeps_translation_unit_directories_distinct(tmp_path, harness, monkeypatch):
    from collections import Counter
    from core.audit import compiler_sweep
    sub = tmp_path / 'sub'
    sub.mkdir()
    (sub / 'b.c').write_text('void f(void) {}\n')
    walks = []
    derive = compiler_sweep._derive_include_dirs
    def count(target, directory):
        walks.append(directory)
        return derive(target, directory)
    monkeypatch.setattr(compiler_sweep, '_derive_include_dirs', count)
    monkeypatch.setattr(cs, '_derive_include_dirs', count)
    result = cs.scan_target(tmp_path)
    assert result.tus_analyzed == 4
    assert Counter(walks) == Counter({tmp_path: 1, sub: 1})
    for command, _ in harness['calls']:
        if '-c' not in command:
            continue
        source = Path(command[command.index('-c') + 1])
        expected = [f'-I{tmp_path}']
        if source.parent == sub:
            expected.append(f'-I{sub}')
        assert [arg for arg in command if arg.startswith('-I')] == expected
