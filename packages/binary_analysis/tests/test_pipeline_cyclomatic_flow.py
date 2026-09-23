"""Artifact-flow tests for per-function cyclomatic complexity.

The blackbox pipeline is the live consumer of ``extract_cfgs``: deep
runs must request CFG extraction on the main analysis call and the
computed ``cyclomatic`` value must reach the emitted
``binary-context-map.json`` / ``context-map.json`` records; quick runs
must stay cheap (no extraction) and omit the field. Plumbing tests are
r2-free (the analysis boundary is patched, the rest of the pipeline is
real); one end-to-end test compiles a real fixture and runs live
radare2 when the toolchain is present.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from packages.binary_analysis.pipeline import analyse_blackbox_binary
from packages.binary_analysis.radare2_understand import (
    BinaryContextMap,
    FunctionInfo,
)


def _write_binary(path: Path, data: bytes = b"\x7fELF" + b"\x00" * 128) -> Path:
    path.write_bytes(data)
    path.chmod(0o755)
    return path


def _fn(name: str, addr: int, cyclomatic: int | None = None) -> FunctionInfo:
    fn = FunctionInfo(name=name, address=addr, size=64)
    fn.cyclomatic = cyclomatic
    return fn


def _ctx(binary: Path, fns: list[FunctionInfo]) -> BinaryContextMap:
    ctx = BinaryContextMap(
        binary_path=binary, arch="x86", bits=64, binary_format="elf")
    ctx.interesting_functions = fns
    return ctx


def _artifact_functions(out: Path) -> list[dict]:
    payload = json.loads((out / "binary-context-map.json").read_text())
    return payload["interesting_functions"]


class TestPipelinePlumbing:
    def test_deep_run_requests_cfgs_and_emits_cyclomatic(self, tmp_path: Path) -> None:
        binary = _write_binary(tmp_path / "sample")
        out = tmp_path / "out"
        seen_kwargs: dict = {}

        def fake_analyse(path, **kwargs):
            seen_kwargs.update(kwargs)
            # The real analyse computes cyclomatic when extract_cfgs=True;
            # mirror that contract here.
            assert kwargs["extract_cfgs"] is True
            return _ctx(binary, [_fn("parse_frame", 0x1000, cyclomatic=3),
                                 _fn("helper", 0x2000, cyclomatic=0)])

        with patch(
            "packages.binary_analysis.pipeline.analyse_binary_context",
            side_effect=fake_analyse,
        ):
            analyse_blackbox_binary(binary, out_dir=out, quick=False)

        assert seen_kwargs["extract_cfgs"] is True
        by_name = {fn["name"]: fn for fn in _artifact_functions(out)}
        assert by_name["parse_frame"]["cyclomatic"] == 3
        # 0 is a real measurement and must survive to the artifact.
        assert by_name["helper"]["cyclomatic"] == 0
        # The twin artifact carries the same records.
        twin = json.loads((out / "context-map.json").read_text())
        assert {fn["name"]: fn.get("cyclomatic")
                for fn in twin["interesting_functions"]} == {
            "parse_frame": 3, "helper": 0}

    def test_quick_run_does_not_request_cfgs_and_omits_field(self, tmp_path: Path) -> None:
        binary = _write_binary(tmp_path / "sample")
        out = tmp_path / "out"
        seen_kwargs: dict = {}

        def fake_analyse(path, **kwargs):
            seen_kwargs.update(kwargs)
            ctx = _ctx(binary, [_fn("parse_frame", 0x1000)])
            ctx.analysis_depth = "metadata_only"
            return ctx

        with patch(
            "packages.binary_analysis.pipeline.analyse_binary_context",
            side_effect=fake_analyse,
        ):
            analyse_blackbox_binary(binary, out_dir=out, quick=True)

        assert seen_kwargs["extract_cfgs"] is False  # quick stays cheap
        for fn in _artifact_functions(out):
            assert "cyclomatic" not in fn

    def test_per_function_failure_degrades_to_absent_field(self, tmp_path: Path) -> None:
        # One function's CFG extraction failed (cyclomatic None, matching
        # _extract_function_cfgs isolation); the pipeline must complete
        # and emit the field only where it was computed.
        binary = _write_binary(tmp_path / "sample")
        out = tmp_path / "out"
        ctx = _ctx(binary, [_fn("ok_fn", 0x1000, cyclomatic=2),
                            _fn("wedged_fn", 0x2000, cyclomatic=None)])
        with patch(
            "packages.binary_analysis.pipeline.analyse_binary_context",
            return_value=ctx,
        ):
            result = analyse_blackbox_binary(binary, out_dir=out, quick=False)

        assert result.manifest.binary_sha256  # pipeline completed
        by_name = {fn["name"]: fn for fn in _artifact_functions(out)}
        assert by_name["ok_fn"]["cyclomatic"] == 2
        assert "cyclomatic" not in by_name["wedged_fn"]


_CC = shutil.which("cc") or shutil.which("gcc")
_HAS_R2 = bool(shutil.which("r2") or shutil.which("radare2"))
try:
    import r2pipe  # noqa: F401
    _HAS_R2PIPE = True
except ImportError:
    _HAS_R2PIPE = False

_FIXTURE_C = r"""
#include <string.h>
#include <stdio.h>

/* One loop + one branch: cyclomatic >= 1, and big enough to survive
   the interesting-function size filter. */
int frobnicate(const char *s) {
    int acc = 0;
    for (int i = 0; s[i]; i++) {
        if (s[i] == 'x')
            acc += i;
        else
            acc ^= s[i];
    }
    return acc;
}

int main(int argc, char **argv) {
    char buf[64];
    if (argc > 1) {
        strncpy(buf, argv[1], sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = 0;
        printf("%d\n", frobnicate(buf));
    }
    return 0;
}
"""


@pytest.mark.skipif(
    not (_CC and _HAS_R2 and _HAS_R2PIPE),
    reason="live E2E needs a C compiler, radare2, and r2pipe",
)
def test_live_pipeline_emits_cyclomatic_for_compiled_fixture(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Isolate the per-build-id CFG cache: without this the E2E wrote
    # into the real shared BASE_OUT_DIR cache that production runs
    # read (cross-process contention + test residue). Same idiom as
    # test_function_cfg's cache_dir fixture.
    from packages.binary_analysis import function_cfg
    monkeypatch.setattr(
        function_cfg, "_cache_dir", lambda: tmp_path / "cfg-cache")
    src = tmp_path / "fixture.c"
    src.write_text(_FIXTURE_C)
    binary = tmp_path / "fixture"
    subprocess.run(
        [_CC, "-O0", "-g", "-o", str(binary), str(src)],
        check=True, capture_output=True, timeout=60,
    )
    out = tmp_path / "out"

    result = analyse_blackbox_binary(binary, out_dir=out, quick=False, max_decompile=0)

    if result.context_map["analysis_scope"]["analysis_depth"] != "full":
        pytest.skip("radare2 analysis unavailable on this runner (sandbox/namespace)")

    functions = _artifact_functions(out)
    assert functions, "deep run recovered no interesting functions"
    with_metric = {
        fn["name"]: fn["cyclomatic"] for fn in functions if "cyclomatic" in fn
    }
    assert with_metric, "no per-function cyclomatic reached the artifact"
    frob = [v for name, v in with_metric.items() if "frobnicate" in name]
    assert frob, f"fixture function missing from {sorted(with_metric)}"
    # loop + if/else: at least 2 independent cycles in the undirected CFG.
    assert frob[0] >= 2
    for value in with_metric.values():
        assert isinstance(value, int)
