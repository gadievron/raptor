"""End-to-end runner/api test - gated on Frida + a C compiler being present
(skipped in their absence so CI without Frida stays green)."""

import shutil
import subprocess

import pytest

from packages.dynamic_instrumentation import api
from packages.dynamic_instrumentation.capability import probe

_FRIDA = probe().available
_CC = shutil.which("gcc") or shutil.which("cc")

pytestmark = pytest.mark.skipif(
    not (_FRIDA and _CC), reason="needs frida binding + a C compiler")

_SRC = r"""
#include <stdio.h>
int secret(int x){ return x*3+1; }
int main(){ for(int i=0;i<3;i++){ printf("%d\n", secret(i)); } return 0; }
"""


@pytest.fixture(scope="module")
def target(tmp_path_factory):
    d = tmp_path_factory.mktemp("frida_target")
    src = d / "t.c"
    src.write_text(_SRC)
    binp = d / "t"
    rc = subprocess.run([_CC, "-O0", "-g", "-o", str(binp), str(src)],
                        capture_output=True, text=True)
    if rc.returncode != 0:
        pytest.skip(f"compile failed: {rc.stderr[:200]}")
    return str(binp)


def test_trace_captures_calls(target, tmp_path):
    res = api.trace_functions(target, ["secret"],
                              output_dir=str(tmp_path / "trace"), timeout=20)
    # secret() is called 3 times with args 0,1,2
    assert res["call_count"] == 3
    assert res["unresolved"] == []
    first_args = [r["args"][0] for r in res["trace"]]
    assert first_args == [0, 1, 2]


def test_coverage_marks_drcov(target, tmp_path):
    res = api.collect_coverage(target, output_dir=str(tmp_path / "cov"),
                               timeout=20)
    # tiny target - may collect few blocks, but the main module must register
    assert res["basic_blocks"] >= 1
    assert res["drcov_path"]
    # the produced drcov resolves to source via the existing pipeline
    from core.coverage.collect import collect_drcov
    src = collect_drcov(res["drcov_path"], target)
    assert any(p.endswith("t.c") for p in src)
