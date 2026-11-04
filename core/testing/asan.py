"""Runtime prerequisites for tests of owned AddressSanitizer fixtures.

A successful link does not prove that the installed ASAN runtime can start.
The clean probe runs outside RAPTOR's sandbox, so sandbox regressions cannot
be mistaken for missing prerequisites. Compile-only tests do not use this gate.
"""
from __future__ import annotations

from functools import lru_cache
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

_CLEAN_SOURCE = '''#include <stdlib.h>
#include <stdio.h>
int main(void) {
    volatile char *p = (volatile char *)malloc(64);
    if (!p) return 2;
    p[0] = 1;
    free((void *)p);
    puts("raptor-asan-main");
    return 0;
}
'''


@lru_cache(maxsize=16)
def _runtime_unavailable_reason(compiler: str) -> str | None:
    from core.config import RaptorConfig

    with tempfile.TemporaryDirectory(prefix="raptor-test-asan-") as raw:
        root = Path(raw)
        binary = root / "clean"
        env = RaptorConfig.get_safe_env()
        env["TMPDIR"] = str(root)
        env["ASAN_OPTIONS"] = "detect_leaks=0:symbolize=0:abort_on_error=0"
        try:
            built = subprocess.run(
                [compiler, "-fsanitize=address", "-x", "c++", "-", "-o", str(binary)],
                input=_CLEAN_SOURCE, timeout=15, env=env, cwd=os.sep,
                capture_output=True, text=True,
            )
            if built.returncode:
                return f"clean ASAN probe did not compile (exit {built.returncode})"
            ran = subprocess.run([str(binary)], timeout=5, env=env, cwd=os.sep,
                                 capture_output=True, text=True)
        except subprocess.TimeoutExpired:
            return "clean ASAN probe timed out before successful completion"
        except OSError as exc:
            return f"clean ASAN probe unavailable ({type(exc).__name__})"
        if ran.returncode or ran.stdout.strip() != "raptor-asan-main":
            return f"clean ASAN probe did not complete normally (exit {ran.returncode})"
    return None


def require_asan_runtime() -> None:
    """Skip only if this compiler's independent clean runtime probe fails."""
    import pytest
    from packages.autonomous.exploit_validator import _detect_cxx_compiler

    try:
        compiler = shutil.which(_detect_cxx_compiler())
    except RuntimeError:
        compiler = None
    if compiler is None:
        pytest.skip("ASAN runtime prerequisite: no C++ compiler")
    reason = _runtime_unavailable_reason(compiler)
    if reason is not None:
        pytest.skip("ASAN runtime prerequisite: " + reason)
