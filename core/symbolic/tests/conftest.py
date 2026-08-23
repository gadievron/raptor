"""Shared fixtures: self-contained C targets compiled into tmp_path.

The suite previously borrowed corpus problems from an external
evaluation tree; these inline sources replace them so the substrate
tests stand alone. Everything compiles fresh into pytest's tmp_path
(standard tmpdir retention applies); hosts without gcc skip.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

#: Non-PIE + no stack protector: symbol addresses are static and the
#: overflow reaches the saved return address unimpeded — the shape
#: the overflow-witness primitive verifies.
FIXTURE_CFLAGS: tuple[str, ...] = (
    "-O0", "-g", "-fno-stack-protector", "-no-pie",
)

#: Stack overflow reaching PC, with an uncalled marker function.
#: ``win`` writes its marker via the write(2) wrapper and _exit(2)s:
#: no printf/SSE, so reaching it via a hijacked (possibly misaligned)
#: return works reliably; no return from a clobbered frame.
OVERFLOW_MARKER_SOURCE = r"""
#include <unistd.h>

void win(void) {
    write(1, "MARKER_REACHED\n", 15);
    _exit(0);
}

void vuln(void) {
    char buf[16];
    read(0, buf, 256);
}

int main(void) {
    vuln();
    write(1, "normal exit\n", 12);
    return 0;
}
"""

#: Same overflow, but the marker is gated on an argument register.
#: At vuln's return the register is unrelated to symbolic stdin, so a
#: bare PC constraint plus a register constraint is unsatisfiable —
#: the diagnostic-failure case the witness primitive must signal
#: instead of returning a solve that would not replay.
ARGCHECKED_MARKER_SOURCE = r"""
#include <unistd.h>

void win(long arg) {
    if (arg == 0xc0ffee) {
        write(1, "MARKER_REACHED\n", 15);
        _exit(0);
    }
    write(1, "wrong arg\n", 10);
    _exit(1);
}

void vuln(void) {
    char buf[16];
    read(0, buf, 256);
}

int main(void) {
    vuln();
    return 0;
}
"""

#: A marker symbol exists but the bug class is heap use-after-free —
#: no unbounded read anywhere. Shape detection must decline.
UAF_MARKER_SOURCE = r"""
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win(void) {
    write(1, "MARKER_REACHED\n", 15);
    _exit(0);
}

int main(void) {
    char *a = malloc(32);
    strncpy(a, "data", 31);
    free(a);
    /* stale read after free — heap bug, not a stack overflow */
    write(1, a, 4);
    return 0;
}
"""


def compile_fixture(
    tmp_path: Path,
    source: str,
    flags: tuple[str, ...] = FIXTURE_CFLAGS,
) -> Path:
    """Compile *source* into ``tmp_path/target``; skip without gcc."""
    if shutil.which("gcc") is None:
        pytest.skip("gcc not installed")
    src = tmp_path / "fixture.c"
    src.write_text(source)
    binary = tmp_path / "target"
    result = subprocess.run(
        ["gcc", *flags, str(src), "-o", str(binary)],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        pytest.skip(f"gcc: {result.stderr[:120]}")
    return binary

#: Branch guard encoding a solver-hard UNSAT instance: 2**64-59 is
#: prime, so the modulus guard has no solution — but proving that
#: forces the SMT backend into factoring-flavoured work. Before the
#: per-call z3 budget, one concretisation call on this target hung
#: past any wall-clock deadline and deferred SIGTERM (native z3).
SOLVER_HARD_SOURCE = r"""
#include <unistd.h>

void win(void) {
    write(1, "MARKER_REACHED\n", 15);
    _exit(0);
}

int main(void) {
    unsigned long a = 0;
    read(0, &a, 8);
    if (a > 2 && a < 0xFFFFFFFFFFFFFFC5UL
            && 0xFFFFFFFFFFFFFFC5UL % a == 0) {
        win();
    }
    return 0;
}
"""
