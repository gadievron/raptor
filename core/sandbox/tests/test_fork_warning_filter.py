"""The multi-threaded-fork DeprecationWarning stays silenced.

Python 3.12+ can emit a DeprecationWarning from ``os.fork()`` in a
multi-threaded process. _spawn's fork sites honour the module's
fork-safety contract, so the warning is noise on this codebase — but
whether the interpreter emits it at all is environment-dependent, so
these pins emit the exact CI-observed message themselves and assert
each suppression layer swallows it:

* the module-level filter in core/sandbox/_spawn (covers production
  and CLI runs) — pinned in a bare subprocess with warnings escalated
  to errors;
* the pytest.ini ``filterwarnings`` entry (covers the test tiers,
  where pytest's per-test filter reset discards runtime-installed
  module filters — the mechanism that let the warning escape into
  nightly output) — pinned by running a warning-emitting test under
  the repo config and asserting an empty warnings summary.
"""

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]

# Verbatim shape of the CI-observed message (pid varies).
_MSG = ("This process (pid=4667) is multi-threaded, "
        "use of fork() may lead to deadlocks in the child.")

_MODULE_LAYER_CHILD = f"""
import warnings
import core.sandbox._spawn  # installs the module-level filter
warnings.warn({_MSG!r}, DeprecationWarning, stacklevel=2)
print("SUPPRESSED-OK")
"""


def test_module_filter_swallows_the_exact_message():
    r = subprocess.run(
        [sys.executable, "-W", "error::DeprecationWarning",
         "-c", _MODULE_LAYER_CHILD],
        capture_output=True, text=True, timeout=60,
        cwd=_REPO, env={**os.environ},
    )
    assert r.returncode == 0, f"stdout={r.stdout}\nstderr={r.stderr}"
    assert "SUPPRESSED-OK" in r.stdout


# Boots a whole nested pytest session under the repo config — the
# child interpreter + collection startup is the cost, and it is the
# mechanism under test; over the fast tier's budget.
@pytest.mark.slow
def test_pytest_config_swallows_the_exact_message(tmp_path):
    probe = tmp_path / "test_forkwarn_probe.py"
    probe.write_text(textwrap.dedent(f"""
        import warnings

        def test_emit():
            warnings.warn({_MSG!r}, DeprecationWarning, stacklevel=2)
    """))
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "-c", str(_REPO / "pytest.ini"),
         "-p", "no:cacheprovider", "-q", str(probe)],
        capture_output=True, text=True, timeout=120,
        cwd=_REPO, env={**os.environ},
    )
    assert r.returncode == 0, f"stdout={r.stdout}\nstderr={r.stderr}"
    assert "1 passed" in r.stdout
    assert "warnings summary" not in r.stdout, (
        "the fork DeprecationWarning escaped the pytest.ini filter:\n"
        + r.stdout
    )


@pytest.mark.parametrize("module", [
    "core.sandbox._landlock_audit",
    "core.sandbox._unix_scope",
])
def test_fork_site_modules_install_the_module_filter(module):
    """The Landlock-audit lane and the unix-scope probe fork too, and
    can do so CONCURRENTLY with _spawn sandboxes on other threads —
    per-fork ``warnings.catch_warnings()`` blocks there mutated the
    process-global filter list and raced (one thread's restore
    re-exposes another thread's fork mid-flight). Each fork-site
    module must install the module-level filter itself, in a bare
    interpreter that never imported _spawn."""
    child = (
        f"import warnings\n"
        f"import {module}\n"
        f"warnings.warn({_MSG!r}, DeprecationWarning, stacklevel=2)\n"
        f"print('SUPPRESSED-OK')\n"
    )
    r = subprocess.run(
        [sys.executable, "-W", "error::DeprecationWarning",
         "-c", child],
        capture_output=True, text=True, timeout=60,
        cwd=_REPO, env={**os.environ},
    )
    assert r.returncode == 0, f"stdout={r.stdout}\nstderr={r.stderr}"
    assert "SUPPRESSED-OK" in r.stdout


def test_fork_sites_carry_no_per_fork_catch_warnings():
    """Source pin: no production fork site may reintroduce the racy
    per-fork suppression block (module-level filters only)."""
    import inspect

    from core.sandbox import _landlock_audit, _unix_scope
    for mod in (_landlock_audit, _unix_scope):
        src = inspect.getsource(mod)
        for lineno, line in enumerate(src.splitlines(), start=1):
            stripped = line.split("#", 1)[0]
            assert "catch_warnings" not in stripped, (
                f"{mod.__name__}:{lineno} uses per-fork "
                f"warnings.catch_warnings() — use the module-level "
                f"filter instead: {line.strip()}"
            )
