"""Guards for the extra_ro_paths bind path in mount_ns.py.

Two groups:

1. Step-aware failure diagnostic. The fail-CLOSED handler on the
   extra_ro_paths bind path used to report any OSError inside the
   outer try as ``"extra_ro_paths bind failed (errno=N)"`` — but the
   same try block also runs ``os.makedirs`` and ``os.open``, whose
   errors were being misattributed to "bind". A ``_step`` local
   variable names which sub-operation is running, so the diagnostic
   reads ``"extra_ro_paths makedirs failed ..."`` when makedirs is
   the actual failure. These tests are static — they read
   ``mount_ns.py`` and assert the step-tracking machinery is present.
   Driving a real ``setup_mount_ns`` through the failure path
   requires Linux-only fork + namespace setup; those integration
   tests live in ``test_fork_safe_warn_sites.py`` and rely on a
   subprocess harness. The static guard catches silent regressions
   of the step diagnostic itself.

2. Path normalisation. ``extra_ro_paths`` entries get the same
   ``os.path.abspath`` normalisation as target/output, so a relative
   or non-normalised entry ("etc", "/tmp/../etc") can neither evade
   the exact-string ``_shadows_per_ns`` check nor produce a malformed
   bind target ("{root}etc"). The mount/pivot syscall wrappers are
   mocked; only the path logic and mount-point directory creation
   run for real.
"""

import os
import re
import sys as _sys
from pathlib import Path

import pytest

from core.sandbox import mount_ns


_MOUNT_NS = Path(__file__).resolve().parent.parent / "mount_ns.py"


def _read_extra_ro_block() -> str:
    """Return the slice of mount_ns.py that handles extra_ro_paths."""
    src = _MOUNT_NS.read_text()
    start = src.index("Bind any extra read-only paths")
    end = src.index("# 9. pivot_root")
    return src[start:end]


def test_step_variable_initialised_before_try():
    """_step must exist BEFORE the try so the outer except can read
    it. A late-initialised _step would NameError under the very
    OSError it's meant to diagnose."""
    block = _read_extra_ro_block()
    init_idx = block.index('_step = b"setup"')
    try_idx = block.index("try:")
    assert init_idx < try_idx, (
        "_step must be initialised before the try block; otherwise "
        "the outer except would NameError when OSError fires"
    )


def test_step_assignments_cover_all_failure_sites():
    """Every operation that can OSError inside the outer try must
    have a preceding _step assignment so the diagnostic names the
    right step. Removing any assignment regresses the step-diagnostic
    contract."""
    block = _read_extra_ro_block()
    # ASCII bytes labels per fork-safety design — non-ASCII would
    # require encoding work in the post-fork path.
    required_labels = [
        b'_step = b"makedirs"',
        b'_step = b"makedirs (parent)"',
        b'_step = b"open mount-point"',
        b'_step = b"bind"',
    ]
    block_b = block.encode()
    for label in required_labels:
        assert label in block_b, (
            f"mount_ns.py extra_ro_paths block must contain "
            f"`{label.decode()}` so the OSError diagnostic names "
            f"the failing step"
        )


def test_outer_except_diagnostic_uses_step_variable():
    """The outer OSError handler must compose its stderr bytes using
    the _step variable rather than a hardcoded 'bind failed' literal.
    Pre-fix the handler always said 'bind failed' regardless of which
    step actually raised.

    Shape-agnostic check: find the ``os.write(2, ...)`` call inside
    the outer except and confirm ``_step`` appears anywhere in its
    argument expression. This tolerates future refactors that swap
    the bytes-concat shape (``b'...' + _step + b'...'``,
    ``b'... %s ...' % _step``, ``b' '.join([..., _step, ...])``,
    f-string-then-encode, ...) as long as the contract — "the
    diagnostic includes the failing step's name" — is preserved.
    """
    block = _read_extra_ro_block()

    # The pre-fix literal must NOT appear — its presence would mean
    # the step-aware diagnostic was reverted to the original
    # always-says-bind form.
    assert (
        'b"RAPTOR: mount_ns: extra_ro_paths bind failed for "' not in block
    ), (
        "outer OSError handler still uses the pre-fix 'bind failed' "
        "literal; the step-aware diagnostic was reverted"
    )

    # Find every os.write(2, ...) call in the block and confirm at
    # least one has `_step` in its argument expression. The block
    # contains both real calls (in warn-only and fail-CLOSED handlers)
    # and bare `os.write(2, ...)` mentions in comments — succeed if
    # any of the real call sites references _step. DOTALL so the
    # args can span lines; non-greedy so we don't span multiple calls.
    write_calls = re.findall(
        r"os\.write\s*\(\s*2\s*,(.*?)\)",
        block,
        flags=re.DOTALL,
    )
    assert write_calls, (
        "outer OSError handler must contain an `os.write(2, ...)` "
        "call to surface the diagnostic"
    )
    assert any("_step" in args for args in write_calls), (
        "outer OSError handler's os.write(2, ...) call must reference "
        "`_step` somewhere in its argument expression so the diagnostic "
        "names the failing step (any bytes-concat shape is fine)"
    )


def test_step_labels_are_bytes_not_str():
    """For fork-safety the _step labels must be `bytes` (not `str`)
    so the post-fork bytes concat doesn't trigger encoding work.
    Encoding allocates and can take locks in cpython under specific
    locale configurations — defence-in-depth: keep the post-fork
    path strictly bytes."""
    block = _read_extra_ro_block()
    # The b"..." prefix on each _step assignment is what makes this
    # fork-safe. Search for any str-form _step assignment as a
    # regression marker.
    str_assignments = re.findall(r'_step\s*=\s*"[^"]+"', block)
    assert not str_assignments, (
        f"_step assignments must be bytes (b\"...\") for fork-safety, "
        f"not str. Found str assignments: {str_assignments}"
    )


# ---------------------------------------------------------------------------
# extra_ro_paths normalisation — Linux-only (runs setup_mount_ns with
# the mount/pivot syscall wrappers mocked out)
# ---------------------------------------------------------------------------

_linux_only = pytest.mark.skipif(
    _sys.platform != "linux",
    reason="mount-ns setup logic is Linux-only",
)


def _run_setup(monkeypatch, tmp_path, extra_ro_paths, cwd=None):
    mounts: list[tuple] = []
    monkeypatch.setattr(
        mount_ns, "_mount",
        lambda *a, **k: mounts.append(a),
    )
    monkeypatch.setattr(mount_ns, "_pivot_root", lambda *a: None)
    monkeypatch.setattr(mount_ns, "_umount", lambda *a, **k: None)
    for var in ("TMPDIR", "TEMP", "TMP"):
        monkeypatch.delenv(var, raising=False)
    root = tmp_path / "sbx-root"
    root.mkdir(exist_ok=True)
    saved_cwd = os.getcwd()
    try:
        if cwd is not None:
            os.chdir(cwd)
        mount_ns.setup_mount_ns(
            None, None,
            extra_ro_paths=extra_ro_paths,
            root_path=str(root),
        )
    finally:
        os.chdir(saved_cwd)
    return root, mounts


@_linux_only
def test_dotdot_entry_cannot_evade_shadow_check(monkeypatch, tmp_path):
    # "/tmp/../etc" normalises to "/etc", which is a per-ns
    # shadow path and must be skipped entirely.
    root, mounts = _run_setup(
        monkeypatch, tmp_path, ["/tmp/../etc"],
    )
    baseline_root, baseline = _run_setup(
        monkeypatch, tmp_path, None,
    )
    extra = [m for m in mounts if m[0] == "/tmp/../etc"
             or (m[1] and "/tmp/../etc" in str(m[1]))]
    assert extra == [], "non-normalised /etc alias was bind-mounted"
    assert len(mounts) == len(baseline), (
        "shadowed entry produced extra mounts"
    )


@_linux_only
def test_relative_entry_no_malformed_bind_target(monkeypatch, tmp_path):
    # A relative entry used to produce inside=f"{root}etc" — a
    # SIBLING of the sandbox root, not a path within it.
    (tmp_path / "etc").mkdir()
    root, mounts = _run_setup(
        monkeypatch, tmp_path, ["etc"], cwd=tmp_path,
    )
    malformed = str(root) + "etc"
    assert not os.path.exists(malformed)
    assert all(m[1] != malformed for m in mounts)
    # The normalised absolute path is what gets bound.
    expected_inside = f"{root}{tmp_path / 'etc'}"
    bound = [m for m in mounts if m[0] == str(tmp_path / "etc")]
    assert bound, "normalised entry was not bind-mounted at all"
    assert bound[0][1] == expected_inside


@_linux_only
def test_relative_and_absolute_spellings_equivalent(monkeypatch, tmp_path):
    (tmp_path / "ro").mkdir()
    _, rel_mounts = _run_setup(
        monkeypatch, tmp_path, ["ro"], cwd=tmp_path,
    )
    _, abs_mounts = _run_setup(
        monkeypatch, tmp_path, [str(tmp_path / "ro")],
    )
    rel_targets = sorted(m[1] for m in rel_mounts if m[1])
    abs_targets = sorted(m[1] for m in abs_mounts if m[1])
    assert rel_targets == abs_targets
