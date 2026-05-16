"""Static guards for the W36.K.2 step-aware diagnostic in mount_ns.py.

The W36.E.1 fail-CLOSED handler on the extra_ro_paths bind path used
to report any OSError inside the outer try as
``"extra_ro_paths bind failed (errno=N)"`` — but the same try block
also runs ``os.makedirs`` and ``os.open``, whose errors were being
misattributed to "bind". W36.K.2 introduces a ``_step`` local variable
that names which sub-operation is running, so the diagnostic reads
``"extra_ro_paths makedirs failed ..."`` when makedirs is the actual
failure.

These tests are static — they read ``mount_ns.py`` and assert the
step-tracking machinery is present. Driving a real ``setup_mount_ns``
through the failure path requires Linux-only fork + namespace setup;
those integration tests live in ``test_fork_safe_warn_sites.py``
(F063b) and rely on a subprocess harness. For W36.K.2 the static
guard is sufficient: it catches silent regressions of the step
diagnostic itself, which is the contract this commit added.
"""

import re
from pathlib import Path


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
    right step. Removing any assignment regresses the contract this
    commit added."""
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
