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
        b'_step = b"create mount-point file"',
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
    step actually raised."""
    block = _read_extra_ro_block()
    # The fix replaces the literal "bind failed for" with bytes
    # concatenation that includes _step. Confirm neither the old
    # literal NOR a substring of it survives where the new pattern
    # should be — and confirm the new pattern is present.
    assert b"b\"RAPTOR: mount_ns: extra_ro_paths bind failed for \"" not in block.encode(), (
        "outer OSError handler still uses the pre-fix 'bind failed' "
        "literal; the step-aware diagnostic was reverted"
    )
    assert b"+ _step\n" in block.encode() or b"+ _step +" in block.encode(), (
        "outer OSError handler must include `_step` in the bytes "
        "concat composing the diagnostic message"
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
    import re
    str_assignments = re.findall(r'_step\s*=\s*"[^"]+"', block)
    assert not str_assignments, (
        f"_step assignments must be bytes (b\"...\") for fork-safety, "
        f"not str. Found str assignments: {str_assignments}"
    )
