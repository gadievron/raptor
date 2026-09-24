"""Unit tests: TU-local caller-held-lock witness (core.audit.caller_lock).

The witness may claim ``held=True`` only when the reviewed function is
verifiably static with a TU-complete caller set and EVERY call site
holds one consistently-identified lock across the call.  These tests
pin the positive anchor shape (a static collapse-range helper whose
single caller is a fallocate-style dispatcher holding the inode lock
at function scope across the call) and — most importantly — every red-team
shape where the caller-held-serialization claim is FALSE or
undecidable: each must refuse.
"""

from __future__ import annotations

from pathlib import Path

from core.audit.caller_lock import (
    CallerLockResult,
    check_caller_lock_serialization,
)

# ---------------------------------------------------------------------------
# Fixtures: a fallocate-shaped TU (static callee, caller-held inode lock)
# ---------------------------------------------------------------------------

CALLEE = """\
static int sample_collapse_range(struct inode *inode, loff_t offset,
\t\t\t\t loff_t len)
{
\tif (offset + len >= i_size_read(inode))
\t\treturn -EINVAL;
\treturn do_collapse(inode, offset, len);
}
"""

CALLER_LOCKED = """
static int punch_hole(struct inode *inode, loff_t offset, loff_t len)
{
\tif (offset >= i_size_read(inode))
\t\treturn -EINVAL;
\treturn do_punch(inode, offset, len);
}

long sample_fallocate(struct file *file, int mode, loff_t offset,
\t\t      loff_t len)
{
\tstruct inode *inode = file_inode(file);
\tlong ret;

\tif (!S_ISREG(inode->i_mode))
\t\treturn -EINVAL;

\tinode_lock(inode);

\tif (mode & FALLOC_FL_PUNCH_HOLE) {
\t\tret = punch_hole(inode, offset, len);
\t} else if (mode & FALLOC_FL_COLLAPSE_RANGE) {
\t\tret = sample_collapse_range(inode, offset, len);
\t} else {
\t\tret = -EOPNOTSUPP;
\t}

\tinode_unlock(inode);
\treturn ret;
}
"""

REL = "fs/sample/file.c"


def _run(
    tmp_path: Path,
    tu_text: str,
    *,
    callee: str = CALLEE,
    extra_files: dict[str, str] | None = None,
    name: str = "sample_collapse_range",
    rel: str = REL,
) -> CallerLockResult:
    root = tmp_path / "target"
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(tu_text)
    for rpath, text in (extra_files or {}).items():
        fp = root / rpath
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_text(text)
    return check_caller_lock_serialization(
        callee, name, rel_file=rel, target_path=root,
    )


# ---------------------------------------------------------------------------
# The witness holds
# ---------------------------------------------------------------------------


class TestHolds:
    def test_anchor_shape_holds(self, tmp_path):
        r = _run(tmp_path, CALLEE + CALLER_LOCKED)
        assert r.held
        assert r.lock_class == "inode_lock"
        assert r.lock_object == "inode"
        assert r.call_sites == 1
        assert r.callers == ("sample_fallocate",)

    def test_two_callers_same_lock_hold(self, tmp_path):
        second = (
            "\nlong sample_punch(struct file *file, loff_t offset, "
            "loff_t len)\n{\n"
            "\tstruct inode *inode = file_inode(file);\n"
            "\tlong ret;\n"
            "\tinode_lock(inode);\n"
            "\tret = sample_collapse_range(inode, offset, len);\n"
            "\tinode_unlock(inode);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + CALLER_LOCKED + second)
        assert r.held
        assert r.call_sites == 2
        assert set(r.callers) == {"sample_fallocate", "sample_punch"}

    def test_label_after_call_is_fine(self, tmp_path):
        # Kernel error-label style: `goto out` targets AFTER the call
        # do not break acquire-dominance (paths through them never
        # reach the call without passing the acquire).
        caller = (
            "\nlong sample_fallocate(struct file *file, int mode, "
            "loff_t offset, loff_t len)\n{\n"
            "\tstruct inode *inode = file_inode(file);\n"
            "\tlong ret = -EINVAL;\n"
            "\tinode_lock(inode);\n"
            "\tif (mode & FALLOC_FL_UNSUPPORTED)\n"
            "\t\tgoto out;\n"
            "\tret = sample_collapse_range(inode, offset, len);\n"
            "out:\n"
            "\tinode_unlock(inode);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + caller)
        assert r.held

    def test_result_serialises(self, tmp_path):
        r = _run(tmp_path, CALLEE + CALLER_LOCKED)
        d = r.to_dict()
        assert d["held"] is True
        assert d["lock_class"] == "inode_lock"
        assert d["callers"] == ["sample_fallocate"]


# ---------------------------------------------------------------------------
# Red team: the claim is FALSE — every shape must refuse
# ---------------------------------------------------------------------------


class TestRefusesFalseClaims:
    def test_second_caller_without_lock(self, tmp_path):
        unlocked = (
            "\nlong sample_ioctl(struct inode *inode, loff_t offset, "
            "loff_t len)\n{\n"
            "\treturn sample_collapse_range(inode, offset, len);\n}\n"
        )
        r = _run(tmp_path, CALLEE + CALLER_LOCKED + unlocked)
        assert not r.held
        assert "no dominating caller-held lock" in r.reasoning

    def test_address_taken_callback_registration(self, tmp_path):
        ops = (
            "\nstatic const struct collapse_ops ops = {\n"
            "\t.collapse = sample_collapse_range,\n};\n"
        )
        r = _run(tmp_path, CALLEE + CALLER_LOCKED + ops)
        assert not r.held
        assert "address-taken" in r.reasoning

    def test_export_symbol_escape(self, tmp_path):
        r = _run(
            tmp_path,
            CALLEE + CALLER_LOCKED
            + "\nEXPORT_SYMBOL(sample_collapse_range);\n",
        )
        assert not r.held
        assert "address-taken" in r.reasoning

    def test_callers_hold_different_lock_objects(self, tmp_path):
        other = (
            "\nlong sample_other(struct inode *inode, struct inode "
            "*peer, loff_t offset, loff_t len)\n{\n"
            "\tlong ret;\n"
            "\tinode_lock(peer);\n"
            "\tret = sample_collapse_range(inode, offset, len);\n"
            "\tinode_unlock(peer);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + CALLER_LOCKED + other)
        assert not r.held

    def test_callers_hold_different_lock_classes(self, tmp_path):
        # Both locks are argument-bound, but the classes/objects never
        # intersect across sites — lock identity is ambiguous.
        other = (
            "\nlong sample_other(struct inode *inode, loff_t offset, "
            "loff_t len)\n{\n"
            "\tlong ret;\n"
            "\tmutex_lock(&inode->i_mtx);\n"
            "\tret = sample_collapse_range(inode, offset, len);\n"
            "\tmutex_unlock(&inode->i_mtx);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + CALLER_LOCKED + other)
        assert not r.held
        assert "ambiguous" in r.reasoning

    def test_lock_released_before_the_call(self, tmp_path):
        caller = (
            "\nlong sample_fallocate(struct file *file, int mode, "
            "loff_t offset, loff_t len)\n{\n"
            "\tstruct inode *inode = file_inode(file);\n"
            "\tlong ret;\n"
            "\tinode_lock(inode);\n"
            "\tupdate_time(inode);\n"
            "\tinode_unlock(inode);\n"
            "\tret = sample_collapse_range(inode, offset, len);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + caller)
        assert not r.held

    def test_non_static_function(self, tmp_path):
        ns_callee = CALLEE.replace(
            "static int sample_collapse_range",
            "int sample_collapse_range",
        )
        r = _run(tmp_path, ns_callee + CALLER_LOCKED, callee=ns_callee)
        assert not r.held
        assert "not verifiably static" in r.reasoning

    def test_conditional_lock_acquire(self, tmp_path):
        caller = (
            "\nlong sample_fallocate(struct file *file, int mode, "
            "loff_t offset, loff_t len)\n{\n"
            "\tstruct inode *inode = file_inode(file);\n"
            "\tlong ret;\n"
            "\tif (mode & FALLOC_FL_LOCKED) {\n"
            "\t\tinode_lock(inode);\n"
            "\t}\n"
            "\tret = sample_collapse_range(inode, offset, len);\n"
            "\tif (mode & FALLOC_FL_LOCKED)\n"
            "\t\tinode_unlock(inode);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + caller)
        assert not r.held

    def test_statement_embedded_trylock_acquire(self, tmp_path):
        caller = (
            "\nlong sample_fallocate(struct file *file, int mode, "
            "loff_t offset, loff_t len)\n{\n"
            "\tstruct inode *inode = file_inode(file);\n"
            "\tlong ret;\n"
            "\tif (mutex_lock_interruptible(&inode->i_mtx))\n"
            "\t\treturn -EINTR;\n"
            "\tret = sample_collapse_range(inode, offset, len);\n"
            "\tmutex_unlock(&inode->i_mtx);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + caller)
        assert not r.held

    def test_label_between_acquire_and_call(self, tmp_path):
        caller = (
            "\nlong sample_fallocate(struct file *file, int mode, "
            "loff_t offset, loff_t len)\n{\n"
            "\tstruct inode *inode = file_inode(file);\n"
            "\tlong ret;\n"
            "\tinode_lock(inode);\n"
            "retry:\n"
            "\tret = sample_collapse_range(inode, offset, len);\n"
            "\tif (ret == -EAGAIN)\n"
            "\t\tgoto retry;\n"
            "\tinode_unlock(inode);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + caller)
        assert not r.held

    def test_goto_can_skip_the_acquire(self, tmp_path):
        caller = (
            "\nlong sample_fallocate(struct file *file, int mode, "
            "loff_t offset, loff_t len)\n{\n"
            "\tstruct inode *inode = file_inode(file);\n"
            "\tlong ret;\n"
            "\tif (mode & FALLOC_FL_NOLOCK)\n"
            "\t\tgoto direct;\n"
            "\tinode_lock(inode);\n"
            "direct:\n"
            "\tret = sample_collapse_range(inode, offset, len);\n"
            "\tinode_unlock(inode);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + caller)
        assert not r.held

    def test_callee_releases_the_lock_itself(self, tmp_path):
        callee = CALLEE.replace(
            "\treturn do_collapse(inode, offset, len);",
            "\tinode_unlock(inode);\n"
            "\tret = do_collapse(inode, offset, len);\n"
            "\tinode_lock(inode);\n"
            "\treturn ret;",
        )
        r = _run(tmp_path, callee + CALLER_LOCKED, callee=callee)
        assert not r.held
        assert "touches the inode_lock lock class" in r.reasoning

    def test_lock_object_not_reaching_the_callee(self, tmp_path):
        # The caller holds a lock, but on state unrelated to any
        # argument — per-object serialisation proves nothing about
        # the callee's own state handle.
        caller = (
            "\nlong sample_fallocate(struct sbi *sbi, struct inode "
            "*inode, loff_t offset, loff_t len)\n{\n"
            "\tlong ret;\n"
            "\tmutex_lock(&sbi->mtx);\n"
            "\tret = sample_collapse_range(inode, offset, len);\n"
            "\tmutex_unlock(&sbi->mtx);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + caller)
        assert not r.held

    def test_lock_object_rebound_between_acquire_and_call(self, tmp_path):
        caller = (
            "\nlong sample_fallocate(struct file *file, int mode, "
            "loff_t offset, loff_t len)\n{\n"
            "\tstruct inode *inode = file_inode(file);\n"
            "\tlong ret;\n"
            "\tinode_lock(inode);\n"
            "\tinode = next_inode(inode);\n"
            "\tret = sample_collapse_range(inode, offset, len);\n"
            "\tinode_unlock(inode);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + caller)
        assert not r.held

    def test_loop_backedge_after_release_refuses(self, tmp_path):
        # Acquire before a loop, call inside it, release after the
        # call inside the loop body: the SECOND iteration reaches the
        # call without the lock, and the release sits textually after
        # the call where a linear between-scan cannot see it.  Any
        # loop keyword between acquire and call must refuse.
        caller = (
            "\nlong sample_batch(struct inode *inode, int n)\n{\n"
            "\tlong ret = 0;\n"
            "\tinode_lock(inode);\n"
            "\twhile (n-- > 0) {\n"
            "\t\tret = sample_collapse_range(inode, 0, 0);\n"
            "\t\tinode_unlock(inode);\n"
            "\t\tcond_resched();\n"
            "\t}\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + caller)
        assert not r.held

    def test_for_loop_between_acquire_and_call_refuses(self, tmp_path):
        caller = (
            "\nlong sample_batch(struct inode *inode, int n)\n{\n"
            "\tlong ret = 0;\n"
            "\tint i;\n"
            "\tinode_lock(inode);\n"
            "\tfor (i = 0; i < n; i++) {\n"
            "\t\tret = sample_collapse_range(inode, i, 0);\n"
            "\t\tinode_unlock(inode);\n"
            "\t\tinode_lock(inode);\n"
            "\t}\n"
            "\tinode_unlock(inode);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + caller)
        assert not r.held

    def test_callee_with_local_static_state(self, tmp_path):
        callee = CALLEE.replace(
            "\tif (offset + len",
            "\tstatic int calls;\n\tcalls++;\n\tif (offset + len",
        )
        r = _run(tmp_path, callee + CALLER_LOCKED, callee=callee)
        assert not r.held
        assert "local static state" in r.reasoning

    def test_callee_with_midline_local_static_state(self, tmp_path):
        # `int tmp = 0; static int counter;` — the static does not
        # start its line but is still function-local shared state.
        callee = CALLEE.replace(
            "\tif (offset + len",
            "\tint tmp = 0; static int counter;\n\tcounter += tmp;\n"
            "\tif (offset + len",
        )
        r = _run(tmp_path, callee + CALLER_LOCKED, callee=callee)
        assert not r.held
        assert "local static state" in r.reasoning

    def test_local_static_probe_linear_on_blank_run(self) -> None:
        """The static-state probe runs over attacker-shaped function
        source under MULTILINE.  A ``(?:^|[;{}])\\s*`` boundary gap
        re-scans a run of blank lines from every line start inside it
        — quadratic (seconds at 64K).  The horizontal gap is linear,
        and a ``static`` after the boundary — same line or a later
        line — is still matched."""
        import time

        from core.audit.caller_lock import _LOCAL_STATIC_RE

        start = time.monotonic()
        assert _LOCAL_STATIC_RE.search("{" + "\n" * (1 << 18)) is None
        assert time.monotonic() - start < 1.0
        # Behavior pins: statement-start statics still match ...
        for body in (
            "{\n\tstatic int calls;\n}",
            "{ int tmp = 0; static int counter; }",
            "{\n\tint a;\n\n\n\tstatic int b;\n}",
            "{ };static int c;",
        ):
            assert _LOCAL_STATIC_RE.search(body) is not None, body
        # ... and non-statement-start identifiers still do not.
        assert _LOCAL_STATIC_RE.search("{ int nonstatic = 1; }") is None

    def test_braceless_if_acquire_refuses(self, tmp_path):
        # A braceless `if` guard adds no brace: the guarded acquire
        # sits at depth 1 on its own line but is CONDITIONAL.
        caller = (
            "\nlong sample_fallocate(struct file *file, int mode, "
            "loff_t offset, loff_t len)\n{\n"
            "\tstruct inode *inode = file_inode(file);\n"
            "\tlong ret;\n"
            "\tif (mode & FALLOC_FL_LOCKED)\n"
            "\t\tinode_lock(inode);\n"
            "\tret = sample_collapse_range(inode, offset, len);\n"
            "\tif (mode & FALLOC_FL_LOCKED)\n"
            "\t\tinode_unlock(inode);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + caller)
        assert not r.held

    def test_label_after_code_on_same_line_refuses(self, tmp_path):
        # `if (redo) { note(); } again:` hides a goto entry point
        # mid-line between the acquire and the call.
        caller = (
            "\nlong sample_fallocate(struct file *file, int mode, "
            "loff_t offset, loff_t len)\n{\n"
            "\tstruct inode *inode = file_inode(file);\n"
            "\tlong ret;\n"
            "\tinode_lock(inode);\n"
            "\tif (mode) { note(); } again:\n"
            "\tret = sample_collapse_range(inode, offset, len);\n"
            "\tinode_unlock(inode);\n"
            "\tif (retry_needed(inode))\n"
            "\t\tgoto again;\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + caller)
        assert not r.held

    def test_ifdef_braces_in_caller_refuse(self, tmp_path):
        # Braces under #ifdef decouple the textual brace count from
        # the compiled control structure — depth is untrustworthy.
        caller = (
            "\nlong sample_fallocate(struct file *file, int mode, "
            "loff_t offset, loff_t len)\n{\n"
            "\tstruct inode *inode = file_inode(file);\n"
            "\tlong ret;\n"
            "\tif (mode) {\n"
            "#ifdef CONFIG_NEVER\n"
            "\t}\n"
            "#endif\n"
            "\t\tinode_lock(inode);\n"
            "#ifdef CONFIG_NEVER\n"
            "\t{\n"
            "#endif\n"
            "\t}\n"
            "\tret = sample_collapse_range(inode, offset, len);\n"
            "\tinode_unlock(inode);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + caller)
        assert not r.held

    def test_lock_object_pointer_bump_refuses(self, tmp_path):
        # `inode++` between acquire and call rebinds the lock object
        # without a `=` — arithmetic bumps must refuse too.
        second = (
            "\nlong sample_other(struct inode *inode, loff_t offset, "
            "loff_t len)\n{\n"
            "\tlong ret;\n"
            "\tinode_lock(inode);\n"
            "\tinode++;\n"
            "\tret = sample_collapse_range(inode, offset, len);\n"
            "\tinode--;\n"
            "\tinode_unlock(inode);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + CALLER_LOCKED + second)
        assert not r.held

    def test_wrapper_release_between_acquire_and_call_refuses(
        self, tmp_path,
    ):
        # A one-line TU-local helper hides the release from the
        # literal unlock-name scan.
        tu = (
            "static void give_up_lock(struct inode *inode)\n{\n"
            "\tinode_unlock(inode);\n}\n\n" + CALLEE +
            "\nlong sample_fallocate(struct file *file, int mode, "
            "loff_t offset, loff_t len)\n{\n"
            "\tstruct inode *inode = file_inode(file);\n"
            "\tlong ret;\n"
            "\tinode_lock(inode);\n"
            "\tgive_up_lock(inode);\n"
            "\tret = sample_collapse_range(inode, offset, len);\n"
            "\tinode_lock(inode);\n"
            "\tinode_unlock(inode);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, tu)
        assert not r.held

    def test_drop_lock_macro_refuses(self, tmp_path):
        # A drop-the-lock-around-expression macro: the release lives
        # in the #define body, out of the between-scan's view.
        tu = (
            "#define UNLOCKED(inode, expr) do { inode_unlock(inode); "
            "expr; inode_lock(inode); } while (0)\n\n" + CALLEE +
            "\nlong sample_fallocate(struct file *file, int mode, "
            "loff_t offset, loff_t len)\n{\n"
            "\tstruct inode *inode = file_inode(file);\n"
            "\tlong ret;\n"
            "\tinode_lock(inode);\n"
            "\tUNLOCKED(inode, ret = sample_collapse_range(inode, "
            "offset, len));\n"
            "\tinode_unlock(inode);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, tu)
        assert not r.held

    def test_overlong_call_line_refuses(self, tmp_path):
        # The pre-call fragment of an over-long call line is silently
        # left-truncated upstream — a release could hide in it.
        pad = " " * 2500
        caller = (
            "\nlong sample_fallocate(struct file *file, int mode, "
            "loff_t offset, loff_t len)\n{\n"
            "\tstruct inode *inode = file_inode(file);\n"
            "\tlong ret;\n"
            "\tinode_lock(inode);\n"
            f"\tinode_unlock(inode);{pad}"
            "ret = sample_collapse_range(inode, offset, len);\n"
            "\tinode_lock(inode);\n"
            "\tinode_unlock(inode);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + caller)
        assert not r.held

    def test_digraph_braces_refuse(self, tmp_path):
        caller = (
            "\nlong sample_fallocate(struct file *file, int mode, "
            "loff_t offset, loff_t len)\n{\n"
            "\tstruct inode *inode = file_inode(file);\n"
            "\tlong ret;\n"
            "\tif (mode) <%\n"
            "\t\tinode_lock(inode);\n"
            "\t%>\n"
            "\tret = sample_collapse_range(inode, offset, len);\n"
            "\tif (mode) <%\n"
            "\t\tinode_unlock(inode);\n"
            "\t%>\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + caller)
        assert not r.held
        assert "digraph" in r.reasoning


# ---------------------------------------------------------------------------
# Red team: TU-completeness cannot be established — must refuse
# ---------------------------------------------------------------------------


class TestRefusesUndecidable:
    def test_overlong_argument_list_caller_refuses(self, tmp_path):
        # A call whose argument list overflows the span bound is
        # dropped by the enumerator — an UNLOCKED caller can hide
        # behind one planted over-long call, so the witness must
        # refuse rather than certify the surviving (locked) sites as
        # the whole caller set.
        args = ", ".join(f"arg_{i:04d}" for i in range(600))
        evil = (
            "\nvoid evil_caller(struct inode *inode)\n{\n"
            f"\tsample_collapse_range(inode, {args});\n"
            "}\n"
        )
        r = _run(tmp_path, CALLEE + CALLER_LOCKED + evil)
        assert not r.held
        assert "span bound" in r.reasoning


    def test_name_referenced_in_another_file(self, tmp_path):
        r = _run(
            tmp_path, CALLEE + CALLER_LOCKED,
            extra_files={
                "fs/sample/other.c": (
                    "extern int sample_collapse_range(struct inode *, "
                    "loff_t, loff_t);\n"
                ),
            },
        )
        assert not r.held
        assert "outside the TU" in r.reasoning

    def test_defining_file_included_elsewhere(self, tmp_path):
        r = _run(
            tmp_path, CALLEE + CALLER_LOCKED,
            extra_files={"fs/sample/wrap.c": '#include "file.c"\n'},
        )
        assert not r.held
        assert "include/define path" in r.reasoning

    def test_macro_naming_the_function(self, tmp_path):
        tu = (
            "#define collapse(i, o, l) "
            "sample_collapse_range(i, o, l)\n" + CALLEE + CALLER_LOCKED
        )
        r = _run(tmp_path, tu)
        assert not r.held
        assert "preprocessor" in r.reasoning

    def test_multiline_macro_continuation_naming_the_function(
        self, tmp_path,
    ):
        tu = (
            "#define collapse(i, o, l) \\\n"
            "\tsample_collapse_range(i, o, l)\n" + CALLEE + CALLER_LOCKED
        )
        r = _run(tmp_path, tu)
        assert not r.held
        assert "preprocessor" in r.reasoning

    def test_comment_mention_elsewhere_is_not_a_reference(self, tmp_path):
        # Sanitized view: a comment naming the function in another
        # file is not a cross-TU reference.
        r = _run(
            tmp_path, CALLEE + CALLER_LOCKED,
            extra_files={
                "fs/sample/other.c": (
                    "/* see sample_collapse_range for the collapse "
                    "path */\nint unrelated(void)\n{\n\treturn 0;\n}\n"
                ),
            },
        )
        assert r.held

    def test_recursion_refuses(self, tmp_path):
        callee = CALLEE.replace(
            "\treturn do_collapse(inode, offset, len);",
            "\tif (offset)\n"
            "\t\treturn sample_collapse_range(inode, 0, len);\n"
            "\treturn do_collapse(inode, offset, len);",
        )
        r = _run(tmp_path, callee + CALLER_LOCKED, callee=callee)
        assert not r.held
        assert "recursive" in r.reasoning

    def test_zero_call_sites_refuses(self, tmp_path):
        r = _run(tmp_path, CALLEE)
        assert not r.held
        assert "no TU-local call sites" in r.reasoning

    def test_two_definitions_refuse(self, tmp_path):
        tu = (
            "#ifdef CONFIG_A\n" + CALLEE + "#else\n" + CALLEE + "#endif\n"
            + CALLER_LOCKED
        )
        r = _run(tmp_path, tu)
        assert not r.held

    def test_setjmp_in_caller_refuses(self, tmp_path):
        tu = CALLEE + CALLER_LOCKED.replace(
            "\tinode_lock(inode);",
            "\tsetjmp(env);\n\tinode_lock(inode);",
        )
        r = _run(tmp_path, tu)
        assert not r.held
        assert "non-linear" in r.reasoning

    def test_missing_defining_file_refuses(self, tmp_path):
        (tmp_path / "target").mkdir()
        r = check_caller_lock_serialization(
            CALLEE, "sample_collapse_range",
            rel_file=REL, target_path=tmp_path / "target",
        )
        assert not r.held

    def test_go_source_refuses(self, tmp_path):
        r = _run(
            tmp_path, CALLEE + CALLER_LOCKED,
            callee="func Scan() error {\n\treturn nil\n}\n",
        )
        assert not r.held
        assert "Go source" in r.reasoning

    def test_non_c_translation_unit_refuses(self, tmp_path):
        r = _run(
            tmp_path, CALLEE + CALLER_LOCKED, rel="fs/sample/file.go",
        )
        assert not r.held
        assert "not a C translation unit" in r.reasoning

    def test_empty_source_refuses(self, tmp_path):
        r = _run(tmp_path, CALLEE + CALLER_LOCKED, callee="  \n")
        assert not r.held

    def test_bad_function_name_refuses(self, tmp_path):
        r = _run(tmp_path, CALLEE + CALLER_LOCKED, name="Obj.Method")
        assert not r.held
        assert "not a plain C function name" in r.reasoning

    def test_call_site_cap_refuses(self, tmp_path, monkeypatch):
        import core.audit.caller_lock as cl

        monkeypatch.setattr(cl, "_MAX_CALL_SITES", 1)
        second = (
            "\nlong sample_punch(struct file *file, loff_t offset, "
            "loff_t len)\n{\n"
            "\tstruct inode *inode = file_inode(file);\n"
            "\tlong ret;\n"
            "\tinode_lock(inode);\n"
            "\tret = sample_collapse_range(inode, offset, len);\n"
            "\tinode_unlock(inode);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + CALLER_LOCKED + second)
        assert not r.held
        assert "cap" in r.reasoning

    def test_tree_scan_cap_refuses(self, tmp_path, monkeypatch):
        import core.audit.caller_lock as cl

        monkeypatch.setattr(cl, "_MAX_SCAN_FILES", 1)
        r = _run(
            tmp_path, CALLEE + CALLER_LOCKED,
            extra_files={"fs/sample/aaa.c": "int unrelated(void);\n"},
        )
        assert not r.held
        assert "cap" in r.reasoning

    def test_header_inline_interval_callee_clears(self, tmp_path):
        # A static inline defined in a quoted header the TU #includes
        # is TU code: an interval call to it resolves to its real
        # body, which is inspected (and here clean), so the witness
        # holds.
        header = (
            "#ifndef SAMPLE_H\n#define SAMPLE_H\n\n"
            "static inline int sample_is_pinned(struct inode *inode)\n"
            "{\n\treturn inode->i_flags & 0x10;\n}\n\n#endif\n"
        )
        caller = (
            "\nlong sample_fallocate(struct file *file, int mode, "
            "loff_t offset, loff_t len)\n{\n"
            "\tstruct inode *inode = file_inode(file);\n"
            "\tlong ret;\n"
            "\tinode_lock(inode);\n"
            "\tif (sample_is_pinned(inode))\n"
            "\t\tret = -EINVAL;\n"
            "\telse\n"
            "\t\tret = sample_collapse_range(inode, offset, len);\n"
            "\tinode_unlock(inode);\n"
            "\treturn ret;\n}\n"
        )
        tu = '#include "sample.h"\n' + CALLEE + caller
        r = _run(
            tmp_path, tu,
            extra_files={"fs/sample/sample.h": header},
        )
        assert r.held

    def test_header_inline_touching_lock_refuses(self, tmp_path):
        # Same shape, but the header inline RELEASES the lock — its
        # body is inspected and the interval call refuses.
        header = (
            "#ifndef SAMPLE_H\n#define SAMPLE_H\n\n"
            "static inline int sample_is_pinned(struct inode *inode)\n"
            "{\n\tinode_unlock(inode);\n"
            "\treturn inode->i_flags & 0x10;\n}\n\n#endif\n"
        )
        caller = (
            "\nlong sample_fallocate(struct file *file, int mode, "
            "loff_t offset, loff_t len)\n{\n"
            "\tstruct inode *inode = file_inode(file);\n"
            "\tlong ret;\n"
            "\tinode_lock(inode);\n"
            "\tif (sample_is_pinned(inode))\n"
            "\t\tret = -EINVAL;\n"
            "\telse\n"
            "\t\tret = sample_collapse_range(inode, offset, len);\n"
            "\tinode_lock(inode);\n"
            "\tinode_unlock(inode);\n"
            "\treturn ret;\n}\n"
        )
        tu = '#include "sample.h"\n' + CALLEE + caller
        r = _run(
            tmp_path, tu,
            extra_files={"fs/sample/sample.h": header},
        )
        assert not r.held

    def test_seeded_waiter_in_interval_holds(self, tmp_path):
        # inode_dio_wait is on the adjudicated non-lock-touching
        # seed: the interval call it would otherwise refuse under
        # the out-of-TU rule is cleared — and only that call.
        caller = (
            "\nlong sample_fallocate(struct file *file, int mode, "
            "loff_t offset, loff_t len)\n{\n"
            "\tstruct inode *inode = file_inode(file);\n"
            "\tlong ret;\n"
            "\tinode_lock(inode);\n"
            "\tinode_dio_wait(inode);\n"
            "\tret = sample_collapse_range(inode, offset, len);\n"
            "\tinode_unlock(inode);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + caller)
        assert r.held

    def test_unseeded_extern_in_interval_refuses(self, tmp_path):
        # An extern helper NOT on the seed receiving the lock base
        # refuses — it could release the lock out of view.
        caller = (
            "\nlong sample_fallocate(struct file *file, int mode, "
            "loff_t offset, loff_t len)\n{\n"
            "\tstruct inode *inode = file_inode(file);\n"
            "\tlong ret;\n"
            "\tinode_lock(inode);\n"
            "\taudit_note(inode);\n"
            "\tret = sample_collapse_range(inode, offset, len);\n"
            "\tinode_unlock(inode);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + caller)
        assert not r.held

    def test_seed_cannot_rescue_other_interval_violations(
        self, tmp_path,
    ):
        # A seeded call PLUS a literal release in the interval: the
        # seed clears only its own call — the release still refuses.
        caller = (
            "\nlong sample_fallocate(struct file *file, int mode, "
            "loff_t offset, loff_t len)\n{\n"
            "\tstruct inode *inode = file_inode(file);\n"
            "\tlong ret;\n"
            "\tinode_lock(inode);\n"
            "\tinode_dio_wait(inode);\n"
            "\tinode_unlock(inode);\n"
            "\tret = sample_collapse_range(inode, offset, len);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + caller)
        assert not r.held

    def test_seed_cannot_rescue_unseeded_companion_call(self, tmp_path):
        caller = (
            "\nlong sample_fallocate(struct file *file, int mode, "
            "loff_t offset, loff_t len)\n{\n"
            "\tstruct inode *inode = file_inode(file);\n"
            "\tlong ret;\n"
            "\tinode_lock(inode);\n"
            "\tinode_dio_wait(inode);\n"
            "\taudit_note(inode);\n"
            "\tret = sample_collapse_range(inode, offset, len);\n"
            "\tinode_unlock(inode);\n"
            "\treturn ret;\n}\n"
        )
        r = _run(tmp_path, CALLEE + caller)
        assert not r.held

    def test_non_header_include_refuses(self, tmp_path):
        # A textual `.inc` include can splice an unlocked caller into
        # the TU that neither the call-site enumeration nor the
        # suffix-filtered tree scan attributes here.
        tu = CALLEE + CALLER_LOCKED + '\n#include "extra.inc"\n'
        r = _run(
            tmp_path, tu,
            extra_files={
                "fs/sample/extra.inc": (
                    "long bad_caller(struct inode *inode)\n{\n"
                    "\treturn 0;\n}\n"
                ),
            },
        )
        assert not r.held
        assert "non-header #include" in r.reasoning

    def test_name_in_non_source_file_refuses(self, tmp_path):
        # The name appearing in ANY other file — a .inc fragment, an
        # assembly file, a build script — makes TU-locality
        # unverifiable.
        r = _run(
            tmp_path, CALLEE + CALLER_LOCKED,
            extra_files={
                "fs/sample/callers.inc": (
                    "long bad_caller(struct inode *inode)\n{\n"
                    "\treturn sample_collapse_range(inode, 0, 0);\n}\n"
                ),
            },
        )
        assert not r.held

    def test_line_splice_in_defining_file_refuses(self, tmp_path):
        # A backslash-newline outside a preprocessor directive can
        # split a call site's name across lines, hiding it from every
        # textual scanner while still compiling as a real call.
        tu = (
            CALLEE + CALLER_LOCKED +
            "\nlong sneaky_caller(struct inode *inode)\n{\n"
            "\tsample_col\\\nlapse_range(inode, 0, 0);\n"
            "\treturn 0;\n}\n"
        )
        r = _run(tmp_path, tu)
        assert not r.held
        assert "line-splice" in r.reasoning


class TestDefiningFileContainment:
    """The witness's defining-file read is contained: rel_file
    arrives from finding records, so absolute and ../ values must
    refuse instead of joining out of the target root."""

    def test_escaping_rel_file_refuses_without_reading(self, tmp_path):
        import sys

        target = tmp_path / "target"
        target.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        secret = outside / "evil.c"
        secret.write_text(
            "static void locked_cb(void) { }\n"
            "void call(void) { locked_cb(); }\n",
        )
        opened: list = []

        def hook(event, args):
            if event == "open" and args and str(secret) in str(args[0]):
                opened.append(args)

        sys.addaudithook(hook)
        for rel in (str(secret), "../outside/evil.c"):
            res = check_caller_lock_serialization(
                "static void locked_cb(void) { }\n",
                "locked_cb",
                rel_file=rel,
                target_path=target,
            )
            assert res.held is False
            assert "not found" in res.reasoning
        assert opened == [], (
            "out-of-root defining file was opened by the caller-lock "
            "witness"
        )

    def test_in_tree_fifo_refuses_instead_of_wedging(self, tmp_path):
        import multiprocessing
        import os

        os.mkfifo(tmp_path / "wedge.c")
        child = multiprocessing.Process(
            target=check_caller_lock_serialization,
            args=("static void f(void) { }\n", "f"),
            kwargs={"rel_file": "wedge.c", "target_path": tmp_path},
        )
        child.start()
        child.join(timeout=20)
        try:
            assert not child.is_alive(), (
                "check_caller_lock_serialization blocked on an "
                "in-tree FIFO"
            )
        finally:
            if child.is_alive():
                child.kill()
                child.join()
