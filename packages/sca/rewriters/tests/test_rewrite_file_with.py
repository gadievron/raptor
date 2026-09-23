"""Contract tests for the shared ``rewrite_file_with`` driver."""

from __future__ import annotations

from pathlib import Path

import packages.sca.rewriters as rewriters
from packages.sca.rewriters import (
    RewriteEdit,
    RewriteResult,
    rewrite_file_with,
)


def _edit(loc: str, old: str = "1.0", new: str = "2.0") -> RewriteEdit:
    return RewriteEdit(locator=loc, old_value=old, new_value=new)


def _replace_apply_one(text: str, edit: RewriteEdit):
    """Replace ``<locator>=<old>`` with ``<locator>=<new>``."""
    needle = f"{edit.locator}={edit.old_value}"
    if needle in text:
        return (
            text.replace(needle, f"{edit.locator}={edit.new_value}", 1),
            RewriteResult(edit=edit, applied=True, reason=""),
        )
    return text, RewriteResult(edit=edit, applied=False, reason="not_found")


def test_edits_thread_through_evolving_text(tmp_path: Path):
    f = tmp_path / "manifest.txt"
    f.write_text("a=1.0\nb=1.0\n", encoding="utf-8")
    results = rewrite_file_with(
        f, [_edit("a"), _edit("b")], _replace_apply_one,
    )
    assert [r.applied for r in results] == [True, True]
    assert f.read_text(encoding="utf-8") == "a=2.0\nb=2.0\n"


def test_no_write_when_nothing_applied(tmp_path: Path):
    f = tmp_path / "manifest.txt"
    f.write_text("a=1.0\n", encoding="utf-8")
    before = f.stat().st_mtime_ns
    results = rewrite_file_with(f, [_edit("missing")], _replace_apply_one)
    assert [r.applied for r in results] == [False]
    assert results[0].reason == "not_found"
    assert f.stat().st_mtime_ns == before


def test_read_failure_fails_every_edit(tmp_path: Path):
    f = tmp_path / "absent.txt"
    results = rewrite_file_with(f, [_edit("a"), _edit("b")], _replace_apply_one)
    assert len(results) == 2
    assert all(not r.applied for r in results)
    assert all(r.reason.startswith("error: read refused") for r in results)


def test_write_failure_fails_only_applied_edits(tmp_path: Path, monkeypatch):
    f = tmp_path / "manifest.txt"
    f.write_text("a=1.0\n", encoding="utf-8")

    def _boom(path, text):
        raise OSError("disk full")

    monkeypatch.setattr(rewriters, "_atomic_write", _boom)
    results = rewrite_file_with(
        f, [_edit("a"), _edit("missing")], _replace_apply_one,
    )
    assert results[0].applied is False
    assert results[0].reason.startswith("error: write failed")
    # The edit that never applied keeps its own result untouched.
    assert results[1].reason == "not_found"
    assert f.read_text(encoding="utf-8") == "a=1.0\n"


def test_one_result_per_edit_in_order(tmp_path: Path):
    f = tmp_path / "manifest.txt"
    f.write_text("a=1.0\n", encoding="utf-8")
    edits = [_edit("missing"), _edit("a")]
    results = rewrite_file_with(f, edits, _replace_apply_one)
    assert [r.edit for r in results] == edits


def test_rewriter_modules_share_the_single_write_path() -> None:
    """Every rewriter module must route file IO through the shared
    ``rewrite_file_with`` driver — a module importing the atomic
    writer itself is re-growing the hand-rolled read/apply/write
    loop this driver replaced (and stepping around the registry's
    version-literal chokepoint discipline)."""
    from pathlib import Path

    import packages.sca.rewriters as rewriters

    pkg_dir = Path(rewriters.__file__).parent
    offenders = sorted(
        p.name
        for p in pkg_dir.glob("*.py")
        if p.name != "__init__.py"
        and "atomic_fs" in p.read_text(encoding="utf-8")
    )
    assert offenders == []


def test_symlinked_manifest_is_refused(tmp_path: Path):
    """A symlinked rewrite target must not be read THROUGH the link:
    out-of-tree content otherwise reached the evolving text and was
    echoed into operator-facing ``value_mismatch`` reason strings.
    Scan and fix are separate invocations — the rewrite side cannot
    assume the parse side vetted the same path."""
    real = tmp_path / "outside.props"
    real.write_text("pkg=OUT-OF-TREE-9.9.9\n", encoding="utf-8")
    link = tmp_path / "Directory.Packages.props"
    link.symlink_to(real)
    results = rewrite_file_with(link, [_edit("pkg")], _replace_apply_one)
    assert [r.applied for r in results] == [False]
    assert results[0].reason.startswith("error: read refused")
    # The linked-to content stayed out of the verdict.
    assert "OUT-OF-TREE" not in results[0].reason


def test_oversize_manifest_is_refused(tmp_path: Path):
    """A manifest over the parsers' read cap fails every edit with a
    loud refusal instead of being buffered whole."""
    from packages.sca.parsers._safe_read import _MAX_PARSER_BYTES

    big = tmp_path / "big.props"
    with big.open("w", encoding="utf-8") as fh:
        fh.write("pkg=1.0\n")
        fh.seek(_MAX_PARSER_BYTES + 1)
        fh.write("x")
    results = rewrite_file_with(big, [_edit("pkg")], _replace_apply_one)
    assert [r.applied for r in results] == [False]
    assert results[0].reason.startswith("error: read refused")


def test_crlf_manifest_keeps_lf_view(tmp_path: Path):
    """The bounded reader returns raw text; the driver restores the
    historical text-mode view (CRLF read as LF) so the recorded
    write-side newline behaviour is unchanged."""
    p = tmp_path / "win.props"
    p.write_bytes(b"pkg=1.0\r\nother=3.0\r\n")
    results = rewrite_file_with(p, [_edit("pkg")], _replace_apply_one)
    assert [r.applied for r in results] == [True]
    assert p.read_bytes() == b"pkg=2.0\nother=3.0\n"
