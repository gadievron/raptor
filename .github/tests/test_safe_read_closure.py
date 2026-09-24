"""Closure gate: runtime reads of influenceable paths go through the
safe-read chokepoint family.

Doctrine (``core.source.contained``): a runtime read of a path that
any other principal can influence goes through the ``core.source``
family (``read_text_capped`` / ``read_bytes_capped`` /
``read_contained`` / ``read_text_gated`` / ``open_regular`` /
``open_regular_beneath``) — raw ``open()`` / ``read_text()`` on such
a path is a CI failure, not a review comment. A raw read is the
exception a caller must spell out AND justify inline::

    text = path.read_text()  # raw-open: RAPTOR-owned pack file

This census is AST-derived (never grep) over the shared
``runtime_file_universe()`` derivation, restricted to a covered
directory-prefix list that GROWS per fix series — each expansion is
a one-line diff to ``_COVERED_PREFIXES``, so the ratchet is
mechanical, visible, and monotone. There is deliberately NO
allowlist file: the marker at the call site IS the adjudication
record, so the justification lives next to the read it excuses and
moves with it (same rule as ``json-unbounded:``).

Flagged spellings, read side only:

* builtin ``open(...)`` in a read mode (no mode, ``r``-modes, or
  ``+``);
* ``.read_text(`` / ``.read_bytes(`` attribute calls;
* ``.open(`` attribute calls in a read mode (``Path.open`` is the
  common raw bypass), except ``os.open`` which has its own arm;
* ``os.open(...)`` whose flags carry neither ``O_NOFOLLOW`` nor
  ``O_NONBLOCK`` (unhardened). Write-side opens — ``O_WRONLY`` /
  ``O_RDWR`` / ``O_CREAT`` / ``O_EXCL`` / ``O_APPEND`` — pass: the
  write-side family is a separate doctrine (core.atomic_fs).

The helper homes themselves are the only files allowed to spell the
raw idiom without a marker — a FIXED frozenset that shrinks as local
copies collapse onto the family.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from runtime_universe import repo_root, runtime_file_universe  # noqa: E402

_MARKER = "raw-open:"
# The marker must carry an actual justification — a bare
# "# raw-open:" is a rubber stamp, not an adjudication record.
_MARKER_RE = re.compile(re.escape(_MARKER) + r"[ \t]*\S")

#: The ratchet: directories whose runtime source is under closure.
#: Grows one line per fix series as adoption/marker sweeps land —
#: never shrink it.
_COVERED_PREFIXES = (
    "core/audit/",
    "packages/source_intel/",
)

#: The chokepoint family's own homes — the only files allowed to
#: carry the raw open/fstat idiom without a per-site marker. Fixed
#: here by design (shrinks as hardened local copies collapse onto
#: core.source; never grows without a series landing the new home).
_HELPER_HOMES = frozenset({
    "core/source/beneath.py",
    "core/source/contained.py",
    "core/source/gated.py",
    "core/json/utils.py",
    "core/json/bounded.py",
    "core/security/capped_read.py",
    "core/sandbox/_pathpin.py",
    "packages/sca/parsers/_safe_read.py",
    "packages/sca/resolvers/_safe_io.py",
})

_READ_ATTRS = ("read_text", "read_bytes")


def _mode_is_read(node: ast.Call, *, builtin: bool) -> bool:
    """True when the open call is a read (default mode counts)."""
    mode = None
    args = node.args
    if builtin:
        if len(args) >= 2 and isinstance(args[1], ast.Constant):
            mode = args[1].value
        elif len(args) >= 2:
            return True  # dynamic mode: fail toward visibility
    else:
        if len(args) >= 1 and isinstance(args[0], ast.Constant):
            mode = args[0].value
        elif len(args) >= 1:
            return True
    for kw in node.keywords:
        if kw.arg == "mode":
            if isinstance(kw.value, ast.Constant):
                mode = kw.value.value
            else:
                return True
    if mode is None:
        return True
    if not isinstance(mode, str):
        return True
    return "r" in mode or "+" in mode


def _flag_names(expr: ast.AST) -> set[str]:
    """O_* identifiers mentioned anywhere in an os.open flags expr."""
    names: set[str] = set()
    for sub in ast.walk(expr):
        if isinstance(sub, ast.Attribute):
            names.add(sub.attr)
        elif isinstance(sub, ast.Name):
            names.add(sub.id)
        elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            # getattr(os, "O_NONBLOCK", 0) spells the flag as a string
            names.add(sub.value)
    return names

_WRITE_FLAGS = {"O_WRONLY", "O_RDWR", "O_CREAT", "O_EXCL", "O_APPEND"}
_HARDENED_FLAGS = {"O_NOFOLLOW", "O_NONBLOCK"}


def census_offenders(rel: str, source: str) -> list[str]:
    """Raw read spellings in *source* lacking the inline marker."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    lines = source.splitlines()
    offenders: list[str] = []

    def _line_has_marker(lineno: int) -> bool:
        return _MARKER_RE.search(lines[lineno - 1]) is not None

    def _flag(node: ast.Call, why: str) -> None:
        if not _line_has_marker(node.lineno):
            src_line = lines[node.lineno - 1].strip()
            offenders.append(f"{rel}:{node.lineno}: {why} — {src_line}")

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Name) and f.id == "open":
            if _mode_is_read(node, builtin=True):
                _flag(node, "raw builtin open() read")
        elif isinstance(f, ast.Attribute):
            if f.attr in _READ_ATTRS:
                _flag(node, f"raw .{f.attr}()")
            elif f.attr == "open":
                recv = f.value
                if isinstance(recv, ast.Name) and recv.id == "os":
                    if len(node.args) >= 2:
                        flags = _flag_names(node.args[1])
                        if flags & _WRITE_FLAGS:
                            continue  # write side: separate doctrine
                        if not (flags & _HARDENED_FLAGS):
                            _flag(
                                node,
                                "unhardened os.open (no O_NOFOLLOW / "
                                "O_NONBLOCK)",
                            )
                    else:
                        _flag(node, "os.open without inspectable flags")
                elif _mode_is_read(node, builtin=False):
                    _flag(node, "raw .open() read")
    return offenders


def test_no_unjustified_raw_reads_in_covered_runtime_source() -> None:
    repo = repo_root()
    offenders: list[str] = []
    for path in runtime_file_universe(repo, include_dev_scripts=True):
        rel = path.relative_to(repo).as_posix()
        if not rel.startswith(_COVERED_PREFIXES):
            continue
        if rel in _HELPER_HOMES:
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        offenders.extend(census_offenders(rel, source))
    assert not offenders, (
        "raw read of a potentially influenceable path without an "
        "inline justification — use core.source.read_text_capped / "
        "read_contained / read_text_gated / open_regular(_beneath), "
        f"or justify inline with '# {_MARKER} <why>' on the call's "
        "first line:\n" + "\n".join(offenders)
    )


class TestCensusMechanics:
    """The census's own failure directions, on planted sources."""

    def test_unmarked_builtin_open_fires(self):
        assert census_offenders("x.py", "fh = open(p)\n")

    def test_unmarked_read_text_fires(self):
        assert census_offenders("x.py", "t = p.read_text()\n")

    def test_unmarked_read_bytes_fires(self):
        assert census_offenders("x.py", "b = p.read_bytes()\n")

    def test_unmarked_path_open_fires(self):
        assert census_offenders("x.py", "with p.open() as fh:\n    pass\n")

    def test_marker_excuses(self):
        src = "t = p.read_text()  # raw-open: RAPTOR-owned pack file\n"
        assert census_offenders("x.py", src) == []

    def test_bare_marker_is_a_rubber_stamp(self):
        assert census_offenders("x.py", "t = p.read_text()  # raw-open:\n")

    def test_write_mode_open_passes(self):
        src = 'with open(p, "w") as fh:\n    pass\n'
        assert census_offenders("x.py", src) == []

    def test_append_path_open_passes(self):
        src = 'with p.open("a") as fh:\n    pass\n'
        assert census_offenders("x.py", src) == []

    def test_read_plus_mode_fires(self):
        assert census_offenders("x.py", 'fh = open(p, "r+")\n')

    def test_dynamic_mode_fails_toward_visibility(self):
        assert census_offenders("x.py", "fh = open(p, mode)\n")

    def test_unhardened_os_open_fires(self):
        assert census_offenders("x.py", "fd = os.open(p, os.O_RDONLY)\n")

    def test_nofollow_os_open_passes(self):
        src = "fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)\n"
        assert census_offenders("x.py", src) == []

    def test_getattr_spelled_nonblock_passes(self):
        src = (
            "fd = os.open(p, os.O_RDONLY | "
            'getattr(os, "O_NONBLOCK", 0))\n'
        )
        assert census_offenders("x.py", src) == []

    def test_excl_creator_passes(self):
        src = "fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL)\n"
        assert census_offenders("x.py", src) == []

    def test_offender_message_names_file_line_and_source(self):
        got = census_offenders("pkg/mod.py", "t = p.read_text()\n")
        assert got and got[0].startswith("pkg/mod.py:1: ")
        assert "p.read_text()" in got[0]

    def test_unparseable_source_skipped(self):
        assert census_offenders("x.py", "def broken(:\n") == []
