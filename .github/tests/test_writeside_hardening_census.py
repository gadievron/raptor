"""Closure gate: write-side symlink/FIFO hardening in the campaign
packages cannot silently regrow.

The four packages below execute or supervise attacker-built targets
and hostile harnesses whose sandbox write scope is the run/output
directory the packages' own writers also use. Inside that shared
scope, a bare write-follow open is a write-laundering primitive and a
reader-less FIFO is a writer-wedge:

* ``open(path, "w"/"a")`` and ``Path.open("w"/"a")`` (mode positional
  or keyword) follow a planted symlink and block forever on a planted
  reader-less FIFO;
* ``.write_text(`` / ``.write_bytes(`` / ``.touch(`` are the same
  open in convenience clothing;
* ``shutil.copy`` / ``copy2`` / ``copyfile`` open the DESTINATION
  with O_TRUNC and follow whatever occupies it —
  ``follow_symlinks=False`` only governs the source side;
  ``shutil.move`` shares the destination-follow when it falls back to
  copy, and ``shutil.copytree(dirs_exist_ok=True)`` merges through
  whatever occupies the existing destination tree;
* ``os.open`` carrying ``O_CREAT`` or ``O_TRUNC`` with neither
  ``O_NOFOLLOW`` nor ``O_EXCL`` is the lock-capture /
  truncate-through-symlink shape.

Accepted static gaps (undetectable without dataflow, named so the
boundary is explicit): a mode carried in a VARIABLE or default
argument (``mode=m``), opens routed through an alias or
``functools.partial``, fd-wrapping helpers (``os.fdopen`` — the fd's
own open is what this census checks), ``os.rename``/``os.replace``
(replace a symlink, never follow it), and ``tempfile`` constructors
(O_EXCL by construction). A site reachable only through those shapes
still needs reviewer eyes — this gate is the fence, not the proof.

Hardened routes that vanish from this census: ``core.atomic_fs``
(``write_text_atomically`` / ``write_bytes_atomically`` — os.replace
never follows a symlink; ``open_exclusive_artifact`` /
``write_new_bytes`` / ``write_new_text`` — O_EXCL|O_NOFOLLOW;
``open_hardened_append``), ``core.json.save_json`` /
``append_jsonl``, and kept-fd writes through a ``mkstemp`` fd.

Every remaining site must be adjudicated in ``_ALLOWLIST`` below,
keyed by (relpath, exact stripped source line) with the reason it is
safe as written. Both directions are enforced: an unlisted site fails
(the class regrew), and a stale entry fails (the site changed or
moved — re-adjudicate it). Tests, fixtures, conftest and subsystem
``scripts/`` dirs are outside the runtime universe and exempt by
construction.

The boundary, named: writers into freshly created process-private
dirs (``mkdtemp`` / ``TemporaryDirectory``, or an rmtree'd+re-mkdir'd
staging dir with no hostile child live) and operator-argument
destinations are safe as written — those are exactly the allowlisted
shapes. Sites in other packages are out of this census's scope; the
shared wrappers they route through are hardened at the source.
"""

from __future__ import annotations

import ast
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from runtime_universe import repo_root, runtime_file_universe  # noqa: E402

_PACKAGES = (
    "packages/fuzzing/",
    "packages/binary_analysis/",
    "packages/ghidra/",
    "packages/web/",
)

# (relpath, exact stripped first source line of the call) -> reason
# the site is safe as written. Keep entries tight: every one is an
# adjudication record, not an exemption of convenience.
_ALLOWLIST: dict[tuple[str, str], str] = {
    (
        "packages/fuzzing/afl_runner.py",
        "shutil.copy2(entry, staged / entry.name)",
    ): (
        "staging runs pre-campaign into a dir rmtree'd + freshly "
        "mkdir'd two lines above — no hostile child is live and no "
        "planted entry can pre-occupy the fresh destination names"
    ),
    (
        "packages/fuzzing/afl_runner.py",
        "shutil.copy2(source, staged / source.name)",
    ): (
        "same fresh pre-campaign staging dir as the dir-copy branch "
        "above"
    ),
    (
        "packages/fuzzing/capability.py",
        'with open(src_path, "w") as src:',
    ): (
        "probe source written into a fresh process-private "
        "TemporaryDirectory created in the enclosing with-block"
    ),
    (
        "packages/fuzzing/capability.py",
        '(seeds / "seed").write_bytes(b"seed\\n")',
    ): (
        "probe seed written into a fresh process-private "
        "TemporaryDirectory created in the enclosing with-block"
    ),
    (
        "packages/ghidra/headless.py",
        '(script_dir / "ExportRaptor.java").write_text(EXPORT_SCRIPT_JAVA, encoding="utf-8")',
    ): (
        "script dir freshly mkdir'd inside a process-private "
        "TemporaryDirectory work dir"
    ),
    (
        "packages/ghidra/headless.py",
        'script_path.write_text(IMPORT_SCRIPT_JAVA, encoding="utf-8")',
    ): (
        "script written into a fresh process-private "
        "TemporaryDirectory created in the enclosing with-block"
    ),
    (
        "packages/ghidra/match_precision.py",
        "src.write_text(_CORPUS_C)",
    ): (
        "corpus source written into a fresh process-private "
        "TemporaryDirectory work dir"
    ),
    (
        "packages/ghidra/match_precision.py",
        "shutil.copy2(v2, v2s)",
    ): (
        "copy between two fresh names inside the same process-"
        "private TemporaryDirectory work dir"
    ),
    (
        "packages/ghidra/project_util.py",
        "shutil.copy2(src, dst_rep / rel / f, follow_symlinks=False)",
    ): (
        "destination tree is rmtree'd and rebuilt fresh by "
        "prepare_working_copy immediately before this walk — no "
        "planted entry can occupy the fresh destination names; "
        "follow_symlinks=False covers the vetted source side"
    ),
    (
        "packages/web/benchmark.py",
        'args.out.write_text(rendered + "\\n", encoding="utf-8")',
    ): (
        "destination is an operator-supplied CLI argument, not a "
        "predictable name inside a target-writable run dir"
    ),
}

_WRITE_MODE_PREFIXES = ("w", "a")


def _mode_of(call: ast.Call, positional_index: int) -> str | None:
    """The literal mode string of an open()-family call, if present.

    ``positional_index`` is where the mode rides positionally: 1 for
    builtin ``open(path, mode)``, 0 for method-style ``p.open(mode)``
    — the most common ``Path.open("w")`` spelling puts the mode
    FIRST, and reading only args[1] let it pass the census silently.
    """
    for kw in call.keywords:
        if (
            kw.arg == "mode"
            and isinstance(kw.value, ast.Constant)
            and isinstance(kw.value.value, str)
        ):
            return kw.value.value
    if (
        len(call.args) > positional_index
        and isinstance(call.args[positional_index], ast.Constant)
        and isinstance(call.args[positional_index].value, str)
    ):
        return call.args[positional_index].value
    return None


def _names_in(node: ast.AST) -> set[str]:
    """Flag-constant spellings in a flags expression: ``os.O_X``
    attributes, bare names, and the ``getattr(os, "O_X", 0)``
    degrade-gracefully idiom (string constants)."""
    names: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute):
            names.add(sub.attr)
        elif isinstance(sub, ast.Name):
            names.add(sub.id)
        elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            names.add(sub.value)
    return names


def _flag(call: ast.Call) -> str | None:
    """Why this call is a write-side hazard, or None."""
    fn = call.func
    if isinstance(fn, ast.Name) and fn.id == "open":
        mode = _mode_of(call, positional_index=1)
        if mode and mode[0] in _WRITE_MODE_PREFIXES:
            return f"builtin open mode={mode!r}"
        return None
    if not isinstance(fn, ast.Attribute):
        return None
    if fn.attr == "open":
        if isinstance(fn.value, ast.Name) and fn.value.id == "os":
            if len(call.args) >= 2:
                names = _names_in(call.args[1])
                unhardened = (
                    "O_NOFOLLOW" not in names and "O_EXCL" not in names
                )
                if "O_CREAT" in names and unhardened:
                    return "os.open with O_CREAT but no O_NOFOLLOW/O_EXCL"
                if "O_TRUNC" in names and unhardened:
                    return "os.open with O_TRUNC but no O_NOFOLLOW/O_EXCL"
            return None
        # Method-style open: the mode rides FIRST positionally
        # (Path.open("w")) or as mode=.
        mode = _mode_of(call, positional_index=0)
        if mode and mode[0] in _WRITE_MODE_PREFIXES:
            return f".open mode={mode!r}"
        return None
    if fn.attr in ("write_text", "write_bytes"):
        return f".{fn.attr}()"
    if fn.attr == "touch":
        return ".touch() (creates through a planted symlink)"
    if isinstance(fn.value, ast.Name) and fn.value.id == "shutil":
        if fn.attr in ("copy", "copy2", "copyfile"):
            return f"shutil.{fn.attr}() (destination-side follow)"
        if fn.attr == "move":
            return "shutil.move() (destination-side follow on copy fallback)"
        if fn.attr == "copytree" and any(
            kw.arg == "dirs_exist_ok"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is True
            for kw in call.keywords
        ):
            return "shutil.copytree(dirs_exist_ok=True) merges into occupied names"
    return None


def _census() -> tuple[list[tuple[str, str, int, str]], Counter]:
    """All flagged sites: (relpath, stripped line, lineno, why)."""
    root = repo_root()
    found: list[tuple[str, str, int, str]] = []
    keys: Counter = Counter()
    for path in sorted(runtime_file_universe()):
        rel = path.relative_to(root).as_posix()
        if not rel.startswith(_PACKAGES):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        lines = text.splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            why = _flag(node)
            if why is None:
                continue
            line = (
                lines[node.lineno - 1].strip()
                if node.lineno <= len(lines) else ""
            )
            found.append((rel, line, node.lineno, why))
            keys[(rel, line)] += 1
    return found, keys


def test_no_unadjudicated_write_side_sites() -> None:
    found, _keys = _census()
    unlisted = [
        f"{rel}:{lineno}: [{why}] {line}"
        for rel, line, lineno, why in found
        if (rel, line) not in _ALLOWLIST
    ]
    assert not unlisted, (
        "write-side symlink/FIFO hazard(s) outside the adjudicated "
        "allowlist — route through core.atomic_fs "
        "(write_*_atomically / write_new_* / open_exclusive_artifact "
        "/ open_hardened_append), core.json.save_json/append_jsonl, "
        "or a kept mkstemp fd; only a genuinely process-private or "
        "operator-owned destination earns an allowlist entry:\n"
        + "\n".join(sorted(unlisted))
    )


def _flags_of(snippet: str) -> list[str]:
    """Self-test helper: every _flag verdict in a parsed snippet."""
    return [
        why
        for node in ast.walk(ast.parse(snippet))
        if isinstance(node, ast.Call) and (why := _flag(node)) is not None
    ]


def test_flagger_catches_bypass_spellings() -> None:
    """Self-test: the shapes that once passed (or would pass) the
    census silently must flag. Guards the flagger itself against
    regressions — the tree census only proves the tree is clean
    AGAINST the current flagger."""
    # Path.open with the mode FIRST POSITIONAL — the most common
    # spelling; reading only args[1] let it through.
    assert _flags_of('p.open("w")')
    assert _flags_of('p.open("ab")')
    assert _flags_of('p.open(mode="w")')
    assert _flags_of('open(p, "wb")')
    # os.open truncate-through-symlink without O_CREAT.
    assert _flags_of("os.open(p, os.O_WRONLY | os.O_TRUNC)")
    assert _flags_of(
        'os.open(p, os.O_WRONLY | os.O_CREAT | getattr(os, "O_LARGEFILE", 0))'
    )
    # Destination-follow copy family.
    assert _flags_of("shutil.move(src, dst)")
    assert _flags_of("shutil.copytree(src, dst, dirs_exist_ok=True)")
    assert _flags_of("p.touch()")
    assert _flags_of("p.write_text(x)")


def test_flagger_ignores_hardened_and_read_shapes() -> None:
    assert not _flags_of('p.open("rb")')
    assert not _flags_of('open(p, "r")')
    assert not _flags_of("p.open()")  # default mode is read
    assert not _flags_of(
        "os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW)"
    )
    assert not _flags_of(
        'os.open(p, os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0))'
    )
    assert not _flags_of("shutil.copytree(src, dst)")  # fresh dest only
    assert not _flags_of("shutil.copyfileobj(a, b)")  # file objects


def test_allowlist_entries_still_live() -> None:
    """A stale entry means the site changed or moved — re-adjudicate
    rather than carry a dead exemption."""
    _found, keys = _census()
    stale = [
        f"{rel}: {line}"
        for (rel, line) in _ALLOWLIST
        if keys[(rel, line)] == 0
    ]
    assert not stale, (
        "allowlist entries no longer match any flagged site "
        "(fixed or drifted — remove or re-key them):\n"
        + "\n".join(sorted(stale))
    )
