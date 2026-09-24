#!/usr/bin/env python3
"""Tracked-file census gate for enumerable rule-pack subsystems.

Every other gate in this directory checks what tracked files SAY
(vocabulary, canonical JSON, command metadata, imports, chokepoints),
and ruff only sees ``.py`` — nothing censuses which files are TRACKED
in the first place. An extensionless scratch file committed beside a
rule pack therefore passes every content gate (the fixture suites
derive their universe from ``rules/**/*.yaml`` and never look beside
it) and ships in release archives. This gate closes that class where
it is closable: subsystems whose legitimate file population is small,
convention-shaped, and enumerable.

Deliberately NOT a repo-wide extensionless blocklist: ``libexec/``
dispatch shims are extensionless by design, and subsystem ``scripts/``
dirs carry their own conventions — a global shape rule would either
allowlist half the repo or misfire constantly. A per-subsystem
allowlist over ``git ls-files`` is the durable shape: each censused
root declares the shapes its files may take, and any tracked file that
matches no shape fails the gate.

What counts as a violation, beyond a name matching no shape:

  control chars   a path containing a control or format character
                  (newline, ESC, C1 CSI, bidi overrides, ...) is
                  NEVER censusable — C0 names split glob dialects
                  from directory walks, and C1/format names render as
                  something they are not, so a reviewer and a content
                  gate can disagree about which file they are looking
                  at. Categorical violation (Unicode categories Cc
                  and Cf, whole categories: every Cf character is
                  invisible or direction-altering, and no legitimate
                  rule-pack file name needs one).
  non-UTF-8       a path that does not decode as UTF-8 is reported
                  (escaped) and fails the gate — fail-closed, never
                  silently normalised into a pass.
  index mode      only regular files (100644/100755) are censusable.
                  A tracked symlink or a gitlink/submodule pointer
                  named like an allowed shape is a violation — its
                  content is not what the shape vouches for.
  .gitkeep size   the shared ``.gitkeep`` placeholder shape vouches
                  for an EMPTY file; a content-bearing blob under
                  that name is a violation (no content gate opens
                  it, so emptiness is the only honest contract).

Adding a file with a genuinely new legitimate shape: add a pattern to
``SUBSYSTEMS`` (or ``SHARED_SHAPES``) below with a rationale comment.
There is intentionally no baseline file — a stray tracked file has no
"deliberate exception" mode; it is either a new convention (allowlist
it here, visibly) or it gets removed from the index.

Usage:
    python3 .github/scripts/check_tracked_file_census.py
    python3 .github/scripts/check_tracked_file_census.py --root <tree>
    python3 .github/scripts/check_tracked_file_census.py --require-git

Exit codes: 0 clean (or, without --require-git, no git tracking data —
notice printed), 1 violations or git/tracking errors, 2 usage error.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import unicodedata
from pathlib import Path

_DEFAULT_ROOT = Path(__file__).resolve().parents[2]

# Regular files only. 120000 (symlink) and 160000 (gitlink) entries
# carry content the shape allowlist cannot vouch for.
_ALLOWED_MODES = frozenset({"100644", "100755"})

# Shapes legitimate in EVERY censused subsystem. Kept minimal on
# purpose: every entry here widens all subsystems at once, so only
# repo-wide conventions belong (a subsystem-local shape goes in its
# own SUBSYSTEMS tuple).
SHARED_SHAPES: tuple[str, ...] = (
    "**/README.md",   # per-directory docs are always legitimate
    "**/.gitkeep",    # placeholder keeping an otherwise-empty dir
                      # tracked — must be EMPTY (checked below)
)

# Per-subsystem allowed shapes, matched against the path RELATIVE to
# the subsystem root. Glob dialect: ``*``/``?`` never cross ``/``;
# ``**`` as a whole component matches zero or more directory
# components; character classes are NOT supported (asserted at
# compile time — a ``[ab]`` pattern would silently match nothing).
#
# Churn trade-off, both directions: every new legitimate shape costs a
# one-line edit here (tighter). Without the pin, scratch files —
# extensionless notes, editor droppings, misplaced sources — hide
# among rule packs and fixtures forever (looser), because no content
# gate ever opens them. The one-line edit is the cheap side.
SUBSYSTEMS: dict[str, tuple[str, ...]] = {
    "engine/semgrep": (
        "rules/**/*.yaml",   # the rule packs; the fixture suites derive
                             # their universe from exactly this glob
        # Fixture sources, one entry per fixture language. A new
        # fixture language is a deliberate addition — listing it here
        # is the point: without the extension pin, any file at all
        # passes as a "fixture".
        "tests/**/*.go",
        "tests/**/*.java",
        "tests/**/*.js",
        "tests/**/*.php",
        "tests/**/*.py",
        "tests/**/*.rb",
        "tools/**/*.py",     # maintenance tooling (registry-cache refresh)
    ),
    "engine/coccinelle": (
        "*.py",                          # renderers exposed at the root
        "prereqs/*.cocci",
        "rules/**/*.cocci",
        "source_intel/**/*.cocci",
        "source_intel/crypto/packs/*.json",  # curated API packs (data)
        "tests/**/*.py",
        "tests/.gitignore",              # rule-precision tests write
                                         # scratch beside themselves
    ),
    "engine/codeql": (
        "queries/**/*.ql",
        "queries/**/qlpack.yml",  # pack manifests only — a stray .yml
                                  # that is not a manifest must not
                                  # ride in as "some YAML"
        "tests/**/*.py",
    ),
    "engine/negative_controls": (
        # Flat corpus of intentionally-clean sources, per language.
        "*.c",
        "*.py",
    ),
    # Rules-like dir outside engine/: decompiler audit rule packs.
    "core/audit/rules": (
        "**/*.yaml",
    ),
}


class GitGateError(Exception):
    """git produced an ERROR (corrupt index, CLI drift, ...) — this
    must fail the gate, never ride the tracking-data-absent notice."""


def _uncensusable(ch: str) -> bool:
    """Characters no censusable file name may carry: Cc (C0, DEL, and
    the terminal-live C1 range — U+009B is a bare CSI) and Cf (bidi
    overrides, zero-width joiners, BOM, ...). Whole categories on
    purpose: every Cf character is invisible or direction-altering,
    so a name carrying one displays as something it is not."""
    return unicodedata.category(ch) in ("Cc", "Cf")


def _escape(name: str) -> str:
    """Render a file name inert for CI logs: Cc/Cf characters become
    ``\\xHH``/``\\uHHHH`` escapes (the core.security.log_sanitisation
    contract shape) so a crafted name cannot emit terminal escapes,
    bidi reordering, or GitHub ``::``-workflow-command lines through
    this gate. Applied to EVERY printed-name arm."""
    def esc(ch: str) -> str:
        if not _uncensusable(ch):
            return ch
        o = ord(ch)
        if o < 0x100:
            return f"\\x{o:02x}"
        if o <= 0xFFFF:
            return f"\\u{o:04x}"
        return f"\\U{o:08x}"
    return "".join(esc(ch) for ch in name)


def _git_env() -> dict[str, str]:
    """Subprocess environment with every ``GIT_*`` variable scrubbed.

    Inherited redirections silently swap the censused universe:
    ``GIT_INDEX_FILE`` pointing at a missing file makes git census an
    EMPTY index as "clean", ``GIT_DIR``/``GIT_WORK_TREE`` retarget
    another repository entirely. Repo discovery stays ``-C <root>``
    cwd-based in the child, which is exactly what this gate wants.
    """
    return {
        k: v for k, v in os.environ.items() if not k.startswith("GIT_")
    }


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate the allowlist glob dialect to a fullmatch regex.

    ``**`` as a whole path component matches zero or more directory
    components (trailing ``**`` matches any suffix); ``*`` and ``?``
    match within a single component only; ``[``/``]`` are rejected
    (character classes are outside the dialect and would otherwise
    compile to a literal that matches nothing, i.e. a dead pattern).
    stdlib ``fnmatch`` lets ``*`` cross ``/`` and ``pathlib`` grew
    ``full_match`` only in 3.13, hence the local translation. Matching
    uses ``fullmatch`` — ``$`` would tolerate a trailing newline;
    control-byte names are additionally rejected outright in
    ``census_violations`` before any pattern is consulted.
    """
    if "[" in pattern or "]" in pattern:
        raise ValueError(
            f"character classes are not part of the allowlist glob "
            f"dialect: {pattern!r}"
        )
    parts = pattern.split("/")
    pieces: list[str] = []
    for i, part in enumerate(parts):
        last = i == len(parts) - 1
        if part == "**":
            pieces.append(".*" if last else "(?:[^/]+/)*")
            continue
        seg = "".join(
            "[^/]*" if ch == "*" else "[^/]" if ch == "?" else re.escape(ch)
            for ch in part
        )
        pieces.append(seg if last else seg + "/")
    # \A...\Z anchors (not ^...$: $ tolerates a final newline) so the
    # pattern is safe under .match() and .search() callers too.
    return re.compile("\\A" + "".join(pieces) + "\\Z")


def census_violations(tracked: list[str]) -> dict[str, list[str]]:
    """Pure census: repo-relative tracked paths -> violations per root.

    Paths outside every censused root are ignored (this gate only
    claims the subsystems it enumerates). A path containing a control
    or format character (Cc/Cf) is a violation regardless of any
    pattern — such names are never matched and rendered consistently,
    which makes them exactly the smuggle surface this gate exists to
    close.
    """
    compiled = {
        root: [_glob_to_regex(p) for p in shapes + SHARED_SHAPES]
        for root, shapes in SUBSYSTEMS.items()
    }
    violations: dict[str, list[str]] = {}
    for path in tracked:
        for root, patterns in compiled.items():
            if not path.startswith(root + "/"):
                continue
            rel = path[len(root) + 1:]
            if any(_uncensusable(ch) for ch in rel):
                violations.setdefault(root, []).append(
                    f"{_escape(path)}  (control character in file name)"
                )
            elif not any(rx.fullmatch(rel) for rx in patterns):
                # _escape is a no-op here (Cc/Cf names took the arm
                # above) — applied anyway so no printed-name arm ever
                # bypasses it.
                violations.setdefault(root, []).append(_escape(path))
            break  # censused roots do not nest; first match owns the path
    return {root: sorted(paths) for root, paths in sorted(violations.items())}


def mode_violations(entries: list[tuple[str, str]]) -> list[str]:
    """Pure mode census over (index-mode, repo-relative-path) pairs:
    non-regular entries under a censused root, as display lines."""
    out: list[str] = []
    for mode, path in entries:
        if mode in _ALLOWED_MODES:
            continue
        if any(path.startswith(root + "/") for root in SUBSYSTEMS):
            kind = {"120000": "symlink", "160000": "gitlink/submodule"}.get(
                mode, f"mode {mode}"
            )
            out.append(f"{_escape(path)}  ({kind} — not a regular file)")
    return sorted(out)


def tracked_entries(root: Path) -> list[tuple[str, str, bytes]] | None:
    """(index-mode, blob-oid, raw path bytes) for every tracked entry
    under the censused roots.

    Returns None ONLY when tracking data is genuinely absent (no git
    binary, or ``root`` is not inside a git work tree). Any other git
    failure raises GitGateError — a corrupt index or CLI drift must
    fail the gate, not ride the notice arm. ``git ls-files`` reads the
    index only, so shallow CI clones are fine; ``-z`` plus bytes-mode
    parsing because file names are DATA to this gate, not trusted text.
    """
    env = _git_env()
    try:
        probe = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
            capture_output=True, check=False, env=env,
        )
    except OSError:
        return None  # git binary absent
    if probe.returncode != 0:
        return None  # not a git work tree
    proc = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--stage", "--",
         *sorted(SUBSYSTEMS)],
        capture_output=True, check=False, env=env,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", "backslashreplace").strip()
        raise GitGateError(
            f"git ls-files failed (exit {proc.returncode}): "
            f"{_escape(stderr)}"
        )
    entries: list[tuple[str, str, bytes]] = []
    for record in proc.stdout.split(b"\0"):
        if not record:
            continue
        meta, _tab, bpath = record.partition(b"\t")
        fields = meta.split()
        if len(fields) < 2 or not bpath:
            raise GitGateError(
                f"unparseable ls-files record: "
                f"{_escape(record.decode('utf-8', 'backslashreplace'))!r}"
            )
        entries.append((fields[0].decode("ascii"), fields[1].decode("ascii"),
                        bpath))
    return entries


def gitkeep_violations(
    root: Path, entries: list[tuple[str, str, str]]
) -> list[str]:
    """``.gitkeep`` entries whose STAGED blob is non-empty, as display
    lines. Sizes come from the index oid (``git cat-file -s``), not the
    working tree — the tracked content is what ships."""
    out: list[str] = []
    for mode, oid, path in entries:
        if path.rpartition("/")[2] != ".gitkeep":
            continue
        if mode not in _ALLOWED_MODES:
            continue  # already a mode violation; its oid may not be a blob
        if not any(path.startswith(r + "/") for r in SUBSYSTEMS):
            continue
        proc = subprocess.run(
            ["git", "-C", str(root), "cat-file", "-s", oid],
            capture_output=True, check=False, env=_git_env(),
        )
        if proc.returncode != 0:
            stderr = proc.stderr.decode("utf-8", "backslashreplace").strip()
            raise GitGateError(
                f"git cat-file -s {oid} failed: {_escape(stderr)}"
            )
        size = int(proc.stdout.strip() or 0)
        if size:
            out.append(
                f"{_escape(path)}  (content-bearing .gitkeep, {size} bytes "
                f"— the placeholder shape vouches for an empty file)"
            )
    return sorted(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=_DEFAULT_ROOT)
    parser.add_argument(
        "--require-git", action="store_true",
        help="fail (exit 1) instead of noticing when tracking data is "
             "absent — belt-and-braces for CI, which always runs "
             "post-checkout and must never ride the notice arm",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        print(f"[file-census] usage error: --root {root} is not a directory")
        return 2

    try:
        raw = tracked_entries(root)
        if raw is None:
            # No git tracking data (exported tree, or git missing). The
            # census subject is the TRACKED set, so there is nothing to
            # judge — notice loudly rather than fail a tree that
            # carries no index. Only this genuinely-absent case
            # degrades; git ERRORS raise and fail below.
            if args.require_git:
                print("[file-census] error: no git tracking data under "
                      f"{root} and --require-git is set")
                return 1
            print("[file-census] notice: no git tracking data under "
                  f"{root} — tracked-file census skipped")
            return 0
        if not raw and args.require_git:
            # Anti-vacuity floor: tracking data is present, yet ZERO
            # files matched five populated roots — always wrong where
            # --require-git is set (CI on this repo). Catches a wrong
            # --root and any universe-swapping condition the GIT_*
            # scrub did not anticipate.
            print(f"[file-census] error: censused zero tracked files "
                  f"across {len(SUBSYSTEMS)} roots under {root} and "
                  f"--require-git is set — wrong tree or swapped "
                  f"tracking universe")
            return 1

        # Names are validated before any shape logic: a non-UTF-8 path
        # is reported (escaped) and fails the gate — fail-closed, never
        # normalised into a pass.
        decoded: list[tuple[str, str, str]] = []
        extra: list[str] = []
        for mode, oid, bpath in raw:
            try:
                decoded.append((mode, oid, bpath.decode("utf-8")))
            except UnicodeDecodeError:
                shown = _escape(bpath.decode("utf-8", "backslashreplace"))
                extra.append(f"{shown}  (path is not valid UTF-8)")

        shape = census_violations([p for _m, _o, p in decoded])
        flat = [line for lines in shape.values() for line in lines]
        flat += mode_violations([(m, p) for m, _o, p in decoded])
        flat += gitkeep_violations(root, decoded)
        flat += extra
    except GitGateError as err:
        print(f"[file-census] error: {err}")
        return 1

    if flat:
        lines = sorted(set(flat))  # a path can trip several lanes;
                                   # count what is printed
        print(f"[file-census] {len(lines)} tracked file(s) violate "
              f"the census:")
        for line in lines:
            print(f"  {line}")
        print(
            "[file-census] every tracked file in a censused subsystem "
            "must be a regular file matching one of its declared "
            "shapes. A genuinely new convention gets a pattern (with "
            "rationale) in SUBSYSTEMS in "
            ".github/scripts/check_tracked_file_census.py; a stray "
            "or scratch file gets removed from the index.",
        )
        return 1

    print(f"[file-census] clean: {len(raw)} tracked files across "
          f"{len(SUBSYSTEMS)} censused subsystems all match their "
          f"allowed shapes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
