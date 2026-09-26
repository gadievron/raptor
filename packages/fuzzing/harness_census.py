"""Multi-engine fuzz-harness census — detection only, never execution.

``detect_target`` classifies a directory as ONE kind, but a polyglot
repo can ship several engines' harnesses at once (a Rust crate with
cargo-fuzz targets AND a C FFI layer with libFuzzer harnesses). The
census answers the narrower surfacing question — "what fuzz harnesses
does this tree already ship?" — so /describe and the /agentic
end-of-run digest can point the operator at /fuzz instead of leaving
shipped harnesses undiscovered.

Contract:

* **Read-only.** One bounded ``os.walk`` (symlinks never followed,
  non-regular files never opened) plus bounded content sniffs through
  ``O_RDONLY | O_NOFOLLOW`` descriptors. Zero writes, zero subprocess
  spawns, zero toolchain probes — whether a fuzzer can RUN these
  harnesses is the campaign PLAN's job (:mod:`packages.fuzzing.capability`),
  not the census's.
* **Bounded.** The walk visits at most ``_MAX_WALK_ENTRIES`` names and
  content-sniffs at most ``_MAX_SNIFF_FILES`` files at
  ``_MAX_SNIFF_BYTES`` each; ``truncated`` flags any cap hit so
  consumers can say "counts partial". Both caps trade completeness
  against I/O on huge trees: higher values make the census exact on
  monorepos but turn a cheap end-of-run read into a full tree scan;
  lower values start missing harnesses on ordinary projects.
* **Hostile-name discipline.** Example target names are target-derived
  bytes. They are charset-vetted here (``_SAFE_NAME_RE``) and capped
  (≤ ``_MAX_EXAMPLES`` per engine, ≤ ``_MAX_NAME_LEN`` chars);
  non-conforming names still COUNT but are never exemplified. Counts
  are always safe; names are decoration. Rendering surfaces still
  apply their own escape-at-render convention on top.

Engine arms detect the layouts RAPTOR's fuzzing stack understands
today. Engines whose enumeration helpers land later (the jazzer arm)
slot into ``_EXTRA_ENGINE_SWEEPS`` as pure one-entry additions — the
walk, caps, and result shape do not change.
"""

from __future__ import annotations

import os
import re
import stat as _stat
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

# Walk / sniff budgets. See module docstring for the two-direction
# trade-off; the values cover ordinary repos (harnesses live in
# shallow, conventionally-named dirs) without letting a hostile or
# monorepo-scale tree turn the census into a long scan.
_MAX_WALK_ENTRIES = 20_000
_MAX_SNIFF_FILES = 256
_MAX_SNIFF_BYTES = 64 * 1024

# Example-name decoration caps.
_MAX_EXAMPLES = 3
_MAX_NAME_LEN = 64
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._+-]{1,64}$")

# Dirs never descended into — mirrors the /describe inventory walk's
# exclusion set (vendored / build trees are not "this repo ships").
_SKIP_DIRS = frozenset({
    "node_modules", "vendor", "build", "dist",
    "target", "__pycache__", "out",
})

_C_FAMILY_EXTS = frozenset({".c", ".cc", ".cpp", ".cxx"})

# Content markers (bytes — sniffs are binary reads).
_LIBFUZZER_MARKER = b"LLVMFuzzerTestOneInput"
_AFL_MARKERS = (b"__AFL_LOOP", b"__AFL_FUZZ_TESTCASE")
_ATHERIS_MARKERS = (b"import atheris", b"atheris.Setup")

# Engine identifiers — also the ``engines_checked`` vocabulary.
ENGINE_CARGO_FUZZ = "cargo-fuzz"
ENGINE_LIBFUZZER = "libfuzzer"
ENGINE_AFL = "afl"
ENGINE_ATHERIS = "atheris"

# Ready-to-run /fuzz pointers per engine. Operator-authored constants
# (RAPTOR commands only — never shell commands; the /describe scope
# guardrail applies to every surface rendering these). ``{path}`` is
# the censused target path, substituted at build time.
_INVOCATION_HINTS: dict[str, str] = {
    ENGINE_CARGO_FUZZ: (
        "/fuzz --binary {path} — cargo-fuzz drives the "
        "fuzz/fuzz_targets/ harnesses"
    ),
    ENGINE_LIBFUZZER: (
        "/fuzz --binary <compiled-harness> — libFuzzer harness "
        "sources ship in-tree"
    ),
    ENGINE_AFL: (
        "/fuzz --binary <instrumented-harness> — AFL harness "
        "sources ship in-tree"
    ),
    ENGINE_ATHERIS: (
        "/fuzz --binary {path} --py-harness <harness.py> — atheris "
        "harness sources ship in-tree"
    ),
}

# Extension seam for engines whose enumerators land separately:
# ``(engine_name, invocation_hint, enumerate(root) -> list[str])``
# entries run AFTER the shared walk, reusing those enumerators
# verbatim; their names pass through the same vet/cap discipline.
# The jazzer arm is a single entry here when its enumeration helper
# lands.
_EXTRA_ENGINE_SWEEPS: tuple[
    tuple[str, str, Callable[[Path], list[str]]], ...
] = ()


@dataclass(frozen=True)
class EngineCensus:
    """One engine's shipped-harness tally."""

    engine: str
    count: int
    # ≤ _MAX_EXAMPLES charset-vetted example target names.
    examples: list[str]
    # Ready-to-run /fuzz pointer for this engine (constant text plus
    # the censused path).
    invocation_hint: str


@dataclass(frozen=True)
class FuzzHarnessCensus:
    """Result of :func:`census_fuzz_harnesses`."""

    target_path: Path
    # Every engine the census looked for, found or not.
    engines_checked: list[str]
    # Engines with count > 0, in engines_checked order.
    engines: list[EngineCensus] = field(default_factory=list)
    # True when any walk/sniff cap was hit — counts may be partial.
    truncated: bool = False

    @property
    def total_harnesses(self) -> int:
        return sum(e.count for e in self.engines)

    def to_dict(self) -> dict:
        return {
            "target_path": str(self.target_path),
            "engines_checked": list(self.engines_checked),
            "engines": [
                {
                    "engine": e.engine,
                    "count": e.count,
                    "examples": list(e.examples),
                    "invocation_hint": e.invocation_hint,
                }
                for e in self.engines
            ],
            "total_harnesses": self.total_harnesses,
            "truncated": self.truncated,
        }


def _vet_example(name: str) -> str | None:
    """Charset-vetted decoration name, or None to withhold.

    Withholding never changes the count — a harness whose file name
    fails the vet still ticks its engine's tally.
    """
    if len(name) > _MAX_NAME_LEN:
        return None
    if not _SAFE_NAME_RE.fullmatch(name):
        return None
    return name


class _Tally:
    """Per-engine count + bounded vetted examples."""

    def __init__(self) -> None:
        self.count = 0
        self.examples: list[str] = []

    def add(self, name: str) -> None:
        self.count += 1
        if len(self.examples) < _MAX_EXAMPLES:
            vetted = _vet_example(name)
            if vetted is not None and vetted not in self.examples:
                self.examples.append(vetted)


def _fuzz_hinted(rel_parts: tuple[str, ...], filename: str) -> bool:
    """True when the path advertises fuzzing intent.

    Content sniffs are the census's only per-file reads; restricting
    them to conventionally-named locations ("fuzz" in the file name
    or any ancestor dir) keeps the I/O proportional to the fuzzing
    surface, not the tree. A harness hidden in an unrelated dir under
    a non-fuzz name is invisible here by design — the census surfaces
    what a repo SHIPS as fuzz harnesses, not everything that could be
    one.
    """
    if "fuzz" in filename.lower():
        return True
    return any("fuzz" in part.lower() for part in rel_parts)


def _lstat_is_regular(path: Path) -> bool:
    """Pre-open refusal of symlinks and special files."""
    try:
        return _stat.S_ISREG(path.lstat().st_mode)
    except OSError:
        return False


def _sniff(path: Path) -> bytes | None:
    """First ``_MAX_SNIFF_BYTES`` of a regular file, or None.

    The target tree is untrusted, so non-regular files are refused
    BEFORE any open(2) (the lstat check: symlinks must not make the
    census read host paths; opening a hostile character device can
    itself have side effects; a FIFO would block a plain open). The
    ``O_NOFOLLOW`` + ``O_NONBLOCK`` open with a post-open
    ``fstat``/``S_ISREG`` re-check stays as the TOCTOU belt for a
    swap between the lstat and the open — same idiom as
    ``core.run.target_types._read_magic``.
    """
    if not _lstat_is_regular(path):
        return None
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError:
        return None
    try:
        if not _stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return os.read(fd, _MAX_SNIFF_BYTES)
    except OSError:
        return None
    finally:
        os.close(fd)


def census_fuzz_harnesses(path: Path) -> FuzzHarnessCensus:
    """Sweep ``path`` for shipped fuzz harnesses across every engine.

    Returns a :class:`FuzzHarnessCensus`; a nonexistent or non-dir
    ``path`` yields an empty census (all engines checked, none found)
    rather than raising — consumers surface the census
    opportunistically and must never fail their own report over it.
    """
    root = Path(path)
    engines_checked = [
        ENGINE_CARGO_FUZZ, ENGINE_LIBFUZZER, ENGINE_AFL, ENGINE_ATHERIS,
    ]
    for name, _hint, _fn in _EXTRA_ENGINE_SWEEPS:
        # Dedupe: a seam entry reusing a built-in engine name merges
        # into that engine's tally rather than double-listing the
        # name in the engines-checked vocabulary.
        if name not in engines_checked:
            engines_checked.append(name)
    tallies: dict[str, _Tally] = {name: _Tally() for name in engines_checked}
    truncated = False

    if root.is_dir():
        truncated = _walk_census(root, tallies)

    for name, _hint, enumerate_targets in _EXTRA_ENGINE_SWEEPS:
        try:
            found = enumerate_targets(root)
        except Exception:  # noqa: BLE001 — one engine arm never sinks the census
            continue
        for target_name in found:
            tallies[name].add(str(target_name))

    engines = [
        EngineCensus(
            engine=name,
            count=tally.count,
            examples=list(tally.examples),
            invocation_hint=_hint_for(name, root),
        )
        for name, tally in tallies.items()
        if tally.count > 0
    ]
    return FuzzHarnessCensus(
        target_path=root,
        engines_checked=engines_checked,
        engines=engines,
        truncated=truncated,
    )


def _hint_for(engine: str, root: Path) -> str:
    template = _INVOCATION_HINTS.get(engine)
    if template is None:
        template = next(
            (hint for name, hint, _fn in _EXTRA_ENGINE_SWEEPS
             if name == engine),
            "/fuzz --binary {path}",
        )
    return template.replace("{path}", str(root))


def _walk_census(root: Path, tallies: dict[str, _Tally]) -> bool:
    """One bounded walk classifying files into engine tallies.

    Returns True when a cap was hit (counts partial).
    """
    entries_seen = 0
    sniffs_done = 0
    truncated = False
    # Dirs whose Cargo.toml presence has been checked — one stat per
    # fuzz_targets parent, not per .rs file.
    cargo_manifest_cache: dict[str, bool] = {}

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [
            d for d in dirnames
            if not d.startswith(".") and d not in _SKIP_DIRS
        ]
        # Directories count against the walk budget too — a
        # dir-heavy tree (dirs survive git/tar, unlike special
        # files) must not walk unbounded just because it holds few
        # classifiable FILES.
        entries_seen += len(dirnames)
        if entries_seen > _MAX_WALK_ENTRIES:
            return True
        rel_parts = Path(dirpath).relative_to(root).parts
        parent_name = rel_parts[-1] if rel_parts else ""
        for filename in filenames:
            entries_seen += 1
            if entries_seen > _MAX_WALK_ENTRIES:
                return True
            dot = filename.rfind(".")
            ext = filename[dot:].lower() if dot > 0 else ""
            stem = filename[:dot] if dot > 0 else filename

            # cargo-fuzz: fuzz/fuzz_targets/<name>.rs beside the fuzz
            # crate's Cargo.toml (the `cargo fuzz init` layout).
            if ext == ".rs" and parent_name == "fuzz_targets":
                key = dirpath
                has_manifest = cargo_manifest_cache.get(key)
                if has_manifest is None:
                    has_manifest = (
                        Path(dirpath).parent / "Cargo.toml"
                    ).is_file()
                    cargo_manifest_cache[key] = has_manifest
                if has_manifest:
                    tallies[ENGINE_CARGO_FUZZ].add(stem)
                continue

            # C-family / python harnesses: content-sniffed, but only
            # in fuzz-hinted locations and inside the sniff budget.
            if ext not in _C_FAMILY_EXTS and ext != ".py":
                continue
            if not _fuzz_hinted(rel_parts, filename):
                continue
            if sniffs_done >= _MAX_SNIFF_FILES:
                truncated = True
                continue
            sniffs_done += 1
            head = _sniff(Path(dirpath) / filename)
            if head is None:
                continue
            if ext in _C_FAMILY_EXTS:
                # Precedence: AFL markers are AFL-specific, while
                # AFL++ can also drive a plain libFuzzer entry point
                # — a file carrying both is counted once, as AFL.
                if any(m in head for m in _AFL_MARKERS):
                    tallies[ENGINE_AFL].add(stem)
                elif _LIBFUZZER_MARKER in head:
                    tallies[ENGINE_LIBFUZZER].add(stem)
            elif any(m in head for m in _ATHERIS_MARKERS):
                tallies[ENGINE_ATHERIS].add(stem)
    return truncated


__all__ = [
    "EngineCensus",
    "FuzzHarnessCensus",
    "census_fuzz_harnesses",
]
