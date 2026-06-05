"""Target-shape inference for the ``/describe`` command (QoL #14).

Composes existing substrates rather than introducing new
detectors:

* ``core/inventory/languages.py:LANGUAGE_MAP`` — extension →
  language id (single source of truth). Counted directly here
  rather than via ``codeql.LanguageDetector`` because the
  latter applies a ``min_files=3`` floor for codeql's DB-build
  use case and silently drops languages with few files —
  wrong for /describe's "what's actually in this tree"
  question.
* ``packages/codeql/build_detector.py:BuildDetector`` — per-
  language build system (autotools / cmake / poetry / npm / …)
* ``core/run/target_types`` — catalog entry (#17 substrate)

The output is a ``TargetShape`` dataclass the renderer turns
into the operator-facing block::

    Target analysis:
      Languages: C (95%), Python (5%)
      Build system: autotools
      Size: ~52k LOC, 189 source files
      Detected type: c.userspace-daemon

``TargetShape`` is deliberately a passive data container — all
field derivation happens in ``infer_target_shape`` so consumers
(the text renderer, the JSON renderer, downstream tools) read
the same shape without re-running detection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from packages.describe.deps import (
    DependencyCounts,
    detect_dependency_counts,
)
from packages.describe.git_provenance import (
    GitProvenance,
    detect_git_provenance,
)


@dataclass(frozen=True)
class TargetShape:
    """Inferred shape of a target codebase. All fields are
    derived from ``infer_target_shape``; consumers treat this
    as read-only.

    ``languages`` maps language id to file count (cpp, python,
    go, …). Ids match the codeql/catalog convention: C and C++
    extensions both roll up to ``cpp``. ``language_breakdown``
    is the same map normalised to percentages (sum to 100.0)
    so the renderer can show "C (95%), Python (5%)" without
    recomputing.

    ``build_systems`` maps language → build-system type ("autotools",
    "cmake", "poetry", …). May be empty when no build manifests
    matched (header-only library, script collection, …); the
    renderer treats absent build system as "unknown".

    ``target_type`` is the matched ``core/run/target_types``
    entry name, or "generic" when nothing more specific matched.
    ``None`` only when the catalog substrate failed to load —
    defensive against future catalog substrate bugs.
    """
    target_path: Path
    languages: Dict[str, int]
    language_breakdown: Dict[str, float]
    primary_language: Optional[str]
    build_systems: Dict[str, str]
    target_type: Optional[str]
    total_files: int
    total_lines: int
    file_extensions: Dict[str, int] = field(default_factory=dict)
    # Per-language LOC, e.g. {"cpp": 8000, "python": 1200}.
    # Sums to ``total_lines``. Lets the renderer show where the
    # mass of a mixed-language tree actually sits — file-count
    # share over-represents languages with many tiny files
    # (Java's one-class-per-file convention can dwarf a much
    # larger C++ kernel by file count alone).
    language_lines: Dict[str, int] = field(default_factory=dict)
    # Git provenance for the target tree. All-None when the
    # target isn't a git checkout — render shows "Git: none
    # detected". Distinct from RAPTOR's own framework
    # provenance (core/run/provenance.py).
    git: Optional[GitProvenance] = None
    # Target's own license (LICENSE / COPYING etc. at the repo
    # root). Reused from ``core.license`` so /describe and the
    # run-lifecycle license warning share a single detector.
    # ``Any`` typed here to avoid an unconditional import at
    # module load — keeps target_shape importable when
    # core.license is unavailable (defence in depth).
    license: Optional[Any] = None
    # Direct-dep counts per ecosystem (npm / pypi / cargo /
    # gomod / …). Lockfiles excluded (those inflate to
    # transitive). Sourced from packages.sca substrate; empty
    # when no manifests / parser failure / /sca unavailable.
    deps: Optional[DependencyCounts] = None


def infer_target_shape(target_path: Path) -> TargetShape:
    """Walk ``target_path`` and compose language / build-system /
    catalog signals into a ``TargetShape``.

    All sub-detectors are best-effort: a missing dependency or
    sub-detector exception yields an empty value in the
    corresponding field rather than failing the whole inference.
    The operator-facing renderer can degrade gracefully — "Build
    system: unknown" is better than no output at all when only
    the build detector failed.
    """
    target_path = Path(target_path).resolve()

    # Single tree walk; per-extension counts feed both the
    # inventory (size, file_extensions) AND the per-language
    # rollup. Detection lives in core.inventory.languages
    # (LANGUAGE_MAP) — single source of truth, shared with
    # other RAPTOR consumers.
    total_files, total_lines, ext_counts, ext_lines = _scan_inventory(
        target_path,
    )
    languages = _per_language_counts(ext_counts)
    language_lines = _per_language_counts(ext_lines)
    breakdown = _compute_breakdown(languages)
    primary = _pick_primary(breakdown)
    build_systems = _detect_build_systems(target_path, languages)
    target_type = _detect_target_type(target_path)
    git = detect_git_provenance(target_path)
    license_obj = _detect_license(target_path)
    deps = detect_dependency_counts(target_path)

    return TargetShape(
        target_path=target_path,
        languages=languages,
        language_breakdown=breakdown,
        primary_language=primary,
        build_systems=build_systems,
        target_type=target_type,
        total_files=total_files,
        total_lines=total_lines,
        file_extensions=ext_counts,
        language_lines=language_lines,
        git=git,
        license=license_obj,
        deps=deps,
    )


def _per_language_counts(ext_amounts: Dict[str, int]) -> Dict[str, int]:
    """Aggregate per-extension integer amounts into per-language
    integer amounts. Used twice in ``infer_target_shape``:
    once for file-counts, once for LOC. Same rollup rule for
    both because the language-id mapping (LANGUAGE_MAP) is the
    same operation either way.

    Languages with multiple extensions (e.g. C++ owns .cpp /
    .cc / .cxx / .hpp / .hh / .hxx) sum across them. C and C++
    extensions both map to "cpp" here — matching what the
    rest of the codebase uses (codeql LanguageDetector merges
    them into a single ``cpp`` id; catalog file_extensions
    use the same), so downstream consumers see a consistent
    language id whether they came in through /describe or
    through /codeql.
    """
    from core.inventory.languages import LANGUAGE_MAP
    out: Dict[str, int] = {}
    for ext, amount in ext_amounts.items():
        lang = LANGUAGE_MAP.get(ext)
        if lang is None:
            continue
        # Merge bare-C into cpp for consistency with the rest
        # of the codebase. LANGUAGE_MAP has .c→"c" and .cpp→
        # "cpp"; we want both extensions under one language
        # id ("cpp") because that's the codeql convention and
        # what the catalog file_extensions enumerate.
        if lang == "c":
            lang = "cpp"
        out[lang] = out.get(lang, 0) + amount
    return out


def _compute_breakdown(languages: Dict[str, int]) -> Dict[str, float]:
    """Normalise file counts to percentages. Empty input → empty
    output (renderer skips the breakdown line)."""
    total = sum(languages.values())
    if total == 0:
        return {}
    return {
        lang: round((count / total) * 100.0, 1)
        for lang, count in languages.items()
    }


def _pick_primary(breakdown: Dict[str, float]) -> Optional[str]:
    """Language with the largest share. None when no languages
    detected. Ties broken by alphabetical name (deterministic)."""
    if not breakdown:
        return None
    return max(breakdown.items(), key=lambda x: (x[1], -ord(x[0][0])))[0]


def _detect_build_systems(
    target_path: Path, languages: Dict[str, int],
) -> Dict[str, str]:
    """Per-language build-system type. Skips languages the
    BuildDetector can't classify (returns None).

    Silences ``BuildDetector``'s INFO / WARNING log lines for
    the duration of detection — its "Detecting … / No build
    system detected …" output is noise in /describe's
    operator-facing block (one INFO + one WARNING per language
    we probe, which on multi-language targets dominates the
    actual report). Probe outcome already shown in the
    "Build system: …" line of the report.
    """
    out: Dict[str, str] = {}
    if not languages:
        return out
    try:
        import logging
        from packages.codeql.build_detector import BuildDetector

        # Drop the per-language probe chatter from the report.
        # BuildDetector uses ``get_logger()`` (no name), which
        # resolves to the shared "raptor" logger — so we can't
        # silence by logger name without quieting unrelated
        # modules. Instead install a record-content filter for
        # the duration of probing: drops ONLY the "Detecting …"
        # / "No build system detected …" probe lines, leaves
        # every other log record alone.
        class _ProbeNoiseFilter(logging.Filter):
            def filter(self, record: logging.LogRecord) -> bool:
                msg = record.getMessage()
                return not (
                    msg.startswith("Detecting build system for ")
                    or msg.startswith("No build system detected for ")
                    or msg.startswith("✓ Detected ")
                    or msg.startswith("  Command: ")
                )

        raptor_logger = logging.getLogger("raptor")
        noise_filter = _ProbeNoiseFilter()
        raptor_logger.addFilter(noise_filter)
        try:
            detector = BuildDetector(target_path)
            for lang in languages:
                try:
                    bs = detector.detect_build_system(lang)
                    if bs is not None:
                        out[lang] = bs.type
                except Exception:  # noqa: BLE001
                    continue
        finally:
            raptor_logger.removeFilter(noise_filter)
    except Exception:  # noqa: BLE001
        return out
    return out


def _detect_license(target_path: Path):
    """Reuse ``core.license.detect_target_license`` — same
    substrate that fires at every run lifecycle's start. None
    on substrate failure (defensive against import / missing-
    deps; render falls back to "License: none detected")."""
    try:
        from core.license import detect_target_license
        return detect_target_license(target_path)
    except Exception:  # noqa: BLE001
        return None


def _detect_target_type(target_path: Path) -> Optional[str]:
    """Matched target-type entry name via the existing
    ``core/run/target_types`` substrate. None on substrate
    failure (the catalog is best-effort throughout RAPTOR)."""
    try:
        from core.run.target_types import load
        entry = load(target_path)
        return entry.name if entry is not None else None
    except Exception:  # noqa: BLE001
        return None


def _scan_inventory(
    target_path: Path,
) -> tuple[int, int, Dict[str, int], Dict[str, int]]:
    """Total source file count + LOC + per-extension file count
    + per-extension LOC. Walks the tree once and counts every
    file whose extension is in ``LANGUAGE_MAP`` (i.e. a
    recognised source language).

    Two parallel per-extension dicts (file count + LOC) instead
    of one dict-of-tuples because both feed the same per-
    language rollup helper, and a separate LOC dict keeps the
    JSON serialisation simple.

    Skips hidden + common build / vendored dirs (node_modules,
    vendor, build, dist, target, __pycache__, out) — those
    exclusions are the real bound on the walk size. No file
    cap: pre-fix this scanned at most 50k files, which silently
    truncated real targets (Linux kernel ~80k .c+.h, Chromium
    larger) and produced wrong totals. The dir-exclusions
    contain pathological inputs in practice, and an honest
    high count is more useful than a silently-clamped one.

    No language-filter argument: previous version took a
    pre-detected language set and only counted its extensions,
    which double-walked and missed languages the upstream
    detector dropped (e.g. Java + JS with <3 files filtered
    out by codeql's ``min_files``). The unconditional walk
    over LANGUAGE_MAP extensions catches every present
    language for /describe's "what's in this tree" purpose.
    """
    from core.inventory.languages import LANGUAGE_MAP
    counted_exts = set(LANGUAGE_MAP.keys())

    total_files = 0
    total_lines = 0
    ext_counts: Dict[str, int] = {}
    ext_lines: Dict[str, int] = {}
    # Per-file LOC read budget. Hostile targets can include a
    # huge text file (10s of GB) to make line counting allocate
    # forever; cap at 20 MB per file (covers every legitimate
    # source file, including auto-generated lexers).
    _MAX_FILE_BYTES_FOR_LOC = 20 * 1024 * 1024
    try:
        import os
        # ``followlinks=False`` (the default, but stated explicitly)
        # — a symlinked directory inside the target would otherwise
        # let an attacker make /describe walk arbitrary host paths.
        # We also skip individual symlinked FILES below: opening
        # them resolves to whatever they point at (possibly
        # /etc/shadow), and reading the LOC count from a host path
        # gives an attacker a sandbox-side-channel probe.
        for root, dirs, files in os.walk(target_path, followlinks=False):
            # Skip hidden + common build/vendored dirs.
            dirs[:] = [
                d for d in dirs
                if not d.startswith(".")
                and d not in {
                    "node_modules", "vendor", "build", "dist",
                    "target", "__pycache__", "out",
                }
            ]
            for f in files:
                ext = "." + f.rsplit(".", 1)[-1].lower() if "." in f else ""
                if ext not in counted_exts:
                    continue
                fp = Path(root) / f
                try:
                    st = fp.lstat()
                except OSError:
                    continue
                # Refuse symlinks: their target may be outside the
                # tree and reading it leaks host-fs state into LOC.
                import stat as _stat
                if _stat.S_ISLNK(st.st_mode):
                    continue
                # Refuse non-regular files (FIFOs, sockets, devices)
                # — opening them can block or be a probe primitive.
                if not _stat.S_ISREG(st.st_mode):
                    continue
                total_files += 1
                ext_counts[ext] = ext_counts.get(ext, 0) + 1
                # Cap the read at _MAX_FILE_BYTES_FOR_LOC; on a
                # truly huge file we count the bytes we read and
                # skip the rest (the file count still ticks; the
                # LOC contribution is bounded).
                try:
                    # O_NOFOLLOW: defence in depth — even though we
                    # already ruled out symlinks via lstat, between
                    # lstat and open a TOCTOU swap could substitute
                    # a symlink. O_NOFOLLOW refuses to open one.
                    fd = os.open(
                        str(fp), os.O_RDONLY | os.O_NOFOLLOW,
                    )
                    try:
                        with os.fdopen(fd, "rb") as fh:
                            n = 0
                            remaining = _MAX_FILE_BYTES_FOR_LOC
                            while remaining > 0:
                                chunk = fh.read(min(remaining, 65536))
                                if not chunk:
                                    break
                                n += chunk.count(b"\n")
                                remaining -= len(chunk)
                    except Exception:  # noqa: BLE001
                        continue
                    total_lines += n
                    ext_lines[ext] = ext_lines.get(ext, 0) + n
                except OSError:
                    continue
    except OSError:
        return (0, 0, {}, {})
    return (total_files, total_lines, ext_counts, ext_lines)


__all__ = ["TargetShape", "infer_target_shape"]
