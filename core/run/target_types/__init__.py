"""Target-type catalog substrate (QoL #17).

Per-target-type policy lives in YAML siblings of this module
(``<name>.yml``). The catalog tells consumers (``raptor plan``,
attack-surface ranking, default pack selection, budget defaults,
smart ``project create``) what the right defaults look like for a
given target shape, so each consumer doesn't have to invent its
own per-target-type heuristics fragmentarily.

## Schema

Each ``<name>.yml`` carries::

  name: c.userspace-daemon
  description: |
    Human-readable summary of what this target shape looks like.

  detection:
    # Positive signals — present-when-true.
    file_globs:        ["configure.ac", "Makefile.am"]
    file_extensions:   [".c", ".h"]
    function_names:    [main_loop, accept, listen]   # tree-sitter
    # Negative signals — disqualify this entry if matched.
    negative_globs:    ["kernel/**", "drivers/**"]

  semgrep_packs:
    default:  [security-audit, command-injection, owasp-top-ten]
    optional: [secrets, jwt]

  attack_surface:
    high_priority_dirs: [src/http, src/net, src/protocols]
    low_priority_dirs:  [src/device/sysdep_*, tests/, examples/]

  pipeline:
    recommended: [understand-map, scan-with-codeql, agentic-with-validate]

  budget_defaults:
    typical_findings_count:  25
    typical_cost_per_run_usd: 30

  version: 1

## Detection

``detect(target_path)`` walks the target's top-level files and
matches signals against each catalog entry. Negative signals are
deal-breakers (entry is dropped if any matches). Positive signals
contribute to a confidence score; the highest-scoring entry wins.

Tree-sitter function-name matching is on the roadmap but the v1
substrate uses file globs + extensions only — those cover the
common cases (Cargo.toml → rust, package.json → node, configure.ac
→ autotools daemon) without pulling in the tree-sitter dependency
chain.

## Why standalone substrate (not folded into ``raptor plan``)

Multiple consumers (#7 default pack selection, #9 attack-surface
ranking, #14 plan recommendation, #15 budget defaults, #18 smart
project-create) all depend on the same per-target-type mapping.
Folding into plan would force every other consumer to call into
plan to read its catalog. The substrate as a separate module is
authorable independently (community contributors can add
``php.wordpress-plugin.yml`` without touching the planner).

This commit ships substrate + 3 seed entries + the loader/detect
API. Per-consumer backfill (#7, #9, #14, #15, #18 wiring) lands
in follow-on commits as those code paths get touched.
"""

from __future__ import annotations

import fnmatch
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Cap how deep we walk when matching ``**``-style globs. 4 levels
# covers ``src/<subsystem>/<file>.c`` shapes without exploding on
# pathological trees (node_modules / .git / build outputs).
_MAX_DETECT_DEPTH = 4

# Cap how many files we examine during detection. Walking a
# 100k-file target tree for every signal would dominate the
# lifecycle's startup cost; 10k is enough to catch the structural
# signals catalog entries rely on.
_MAX_DETECT_FILES = 10_000


@dataclass(frozen=True)
class CatalogEntry:
    """One target-type entry — loaded from its ``<name>.yml`` sibling.

    Frozen so a single instance can be safely shared across
    consumers without one mutating the catalog state another sees.
    """

    name: str
    description: str = ""

    # Detection signals
    file_globs: tuple[str, ...] = field(default_factory=tuple)
    file_extensions: tuple[str, ...] = field(default_factory=tuple)
    function_names: tuple[str, ...] = field(default_factory=tuple)
    negative_globs: tuple[str, ...] = field(default_factory=tuple)

    # Default policy hints — consumers consult these but the
    # substrate doesn't enforce them (operator overrides win).
    semgrep_packs_default: tuple[str, ...] = field(default_factory=tuple)
    semgrep_packs_optional: tuple[str, ...] = field(default_factory=tuple)
    attack_surface_high: tuple[str, ...] = field(default_factory=tuple)
    attack_surface_low: tuple[str, ...] = field(default_factory=tuple)
    pipeline_recommended: tuple[str, ...] = field(default_factory=tuple)

    typical_findings_count: int = 0
    typical_cost_per_run_usd: float = 0.0

    # Versioning — provenance + reproducibility. Bump when the
    # entry's defaults shift in a way operators might want to
    # detect (e.g. new packs added to ``semgrep_packs_default``).
    version: int = 1

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CatalogEntry:
        """Build a CatalogEntry from parsed YAML. Tolerant of
        missing optional sections — only ``name`` is required."""
        if "name" not in data:
            msg = "CatalogEntry.from_dict: missing required 'name' field"
            raise ValueError(msg)
        detection = data.get("detection") or {}
        packs = data.get("semgrep_packs") or {}
        surface = data.get("attack_surface") or {}
        pipeline = data.get("pipeline") or {}
        budget = data.get("budget_defaults") or {}

        def _t(seq):
            return tuple(seq) if seq else ()

        return cls(
            name=data["name"],
            description=data.get("description", "").strip(),
            file_globs=_t(detection.get("file_globs")),
            file_extensions=_t(detection.get("file_extensions")),
            function_names=_t(detection.get("function_names")),
            negative_globs=_t(detection.get("negative_globs")),
            semgrep_packs_default=_t(packs.get("default")),
            semgrep_packs_optional=_t(packs.get("optional")),
            attack_surface_high=_t(surface.get("high_priority_dirs")),
            attack_surface_low=_t(surface.get("low_priority_dirs")),
            pipeline_recommended=_t(pipeline.get("recommended")),
            typical_findings_count=int(budget.get("typical_findings_count") or 0),
            typical_cost_per_run_usd=float(
                budget.get("typical_cost_per_run_usd") or 0),
            version=int(data.get("version") or 1),
        )


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


_CATALOG_DIR = Path(__file__).parent
_CACHED_CATALOG: tuple[CatalogEntry, ...] | None = None


def _load_one(yml_path: Path) -> CatalogEntry | None:
    """Parse a single catalog YAML. Returns None on missing file /
    malformed YAML / missing required fields — substrate stays
    best-effort so a single broken entry doesn't break the loader
    for all consumers."""
    try:
        text = yml_path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            return None
        return CatalogEntry.from_dict(data)
    except (OSError, yaml.YAMLError, ValueError, IndexError, TypeError):
        return None


def all_entries() -> tuple[CatalogEntry, ...]:
    """Load every ``<name>.yml`` in the catalog dir (excluding
    ``tests/``). Cached after first call — entries are immutable so
    re-reading the YAML on every call would be wasted IO."""
    global _CACHED_CATALOG
    if _CACHED_CATALOG is not None:
        return _CACHED_CATALOG
    entries: list[CatalogEntry] = []
    for p in sorted(_CATALOG_DIR.glob("*.yml")):
        entry = _load_one(p)
        if entry is not None:
            entries.append(entry)
    _CACHED_CATALOG = tuple(entries)
    return _CACHED_CATALOG


def load_by_name(name: str) -> CatalogEntry | None:
    """Direct lookup by catalog name (e.g. ``c.userspace-daemon``).
    Returns None if no entry matches — caller should fall back to
    ``generic`` or operator-prompt."""
    for entry in all_entries():
        if entry.name == name:
            return entry
    return None


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def _walk_target(target_path: Path) -> list[str]:
    """Walk ``target_path`` up to ``_MAX_DETECT_DEPTH`` levels deep,
    returning relative POSIX paths (cap at ``_MAX_DETECT_FILES``).
    Skips dotted directories (``.git``, ``.cache``) — these are
    never the structural signals catalog entries care about."""
    if not target_path.is_dir():
        return []
    rels: list[str] = []
    target_path = target_path.resolve()
    import os
    for root, dirs, files in os.walk(target_path):
        # Skip dotted dirs.
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        root_path = Path(root)
        # Depth check.
        try:
            depth = len(root_path.relative_to(target_path).parts)
        except ValueError:
            continue
        if depth > _MAX_DETECT_DEPTH:
            dirs[:] = []
            continue
        for f in files:
            rels.append(
                str((root_path / f).relative_to(target_path).as_posix())
            )
            if len(rels) >= _MAX_DETECT_FILES:
                return rels
    return rels


def _matches_any(paths: list[str], globs: tuple[str, ...]) -> int:
    """Count how many ``globs`` match at least one path. (Not
    ''how many path-glob pairs match'' — that would over-weight
    distinctive globs that happen to hit many files.)"""
    hits = 0
    for g in globs:
        if any(fnmatch.fnmatch(p, g) for p in paths):
            hits += 1
    return hits


def _has_extension(paths: list[str], extensions: tuple[str, ...]) -> int:
    """Count distinct extensions matched (same intent as
    ``_matches_any`` — bool-per-signal, not per-file)."""
    matched: set = set()
    ext_set = {e.lower() for e in extensions}
    for p in paths:
        suffix = Path(p).suffix.lower()
        if suffix in ext_set:
            matched.add(suffix)
    return len(matched)


def _score_entry(entry: CatalogEntry, paths: list[str]) -> float | None:
    """Score how well ``entry``'s detection signals match the
    target's file tree. Returns None when negative signals match
    (entry disqualified). Otherwise: positive-signal-count
    weighted by signal type.

    Weighting reflects how DISCRIMINATING each signal type is:
    file_globs (often specific like ``configure.ac``) > file_extensions
    (broad, many entries claim ``.c``). Function-name matching when
    tree-sitter substrate exists earns a higher weight; not used
    in v1.

    Specificity gate: if an entry declares ``file_globs`` (= it
    requires specific framework markers) but ZERO matched, refuse
    to count the extension hits — extensions alone don't validate
    the specificity claim, and would otherwise let python.web-app
    win on any project that has .py + .html files (security
    frameworks, doc generators, library examples). Entries with
    no file_globs declared (``generic``) skip the gate and score
    via extensions as before.
    """
    # Negative signals are deal-breakers.
    if entry.negative_globs and _matches_any(paths, entry.negative_globs):
        return None
    file_glob_score = 2.0 * _matches_any(paths, entry.file_globs)
    ext_score = 1.0 * _has_extension(paths, entry.file_extensions)
    if entry.file_globs and file_glob_score == 0:
        # Specificity gate fired — entry claimed framework
        # signals that aren't here. Fall through to the
        # next-best entry (likely ``generic``).
        return 0.0
    # function_names ignored in v1 (no tree-sitter dependency here).
    return file_glob_score + ext_score


def detect(target_path: Path) -> list[tuple[CatalogEntry, float]]:
    """Walk the target and return all catalog entries ranked by
    confidence score (descending). Entries with score 0 are
    excluded — no positive signal matched.

    Caller picks the highest-scoring entry, or prompts the
    operator when scores are close (ambiguous polyglot repo), or
    falls back to ``generic`` when nothing matched.
    """
    paths = _walk_target(Path(target_path))
    if not paths:
        return []
    scored: list[tuple[CatalogEntry, float]] = []
    for entry in all_entries():
        s = _score_entry(entry, paths)
        if s is None or s <= 0:
            continue
        scored.append((entry, s))
    scored.sort(key=lambda x: (-x[1], x[0].name))
    return scored


def load(target_path: Path) -> CatalogEntry | None:
    """Pick the best-matching catalog entry for ``target_path``.
    Returns the best-scoring entry, else the ``generic`` entry when
    nothing scored above 0, else None when no generic entry exists
    (caller prompts the operator)."""
    ranked = detect(target_path)
    if not ranked:
        # Fall back to ``generic`` when present — operator gets a
        # working default rather than a None to handle.
        return load_by_name("generic")
    return ranked[0][0]


# ---------------------------------------------------------------------------
# Binary-dominance detection (magic bytes, never extensions)
# ---------------------------------------------------------------------------

# Cap how many files get their first bytes read during
# binary-dominance sampling. The capped ``_walk_target`` enumeration
# already bounds the candidate list; this second cap bounds the
# number of ``open()`` calls, so classification stays cheap even on
# a 10k-file artifact drop.
_BINARY_SAMPLE_CAP = 200

# Minimum number of successfully examined files before a dominance
# verdict is allowed. Without a floor, a single planted 2-byte
# ``MZ`` file plus unreadable noise could classify a whole tree.
_BINARY_MIN_EXAMINED = 3

# First-bytes signatures of compiled artifacts. Prefix checks for
# ELF, PE (the ``MZ`` DOS stub) and ar static archives (``.a`` —
# a static-library drop is a compiled-artifact tree too); Mach-O
# thin and 64-bit fat magics are exact 4-byte words in both byte
# orders. The 32-bit fat Mach-O magic (``0xCAFEBABE``) is
# deliberately absent — it collides with JVM class files, which
# live in source-shaped trees; 32-bit fat binaries therefore
# dilute the sample (documented residual). ``0xCAFEBABF``
# (FAT_MAGIC_64) has no such collision and is included.
_COMPILED_MAGIC_PREFIXES: tuple[bytes, ...] = (
    b"\x7fELF",    # ELF
    b"MZ",         # PE
    b"!<arch>\n",  # ar static archive
)
_MACHO_MAGICS: frozenset[bytes] = frozenset({
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",  # Mach-O 32-bit
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit
    b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",  # fat 64-bit (FAT_MAGIC_64)
})

# Extensions that mark a *source* tree. Used only to veto the
# binary classification when a substantial source tree co-exists
# with built artifacts (a ``build/`` dir inside a source repo must
# keep the source-tree pipeline). Extension check only — no reads —
# so the veto covers the full capped walk, not just the magic
# sample.
_SOURCE_EXTENSIONS: frozenset[str] = frozenset({
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh",
    ".rs", ".go", ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".kt", ".scala", ".rb", ".php", ".cs",
    ".swift", ".m", ".mm", ".pl", ".pm", ".lua", ".zig",
})


def _read_magic(path: Path) -> bytes | None:
    """Read the first 8 bytes of a regular file. Returns None for
    anything unreadable or non-regular — callers treat that as
    "no evidence either way", never an error.

    The target tree is untrusted, so non-regular files are refused
    BEFORE any open(2): opening a hostile character device can
    itself have side effects (canonically ``/dev/watchdog``, which
    arms on open), and a FIFO would block a plain open. The
    ``os.lstat`` check refuses symlinks and special files pre-open;
    the ``O_NOFOLLOW`` + ``O_NONBLOCK`` open with a post-open
    ``fstat``/``S_ISREG`` re-check stays as the TOCTOU belt for a
    swap between the lstat and the open. Nothing is executed or
    parsed beyond the 8-byte read.
    """
    try:
        if not stat.S_ISREG(os.lstat(str(path)).st_mode):
            return None
    except OSError:
        return None
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return os.read(fd, 8)
    except OSError:
        return None
    finally:
        os.close(fd)


def _is_compiled_artifact(head: bytes) -> bool:
    """True when ``head`` (the file's first bytes) carries a
    compiled-artifact signature (ELF / Mach-O / PE / ar)."""
    for magic in _COMPILED_MAGIC_PREFIXES:
        if head.startswith(magic):
            return True
    return head[:4] in _MACHO_MAGICS


def binary_dominant(
    target_path: Path, sample_cap: int = _BINARY_SAMPLE_CAP,
) -> bool:
    """True when ``target_path`` is dominated by compiled artifacts
    (ELF / Mach-O / PE / ar magic bytes) and no substantial source
    tree exists — a firmware dump, an extracted package, a
    static-archive or build-output drop — or is itself a single
    compiled-artifact file. Such targets give the source-tree
    pattern scanners nothing to work on; consumers use this verdict
    to steer operators to the binary lane instead.

    Cheap and safe by construction: reuses the capped
    ``_walk_target`` enumeration, reads only the first 8 bytes of
    at most ``sample_cap`` files via ``_read_magic`` (list-based
    filesystem ops only — nothing is executed or shell-quoted),
    and skips unreadable files gracefully.
    """
    root = Path(target_path)
    if root.is_file():
        # Single-file target (``--target ./firmware.elf``): the
        # walk-based census has nothing to walk, so classify by the
        # file's own magic — same lstat/open hardening.
        head = _read_magic(root)
        return head is not None and _is_compiled_artifact(head)
    paths = _walk_target(root)
    if not paths:
        return False
    if len(paths) >= _MAX_DETECT_FILES:
        # The walk hit its file cap, so the census is TRUNCATED —
        # it saw only whichever files happened to enumerate first.
        # A truncated census is not evidence: a hostile tree can
        # front-load the cap with binary-magic names so no real
        # source is ever walked, and the source veto below would
        # then see zero sources on a genuine source repo (which
        # --require-target-type would turn into a refused create).
        # Refuse the binary verdict and fail toward the status-quo
        # source pipeline.
        return False
    # Substantial-source veto: whatever the magic sample says, a
    # real source tree keeps the source pipeline. Threshold: 3
    # source files minimum, scaling to 10% of the walked tree so
    # a handful of generated stubs in a large artifact drop can't
    # veto, while any small source project always does.
    source_count = sum(
        1 for p in paths if Path(p).suffix.lower() in _SOURCE_EXTENSIONS
    )
    if source_count >= max(3, len(paths) // 10):
        return False
    # Evenly-strided sample so one crowded subdirectory doesn't
    # monopolise the cap.
    if sample_cap <= 0:
        return False
    if len(paths) > sample_cap:
        step = len(paths) / sample_cap
        sample = [paths[int(i * step)] for i in range(sample_cap)]
    else:
        sample = paths
    resolved = root.resolve()
    compiled = 0
    examined = 0
    for rel in sample:
        head = _read_magic(resolved / rel)
        if head is None:
            continue  # unreadable / special / symlink — no evidence
        examined += 1
        if _is_compiled_artifact(head):
            compiled += 1
    # Dominance = a STRICT majority of the examined sample carries
    # a compiled-artifact magic, and at least _BINARY_MIN_EXAMINED
    # files were actually examined — a single planted magic file
    # plus unreadable noise must never classify a tree.
    return examined >= _BINARY_MIN_EXAMINED and compiled * 2 > examined


def _reset_cache_for_tests() -> None:
    """Clear the loader cache. Test-only hook — production code
    treats the catalog as immutable per process."""
    global _CACHED_CATALOG
    _CACHED_CATALOG = None


__all__ = [
    "CatalogEntry",
    "all_entries",
    "binary_dominant",
    "detect",
    "load",
    "load_by_name",
]
