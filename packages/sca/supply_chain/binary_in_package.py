"""Detector for ``binary_in_tests`` — generalised to "any executable
binary in a source-language published package, outside the opt-in
allowlist".

The narrow predecessor (``artefacts.binary_in_tests``) only fires
under ``tests/`` / ``__tests__/`` / etc.  This module covers the
broader case: an attacker who ships a payload at ``tools/``,
``scripts/``, ``bin/``, or the package root evades the narrow rule.
The Iron Worm attack archetype.

# Adversarial model

What this detector must defend against:

  * **Allowlist abuse** — attacker places the payload under
    ``prebuilds/linux-x64/`` to ride the legitimate prebuildify slot.
    Defence: per-pattern ``magic_required`` (e.g. ``.wasm`` slots
    suppress only on true WebAssembly magic) + opt-in PATTERNS not
    plain prefix matches; legitimate prebuildify is platform-arch
    scoped — an ELF in ``prebuilds/foo/`` doesn't ride.

  * **Polyglot files** — a file with valid script magic AT the head
    + ELF embedded later.  Defence: we don't try to detect
    polyglots; we classify on first bytes.  A polyglot CALLED FROM
    AN INSTALL HOOK is still caught by the script-classification
    intree finding (lower severity but visible) + composite scoring
    on the dep.

  * **Allowlist DOS via huge fixture trees** — attacker ships a
    million binaries in ``tests/fixtures/`` to slow the walk.
    Defence: we honour the same ``EXCLUDED_DIR_NAMES`` discovery
    uses + cap the walk via a stat budget.

  * **Magic-byte spoofing** — file starts with ``\\x7fELF`` but is
    actually a text wrapper.  Defence: we don't claim "this WILL
    execute" — we claim "this LOOKS LIKE an executable that
    shouldn't be in a source distribution".  Operators decide.

  * **Symlinks to host binaries** — same defence as
    ``_intree_resolve``: symlinks rejected outright.

  * **Per-platform binary packages** evaluated as malicious — esbuild
    ships ``@esbuild/linux-x64/bin/esbuild`` and 14 sibling packages
    that exist ENTIRELY to ship the per-platform binary.  Defence:
    name-suffix allowlist via regex in
    ``data/binary_opt_in_locations.json``.

  * **TOCTOU race** — file modified between stat and read.  Defence:
    one read of first 256 bytes; downstream review reads the file
    separately if needed.  This is a scan, not a runtime gate.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from ..discovery import EXCLUDED_DIR_NAMES
from ..models import Confidence, Dependency, Manifest

# Subset of EXCLUDED_DIR_NAMES that's safe to skip during binary
# scanning.  We DELIBERATELY recurse into ``dist/``, ``build/``,
# ``target/``, ``vendor/`` — discovery skips these to avoid walking
# vendored deps when looking for first-party MANIFESTS, but those
# same directories are common publication paths for attackers
# (``dist/`` is the typical publish-from path for built JS/TS
# packages; ``vendor/`` is the Go convention).  Allowlist entries
# in ``binary_opt_in_locations.json`` handle the legitimate
# inhabitants of those dirs.
_BINARY_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn",
    ".cache", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
    ".venv", "venv",
    "node_modules",        # installed deps; not the project's own
                           # publication surface.  Allowlist entry
                           # also covers it for completeness.
    ".idea", ".vscode", ".claude", ".angular",
    "codeql_db", "codeql_dbs",
    ".gradle", ".turbo", ".next", ".nuxt",
    "_build",
    "bower_components",
    # Generic build / scan-output directories.  Repositories use
    # ``out`` / ``.out`` for analyser output, test corpora,
    # SCA / CodeQL artifacts, etc.  These are NOT publication
    # paths — when an attacker drops a payload, it goes into one
    # of the publication-staging dirs (``dist``, ``build``,
    # ``target``, ``vendor``) covered by the allowlist + per-
    # platform-package logic, not into a generic operator-scan
    # output dir.  Dogfooded against RAPTOR's own ``out/`` tree
    # (juice-shop ``.exe`` fixtures, OWASP-benchmark ``.class``
    # files) — both produced FP floods before this entry.
    "out", ".out",
})
# Sanity: every entry must already be in the discovery skip set
# (otherwise we're skipping something discovery walks, which is
# inconsistent).  Defensive — the discovery list is the canonical
# upper bound.
assert _BINARY_SKIP_DIRS <= EXCLUDED_DIR_NAMES, (
    f"_BINARY_SKIP_DIRS leaked entries not in EXCLUDED_DIR_NAMES: "
    f"{_BINARY_SKIP_DIRS - EXCLUDED_DIR_NAMES}"
)

logger = logging.getLogger(__name__)


# Magic-byte signatures keyed by classification name.  Used both for
# detection (any of these → binary) and for ``magic_required``
# allowlist entries (e.g. ``.wasm`` slots demand the WASM magic).
_MAGIC: dict = {
    "elf":    (b"\x7fELF",),
    "pe":     (b"MZ",),
    "macho":  (
        b"\xca\xfe\xba\xbe",          # fat
        b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce",
    ),
    "wasm":   (b"\x00asm",),
}

# Reverse — first-byte classification.
_EXEC_FAMILIES: tuple = ("elf", "pe", "macho", "wasm")

# Cap on the number of files we'll stat in the source walk.  Adversary
# can't DOS us by shipping a million empty files.  Real packages have
# at most a few thousand source files; we generously allow 50k.
_MAX_WALKED_FILES: int = 50_000


# Lazy-loaded allowlist data.
_ALLOWLIST: Optional[dict] = None


def _allowlist_path() -> Path:
    """``packages/sca/data/binary_opt_in_locations.json`` relative to
    this file.  Hand-rolled so we don't import ``..`` at module-init."""
    return Path(__file__).resolve().parents[1] / "data" / "binary_opt_in_locations.json"


def _load_allowlist() -> dict:
    global _ALLOWLIST
    if _ALLOWLIST is not None:
        return _ALLOWLIST
    path = _allowlist_path()
    try:
        _ALLOWLIST = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning(
            "sca.supply_chain.binary_in_package: allowlist load failed (%s); "
            "every binary will report — extend %s",
            e, path,
        )
        _ALLOWLIST = {
            "patterns": [],
            "manifest_opt_in_fields": {},
            "name_suffix_opt_in": {"patterns": []},
        }
    return _ALLOWLIST


@dataclass(frozen=True)
class BinaryHit:
    """One file in the package tree that looks like an executable
    payload and isn't in the allowlist."""

    dependency: Dependency
    path: Path
    family: str                    # "elf" / "pe" / "macho" / "wasm" / "binary"
    relpath: str                   # path relative to manifest dir, for evidence
    # Phase 8 forensic evidence — populated by
    # :func:`_forensic_evidence` on each hit.  Empty dict when the
    # forensic pass fails (non-ELF, capability_fingerprint error,
    # etc.); the BinaryHit is still emitted regardless.
    forensic_evidence: dict = field(default_factory=dict)


def _classify_magic(head: bytes) -> Optional[str]:
    """Return ``"elf"``/``"pe"``/``"macho"``/``"wasm"`` or None.

    Disambiguates the ``\\xca\\xfe\\xba\\xbe`` collision: Mach-O fat
    binaries and Java ``.class`` files share the same first 4 bytes.
    Bytes 4-7 distinguish them:

      * Mach-O fat: u32 big-endian = ``nfat_arch`` (number of
        embedded architectures).  In practice 1-8; never approaches
        the high tens.
      * Java class: u16 ``minor_version`` + u16 ``major_version``.
        ``major_version >= 45`` for all valid class files (Java
        1.1 = 45, Java 21 = 65); ``minor_version`` is 0 for normal
        files and ``0xFFFF`` for preview class files.

    Threshold of 20: a u32 value < 20 is Mach-O fat; ≥ 20 is Java.
    Java class files are out of scope for binary_in_package
    (Java packages don't ship as native binaries; ``.jar`` /
    ``.war`` carry classes); we return None so they don't fire.
    """
    for family, magics in _MAGIC.items():
        if not any(head.startswith(m) for m in magics):
            continue
        if family == "macho" and head.startswith(b"\xca\xfe\xba\xbe"):
            if len(head) < 8:
                # Truncated; can't disambiguate.  Conservative:
                # treat as Java (out of scope) rather than risk a
                # `.class` FP.
                return None
            value = int.from_bytes(head[4:8], "big")
            if value >= 20:
                return None       # Java class file
        return family
    return None


def _is_executable_extension(path: Path) -> bool:
    """Extensions that strongly suggest the file IS an executable
    even without magic-byte confirmation.  Used as a backup check
    for ``.so`` / ``.dylib`` / ``.dll`` whose magic is shared with
    other binary formats but whose extension is unambiguous."""
    return path.suffix.lower() in {".so", ".dylib", ".dll", ".node", ".exe"}


def _name_is_per_platform_pkg(dep: Dependency) -> bool:
    """True if the dep's NAME matches a per-platform binary package
    convention (esbuild, swc, bun, etc.)."""
    allowlist = _load_allowlist()
    patterns = allowlist.get("name_suffix_opt_in", {}).get("patterns", [])
    for pat in patterns:
        try:
            if re.match(pat, dep.name):
                return True
        except re.error:
            logger.warning(
                "sca.supply_chain.binary_in_package: bad regex in "
                "name_suffix_opt_in: %r — ignoring",
                pat,
            )
    return False


def _manifest_declares_native(manifest: Manifest) -> bool:
    """True if the manifest declares it ships native binaries via a
    known opt-in field (npm ``binary``, Cargo ``links``, etc.).

    Conservative: only checks fields enumerated in the allowlist
    data file.  Unrecognised fields don't grant suppression.
    """
    allowlist = _load_allowlist()
    fields_per_ecosystem = allowlist.get("manifest_opt_in_fields", {})
    fields = fields_per_ecosystem.get(manifest.ecosystem, [])
    if not fields or manifest.path.name != "package.json":
        # Today we only know how to peek at npm package.json bodies.
        # Cargo's ``links`` is in TOML and not parsed here yet.
        return False
    try:
        data = json.loads(manifest.path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(data, dict):
        return False
    return any(f in data for f in fields)


def _glob_to_regex(glob: str) -> str:
    """Convert a recursive glob (supporting ``**``) to a regex.

    Standards: ``**`` matches any number of path components
    (including zero); ``*`` matches anything except ``/``; ``?``
    matches a single non-``/`` character.

    Pathlib's ``Path.match`` deliberately does NOT support recursive
    ``**`` (path-traversal semantics conflict with its purer
    path-shape API), so we translate to regex ourselves.
    """
    parts: List[str] = ["^"]
    i = 0
    n = len(glob)
    while i < n:
        # ``**/`` — zero or more path components followed by /
        if glob[i:i + 3] == "**/":
            parts.append("(?:.*/)?")
            i += 3
        # bare ``**`` at end
        elif glob[i:i + 2] == "**":
            parts.append(".*")
            i += 2
        elif glob[i] == "*":
            parts.append("[^/]*")
            i += 1
        elif glob[i] == "?":
            parts.append("[^/]")
            i += 1
        else:
            parts.append(re.escape(glob[i]))
            i += 1
    parts.append("$")
    return "".join(parts)


def _path_matches_allowlist(
    rel: Path, head: bytes,
) -> bool:
    """True when ``rel`` (relative to manifest dir) matches any
    allowlist pattern.  ``magic_required`` entries additionally
    require the file's first bytes to match the named family — so a
    ``foo.wasm`` that ships an ELF wearing the wasm extension does
    NOT ride the wasm allowlist."""
    allowlist = _load_allowlist()
    rel_str = rel.as_posix()
    for entry in allowlist.get("patterns", []):
        pattern = entry.get("pattern", "")
        if not pattern:
            continue
        try:
            regex = _glob_to_regex(pattern)
        except re.error:
            continue
        if not re.match(regex, rel_str):
            continue
        magic_required = entry.get("magic_required")
        if magic_required:
            required_magics = _MAGIC.get(magic_required, ())
            if not any(head.startswith(m) for m in required_magics):
                # Pattern matched on the PATH but content doesn't
                # match the required family — refuse the
                # suppression.
                continue
        return True
    return False


def _walk_for_binaries(
    root: Path,
) -> Iterable[Path]:
    """Yield files under ``root`` skipping the same excluded dirs
    discovery skips.  Bounded by ``_MAX_WALKED_FILES``."""
    yielded = 0
    # ``Path.walk`` (3.12+) would be nicer but we keep compatibility.
    for dirpath, dirnames, filenames in __import__("os").walk(root):
        # Mutate dirnames in place so skipped dirs are not recursed.
        dirnames[:] = [d for d in dirnames if d not in _BINARY_SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            yielded += 1
            if yielded > _MAX_WALKED_FILES:
                logger.warning(
                    "sca.supply_chain.binary_in_package: walked >%d files "
                    "under %s — capping",
                    _MAX_WALKED_FILES, root,
                )
                return
            yield p


def _classify_or_none(path: Path) -> Optional[tuple]:
    """Return ``(family, head_bytes)`` for files that look like
    executable payloads, otherwise None.  Reads only first 256 bytes.

    Family ``binary`` is returned for extension-driven hits (``.so``
    / ``.dylib`` / etc.) when magic-byte classification is
    inconclusive — the extension is enough to flag for review.
    """
    try:
        if path.is_symlink() or not path.is_file():
            return None
    except OSError:
        return None
    try:
        with open(path, "rb") as f:
            head = f.read(256)
    except OSError:
        return None
    if not head:
        return None
    family = _classify_magic(head)
    if family is not None:
        return (family, head)
    if _is_executable_extension(path):
        return ("binary", head)
    return None


def scan_target(
    target: Path,
    manifests: Sequence[Manifest],
    deps: Sequence[Dependency] = (),
) -> List[BinaryHit]:
    """Walk ``target`` for files that look like executable binaries
    and aren't in the allowlist.  Emits one ``BinaryHit`` per such
    file.

    Soundness notes:

      * Skips the same excluded dirs as discovery (so vendored deps
        / VCS metadata don't dominate the noise).
      * Suppresses via the data-file allowlist (legitimate
        per-platform layouts) AND per-package opt-in (manifest
        fields, per-platform package naming).
      * Walked-file budget capped to defend against pathological
        repos and tarball bombs that have somehow been extracted.
    """
    target = target.resolve()
    if not target.is_dir():
        return []
    # Index manifests by their containing dir so we can decide which
    # manifest "owns" each binary hit.  Most projects have one
    # top-level manifest; monorepos have several.
    manifests_list = list(manifests)
    # Skip the walk entirely if every manifest declares native
    # opt-in — caller's already saying "yes this ships binaries".
    if manifests_list and all(
        _manifest_declares_native(m) for m in manifests_list
    ):
        return []
    deps_list = list(deps)
    out: List[BinaryHit] = []
    for path in _walk_for_binaries(target):
        result = _classify_or_none(path)
        if result is None:
            continue
        family, head = result
        try:
            rel = path.relative_to(target)
        except ValueError:
            continue
        if _path_matches_allowlist(rel, head):
            continue
        # Find the closest manifest above this path; default to the
        # placeholder dep if none.
        host = _closest_dep(path, manifests_list, deps_list)
        if host is not None and _name_is_per_platform_pkg(host):
            continue
        if host is None:
            host = _placeholder_dep(target)
        out.append(BinaryHit(
            dependency=host,
            path=path,
            family=family,
            relpath=str(rel),
            forensic_evidence=_forensic_evidence(path, family),
        ))
    return out


def _forensic_evidence(path: Path, family: str) -> dict:
    """Phase 8 — surface capability-fingerprint buckets + packer
    detection alongside each ``binary_in_package`` hit so reviewers
    see WHICH dangerous capabilities the dropped binary actually
    imports.

    Best-effort: failure at any stage returns ``{}`` rather than
    propagating; ``binary_in_package`` should never fail to emit a
    finding because the forensic pass had a problem.

    Notes:
      * Capability fingerprint is import-table-based.  An attacker
        could strip the dynamic symbol table; that's a different
        signal (handled elsewhere) and isn't this layer's concern.
      * Packer detection is signature-based against the leading
        4 KB; the documented packers we cover are the common ones
        seen in supply-chain payloads.
    """
    evidence: dict = {}
    # Packer detection runs on every family — UPX-packed PE / Mach-O
    # binaries are common in cross-platform malware.
    try:
        from core.binary.elf import is_packed
        packer = is_packed(path)
    except Exception:                                  # pragma: no cover
        packer = None
    if packer is not None:
        evidence["packer"] = packer
    # Capability fingerprint is ELF-only at the stdlib tier (PE /
    # Mach-O require radare2 which we don't take a hard dep on).
    if family == "elf":
        try:
            from core.binary.fingerprint import (
                HIGH_SEVERITY_BUCKETS,
                capability_fingerprint,
            )
            fp = capability_fingerprint(path)
        except Exception as exc:                       # pragma: no cover
            logger.debug(
                "sca.supply_chain.binary_in_package: capability "
                "fingerprint failed for %s: %r",
                path, exc,
            )
            return evidence
        if fp is not None:
            buckets = dict(fp.capability_buckets)
            if buckets:
                evidence["capability_buckets"] = {
                    k: sorted(v) for k, v in buckets.items()
                }
                high = sorted(set(buckets) & HIGH_SEVERITY_BUCKETS)
                if high:
                    evidence["high_severity_buckets"] = high
    return evidence


def _closest_dep(
    path: Path,
    manifests: Sequence[Manifest],
    deps: Sequence[Dependency],
) -> Optional[Dependency]:
    """Return the dep declared by the manifest closest to ``path``
    in the directory tree.  Returns None when no manifest dominates
    the file (caller falls back to a placeholder)."""
    best_depth = -1
    best: Optional[Dependency] = None
    for m in manifests:
        m_dir = m.path.parent.resolve()
        try:
            path.resolve().relative_to(m_dir)
        except ValueError:
            continue
        depth = len(m_dir.parts)
        if depth <= best_depth:
            continue
        # Find a dep declared in this manifest.
        for d in deps:
            if d.declared_in == m.path:
                best = d
                best_depth = depth
                break
    return best


def _placeholder_dep(target: Path) -> Dependency:
    """Synthesised dep used when no manifest dominates the path.
    Mirrors the shape ``install_hooks._placeholder_for_manifest``
    uses so downstream code (display / aggregation) treats it the
    same."""
    from ..models import PinStyle
    return Dependency(
        ecosystem="unknown",
        name="<project-tree>",
        version=None,
        declared_in=target,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.UNKNOWN,
        direct=True,
        purl="",
        parser_confidence=Confidence(
            "low", reason="placeholder for binary_in_package finding host",
        ),
    )


__all__ = ["BinaryHit", "scan_target"]
