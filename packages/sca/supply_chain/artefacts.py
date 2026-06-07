"""Artefact-shape heuristics — files in the project tree that look
suspicious before any code is read.

Four checks in one tree-walking pass:

- ``python_pth_file`` — a ``.pth`` file in the project tree. ``.pth``
  files in ``site-packages`` get *executed* by the Python interpreter
  at startup; one shipped in the project source root is genuinely
  weird.
- ``binary_in_tests`` — a non-text file inside a ``tests/`` directory
  that is also large enough to plausibly be an executable payload.
- ``disguised_filename`` — a file whose extension lies about its
  contents. ``image.png`` whose first bytes are ELF, ``config.json``
  whose first bytes are a shebang, ``data.txt`` whose first bytes are
  a ZIP magic. Real attacks use this to hide payloads in places code
  reviewers won't open in a viewer.
- ``large_obfuscated_artefact`` — large source-extension files
  (``.js`` / ``.py``) outside build / dist directories whose entropy
  or line length suggests minification or obfuscation. Real-world
  npm supply-chain attacks frequently ship obfuscated payloads in
  source-tree directories that would normally hold human-edited code.

These checks walk the *target* tree, not installed deps. We deliberately
skip the same vendored-tree directories discovery already excludes;
operators who want to scan ``node_modules`` for shipped artefacts run
the full deep scan in the supply-chain follow-up.
"""

from __future__ import annotations

import logging
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Set

from ..discovery import EXCLUDED_DIR_NAMES
from ..models import Confidence, Dependency, Manifest, PinStyle

logger = logging.getLogger(__name__)

# Canonical skip set + this walker's extras. Drift-free: a new entry
# in discovery.EXCLUDED_DIR_NAMES propagates to every walker.
_EXCLUDED_DIRS: Set[str] = EXCLUDED_DIR_NAMES | {
    "site-packages",        # any virtualenv that snuck in
}

_TEST_DIR_NAMES: Set[str] = {"tests", "test", "__tests__", "spec", "e2e"}

_BINARY_MAGIC = (
    b"\x7fELF",          # Linux / BSD ELF
    b"MZ",                # Windows PE/COFF
    b"\xCA\xFE\xBA\xBE", # JVM class / Mach-O fat
    b"\xFE\xED\xFA\xCE", # Mach-O 32
    b"\xFE\xED\xFA\xCF", # Mach-O 64
    b"\xCF\xFA\xED\xFE", # Mach-O 64 reversed
    b"PK\x03\x04",        # ZIP / JAR / DOCX / wheel
    b"\x1f\x8b",          # gzip
)

_BIN_IN_TESTS_MIN_BYTES = 16 * 1024

_EXTENSION_MAGIC: dict[str, "tuple[bytes, ...] | None"] = {
    ".png":  (b"\x89PNG\r\n\x1a\n",),
    ".jpg":  (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".gif":  (b"GIF87a", b"GIF89a"),
    ".webp": (b"RIFF",),
    ".bmp":  (b"BM",),
    ".ico":  (b"\x00\x00\x01\x00", b"\x00\x00\x02\x00"),
    ".pdf":  (b"%PDF-",),
    ".mp3":  (b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"),
    ".mp4":  (b"\x00\x00\x00\x18ftyp", b"\x00\x00\x00 ftyp"),
    ".zip":  (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
    ".jar":  (b"PK\x03\x04",),
    ".gz":   (b"\x1f\x8b",),
    ".7z":   (b"7z\xbc\xaf\x27\x1c",),
    ".json": None, ".yaml": None, ".yml": None, ".toml": None,
    ".xml":  None, ".html": None, ".md": None, ".txt": None,
    ".py":   None, ".js": None, ".ts": None, ".jsx": None, ".tsx": None,
    ".mjs":  None, ".cjs": None, ".css": None, ".sh": None,
    ".rs":   None, ".go": None, ".java": None, ".rb": None,
    ".lock": None, ".cfg": None, ".ini": None,
}

_OBFUSC_MIN_BYTES = 100 * 1024
_OBFUSC_MAX_LINE_LEN = 1000
_OBFUSC_HIGH_ENTROPY = 5.5
_OBFUSC_EXTS: Set[str] = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".py"}

# Extensions where a shebang line is normal — don't flag
# `disguised_filename` for shebangs in these. Other text-typed
# extensions (.json, .yaml, .toml, .md, .txt, .html, .css, .lock,
# .cfg, .ini, .xml) are pure data and a shebang is suspicious.
_SHEBANG_OK_EXTS: Set[str] = {
    ".sh", ".py", ".js", ".mjs", ".cjs", ".rb", ".pl", ".lua",
    ".ts", ".rs", ".go",
}
_BUILT_OUTPUT_DIRS: Set[str] = {
    "dist", "build", "out", "_build", "min", "minified",
    "vendor", "node_modules", "site-packages", ".webpack", ".rollup",
    "static", "public", "assets",
}

_DEFAULT_MAX_DEPTH = 12


@dataclass(frozen=True)
class ArtefactFinding:
    dependency: Dependency
    kind: str           # see module docstring for the four kinds
    detail: str
    path: Path
    severity: str
    confidence: Confidence


def scan_target(
    target: Path,
    manifests: Iterable[Manifest],
    *,
    max_depth: int = _DEFAULT_MAX_DEPTH,
) -> List[ArtefactFinding]:
    """Walk ``target`` and return every artefact-shape finding."""
    target = target.resolve()
    manifests_list = list(manifests)
    out: List[ArtefactFinding] = []
    for path in _walk(target, max_depth=max_depth):
        finding = _classify(path, target, manifests_list)
        if finding is not None:
            out.append(finding)
    return out


# ---------------------------------------------------------------------------
# Per-file classifier
# ---------------------------------------------------------------------------

def _classify(
    path: Path, target: Path, manifests: List[Manifest],
) -> "ArtefactFinding | None":
    name = path.name
    if name.endswith(".pth"):
        return _make_finding(
            path, target, manifests,
            kind="python_pth_file",
            detail=(
                f"`.pth` file at {_rel(path, target)} executes at Python "
                "startup; verify it's intentional and not an attacker drop."
            ),
            severity="high",
            confidence=Confidence(
                "high",
                reason=".pth files run code at interpreter startup",
            ),
        )

    if _looks_like_test_path(path, target):
        try:
            stat = path.stat()
        except OSError:
            return None
        if (stat.st_size >= _BIN_IN_TESTS_MIN_BYTES
                and _is_binary(path)):
            # Align with the binary-opt-in allowlist shared with
            # :mod:`binary_in_package` (Phase 3).  When a path
            # matches an allowlist pattern (eg ``tests/fixtures/**``,
            # ``testdata/**``) the binary is a known-convention
            # fixture; don't fire here either, otherwise the two
            # detectors give contradictory verdicts on the same
            # path.  Attacker placements that bypass the convention
            # (``tests/setup_bun.js``, ``tests/payload.bin`` at the
            # tests/ root) still fire.
            if _allowlisted_binary(path, target):
                return None
            return _make_finding(
                path, target, manifests,
                kind="binary_in_tests",
                detail=(
                    f"binary fixture {_rel(path, target)} "
                    f"({stat.st_size:,} bytes) inside test directory"
                ),
                severity="low",
                confidence=Confidence(
                    "medium",
                    reason="binary in test tree; may be a legitimate fixture",
                ),
            )

    suffix = path.suffix.lower()
    if suffix in _EXTENSION_MAGIC:
        # Skip ``disguised_filename`` detection inside test fixtures.
        # Test trees routinely include intentionally-misnamed files
        # as detector inputs (e.g. ``tests/fixtures/*.txt`` whose
        # content is a shell script — the very thing this rule
        # exists to catch). Firing on these produces noise that
        # operators rightly ignore, drowning out real hits.
        # ``binary_in_tests`` above intentionally DOES fire on test
        # paths because attacker-planted binaries-as-test-fixtures
        # is itself a known attack pattern; ``disguised_filename``
        # doesn't have that adversarial framing.
        if _looks_like_test_path(path, target):
            return None
        disguise = _check_disguised_filename(path, suffix)
        if disguise is not None:
            return _make_finding(
                path, target, manifests,
                kind="disguised_filename",
                detail=(
                    f"`{_rel(path, target)}` has extension `{suffix}` but "
                    f"its content is {disguise}; deliberate disguise is "
                    "rare and high-signal."
                ),
                severity="high",
                confidence=Confidence(
                    "high",
                    reason="extension does not match magic-byte signature",
                ),
            )

    if (suffix in _OBFUSC_EXTS
            and not _under_built_output(path, target)):
        obfusc_detail = _check_obfuscated(path, target)
        if obfusc_detail is not None:
            return _make_finding(
                path, target, manifests,
                kind="large_obfuscated_artefact",
                detail=obfusc_detail,
                severity="medium",
                confidence=Confidence(
                    "medium",
                    reason="size + entropy / line-length suggest "
                           "minified or obfuscated payload",
                ),
            )

    return None


# ---------------------------------------------------------------------------
# disguised_filename
# ---------------------------------------------------------------------------

def _check_disguised_filename(path: Path, suffix: str) -> Optional[str]:
    """Return a short description of the disguise, or None if benign."""
    expected_magics = _EXTENSION_MAGIC.get(suffix)
    try:
        with path.open("rb") as fh:
            head = fh.read(512)
    except OSError:
        return None
    if not head:
        return None

    if expected_magics is None:
        # Text-typed extension. Leading 256 bytes must look like text.
        if b"\x00" in head[:256]:
            return _classify_binary_payload(head) or "embedded null bytes"
        for sig in _BINARY_MAGIC:
            if head.startswith(sig):
                return (_classify_binary_payload(head)
                        or "an unrelated binary format")
        # Shebangs are fine in script extensions; suspicious in pure
        # data extensions (`.json`, `.txt`, `.md`, etc. shouldn't
        # masquerade as executables).
        if suffix not in _SHEBANG_OK_EXTS and head.startswith(b"#!"):
            return (_classify_binary_payload(head)
                    or "an executable shebanged script")
        return None

    for magic in expected_magics:
        if head.startswith(magic):
            return None
    return _classify_binary_payload(head) or "an unrelated binary format"


def _classify_binary_payload(head: bytes) -> Optional[str]:
    if head.startswith(b"\x7fELF"):
        return "an ELF executable"
    if head.startswith(b"MZ"):
        return "a Windows PE/COFF executable"
    if head.startswith(b"PK\x03\x04"):
        return "a ZIP/JAR archive"
    if head.startswith(b"\x1f\x8b"):
        return "a gzip-compressed payload"
    if head.startswith((b"\xCA\xFE\xBA\xBE", b"\xFE\xED\xFA\xCE",
                        b"\xFE\xED\xFA\xCF", b"\xCF\xFA\xED\xFE")):
        return "a Java class or Mach-O binary"
    if head.startswith((b"#!/bin/sh", b"#!/bin/bash", b"#!/usr/bin/env")):
        return "an executable shell script"
    if head[:1] == b"#" and b"!" in head[:8]:
        return "an executable shebanged script"
    return None


# ---------------------------------------------------------------------------
# large_obfuscated_artefact
# ---------------------------------------------------------------------------

def _check_obfuscated(path: Path, target: Path) -> Optional[str]:
    try:
        stat = path.stat()
    except OSError:
        return None
    if stat.st_size < _OBFUSC_MIN_BYTES:
        return None
    try:
        with path.open("rb") as fh:
            data = fh.read(min(stat.st_size, 1024 * 1024))
    except OSError:
        return None
    if not data:
        return None

    longest = 0
    line_start = 0
    for i, b in enumerate(data):
        if b == 0x0a:                      # b'\n'
            longest = max(longest, i - line_start)
            line_start = i + 1
    longest = max(longest, len(data) - line_start)

    entropy = _shannon_entropy(data)
    rel = _rel(path, target)

    if longest > _OBFUSC_MAX_LINE_LEN and entropy > _OBFUSC_HIGH_ENTROPY:
        return (f"`{rel}` ({stat.st_size:,} bytes) has a "
                f"{longest:,}-char line and entropy {entropy:.1f} "
                "bits/byte — looks minified/obfuscated")
    if longest > _OBFUSC_MAX_LINE_LEN * 4:
        return (f"`{rel}` ({stat.st_size:,} bytes) has a "
                f"{longest:,}-char single line — looks minified")
    return None


def _shannon_entropy(data: bytes) -> float:
    """Bit-entropy per byte; 0 ≤ result ≤ 8.0."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(
        (c / n) * math.log2(c / n) for c in counts if c
    )


def _under_built_output(path: Path, target: Path) -> bool:
    try:
        rel = path.relative_to(target)
    except ValueError:
        rel = path
    return any(part in _BUILT_OUTPUT_DIRS for part in rel.parts)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_finding(
    path: Path,
    target: Path,
    manifests: List[Manifest],
    *,
    kind: str,
    detail: str,
    severity: str,
    confidence: Confidence,
) -> ArtefactFinding:
    host = _project_host_dep(manifests, path, target)
    return ArtefactFinding(
        dependency=host,
        kind=kind,
        detail=detail,
        path=path,
        severity=severity,
        confidence=confidence,
    )


def _project_host_dep(
    manifests: List[Manifest], path: Path, target: Path,
) -> Dependency:
    closest: "Manifest | None" = None
    for m in manifests:
        if m.is_lockfile:
            continue
        try:
            common = os.path.commonpath([m.path.parent, path])
        except ValueError:
            continue
        if not closest or len(common) > len(
            os.path.commonpath([closest.path.parent, path])
        ):
            closest = m
    declared_in = closest.path if closest else target
    ecosystem = closest.ecosystem if closest else "Project"
    return Dependency(
        ecosystem=ecosystem,
        name="<project>",
        version=None,
        declared_in=declared_in,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.UNKNOWN,
        direct=True,
        purl="",
        parser_confidence=Confidence(
            "low",
            reason="placeholder for project-artefact finding host",
        ),
    )


def _allowlisted_binary(path: Path, target: Path) -> bool:
    """Cross-detector consistency: when ``binary_in_package``'s
    opt-in allowlist (``data/binary_opt_in_locations.json``) treats
    this path as a known-convention fixture / build output, do not
    emit a ``binary_in_tests`` row either.

    Best-effort: any failure (file read, import, classify error)
    returns False so the surrounding detector falls back to
    emitting (better noisy than silently missing).
    """
    try:
        from . import binary_in_package
        try:
            rel = path.resolve().relative_to(target.resolve())
        except ValueError:
            return False
        # ``binary_in_package._path_matches_allowlist`` takes the
        # relative path + the first bytes (for magic_required entries
        # like ``.wasm``).  Read just enough to satisfy that signature.
        try:
            with path.open("rb") as fh:
                head = fh.read(256)
        except OSError:
            return False
        return binary_in_package._path_matches_allowlist(rel, head)
    except Exception:                              # pragma: no cover
        return False


def _looks_like_test_path(path: Path, target: Path) -> bool:
    try:
        rel = path.relative_to(target)
    except ValueError:
        rel = path
    return any(part in _TEST_DIR_NAMES for part in rel.parts)


def _is_binary(path: Path, sniff_bytes: int = 256) -> bool:
    try:
        with path.open("rb") as fh:
            head = fh.read(sniff_bytes)
    except OSError:
        return False
    if any(head.startswith(sig) for sig in _BINARY_MAGIC):
        return True
    if b"\x00" in head:
        return True
    return False


def _walk(root: Path, *, max_depth: int) -> Iterable[Path]:
    """Walk every file under ``root``, skipping vendored / build trees.

    Note: tests/ directories are NOT skipped at the walker level —
    artefacts has a deliberate ``binary_in_tests`` rule that targets
    binaries planted in test data (a real attack pattern). Per-rule
    logic decides whether a path is interesting; the walker yields
    everything below the depth cap.
    """
    base = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(str(root), followlinks=False):
        cur = Path(dirpath)
        depth = len(cur.parts) - base
        if depth >= max_depth:
            dirnames[:] = []
        else:
            dirnames[:] = [d for d in dirnames if d not in _EXCLUDED_DIRS]
        for fn in filenames:
            yield cur / fn


def _rel(path: Path, target: Path) -> Path:
    try:
        return path.relative_to(target)
    except ValueError:
        return path


__all__ = ["ArtefactFinding", "scan_target"]
