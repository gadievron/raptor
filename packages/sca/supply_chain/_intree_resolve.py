"""In-tree target resolution for lifecycle-hook bodies.

Used by :mod:`install_hooks` (and any future lifecycle adapter) to
answer: "does this hook body reference a file that ships in the
package's own source tree?"  If yes, what kind of file is it?

The signal feeds composite scoring: a hook whose body executes a
**binary** that's bundled in the same tarball is the Iron Worm shape
— but the install_hooks detector alone can't tell that apart from
``node-gyp rebuild`` (a hook that calls a build tool from ``$PATH``).
This module bridges that gap.

# Adversarial model

What this helper must defend against:

  * **Shell quoting evasion** — ``"./tools/setup"``, ``'./tools/setup'``,
    backslash-escaped paths.  Defence: ``shlex.split(posix=True)``
    handles standard quoting.  Unterminated quotes return None
    (uninterpretable — safer to skip than to misread).

  * **Path-traversal escape** — ``../../etc/payload`` would let an
    attacker point our "in-tree" classification at a host file.
    Defence: paths containing ``..`` components are rejected outright.

  * **Symlink redirection** — a symlink in the package pointing to a
    host file would make us classify host content as the package's
    payload.  Defence: ``is_symlink()`` rejects; only real files in
    the tree are classified.

  * **Resolved-path escape** — even without explicit ``..``, a
    symlink chain could resolve outside the package tree.  Defence:
    after resolution we re-check that ``candidate.resolve()`` stays
    inside ``manifest_dir.resolve()``.  Belt-and-braces with the
    symlink rejection.

  * **Indirection through interpreters** — ``node -e 'require("./x")'``,
    ``bash -c './tools/setup'``.  We do NOT recursively evaluate
    interpreter args (any attempt would itself be an attack
    surface).  We scan all tokens; ``./tools/setup`` *as a token in
    a ``bash -c`` argument* still gets resolved and classified.
    The shape we miss: deeply-encoded indirection
    (``echo Li90b29scy9zZXR1cA== | base64 -d | bash``).  That shape
    is caught by ``install_hooks._DANGEROUS_PATTERNS`` (base64-piped)
    already; we don't need to duplicate it here.

  * **Large file DoS** — an attacker could ship a 2GB file referenced
    by the hook.  Defence: classification reads only the first 256
    bytes; never reads the whole file.

  * **Race condition (TOCTOU)** — the file could be modified between
    our resolution check and our magic-byte read.  Defence: this is
    a SCAN, not a runtime gate — the artefact is whatever it is at
    scan time, and downstream review reads the same file separately.
    Concurrent modification only hides the attacker from us; it
    doesn't let them slip a different payload past a CI gate that
    re-reads later.

  * **Compound-command splitting bypass** — semicolons, ``&&``, ``||``,
    pipes, backgrounding.  Defence: we split on these BEFORE shlex,
    so each sub-command's tokens are evaluated independently.
"""

from __future__ import annotations

import logging
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


# Magic-byte prefixes for executable formats.  We tag a file as
# ``binary`` when it leads with any of these.  We do NOT try to
# scan for offset-hidden magic — a polyglot that hides ELF inside
# a JS file would not be picked up here, but the SAME polyglot
# would still be unusual enough to trip other detectors
# (size, obfuscation) and the file-it-impersonates classification
# is what install_hooks would key off anyway.
_BINARY_MAGICS: tuple = (
    b"\x7fELF",                                   # ELF (Linux/BSD)
    b"MZ",                                        # PE (Windows .exe/.dll)
    b"\xca\xfe\xba\xbe",                          # Mach-O fat
    b"\xcf\xfa\xed\xfe",                          # Mach-O 64 LE
    b"\xfe\xed\xfa\xcf",                          # Mach-O 64 BE
    b"\xce\xfa\xed\xfe",                          # Mach-O 32 LE
    b"\xfe\xed\xfa\xce",                          # Mach-O 32 BE
)

# WASM is allow-listed elsewhere (Phase 3) — classified here as
# ``binary`` so the composite-pair logic can still notice if a WASM
# blob is invoked from an install hook.
_WASM_MAGIC: bytes = b"\x00asm"

# Compound-command separators.  We split on these BEFORE shlex so each
# sub-command's tokens can be evaluated independently.  Order matters:
# longer separators first so ``&&`` doesn't get pre-split as two ``&``.
_COMPOUND_RE = re.compile(r"(?:&&|\|\||\||;|&(?!\&))")

# Strip these prefixes from a token before treating it as a path —
# they're shell idioms for "this path, here, now".
_PATH_PREFIXES_TO_STRIP: tuple = ("./", "$PWD/", "${PWD}/", "$(pwd)/")


@dataclass(frozen=True)
class IntreeTarget:
    """A resolved file inside the manifest's parent tree that some
    hook-body token referenced."""

    path: Path
    kind: str         # "binary" | "script" | "source" | "unknown"

    @property
    def is_executable_payload(self) -> bool:
        """True for kinds that ship executable bytes (the
        composite-pair signal that makes A∧B = critical).  Scripts
        are NOT included — they're a softer signal that needs further
        inspection via the install_hooks pattern table."""
        return self.kind == "binary"


def _split_compound(body: str) -> List[str]:
    """Break ``body`` into sub-commands at shell separators.  Returns
    a list (possibly singleton) of stripped sub-command strings."""
    pieces = _COMPOUND_RE.split(body)
    return [p.strip() for p in pieces if p.strip()]


def _strip_path_prefix(tok: str) -> Optional[str]:
    """Drop ``./``, ``$PWD/``, etc. — return the path-relative form,
    or None if the token is clearly not a path (absolute, contains
    ``..``, looks like a flag)."""
    if not tok:
        return None
    if tok.startswith("-"):
        # A flag, not a path.
        return None
    for prefix in _PATH_PREFIXES_TO_STRIP:
        if tok.startswith(prefix):
            return tok[len(prefix):]
    if tok.startswith("/"):
        # Absolute path — almost certainly out of tree; resolution
        # would walk into host territory.  Skip.
        return None
    return tok


def _safe_resolve_intree(
    rel: str, manifest_dir: Path,
) -> Optional[Path]:
    """Resolve ``rel`` against ``manifest_dir``, defending against
    traversal and symlink escapes.  Returns the resolved path or
    None when not resolvable to a regular file inside the tree."""
    if not rel:
        return None
    rel_path = Path(rel)
    # Reject any path component that's '..' — no climbing out.
    if ".." in rel_path.parts:
        return None
    candidate = manifest_dir / rel_path
    try:
        if not candidate.is_file():
            return None
    except OSError:
        return None
    # Reject symlinks outright; following them could escape the tree
    # even when the immediate name doesn't contain '..'.
    if candidate.is_symlink():
        return None
    # Belt-and-braces: ensure the RESOLVED path is inside the tree
    # too.  Catches symlink chains we don't follow but might still
    # exist as intermediate components.
    try:
        candidate.resolve(strict=True).relative_to(manifest_dir.resolve())
    except (OSError, ValueError):
        return None
    return candidate


def _classify_first_bytes(path: Path) -> str:
    """Return ``binary``, ``script``, ``source``, or ``unknown`` based
    on the first 256 bytes of ``path``."""
    try:
        with open(path, "rb") as f:
            head = f.read(256)
    except OSError:
        return "unknown"
    if not head:
        return "source"          # empty file — uninteresting
    for magic in _BINARY_MAGICS:
        if head.startswith(magic):
            return "binary"
    if head.startswith(_WASM_MAGIC):
        return "binary"
    if head[:2] == b"#!":
        return "script"
    # If the first 256 bytes round-trip through UTF-8, it's almost
    # certainly text.  Otherwise we treat it as binary-ish (PNG,
    # gzip, etc., none of which are a hook's interesting target).
    try:
        head.decode("utf-8")
        return "source"
    except UnicodeDecodeError:
        return "binary"


def resolve_intree_targets(
    body: str, manifest_dir: Path,
) -> List[IntreeTarget]:
    """Find every shell token in ``body`` that resolves to a file
    inside ``manifest_dir``, classify each by magic bytes.

    Returns deduplicated targets in encounter order.  Empty list
    when nothing in the body looks like an in-tree path (the
    legitimate ``node-gyp rebuild`` case).

    Defensive against shell quoting, compound commands, path
    traversal, symlinks; see module docstring.
    """
    seen: set = set()
    out: List[IntreeTarget] = []
    for sub in _split_compound(body):
        try:
            tokens = shlex.split(sub, posix=True, comments=True)
        except ValueError:
            # Unterminated quote — uninterpretable.  Skip rather
            # than misclassify.
            continue
        for tok in tokens:
            rel = _strip_path_prefix(tok)
            if rel is None:
                continue
            resolved = _safe_resolve_intree(rel, manifest_dir)
            if resolved is None:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            kind = _classify_first_bytes(resolved)
            out.append(IntreeTarget(path=resolved, kind=kind))
    return out
