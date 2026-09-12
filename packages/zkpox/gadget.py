"""Phase 1.5.1 — ``gadget_code_hash`` computation.

Binds a disclosure bundle to the *specification + implementation* of
the violation gadget it claims to use. ``gadget_id_hash`` (which 1.5
already carried) hashes only the identifier string ("here is an opaque
name"); ``gadget_code_hash`` hashes the gadget's markdown spec **and**
the guest source files that materially decide the verdict. A producer
that tampers with either the spec or the implementation produces a
different ``gadget_code_hash``, which a verifier with the same
checkout recomputes and compares.

Scope and honesty:

- The hash binds to a **declared file manifest** (``_GADGET_FILES``),
  not to a recursive scan. New files added to the guest source tree
  do NOT silently re-key the gadget — they must be added to the
  manifest. Trade-off: the manifest is hand-curated and review-gated.
- The gadget identifier is versioned (``crash-only@0.1.0``); a gadget
  bump is a content bump. Manifest changes in lockstep.
- The hash is over **gadget code**, not over the compiled SP1 guest
  ELF; ``harness.hash`` (Phase 1.5.1 §1) already binds to the binary.
  ``gadget_code_hash`` lets a reviewer audit the source side
  independently — including the markdown spec, which the harness
  hash can't capture.

Phase 1.6 will likely lift the hand-curated manifest into a per-gadget
Cargo crate so the hash falls out of the guest build; for 1.5.1 the
manifest is the simplest thing that's honest.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path


# Map: gadget identifier base (no ``@version`` suffix) → declared
# manifest of files that materially constitute the gadget. Order matters
# for the canonical hash; preserve it on edits.
#
# Both gadgets currently share the guest dispatch + the redzone
# primitive that decides the verdict. Their distinct markdown specs
# differ. Phase 1.5.1 binds all three per gadget; future gadgets with
# distinct implementations register their own files here.
_GADGET_FILES: dict[str, tuple[str, ...]] = {
    "crash-only": (
        ".claude/skills/zkpox/violation-gadgets/crash-only.md",
        "core/zkpox/guest/src/main.rs",
        "core/zkpox/guest/src/redzone.rs",
    ),
    "memory-safety::oob-write": (
        ".claude/skills/zkpox/violation-gadgets/memory-safety-oob-write.md",
        "core/zkpox/guest/src/main.rs",
        "core/zkpox/guest/src/redzone.rs",
    ),
}


class GadgetCodeHashError(Exception):
    """Raised when ``compute_gadget_code_hash`` can't honour the
    contract — unknown gadget_id, missing manifest file, etc.

    cmd_prove turns this into a SystemExit so a typo in ``--gadget-id``
    or a moved file fails loudly before any bundle is written.
    """


def _gadget_base(gadget_id: str) -> str:
    """Strip the ``@version`` suffix. ``memory-safety::oob-write@0.1.0``
    → ``memory-safety::oob-write``. A missing ``@`` is tolerated: the
    full id is treated as the base (no version pinning)."""
    return gadget_id.split("@", 1)[0]


def _canonicalise(blob: bytes) -> bytes:
    """Normalise file bytes before hashing: strip a UTF-8 BOM and
    fold CRLF to LF. The two adjustments handle the cases git's
    autocrlf and editor-defaults inject on Windows / cross-platform
    checkouts, so the hash is the same regardless of who cloned the
    file. No other transforms — content is otherwise byte-faithful."""
    if blob.startswith(b"\xef\xbb\xbf"):
        blob = blob[3:]
    return blob.replace(b"\r\n", b"\n")


def compute_gadget_code_hash(
    gadget_id: str, *, repo_root: Path | None = None,
) -> str:
    """Return the ``sha256:HEX`` Phase 1.5.1 binding for ``gadget_id``.

    Looks up the file manifest for the gadget's base identifier,
    canonicalises each file's bytes, and hashes a deterministic
    concatenation of ``gadget_id`` + per-file ``path|sha256`` records.
    The per-file inner hash makes file-by-file tamper evident; the
    outer hash gives the bundle's single ``sha256:HEX`` field.

    Raises :class:`GadgetCodeHashError` on unknown gadget_id or
    missing manifest file — cmd_prove turns either into a hard
    refusal to write a bundle.
    """
    base = _gadget_base(gadget_id)
    files = _GADGET_FILES.get(base)
    if files is None:
        raise GadgetCodeHashError(
            f"unknown gadget_id base {base!r} (from {gadget_id!r}); "
            f"register its file manifest in packages/zkpox/gadget.py. "
            f"Known gadgets: {sorted(_GADGET_FILES)}"
        )

    root = repo_root or Path(
        os.environ.get("RAPTOR_DIR") or Path(__file__).resolve().parents[2]
    )

    outer = hashlib.sha256()
    outer.update(gadget_id.encode("utf-8"))
    outer.update(b"\n")
    for rel in files:
        path = (root / rel).resolve()
        try:
            raw = path.read_bytes()
        except OSError as e:
            raise GadgetCodeHashError(
                f"gadget {base!r} manifest references missing/unreadable "
                f"file {rel!r}: {e}"
            ) from e
        inner = hashlib.sha256(_canonicalise(raw)).hexdigest()
        outer.update(rel.encode("utf-8"))
        outer.update(b"|")
        outer.update(inner.encode("ascii"))
        outer.update(b"\n")
    return f"sha256:{outer.hexdigest()}"
