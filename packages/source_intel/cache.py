"""Content-addressed cache for :class:`SourceIntelResult`.

Phase 2 ships an in-memory cache; persistence to disk lands in axis-N
PRs when cocci run-cost becomes the dominant cross-stage cost.

Cache key composition:

  rules_hash :  sha256 of the contents of every ``.cocci`` file under
                the rules dir, sorted by name. Captures rule-corpus
                version.
  target_hash : sha256 of the target's source-file tree. Every file's
                name + (mtime, size) participates; content hashes are
                bounded to a deterministic (sorted-path) subset for
                cost, so any edit still flips the key.
  schema_version : module-level constant, bumped when the result shape
                changes meaningfully.

Cache miss → re-run analyze; hit → load result. The cache key
includes target so multiple targets co-exist; the schema_version
guards against stale shapes.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from packages.source_intel.analyze import (
    SCHEMA_VERSION,
    SourceIntelResult,
    _shipped_rules_root,
)


@dataclass
class SourceIntelCache:
    """In-memory cache mapping (target, rules_hash) → result.

    Process-local; thread-safe under the GIL for our usage (analyze is
    a long-running spatch invocation; the entry store/lookup is an
    atomic dict op, though key DERIVATION walks and hashes the target
    tree — stat-cheap on repeat lookups via the tree-hash memo, a
    content-hash walk when the tree changed). Not durable — restart
    loses cached entries. Persistence to disk is deferred per
    ``project_source_intel_kickoff.md``.
    """

    _entries: dict[tuple[str, str], SourceIntelResult] = field(default_factory=dict)

    def get(
        self,
        target: Path,
        rules_dir: Path | None = None,
    ) -> SourceIntelResult | None:
        """Lookup. Returns None on miss."""
        key = self._key_for(target, rules_dir)
        return self._entries.get(key)

    def put(
        self,
        target: Path,
        rules_dir: Path | None,
        result: SourceIntelResult,
    ) -> None:
        """Store result under (target, rules_hash)."""
        key = self._key_for(target, rules_dir)
        self._entries[key] = result

    # Key-carrying API: derive the key ONCE and reuse it for both the
    # lookup and the store. get()/put() each re-derive the key from
    # the live tree, so a get → analyze → put sequence spanning a
    # minutes-long analyze() would, if the tree drifted mid-analyze,
    # store a result computed over the OLD tree under the NEW tree's
    # hash — and serve it as fresh thereafter. Carrying the key pins
    # the stored entry to the tree state the lookup actually saw.

    def key_for(
        self,
        target: Path,
        rules_dir: Path | None = None,
    ) -> tuple[str, str]:
        """Derive the cache key for (target, rules_dir) as of now."""
        return self._key_for(target, rules_dir)

    def get_by_key(
        self, key: tuple[str, str],
    ) -> SourceIntelResult | None:
        """Lookup under a key from :meth:`key_for`. None on miss."""
        return self._entries.get(key)

    def put_by_key(
        self, key: tuple[str, str], result: SourceIntelResult,
    ) -> None:
        """Store ``result`` under a key from :meth:`key_for`."""
        self._entries[key] = result

    def invalidate(self) -> None:
        """Clear all entries — used on schema-version bumps or when
        the caller knows the rule set or target has changed mid-run."""
        self._entries.clear()

    def size(self) -> int:
        return len(self._entries)

    @staticmethod
    def _key_for(
        target: Path,
        rules_dir: Path | None,
    ) -> tuple[str, str]:
        target_hash = _hash_target_tree_cached(Path(target))
        rules_hash = _hash_rules_dir(
            Path(rules_dir) if rules_dir else None
        )
        # Schema version is part of the key so a SCHEMA_VERSION bump
        # invalidates the cache even when target + rules unchanged.
        return (
            f"{target_hash}:v{SCHEMA_VERSION}",
            rules_hash,
        )


# =====================================================================
# Hashing helpers
# =====================================================================


# Extension set matches the consumers that key staleness off these
# walks (adapter's pointer-reference scan includes .hxx, so the
# signature must observe .hxx edits too).
_C_CPP_EXTS: tuple[str, ...] = (
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx",
)

# Content-hash budget for `_hash_target_tree`. Every matching file's
# path + (mtime, size) always participates in the hash; only the first
# `_CONTENT_HASH_CAP` files IN SORTED-PATH ORDER additionally get their
# contents hashed. Pre-fix the cap was applied in rglob() enumeration
# order BEFORE sorting — a nondeterministic subset, and edits to any
# file past the cap never invalidated the cache.
_CONTENT_HASH_CAP = 5000


def _sorted_source_files(target: Path) -> list[Path]:
    """Every C/C++ source file under ``target``, sorted by path."""
    return sorted(
        (
            entry for entry in target.rglob("*")
            if entry.is_file() and entry.suffix.lower() in _C_CPP_EXTS
        ),
        key=str,
    )


def compute_target_signature(target: Path) -> str:
    """Fast change-detection signature for a target dir or file.

    Used as a cache-staleness marker — *not* a security-relevant
    fingerprint. Walks every C/C++ file under ``target`` and combines
    each file's (mtime_ns, size) into a single sha256 — stat only, no
    content reads, no file cap. Two invocations on an unchanged tree
    return the same signature; any source edit, file add/remove, or
    build-marker change flips it.

    Cheaper than ``_hash_target_tree`` (no content reads) so it's
    affordable to recompute on every cache lookup. Sub-second on
    kernel-scale repos.

    Falls back to deterministic sentinels for missing targets +
    unresolvable paths so cache misses are predictable rather than
    hash-of-error.
    """
    if not target.exists():
        return "missing"

    h = hashlib.sha256()
    if target.is_file():
        try:
            st = target.stat()
        except OSError:
            return "stat-error"
        h.update(b"FILE\x00")
        h.update(str(target).encode("utf-8", "replace"))
        h.update(b"\x00")
        h.update(f"{st.st_mtime_ns}:{st.st_size}".encode("ascii"))
        return h.hexdigest()

    h.update(b"DIR\x00")
    # No file cap: the stat-only walk is cheap, and any cap would
    # exclude some files from the signature — edits to them would
    # never invalidate downstream caches.
    for path in _sorted_source_files(target):
        try:
            st = path.stat()
        except OSError:
            continue
        h.update(str(path.relative_to(target)).encode("utf-8", "replace"))
        h.update(b"\x00")
        h.update(f"{st.st_mtime_ns}:{st.st_size}".encode("ascii"))
        h.update(b"\x00")

    # Build markers — mirrors `_hash_target_tree`. A Makefile / .config
    # edit changes the build context even if no .c file changed.
    for marker in ("Makefile", "GNUmakefile", "Kbuild",
                   "compile_commands.json", ".config"):
        mp = target / marker
        if not mp.is_file():
            continue
        try:
            st = mp.stat()
        except OSError:
            continue
        h.update(b"BUILD\x00")
        h.update(marker.encode("ascii"))
        h.update(b"\x00")
        h.update(f"{st.st_mtime_ns}:{st.st_size}".encode("ascii"))
        h.update(b"\x00")
    return h.hexdigest()


# Content-hash memo for `_hash_target_tree`: (path → (stat signature,
# tree hash)). Key derivation content-hashes up to _CONTENT_HASH_CAP
# files, and consumers (llm_bridge collector, corpus adapter) derive a
# key PER FINDING against the same tree — orders of magnitude more
# expensive than the stat-only signature check. The stat signature
# observes every file's (mtime_ns, size) plus build markers, so any
# edit recomputes the content hash. Sentinel signatures are never
# memoised. Whole-dict reset on overflow keeps this trivial.
_TREE_HASH_MEMO: dict[str, tuple[str, str]] = {}
_TREE_HASH_MEMO_CAP = 64

_SIG_SENTINELS = ("missing", "stat-error")


def _hash_target_tree_cached(target: Path) -> str:
    """Stat-signature-memoised :func:`_hash_target_tree`."""
    sig = compute_target_signature(target)
    if sig in _SIG_SENTINELS:
        return _hash_target_tree(target)
    key = str(target)
    hit = _TREE_HASH_MEMO.get(key)
    if hit is not None and hit[0] == sig:
        return hit[1]
    value = _hash_target_tree(target)
    if len(_TREE_HASH_MEMO) >= _TREE_HASH_MEMO_CAP:
        _TREE_HASH_MEMO.clear()
    _TREE_HASH_MEMO[key] = (sig, value)
    return value


def clear_key_memo() -> None:
    """Drop the key-derivation memos — explicit reset for
    orchestrators. Signature-based auto-invalidation already covers
    file edits."""
    _TREE_HASH_MEMO.clear()
    _RULES_HASH_MEMO.clear()


def _hash_target_tree(target: Path) -> str:
    """SHA-256 of every C/C++ source file under target, by sorted path.

    For non-directory targets, hashes the single file. For missing
    targets, returns a constant sentinel hash so cache misses are
    deterministic.

    Bounded for cost, complete for change detection: every file's
    path and (mtime_ns, size) participate; only the first
    ``_CONTENT_HASH_CAP`` files in sorted-path order are additionally
    content-hashed (kernel-scale safety). Any edit — including to
    files past the cap — flips the hash via the stat line.
    """
    if not target.exists():
        return "missing"

    h = hashlib.sha256()
    if target.is_file():
        h.update(b"FILE\x00")
        h.update(str(target).encode("utf-8"))
        h.update(b"\x00")
        h.update(_file_hash(target).encode("utf-8"))
        return h.hexdigest()

    h.update(b"DIR\x00")
    for idx, path in enumerate(_sorted_source_files(target)):
        h.update(str(path.relative_to(target)).encode("utf-8"))
        h.update(b"\x00")
        if idx < _CONTENT_HASH_CAP:
            h.update(_file_hash(path).encode("utf-8"))
        else:
            # Past the content budget: the (mtime_ns, size) stat line
            # still participates so an edit here flips the hash.
            try:
                st = path.stat()
            except OSError:
                h.update(b"stat-error")
            else:
                h.update(f"{st.st_mtime_ns}:{st.st_size}".encode("ascii"))
        h.update(b"\x00")

    # Build markers meaningfully affect analyze()'s build_flags output;
    # two targets with identical .c files but different Makefile /
    # compile_commands.json / .config would otherwise collide on the
    # content-only hash and return the wrong cached BuildFlagsContext.
    # Surfaced by axis-6 corpus fixtures `fortify_kconfig/` and
    # `fortify_makefile/` (identical `u.c` but different build markers).
    for marker in ("Makefile", "GNUmakefile", "Kbuild",
                   "compile_commands.json", ".config"):
        mp = target / marker
        if mp.is_file():
            h.update(b"BUILD\x00")
            h.update(marker.encode("utf-8"))
            h.update(b"\x00")
            h.update(_file_hash(mp).encode("utf-8"))
            h.update(b"\x00")
    return h.hexdigest()


def _hash_rules_dir(rules_dir: Path | None) -> str:
    """SHA-256 of every .cocci + pack .json file under rules_dir,
    sorted by name.

    API packs (``packs/*.json``, rendered into slotted rules at analyze
    time) are part of the effective rule set, so they participate in
    the key — a pack edit must invalidate cached results exactly like a
    rule edit.

    ``rules_dir=None`` means "the shipped rules directory" — analyze()
    resolves it the same way — so the shipped dir is what gets hashed:
    an edit / regeneration of the shipped rule corpus must invalidate
    cached results exactly like an explicit-dir edit would. Only when
    the shipped root is absent (minimal install) does the key fall
    back to the ``"default-rules"`` sentinel.
    """
    if rules_dir is None:
        rules_dir = _shipped_rules_root()
        if rules_dir is None:
            return "default-rules"
    if not rules_dir.exists():
        return "missing-rules"

    files = sorted(
        [*rules_dir.rglob("*.cocci"), *rules_dir.rglob("*.json")],
        key=str,
    )

    # Stat-validated memo: the rule corpus is hashed per key
    # derivation (i.e. per finding for the default-resolver
    # consumers), so avoid re-reading every rule file when nothing
    # changed. The stat line covers file set + (mtime_ns, size).
    sig_h = hashlib.sha256()
    for path in files:
        try:
            st = path.stat()
        except OSError:
            continue
        sig_h.update(str(path).encode("utf-8", "replace"))
        sig_h.update(f"\x00{st.st_mtime_ns}:{st.st_size}\x00".encode("ascii"))
    sig = sig_h.hexdigest()
    memo_key = str(rules_dir)
    hit = _RULES_HASH_MEMO.get(memo_key)
    if hit is not None and hit[0] == sig:
        return hit[1]

    h = hashlib.sha256()
    for path in files:
        h.update(str(path.relative_to(rules_dir)).encode("utf-8"))
        h.update(b"\x00")
        h.update(_file_hash(path).encode("utf-8"))
        h.update(b"\x00")
    value = h.hexdigest()
    if len(_RULES_HASH_MEMO) >= _TREE_HASH_MEMO_CAP:
        _RULES_HASH_MEMO.clear()
    _RULES_HASH_MEMO[memo_key] = (sig, value)
    return value


_RULES_HASH_MEMO: dict[str, tuple[str, str]] = {}


def _file_hash(path: Path) -> str:
    """SHA-256 of a single file's contents."""
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
    except OSError:
        return "read-error"
    return h.hexdigest()
