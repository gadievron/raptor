"""Target-kind vocabulary packs for the mechanical checkers.

A vocab pack is a JSON data file under ``core/audit/data/vocab_packs/``
carrying the API-name vocabulary for one target kind (today: the Linux
kernel). Packs exist so the checkers in :mod:`core.audit.condition_smt`
and the prefilter can keep seed-sized hardcoded lists (universal libc
plus a few marked exemplars) without losing coverage on the target
kinds whose API bulk used to be hardcoded for *every* target.

Precedence: hardcoded seeds < pack < study-learned domain model — all
three are unioned, so a pack never suppresses anything; it only adds
names. Packs are DATA, gated on target detection; project-specific
vocabulary should be learned by the study loop (domain-model.json),
not added here.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from core.source import read_text_capped
from typing import TYPE_CHECKING

from core.json import load_json

if TYPE_CHECKING:  # pragma: no cover
    from .condition_smt import DomainVocabulary

logger = logging.getLogger(__name__)

_PACK_DIR = Path(__file__).resolve().parent / "data" / "vocab_packs"

# Kernel out-of-tree module Makefiles assign kernel objects via
# obj-m / obj-y / obj-$(CONFIG_...).
_KBUILD_OBJ_RE = re.compile(r"^obj-(?:[my]|\$\(CONFIG_\w+\))\s*[+:]?=", re.MULTILINE)

_pack_cache: dict[str, DomainVocabulary | None] = {}
_kernel_tree_cache: dict[str, bool] = {}


def load_pack(name: str) -> DomainVocabulary | None:
    """Load a vocab pack by name into a DomainVocabulary (cached).

    Returns None (with a logged warning) when the pack file is missing
    or malformed — checkers then run on seeds + learned vocab alone.
    Failed loads are NOT cached, so a transient read failure does not
    disable the pack for the rest of the process.
    """
    if name in _pack_cache:
        return _pack_cache[name]
    vocab = _load_pack_uncached(name)
    if vocab is not None:
        _pack_cache[name] = vocab
    return vocab


class _MalformedPack(ValueError):
    """A pack field has the wrong JSON shape."""


def _load_pack_uncached(name: str) -> DomainVocabulary | None:
    from .condition_smt import DomainVocabulary

    path = _PACK_DIR / f"{name}.json"
    raw = load_json(path, max_bytes=8 * 1024 * 1024)
    if raw is None:
        logger.warning("vocab pack %s unavailable", path)
        return None
    if not isinstance(raw, dict):
        logger.warning("vocab pack %s is not a JSON object; ignoring", path)
        return None
    # Honour the documented None+warning contract for EVERY malformed
    # shape: a string-valued name list would otherwise iterate into a
    # frozenset of single characters, and a list-shaped auth_predicates
    # would raise out of the loader into callers' broad excepts.
    try:
        return _build_vocabulary(raw, DomainVocabulary)
    except _MalformedPack as exc:
        logger.warning("vocab pack %s is malformed (%s); ignoring", path, exc)
        return None


def _build_vocabulary(raw: dict, vocab_cls: type) -> DomainVocabulary:
    def _names(key: str) -> frozenset:
        val = raw.get(key, [])
        if not isinstance(val, list):
            raise _MalformedPack(f"{key} must be a list of names")
        return frozenset(n for n in val if isinstance(n, str) and n)

    lock_raw = raw.get("lock_pairs", [])
    if not isinstance(lock_raw, list):
        raise _MalformedPack("lock_pairs must be a list of pairs")
    lock_pairs = frozenset(
        (str(a), str(r))
        for a, r in (
            p for p in lock_raw
            if isinstance(p, (list, tuple)) and len(p) == 2
        )
    )
    auth_raw = raw.get("auth_predicates", {})
    if not isinstance(auth_raw, dict):
        raise _MalformedPack("auth_predicates must be an object")
    auth = frozenset(
        (str(k), str(v))
        for k, v in auth_raw.items()
        if isinstance(k, str) and k
    )

    return vocab_cls(
        allocators=_names("allocators"),
        deallocators=_names("deallocators"),
        lock_acquires=frozenset(a for a, _ in lock_pairs),
        lock_releases=frozenset(r for _, r in lock_pairs),
        lock_pairs=lock_pairs,
        callback_registers=_names("callback_registers"),
        callback_cancels=_names("callback_cancels"),
        security_fields=_names("security_fields"),
        nullable_returns=_names("nullable_returns"),
        auth_predicates=auth,
        boundary_transfers=_names("boundary_transfers"),
    )


def is_kernel_tree(target_path: str | Path) -> bool:
    """Heuristic: does the target look like a Linux kernel tree/module?

    Markers (any one suffices): a Kconfig or Kbuild file at the root
    (mainline tree, kernel subtree, or out-of-tree module), an
    ``include/linux`` directory (mainline), or a root Makefile with
    kbuild ``obj-m`` / ``obj-$(CONFIG_...)`` assignments (module).
    Cached per resolved path.
    """
    try:
        root = Path(target_path).resolve()
    except OSError:
        return False
    key = str(root)
    cached = _kernel_tree_cache.get(key)
    if cached is not None:
        return cached

    result = False
    try:
        if (root / "include" / "linux").is_dir() or (root / "Kconfig").is_file() or (root / "Kbuild").is_file():
            result = True
        else:
            makefile = root / "Makefile"
            got = read_text_capped(makefile, 65536)
            if got is not None:
                result = bool(_KBUILD_OBJ_RE.search(got[0]))
    except OSError:
        result = False

    _kernel_tree_cache[key] = result
    return result


def pack_for_target(target_path: str | Path) -> DomainVocabulary | None:
    """Return the vocab pack matching the target kind, if any."""
    if is_kernel_tree(target_path):
        return load_pack("linux_kernel")
    return None
