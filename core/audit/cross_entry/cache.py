"""Content-addressed typed source views; repository discovery is cached separately."""
from __future__ import annotations

import hashlib
import json
import logging
import zlib
from importlib.metadata import version, PackageNotFoundError
from pathlib import Path

from core.atomic_fs import write_bytes_atomically
from core.json import dumps_canonical
from core.source.contained import read_bytes_capped

from .index import build_access_index
from .model import AccessIndex, digest

logger = logging.getLogger(__name__)
_MAX_COMPRESSED_BYTES = 64_000_000
_MAX_SERIALIZED_BYTES = 128_000_000


def load_or_build_index(sources, *, out_dir, limits, entry_points=(), include_edges=None):
    hashes = {p:hashlib.sha256(s.encode("utf-8",errors="replace")).hexdigest() for p,s in sources.items()}
    implementation = {p.name:hashlib.sha256(p.read_bytes()).hexdigest()  # raw-open: __file__-relative module source for cache key
                      for p in (Path(__file__).with_name(n) for n in ("model.py","index.py","dispatch.py"))}
    for name in ("field_census.py", "callsite_consistency.py"):
        implementation[name] = hashlib.sha256(Path(__file__).parent.parent.joinpath(name).read_bytes()).hexdigest()  # raw-open: __file__-relative sibling module for cache key
    for package in ("tree-sitter", "tree-sitter-c", "tree-sitter-cpp", "tree-sitter-languages"):
        try:
            implementation[package] = version(package)
        except PackageNotFoundError:
            implementation[package] = None
    key = digest({"sources":hashes,"implementation":implementation,"entries":sorted(entry_points),
                  "include_edges":include_edges,
                  "settings":limits.content_settings()})
    folder = Path(out_dir)/"cross-entry-index-cache"
    path = folder/f"{key}.json.z"
    try:
        got = read_bytes_capped(path, _MAX_COMPRESSED_BYTES)
        if got is not None and not got[1]:
            decoder = zlib.decompressobj()
            raw = decoder.decompress(got[0], _MAX_SERIALIZED_BYTES)
            if decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data:
                data = json.loads(raw)
                if data["key"] == key and data["index"]["source_hashes"] == hashes:
                    return AccessIndex.from_dict(data["index"]), True
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError, OSError, zlib.error):
        pass
    index = build_access_index(sources,limits=limits,entry_points=entry_points,include_edges=include_edges)
    # Do not permanently cache a parse abandoned by a transient time budget.
    if not any("time_budget" in str(v) for v in index.coverage["truncated"]) and not any(
        v.get("reason") == "scan_budget" for v in index.coverage["skipped"]
    ):
        raw = dumps_canonical({"key":key,"index":index.to_dict()}).encode("utf-8")
        # Only publish entries that this same cache can reload. These are
        # serialized-byte limits; the fresh analysis result remains available.
        if len(raw) <= _MAX_SERIALIZED_BYTES:
            compressed = zlib.compress(raw)
            if len(compressed) <= _MAX_COMPRESSED_BYTES:
                try:
                    folder.mkdir(parents=True, exist_ok=True)
                    write_bytes_atomically(path, compressed)
                except OSError as exc:
                    logger.warning("Could not persist cross-entry index cache: %s", exc)
    return index,False
