"""Standing clone-family index: whole-target function similarity.

``clone_drift`` compares function pairs directly and is therefore
capped at a few hundred functions per run — fine for drift VERDICTS,
useless as a standing "which functions are copies of which" index.
This module builds that index: normalized token-shingle fingerprints
(the clone-drift primitives — one tokenizer, one winnower, two
consumers; a fork of either side would make "clone" mean two things)
bucketed by keyed MinHash-LSH so candidate discovery is near-linear,
then verified pairwise INSIDE buckets with the same containment score
clone_drift uses (containment against the smaller set — a missing
guard must not depress a symmetric score).

Hostile-repo bounds, each marked in-band (``caps_hit``):

* **Keyed LSH.** Band hashes are parameterised from a per-build
  random seed. Unkeyed shingle hashes would let a repo author
  precompute bucket collisions and bury the unfixed clone of a fixed
  function inside a saturated bucket — DoS as evasion against the
  index's future fix-lost join. The seed never persists; the CACHE
  stores the verified families, not the LSH internals.
* **Per-bucket cap with seeded-random survivors,** never
  deterministic first-N: deterministic truncation lets the attacker
  choose what survives a flooded bucket.
* **Verified-pair budget:** bucket flooding cannot turn verification
  into the quadratic sink LSH exists to avoid.
* ``caps_hit`` propagates to the index record so any downstream
  absence-of-match claim ("no clone of the fixed function") carries
  the degradation instead of silently overstating coverage.

Named residual (genuine-near-clone flooding): an attacker who plants
MANY real near-clones of a victim function floods the victim's OWN
buckets with genuine similarity. Keyed hashing cannot help — the
collisions are earned, not precomputed — so the victim's true clone
can still lose its bucket slot to the flood's survivor sample. This
is inherent to similarity bucketing; the ``caps_hit`` marker (and
the bucket-cap event count in the stats) is the operator's signal
that survivor sampling engaged and absence-of-match claims are
degraded.

Cache: ``clone-index.json`` in the run directory, keyed on the
source fingerprint AND the index/tokenizer version — a code change to
the normalization must never serve stale families.

The index renders no verdict. Families are review structure and a
join surface; similarity-derived membership is lower confidence than
the mechanical layers and every consumer labels it so.
"""

from __future__ import annotations

import hashlib
import logging
import os
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Group-type string for the resolver layer (reserved in
# peer_groups' layer table).
GROUP_TYPE_CLONE_FAMILY = "clone_family"

#: Version of the index format AND its normalization chain (the
#: clone_drift tokenizer/winnower parameters ride under it). Bump on
#: any change to tokenization, shingling, hashing, or the family
#: rules — the cache key includes it so stale indexes never load.
CLONE_INDEX_VERSION = 1

#: Functions admitted per build. Both directions: more turns the
#: index build into the prep phase's dominant cost on monorepos
#: (winnowing is ~ms/function; verification is budgeted separately);
#: fewer blinds the index on exactly the large trees where manual
#: clone tracking already fails. 40k ≈ the large-target class the
#: peer-census program sizes for.
MAX_INDEX_FUNCTIONS = 40_000

#: MinHash signature layout: bands × rows hashes per function. Two
#: rows per band keeps recall high at the 0.85 containment floor
#: (P[band collision] = s² per band); more rows would trade recall
#: for fewer candidate pairs, which the verified-pair budget already
#: bounds. 16 bands × 2 rows = 32 hashes/function — linear, cheap.
LSH_BANDS = 16
LSH_ROWS = 2

#: Bucket size ceiling. Both directions: a larger cap admits
#: quadratic verification inside one attacker-saturated bucket
#: (cap² pairs); a smaller one splits legitimately wide clone
#: clusters (generated code). 64 → ≤2016 pairs per flooded bucket,
#: sampled seeded-random.
MAX_BUCKET_MEMBERS = 64

#: Verified-pair budget per build. Both directions: higher re-opens
#: the CPU sink LSH exists to close; lower degrades the index to
#: fewer families on clone-heavy trees — marked caps_hit, and the
#: absence-of-match consumers must carry the marker. 20k pairs at
#: set-intersection cost is well under a second.
MAX_VERIFY_PAIRS = 20_000

#: Families kept per index. Mirrors the census family-cap class.
MAX_CLONE_FAMILIES = 500

#: Members recorded per family. The comparator family-size ceiling
#: class (one hub family must not become a whole-tree blob).
MAX_CLONE_FAMILY_MEMBERS = 32

# 61-bit Mersenne prime for the (a*x + b) % p hash family.
_MERSENNE_P = (1 << 61) - 1

CLONE_INDEX_FILENAME = "clone-index.json"

#: Cache read bound: 500 families × 32 members × ~120 bytes/member
#: is well under 8 MiB; anything larger is not an index this module
#: wrote.
_MAX_CACHE_BYTES = 8 * 1024 * 1024


@dataclass
class CloneIndex:
    """The verified clone families of one source tree."""

    version: int
    source_fingerprint: str
    families: list[dict[str, Any]] = field(default_factory=list)
    caps_hit: bool = False
    stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "source_fingerprint": self.source_fingerprint,
            "families": self.families,
            "caps_hit": self.caps_hit,
            "stats": self.stats,
        }


def source_fingerprint(source_texts: dict[str, str]) -> str:
    """Content fingerprint of the indexed tree (cache key half)."""
    h = hashlib.sha256()
    for path in sorted(source_texts):
        h.update(path.encode("utf-8", "replace"))
        h.update(b"\x00")
        h.update(hashlib.sha256(
            (source_texts[path] or "").encode("utf-8", "replace"),
        ).digest())
    return h.hexdigest()[:16]


def _minhash_params(seed: bytes, n: int) -> list[tuple[int, int]]:
    """(a, b) parameters for *n* keyed hash functions."""
    rnd = random.Random(seed)
    return [
        (rnd.randrange(1, _MERSENNE_P), rnd.randrange(_MERSENNE_P))
        for _ in range(n)
    ]


def _signature(
    prints: frozenset[int],
    params: list[tuple[int, int]],
) -> list[int]:
    sig: list[int] = []
    for a, b in params:
        best = _MERSENNE_P
        for f in prints:
            v = (a * (f & 0xFFFFFFFF) + b) % _MERSENNE_P
            if v < best:
                best = v
        sig.append(best)
    return sig


def build_clone_index(
    source_texts: dict[str, str],
    *,
    seed: bytes | None = None,
) -> CloneIndex | None:
    """Build the index from the run's source texts.

    Returns ``None`` when no family forms (small or clone-free
    trees) — consumers then behave exactly as before (equivalence
    pin). *seed* keys the LSH band hashes; callers leave it ``None``
    (fresh entropy per build) outside tests.
    """
    try:
        from core.audit.clone_drift import (
            _function_bodies,
            _pair_similarity,
            CLONE_SIMILARITY,
        )
    except ImportError:  # pragma: no cover - trimmed deployment
        return None

    fp = source_fingerprint(source_texts)
    if seed is None:
        seed = os.urandom(16)
    # Seeded-random FILE order before the function cap: the span
    # walk admits the first MAX_INDEX_FUNCTIONS functions, and
    # sorted-path order would let early-sorting decoy files
    # (aa_*.c) push late-sorting victims out of the index entirely.
    # File-granular randomization removes the path sortability;
    # per-function reservoir sampling would additionally require
    # winnowing EVERY function first, which is the cost the cap
    # exists to bound.
    rnd_files = random.Random(seed + b"files")
    paths = sorted(source_texts)
    rnd_files.shuffle(paths)
    bodies = _function_bodies(
        {p: source_texts[p] for p in paths},
        max_functions=MAX_INDEX_FUNCTIONS,
    )
    caps_hit = len(bodies) >= MAX_INDEX_FUNCTIONS
    bodies = [b for b in bodies if b.prints]
    if len(bodies) < 2:
        return None

    params = _minhash_params(seed, LSH_BANDS * LSH_ROWS)
    rnd = random.Random(seed + b"survivors")

    # Banded LSH buckets → candidate pairs (deduped), under budget.
    # Buckets are admitted in SEEDED-RANDOM order across all bands:
    # first-come admission in file/signature order let decoy clone
    # clusters in early-sorting files exhaust the pair budget before
    # a late-sorting victim's bucket was ever reached (targeted
    # eviction). Bucket-granular randomization gives every bucket an
    # unchoosable admission slot; a per-PAIR reservoir would need an
    # unbounded distinct-pair seen-set to stay uniform, for no extra
    # unchoosability.
    signatures = [_signature(b.prints, params) for b in bodies]
    all_buckets: list[list[int]] = []
    bucket_cap_events = 0
    for band in range(LSH_BANDS):
        lo = band * LSH_ROWS
        buckets: dict[tuple[int, ...], list[int]] = {}
        for idx, sig in enumerate(signatures):
            buckets.setdefault(
                tuple(sig[lo:lo + LSH_ROWS]), [],
            ).append(idx)
        for members in buckets.values():
            if len(members) < 2:
                continue
            if len(members) > MAX_BUCKET_MEMBERS:
                # Seeded-random survivors — see the module docstring.
                members = sorted(
                    rnd.sample(members, MAX_BUCKET_MEMBERS),
                )
                caps_hit = True
                bucket_cap_events += 1
            all_buckets.append(members)
    rnd_buckets = random.Random(seed + b"buckets")
    rnd_buckets.shuffle(all_buckets)
    candidate_pairs: set[tuple[int, int]] = set()
    verify_budget_hit = False
    for members in all_buckets:
        for i, a in enumerate(members):
            for b in members[i + 1:]:
                if len(candidate_pairs) >= MAX_VERIFY_PAIRS:
                    verify_budget_hit = True
                    break
                candidate_pairs.add((a, b) if a < b else (b, a))
            if verify_budget_hit:
                break
        if verify_budget_hit:
            break
    caps_hit = caps_hit or verify_budget_hit

    # Verify candidates; union-find into families.
    parent = list(range(len(bodies)))

    def _find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    verified = 0
    for a, b in sorted(candidate_pairs):
        sim = _pair_similarity(bodies[a].prints, bodies[b].prints)
        verified += 1
        if sim >= CLONE_SIMILARITY:
            ra, rb = _find(a), _find(b)
            if ra != rb:
                lo_r, hi_r = sorted((ra, rb))
                parent[hi_r] = lo_r

    components: dict[int, list[int]] = {}
    for idx in range(len(bodies)):
        components.setdefault(_find(idx), []).append(idx)

    families: list[dict[str, Any]] = []
    n_eligible = 0
    for root in sorted(components):
        members = components[root]
        if len(members) < 2:
            continue
        n_eligible += 1
        if len(families) >= MAX_CLONE_FAMILIES:
            caps_hit = True
            continue
        if len(members) > MAX_CLONE_FAMILY_MEMBERS:
            members = sorted(
                rnd.sample(members, MAX_CLONE_FAMILY_MEMBERS),
            )
            caps_hit = True
        recs = sorted(
            (
                {
                    "file": bodies[i].file,
                    "function": bodies[i].function,
                    "line": bodies[i].line,
                }
                for i in members
            ),
            key=lambda r: (r["file"], r["function"]),
        )
        families.append({
            "key": f"{recs[0]['file']}:{recs[0]['function']}",
            "members": recs,
        })

    if not families:
        return None
    index = CloneIndex(
        version=CLONE_INDEX_VERSION,
        source_fingerprint=fp,
        families=families,
        caps_hit=caps_hit,
        stats={
            "functions": len(bodies),
            "candidate_pairs": len(candidate_pairs),
            "verified_pairs": verified,
            "bucket_cap_events": bucket_cap_events,
            "families": len(families),
            "eligible_families": n_eligible,
        },
    )
    logger.info(
        "clone index: %d functions, %d verified pairs, %d "
        "families%s",
        len(bodies), verified, len(families),
        " (caps hit)" if caps_hit else "",
    )
    return index


def _index_from_dict(raw: Any) -> CloneIndex | None:
    if not isinstance(raw, dict):
        return None
    families = raw.get("families")
    if not isinstance(families, list):
        return None
    cleaned: list[dict[str, Any]] = []
    for fam in families:
        if not isinstance(fam, dict):
            return None
        members = fam.get("members")
        if not isinstance(members, list):
            return None
        recs = []
        for m in members:
            if not isinstance(m, dict):
                return None
            recs.append({
                "file": str(m.get("file", "")),
                "function": str(m.get("function", "")),
                "line": m.get("line", 0),
            })
        cleaned.append({
            "key": str(fam.get("key", "")), "members": recs,
        })
    return CloneIndex(
        version=int(raw.get("version", 0)),
        source_fingerprint=str(raw.get("source_fingerprint", "")),
        families=cleaned,
        caps_hit=bool(raw.get("caps_hit", False)),
        stats=dict(raw.get("stats") or {}),
    )


def load_or_build_clone_index(
    source_texts: dict[str, str],
    out_dir: Path | None = None,
) -> CloneIndex | None:
    """Cached build: reload ``clone-index.json`` when BOTH the source
    fingerprint and the index version match; rebuild (and rewrite)
    otherwise. The version join means a normalization change can
    never serve a stale index."""
    fp = source_fingerprint(source_texts)
    if out_dir is not None:
        path = Path(out_dir) / CLONE_INDEX_FILENAME
        if path.is_file():
            try:
                from core.json import load_json

                cached = _index_from_dict(
                    load_json(path, max_bytes=_MAX_CACHE_BYTES),
                )
            except Exception:
                cached = None
                logger.debug(
                    "clone index cache load failed", exc_info=True,
                )
            if cached is not None \
                    and cached.version == CLONE_INDEX_VERSION \
                    and cached.source_fingerprint == fp:
                logger.info(
                    "clone index: reloaded %d families from cache "
                    "(fingerprint + version match)",
                    len(cached.families),
                )
                return cached

    index = build_clone_index(source_texts)
    if index is not None and out_dir is not None:
        try:
            from core.json import save_json

            save_json(
                Path(out_dir) / CLONE_INDEX_FILENAME,
                index.to_dict(),
            )
        except Exception:
            logger.debug(
                "clone index cache write failed", exc_info=True,
            )
    return index
