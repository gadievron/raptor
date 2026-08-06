"""Path homology of directed graphs — a structural control-flow signal.

Path homology (Grigor'yan–Lin–Muranov–Yau; applied to control flow by
Huntsman 2020, arXiv:2003.00944) generalises cyclomatic complexity to a
sequence of Betti numbers ``β_0, β_1, β_2, …`` over a **directed** graph:

  * ``β_0`` counts weakly-connected components (1 for a normal CFG).
  * ``β_1`` coincides with cyclomatic complexity for reducible
    (structured) control flow — but is *direction-aware*, so it can
    already differ from McCabe's undirected count.
  * ``β_2`` and above are nonzero only for **unstructured / irreducible**
    control flow (assembly jumps, gotos, control-flow flattening). That
    higher-dimensional signal is what distinguishes path homology from the
    scalar metric, and is the reason this is interesting on disassembled
    binaries (see ``docs/design-path-homology-cfg.md``).

This module is **Phase 1**: the dependency-free homology core. It is a
*metric only* — it never gates a suppression and never participates in the
sanitizer-cut chokepoint.

Theory (non-regular path homology — the variant Huntsman adopts):

  * An *allowed p-path* is a vertex sequence ``(v_0, …, v_p)`` in which
    every consecutive pair ``(v_{i-1}, v_i)`` is an edge — a real walk.
  * The boundary ``∂(v_0…v_p) = Σ_j (v_0 … v̂_j … v_p)`` deletes each
    vertex in turn. Over GF(2) the ``(-1)^j`` signs vanish, so ``∂`` is the
    mod-2 sum of the deletions. Deleting an *endpoint* always yields a
    walk; deleting an *interior* vertex may yield a NON-allowed sequence
    (the newly-adjacent pair isn't an edge).
  * ``Ω_p`` = allowed p-chains whose boundary is again a combination of
    *allowed* ``(p-1)``-paths — the ``∂``-invariant allowed paths.
    ``∂ : Ω_p → Ω_{p-1}`` is then well-defined with ``∂² = 0``, and

        β_p = dim Ω_p − rank(∂_p) − rank(∂_{p+1}).

Field: **GF(2)**. Keeps the implementation exact and dependency-free
(bitset Gaussian elimination, no NumPy / SciPy / NetworkX, per the
runtime-dep rule in CLAUDE.md). GF(2) Betti numbers equal the
characteristic-0 (paper's real) values *except* in the presence of
torsion, which is rare and, when present, shows up as *extra* GF(2)
homology — acceptable for a structural signal, and a future ``β`` over ℚ
is the escape hatch if faithful torsion-free reproduction is ever needed.
Computation is bounded by a per-dimension path budget; on overflow the
result is flagged incomplete.

Input is any object exposing ``nodes()`` and ``successors(node)`` (the
``core.inventory.dominators.Graph`` protocol), or a plain adjacency
mapping via :func:`betti_from_adjacency`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Protocol, Sequence, Tuple

# Per-dimension cap on the number of enumerated allowed paths. Real
# per-function CFGs carry tens of blocks with out-degree ≈ 2, so allowed
# paths stay small; the cap only fires on pathological inputs, where we
# return an incomplete result rather than spending unbounded time/memory.
DEFAULT_MAX_PATHS_PER_DIM = 200_000


class _GraphLike(Protocol):
    def nodes(self) -> Iterable: ...
    def successors(self, node) -> Iterable: ...


@dataclass(frozen=True)
class BettiVector:
    """Path-homology Betti numbers ``(β_0, …, β_d)`` for a digraph.

    ``betti`` is the tuple of Betti numbers up to the highest reliably-
    computed dimension. ``max_dim`` is the dimension requested.
    ``complete`` is ``False`` when the path budget truncated enumeration
    before all requested dimensions could be computed — in that case
    ``betti`` is a (still-correct) prefix shorter than ``max_dim + 1``.
    """

    betti: Tuple[int, ...]
    max_dim: int
    complete: bool

    @property
    def b0(self) -> int:
        return self.betti[0] if self.betti else 0

    @property
    def b1(self) -> int:
        return self.betti[1] if len(self.betti) > 1 else 0

    @property
    def b2(self) -> int:
        return self.betti[2] if len(self.betti) > 2 else 0

    def reduced(self) -> Tuple[int, ...]:
        """Reduced Betti numbers ``β̃`` (Huntsman's convention): identical
        to ``betti`` except ``β̃_0 = β_0 − 1`` (a connected graph has
        ``β̃_0 = 0``). Empty when no dimensions were computed."""
        if not self.betti:
            return ()
        return (self.betti[0] - 1,) + tuple(self.betti[1:])

    def __str__(self) -> str:
        body = ", ".join(str(b) for b in self.betti)
        flag = "" if self.complete else " (truncated)"
        return f"β = ({body}){flag}"


# ---------------------------------------------------------------------------
# GF(2) linear algebra — vectors are Python ints (bitsets)
# ---------------------------------------------------------------------------

def _gf2_rank(vectors: Sequence[int]) -> int:
    """Rank over GF(2) of a set of bitset vectors. Reduces each vector
    against a pivot table keyed by lowest set bit."""
    pivots: Dict[int, int] = {}
    rank = 0
    for v in vectors:
        while v:
            low = v & -v
            p = pivots.get(low)
            if p is None:
                pivots[low] = v
                rank += 1
                break
            v ^= p
    return rank


def _gf2_nullspace(columns: Sequence[int]) -> List[int]:
    """Null space of the GF(2) matrix whose ``c``-th column image is
    ``columns[c]`` (a bitset over rows). Returns a basis of the kernel,
    each element a bitset over *column* indices: the set of columns whose
    XOR maps to zero."""
    pivots: Dict[int, Tuple[int, int]] = {}  # low bit -> (image, combo)
    nullspace: List[int] = []
    for c, col in enumerate(columns):
        img = col
        combo = 1 << c
        while img:
            low = img & -img
            p = pivots.get(low)
            if p is None:
                pivots[low] = (img, combo)
                break
            pimg, pcombo = p
            img ^= pimg
            combo ^= pcombo
        if img == 0:
            nullspace.append(combo)
    return nullspace


def _iter_bits(mask: int) -> Iterable[int]:
    """Yield the indices of set bits in ``mask`` (ascending)."""
    while mask:
        low = mask & -mask
        yield low.bit_length() - 1
        mask ^= low


# ---------------------------------------------------------------------------
# Core
# ---------------------------------------------------------------------------

def _boundary(
    path: Tuple[int, ...],
    allowed_index_pm1: Mapping[Tuple[int, ...], int],
    nonallowed_index: Dict[Tuple[int, ...], int],
) -> Tuple[int, int]:
    """Mod-2 boundary of a single allowed path, split into its allowed and
    non-allowed components. Returns ``(allowed_bits, nonallowed_bits)``:
    bitsets over ``allowed_index_pm1`` positions and over a dynamically-
    grown ``nonallowed_index`` respectively. A ``(p-1)``-tuple produced by
    two deletions cancels (XOR)."""
    ab = 0
    nb = 0
    for j in range(len(path)):
        tup = path[:j] + path[j + 1:]
        pos = allowed_index_pm1.get(tup)
        if pos is not None:
            ab ^= (1 << pos)
        else:
            ni = nonallowed_index.get(tup)
            if ni is None:
                ni = len(nonallowed_index)
                nonallowed_index[tup] = ni
            nb ^= (1 << ni)
    return ab, nb


def _betti_core(
    succ_idx: List[List[int]],
    n_vertices: int,
    max_dim: int,
    max_paths_per_dim: int,
) -> BettiVector:
    if max_dim < 0:
        return BettiVector(betti=(), max_dim=max_dim, complete=True)
    if n_vertices == 0:
        return BettiVector(
            betti=tuple(0 for _ in range(max_dim + 1)),
            max_dim=max_dim, complete=True)

    # --- enumerate allowed p-paths for p = 0 .. max_dim+1 --------------
    # allowed[p] is a list of vertex-index tuples; truncation at the first
    # level that exceeds the budget marks the result incomplete.
    allowed: List[List[Tuple[int, ...]]] = [[(i,) for i in range(n_vertices)]]
    edges = [(i, j) for i in range(n_vertices) for j in succ_idx[i]]
    allowed.append(edges)
    truncated = False
    for p in range(2, max_dim + 2):
        cur: List[Tuple[int, ...]] = []
        for path in allowed[p - 1]:
            for j in succ_idx[path[-1]]:
                cur.append(path + (j,))
                if len(cur) > max_paths_per_dim:
                    truncated = True
                    break
            if truncated:
                break
        if truncated:
            break  # discard the partial level — do not use it
        allowed.append(cur)

    highest_full = len(allowed) - 1            # last fully-built level
    # β_p needs Ω_p and Ω_{p+1}, i.e. allowed[p] and allowed[p+1] full.
    reliable_dim = min(max_dim, highest_full - 1)
    if reliable_dim < 0:
        return BettiVector(betti=(), max_dim=max_dim, complete=False)

    allowed_index = [
        {path: k for k, path in enumerate(allowed[p])}
        for p in range(highest_full + 1)
    ]

    dim_omega = [0] * (highest_full + 1)
    rank_d = [0] * (highest_full + 1)          # rank_d[0] = 0 (∂_0 = 0)
    dim_omega[0] = len(allowed[0])

    if highest_full >= 1:
        # Ω_1 = all edges; image of each edge under ∂_1 lands in allowed[0].
        idx0 = allowed_index[0]
        imgs1 = [
            (1 << idx0[(j,)]) ^ (1 << idx0[(i,)])
            for (i, j) in allowed[1]
        ]
        dim_omega[1] = len(allowed[1])
        rank_d[1] = _gf2_rank(imgs1)

    for p in range(2, highest_full + 1):
        nonallowed_index: Dict[Tuple[int, ...], int] = {}
        ab_list: List[int] = []
        nb_list: List[int] = []
        ai_pm1 = allowed_index[p - 1]
        for path in allowed[p]:
            ab, nb = _boundary(path, ai_pm1, nonallowed_index)
            ab_list.append(ab)
            nb_list.append(nb)
        omega = _gf2_nullspace(nb_list)        # combos over allowed[p]
        dim_omega[p] = len(omega)
        imgs = []
        for combo in omega:
            acc = 0
            for k in _iter_bits(combo):
                acc ^= ab_list[k]
            imgs.append(acc)
        rank_d[p] = _gf2_rank(imgs)

    betti_vals = []
    for p in range(reliable_dim + 1):
        next_rank = rank_d[p + 1] if p + 1 <= highest_full else 0
        betti_vals.append(dim_omega[p] - rank_d[p] - next_rank)

    return BettiVector(
        betti=tuple(betti_vals), max_dim=max_dim, complete=not truncated)


def _normalise(graph: _GraphLike) -> Tuple[List, List[List[int]]]:
    """Materialise a graph-protocol object into a node list and an
    index-keyed successor adjacency. Self-loops are dropped (path homology
    is defined for loopless digraphs); duplicate edges are collapsed;
    successors pointing outside ``nodes()`` are ignored."""
    nodes = list(dict.fromkeys(graph.nodes()))
    idx = {n: i for i, n in enumerate(nodes)}
    succ_idx: List[List[int]] = []
    for n in nodes:
        seen = set()
        row: List[int] = []
        for m in graph.successors(n):
            if m == n or m not in idx or m in seen:
                continue
            seen.add(m)
            row.append(idx[m])
        succ_idx.append(row)
    return nodes, succ_idx


def betti(
    graph: _GraphLike,
    max_dim: int = 3,
    *,
    max_paths_per_dim: int = DEFAULT_MAX_PATHS_PER_DIM,
) -> BettiVector:
    """Compute the path-homology Betti vector of ``graph`` over GF(2).

    ``graph`` exposes ``nodes()`` and ``successors(node)`` (the
    ``core.inventory.dominators.Graph`` protocol). ``max_dim`` is the
    highest homology dimension to compute (default 3 — capped because
    higher dimensions are rarely informative and cost grows).
    """
    nodes, succ_idx = _normalise(graph)
    return _betti_core(succ_idx, len(nodes), max_dim, max_paths_per_dim)


def betti_from_adjacency(
    adjacency: Mapping,
    max_dim: int = 3,
    *,
    max_paths_per_dim: int = DEFAULT_MAX_PATHS_PER_DIM,
) -> BettiVector:
    """Convenience wrapper: compute Betti numbers from a ``{node:
    successors}`` mapping. Nodes that appear only as successors are
    included as vertices with no out-edges."""
    nodes: List = list(dict.fromkeys(adjacency.keys()))
    seen = set(nodes)
    for succs in adjacency.values():
        for m in succs:
            if m not in seen:
                seen.add(m)
                nodes.append(m)
    idx = {n: i for i, n in enumerate(nodes)}
    succ_idx: List[List[int]] = [[] for _ in nodes]
    for n, succs in adjacency.items():
        row_seen = set()
        i = idx[n]
        for m in succs:
            if m == n or m not in idx or m in row_seen:
                continue
            row_seen.add(m)
            succ_idx[i].append(idx[m])
    return _betti_core(succ_idx, len(nodes), max_dim, max_paths_per_dim)


def cyclomatic_number(graph: _GraphLike) -> int:
    """Classic cyclomatic complexity ``|E| − |V| + c`` over the *directed*
    edge set (``c`` = weakly-connected components; anti-parallel edges
    ``a→b`` and ``b→a`` are counted separately, as McCabe does). Provided
    for side-by-side comparison with the direction-aware path-homology
    ``β_1``:

      * On genuine **loops** (back edges, directed cycles) the two agree.
      * On **branch/merge** structure (if/else diamonds) ``β_1`` is
        *smaller* — path homology fills the "commutative square" between
        two branches, so it counts loops and higher voids rather than
        branchiness. ``β_1 ≤ cyclomatic`` always.

    To reproduce the paper's strict ``β_1 = cyclomatic`` for structured
    code, add the virtual exit→entry arc (McCabe's strongly-connected
    convention) before calling — that turns branch/merge regions into
    genuine cycles."""
    nodes, succ_idx = _normalise(graph)
    v = len(nodes)
    if v == 0:
        return 0
    n_edges = sum(len(row) for row in succ_idx)  # directed, deduped in _normalise
    parent = list(range(v))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for i in range(v):
        for j in succ_idx[i]:
            ri, rj = find(i), find(j)
            if ri != rj:
                parent[ri] = rj
    components = sum(1 for i in range(v) if find(i) == i)
    return n_edges - v + components


__all__ = [
    "BettiVector",
    "betti",
    "betti_from_adjacency",
    "cyclomatic_number",
    "DEFAULT_MAX_PATHS_PER_DIM",
]
