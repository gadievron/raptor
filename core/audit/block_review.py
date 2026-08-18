"""Block-level review for complex functions.

When a function's cyclomatic complexity exceeds the LLM's single-pass
reasoning capacity, reviewing it as a unit misses branch-dependent
vulnerabilities.  This module decomposes qualifying functions into
taint-relevant basic-block subgraphs and reviews each block with its
per-block taint state.

Decision function (all computed mechanically from the CFG):

    block_level = (
        cyclomatic_complexity > CC_THRESHOLD
        AND taint_relevant_branches > TAINT_BRANCH_THRESHOLD
    ) OR path_to_sink_count > PATH_TO_SINK_THRESHOLD

Uses the existing CFG builders (``PythonCFG``, ``CPPCFG``) and
taint approximation (``CTaintApprox``) — no LLM call for the
complexity analysis itself.
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

CC_THRESHOLD = 10
TAINT_BRANCH_THRESHOLD = 2
PATH_TO_SINK_THRESHOLD = 3


@dataclass
class BlockTaintState:
    """Per-block taint snapshot for the LLM prompt."""

    block_id: int
    lineno: int
    label: str
    tainted_at_entry: List[str] = field(default_factory=list)
    calls_dangerous: List[str] = field(default_factory=list)
    calls_sanitizer: List[str] = field(default_factory=list)
    defs: List[str] = field(default_factory=list)
    uses: List[str] = field(default_factory=list)
    is_branch: bool = False
    branch_involves_tainted: bool = False


@dataclass
class ComplexityProfile:
    """Mechanical complexity measurements for one function."""

    cyclomatic_complexity: int = 1
    taint_relevant_branches: int = 0
    path_to_sink_count: int = 0
    total_nodes: int = 0
    branch_nodes: int = 0
    dangerous_calls: int = 0

    @property
    def needs_block_review(self) -> bool:
        if self.path_to_sink_count > PATH_TO_SINK_THRESHOLD:
            return True
        return (
            self.cyclomatic_complexity > CC_THRESHOLD
            and self.taint_relevant_branches > TAINT_BRANCH_THRESHOLD
        )


@dataclass
class BlockReviewPlan:
    """Decomposition of a complex function into reviewable blocks."""

    function: str
    file: str
    profile: ComplexityProfile
    blocks: List[BlockTaintState] = field(default_factory=list)
    source_lines: List[str] = field(default_factory=list)


def compute_cyclomatic_complexity(cfg) -> int:
    """Compute cyclomatic complexity from a CFG.

    CC = edges - nodes + 2 (for a single connected component).
    Works with both PythonCFG and CPPCFG.
    """
    nodes = list(cfg.nodes())
    n = len(nodes)
    if n == 0:
        return 1

    e = 0
    for node in nodes:
        e += len(list(cfg.successors(node)))

    return max(1, e - n + 2)


def _is_branch_node(cfg, node) -> bool:
    """A node is a branch if it has >1 successor."""
    return len(list(cfg.successors(node))) > 1


def _get_dangerous_targets() -> FrozenSet[str]:
    """Import the dangerous target set from sink_discovery."""
    try:
        from core.inventory.sink_discovery import DANGEROUS_TARGETS
        return frozenset(DANGEROUS_TARGETS)
    except ImportError:
        return frozenset({
            "system", "popen", "exec", "execve", "execvp",
            "sprintf", "strcpy", "strcat", "gets", "scanf",
            "memcpy", "memmove", "eval", "subprocess.call",
            "os.system", "os.popen",
        })


def _get_sanitizer_callables(cwe: str, language: str) -> FrozenSet[str]:
    """Import the sanitizer catalog for a CWE class."""
    try:
        from core.analysis.sanitizer_cut import sanitizer_callables_for_cwe
        return sanitizer_callables_for_cwe(cwe, language)
    except ImportError:
        return frozenset()
    except Exception:
        logger.warning(
            "sanitizer catalog lookup failed for CWE %s/%s"
            " — taint analysis will see zero sanitisers",
            cwe, language, exc_info=True,
        )
        return frozenset()


def analyze_complexity(
    cfg,
    *,
    taint_approx=None,
) -> ComplexityProfile:
    """Compute the complexity profile from a CFG and optional taint data.

    Parameters
    ----------
    cfg
        A ``PythonCFG`` or ``CPPCFG`` instance.
    taint_approx
        Optional ``CTaintApprox`` with per-function taint flows.
        Used to count taint-relevant branches and paths to sinks.
    """
    nodes = list(cfg.nodes())
    cc = compute_cyclomatic_complexity(cfg)

    dangerous = _get_dangerous_targets()

    branch_count = 0
    taint_branch_count = 0
    dangerous_call_count = 0

    tainted_names: Set[str] = set()
    if taint_approx is not None:
        params = getattr(taint_approx, "params", [])
        if params:
            tainted_names.update(params)

    for node in nodes:
        if _is_branch_node(cfg, node):
            branch_count += 1
            node_uses = getattr(node, "uses", frozenset())
            if tainted_names & set(node_uses):
                taint_branch_count += 1

        node_calls = getattr(node, "calls", frozenset())
        for call in node_calls:
            base = call.rsplit(".", 1)[-1] if "." in call else call
            if base in dangerous or call in dangerous:
                dangerous_call_count += 1

    path_count = _count_paths_to_dangerous(
        cfg, nodes, dangerous, tainted_names,
    )

    return ComplexityProfile(
        cyclomatic_complexity=cc,
        taint_relevant_branches=taint_branch_count,
        path_to_sink_count=path_count,
        total_nodes=len(nodes),
        branch_nodes=branch_count,
        dangerous_calls=dangerous_call_count,
    )


def _count_paths_to_dangerous(
    cfg,
    nodes: list,
    dangerous: FrozenSet[str],
    tainted_names: Set[str],
) -> int:
    """Count distinct tainted paths reaching a dangerous call.

    Uses DFS from the entry node, tracking tainted variables through
    defs/uses. A path counts when it reaches a node that calls a
    dangerous target with a tainted variable. Caps at 20 to avoid
    explosion on pathological CFGs.
    """
    sink_nodes = set()
    for node in nodes:
        calls = getattr(node, "calls", frozenset())
        for call in calls:
            base = call.rsplit(".", 1)[-1] if "." in call else call
            if base in dangerous or call in dangerous:
                sink_nodes.add(id(node))
                break

    if not sink_nodes or not tainted_names:
        return 0

    count = 0
    cap = 20
    entry = cfg.entry if hasattr(cfg, "entry") else getattr(cfg, "entry_node", None)
    if entry is None:
        return 0

    stack: List[Tuple[Any, Set[str], Set[int]]] = [
        (entry, set(tainted_names), set()),
    ]
    max_visits = 100_000

    while stack and count < cap:
        node, current_taint, visited = stack.pop()
        nid = id(node)
        if nid in visited:
            continue
        visited = visited | {nid}
        max_visits -= 1
        if max_visits <= 0:
            break

        node_defs = set(getattr(node, "defs", frozenset()))
        node_uses = set(getattr(node, "uses", frozenset()))

        live_taint = current_taint - node_defs
        if node_uses & current_taint:
            live_taint |= node_defs

        if nid in sink_nodes and live_taint:
            count += 1

        for succ in cfg.successors(node):
            if id(succ) not in visited:
                stack.append((succ, live_taint, visited))

    return count


def build_block_review_plan(
    cfg,
    *,
    file_path: str,
    function_name: str,
    taint_approx=None,
    source: str = "",
    cwe: str = "",
    language: str = "",
) -> Optional[BlockReviewPlan]:
    """Build a block-level review plan for a complex function.

    Returns None if the function doesn't qualify for block-level review.

    Parameters
    ----------
    cfg
        PythonCFG or CPPCFG for the function.
    file_path, function_name
        Identity for the function.
    taint_approx
        Optional CTaintApprox with per-function taint flows.
    source
        Full source text of the function (for line extraction).
    cwe
        If known, used to load relevant sanitizer callables.
    language
        "python", "c", "cpp" — for sanitizer catalog lookup.
    """
    profile = analyze_complexity(cfg, taint_approx=taint_approx)
    if not profile.needs_block_review:
        return None

    dangerous = _get_dangerous_targets()
    sanitizers: FrozenSet[str] = frozenset()
    if cwe and language:
        sanitizers = _get_sanitizer_callables(cwe, language)

    tainted_names: Set[str] = set()
    if taint_approx is not None:
        params = getattr(taint_approx, "params", [])
        if params:
            tainted_names.update(params)

    blocks: List[BlockTaintState] = []
    nodes = list(cfg.nodes())
    current_taint: Dict[int, Set[str]] = {}

    entry = cfg.entry if hasattr(cfg, "entry") else getattr(cfg, "entry_node", None)
    if entry is not None:
        current_taint[id(entry)] = set(tainted_names)

    topo_order = _bfs_traversal(cfg, nodes)

    for idx, node in enumerate(topo_order):
        nid = id(node)
        taint_in = current_taint.get(nid, set())

        node_calls = set(getattr(node, "calls", frozenset()))
        node_defs = set(getattr(node, "defs", frozenset()))
        node_uses = set(getattr(node, "uses", frozenset()))

        dangerous_here = []
        sanitizer_here = []
        for call in node_calls:
            base = call.rsplit(".", 1)[-1] if "." in call else call
            if base in dangerous or call in dangerous:
                dangerous_here.append(call)
            if base in sanitizers or call in sanitizers:
                sanitizer_here.append(call)

        is_branch = _is_branch_node(cfg, node)
        branch_tainted = is_branch and bool(taint_in & node_uses)

        is_interesting = (
            dangerous_here
            or sanitizer_here
            or branch_tainted
            or (is_branch and taint_in)
        )

        if is_interesting or getattr(node, "kind", "") in ("entry", "exit"):
            blocks.append(BlockTaintState(
                block_id=idx,
                lineno=getattr(node, "lineno", 0),
                label=getattr(node, "label", ""),
                tainted_at_entry=sorted(taint_in),
                calls_dangerous=dangerous_here,
                calls_sanitizer=sanitizer_here,
                defs=sorted(node_defs),
                uses=sorted(node_uses),
                is_branch=is_branch,
                branch_involves_tainted=branch_tainted,
            ))

        taint_out = set(taint_in)
        if sanitizer_here:
            killed = set()
            for s_call in sanitizer_here:
                for cs in getattr(node, "call_sites", ()):
                    if cs.name == s_call:
                        killed |= set(getattr(cs, "arg_names", ()))
            taint_out -= killed
            taint_out |= node_defs & node_uses & taint_in
        else:
            taint_out -= node_defs
            if node_uses & taint_in:
                taint_out |= node_defs

        for succ in cfg.successors(node):
            sid = id(succ)
            if sid not in current_taint:
                current_taint[sid] = set()
            current_taint[sid] |= taint_out

    source_lines = source.splitlines() if source else []

    return BlockReviewPlan(
        function=function_name,
        file=file_path,
        profile=profile,
        blocks=blocks,
        source_lines=source_lines,
    )


def _bfs_traversal(cfg, nodes: list) -> list:
    """BFS traversal of CFG nodes from the entry node.

    On cyclic graphs (loops) this visits each node at most once —
    taint propagation over the result is a single-pass approximation,
    not a fixpoint.
    """
    entry = cfg.entry if hasattr(cfg, "entry") else getattr(cfg, "entry_node", None)
    if entry is None:
        return nodes

    visited: Set[int] = set()
    order: list = []

    stack = deque([entry])
    while stack:
        node = stack.popleft()
        nid = id(node)
        if nid in visited:
            continue
        visited.add(nid)
        order.append(node)
        for succ in cfg.successors(node):
            if id(succ) not in visited:
                stack.append(succ)

    for node in nodes:
        if id(node) not in visited:
            order.append(node)

    return order


def format_block_context(plan: BlockReviewPlan) -> str:
    """Format block-level taint state as LLM-consumable context.

    Appended to the function's normal context when block-level review
    is triggered. Tells the LLM exactly which blocks to focus on and
    what the taint state is at each.
    """
    parts = [
        f"\n### Block-level analysis (CC={plan.profile.cyclomatic_complexity}, "
        f"{plan.profile.total_nodes} CFG nodes / "
        f"{plan.profile.branch_nodes} branches, "
        f"{plan.profile.taint_relevant_branches} taint-relevant branches, "
        f"{plan.profile.path_to_sink_count} paths to sink)",
        "",
        "This function is too complex for single-pass review. The following "
        "blocks are security-relevant. For each block, check whether tainted "
        "data is sanitized, passed through, or reaches a dangerous call.",
    ]

    for block in plan.blocks:
        parts.append(
            f"\n**Block {block.block_id}** (line {block.lineno}): "
            f"`{block.label}`"
        )

        if block.tainted_at_entry:
            parts.append(
                "  Tainted at entry: "
                + ", ".join(f"`{v}`" for v in block.tainted_at_entry)
            )

        if block.calls_dangerous:
            parts.append(
                "  DANGEROUS CALLS: "
                + ", ".join(f"`{c}`" for c in block.calls_dangerous)
            )

        if block.calls_sanitizer:
            parts.append(
                "  Sanitizer calls: "
                + ", ".join(f"`{c}`" for c in block.calls_sanitizer)
            )

        if block.is_branch:
            if block.branch_involves_tainted:
                parts.append(
                    "  BRANCH on tainted variable — check both paths"
                )
            else:
                parts.append("  Branch point (not taint-dependent)")

        if plan.source_lines and block.lineno > 0:
            start = max(0, block.lineno - 1)
            end = min(len(plan.source_lines), start + 5)
            snippet = "\n".join(
                f"    {i + 1:4d}  {plan.source_lines[i]}"
                for i in range(start, end)
            )
            if snippet.strip():
                parts.append(f"  ```\n{snippet}\n  ```")

    return "\n".join(parts)


def try_build_cfg(
    file_path: str,
    function_name: str,
    target_path: Path,
    source: str = "",
) -> Optional[Any]:
    """Build a CFG for a function, auto-detecting the language.

    Returns a PythonCFG or CPPCFG, or None if the language is
    unsupported or the builder fails.
    """
    ext = Path(file_path).suffix
    full_path = target_path / file_path

    if ext == ".py":
        try:
            from core.analysis.cfg_builder import build_python_cfg
            src = source or full_path.read_text(errors="replace")
            return build_python_cfg(src, function_name)
        except Exception:
            logger.debug(
                "Python CFG build failed for %s:%s",
                file_path, function_name, exc_info=True,
            )
            return None

    if ext in (".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"):
        try:
            from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg
            lang = "cpp" if ext in (".cpp", ".cc", ".cxx", ".hpp") else "c"
            return build_cpp_intraproc_cfg(
                full_path, function_name, language=lang,
            )
        except Exception:
            logger.debug(
                "C/C++ CFG build failed for %s:%s",
                file_path, function_name, exc_info=True,
            )
            return None

    if ext in (".go", ".java", ".js", ".ts", ".tsx", ".rs"):
        try:
            from core.analysis.cfg_builder_generic import build_generic_cfg
            return build_generic_cfg(full_path, function_name, language=ext.lstrip("."))
        except ImportError:
            logger.debug(
                "no CFG builder for %s — block-level review unavailable for %s:%s",
                ext, file_path, function_name,
            )
            return None
        except Exception:
            logger.debug(
                "%s CFG build failed for %s:%s",
                ext, file_path, function_name, exc_info=True,
            )
            return None

    return None
