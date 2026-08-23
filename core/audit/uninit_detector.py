"""Detect uninitialised-memory leaks in C/C++ source (inject-mode).

Catches the pattern:
1. Stack struct declared without memset/zero-init
2. Partially initialised (some fields set, gaps remain)
3. Copied to user/network via copy_to_user, put_user, sendmsg, etc.

Two tiers:
- **CPG (Joern)**: dataflow query — does any local reach a copy sink
  without passing through memset?  Cross-function, precise.
- **Regex fallback**: same-function pattern matching when Joern is
  unavailable.

This is an inject-mode detector: findings go into the LLM context as
leads, not as hard verdicts.  The LLM decides whether the partial init
constitutes a real info-leak.

Kernel info-leak bugs this pattern covers:
- io_uring_setup: struct io_uring_params partially set, copy_to_user
- perf_copy_attr: struct perf_event_attr partial init
- Any copy_to_user of a stack-allocated struct without memset
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from ._util import safe_joern_name_lenient as _safe_name

logger = logging.getLogger(__name__)


@dataclass
class UninitLeak:
    line: int
    description: str
    struct_var: str
    sink_call: str
    tier: str = "regex"


# ── Tier 1: Joern CPG dataflow ────────────────────────────────────────

_COPY_SINK_NAMES = (
    "copy_to_user", "__copy_to_user", "put_user", "__put_user",
    "nla_put", "skb_put_data", "skb_copy_to_linear_data",
    "simple_copy_to_iter", "copyout", "copy_to_iter",
)

_INIT_NAMES = (
    "memset", "memcpy", "kzalloc", "kcalloc", "vzalloc",
)


def _run_query(server: Any, query: str) -> list | None:
    from core.audit.condition_cpg import _run_query as cpg_run_query
    return cpg_run_query(server, query)


def detect_uninit_leak_cpg(
    function_name: str,
    server: Any,
) -> list[UninitLeak]:
    """Use Joern CPG dataflow to find uninit struct → copy sink paths.

    Query: find locals of struct type in `function_name` that reach a
    copy sink (copy_to_user etc.) without first flowing through memset
    or a zero-init call.
    """
    safe_fn = _safe_name(function_name)
    if safe_fn is None:
        return []

    sink_pattern = "|".join(_COPY_SINK_NAMES)
    init_pattern = "|".join(_INIT_NAMES)

    query = (
        f'cpg.method.name("{safe_fn}").local'
        f'.filter(_.typeFullName.matches(".*struct.*|.*union.*"))'
        f".map {{ local =>\n"
        f'  val sinks = cpg.method.name("{safe_fn}")'
        f'.ast.isCall.name("{sink_pattern}")'
        f'.argument.filter(_.code.matches(".*" + local.name + ".*")).l\n'
        f'  val inits = cpg.method.name("{safe_fn}")'
        f'.ast.isCall.name("{init_pattern}")'
        f'.argument.filter(_.code.matches(".*" + local.name + ".*")).l\n'
        f"  (local.name, local.typeFullName, "
        f"sinks.map(_.lineNumber.getOrElse(0)), "
        f"inits.nonEmpty)\n"
        f"}}.filter {{ case (_, _, sinks, hasInit) => "
        f"sinks.nonEmpty && !hasInit }}.l"
    )

    raw = _run_query(server, query)
    if not raw:
        return []

    results: list[UninitLeak] = []
    for item in raw:
        if not isinstance(item, (list, tuple)) or len(item) < 3:
            continue
        var_name = str(item[0])
        sink_lines = item[2] if isinstance(item[2], list) else [item[2]]
        first_line = int(sink_lines[0]) if sink_lines else 0

        sink_name = "copy_to_user"
        for sn in _COPY_SINK_NAMES:
            if sn in str(item):
                sink_name = sn
                break

        results.append(UninitLeak(
            line=first_line,
            description=(
                f"CPG: struct local `{var_name}` reaches "
                f"`{sink_name}()` without memset/zero-init — "
                f"potential info leak"
            ),
            struct_var=var_name,
            sink_call=sink_name,
            tier="cpg",
        ))

    return results


# ── Tier 2: regex fallback ────────────────────────────────────────────

_COPY_SINKS = re.compile(
    r"\b(copy_to_user|__copy_to_user|put_user|__put_user"
    r"|nla_put|skb_put_data|skb_copy_to_linear_data"
    r"|simple_copy_to_iter|copyout|copy_to_iter"
    r"|sendmsg|send|write)\s*\(",
)

_ZERO_INIT = re.compile(
    r"\bmemset\s*\(\s*&?\s*(\w+)"
    r"|\b(\w+)\s*=\s*\{\s*0?\s*\}"
    r"|\b(\w+)\s*=\s*\{\s*\.\w+\s*="
    r"|\bmemcpy\s*\(\s*&?\s*(\w+)\s*,",
)

_STRUCT_DECL = re.compile(
    r"^\s*(?:struct|union)\s+(\w+)\s+(\w+)\s*;",
)

_FIELD_ASSIGN = re.compile(
    r"(\w+)\.(\w+)\s*="
    r"|(\w+)->(\w+)\s*=",
)


def detect_uninit_leak_regex(source: str) -> list[UninitLeak]:
    """Regex fallback: same-function struct → partial-init → copy sink."""
    lines = source.split("\n")
    results: list[UninitLeak] = []

    stack_structs: dict[str, int] = {}
    zeroed_vars: set[str] = set()
    partial_vars: set[str] = set()

    for i, line in enumerate(lines, 1):
        dm = _STRUCT_DECL.search(line)
        if dm:
            var = dm.group(2)
            stack_structs[var] = i

        for zm in _ZERO_INIT.finditer(line):
            var = zm.group(1) or zm.group(2) or zm.group(3) or zm.group(4)
            if var:
                zeroed_vars.add(var)

        for fm in _FIELD_ASSIGN.finditer(line):
            var = fm.group(1) or fm.group(3)
            if var and var in stack_structs and var not in zeroed_vars:
                partial_vars.add(var)

    for i, line in enumerate(lines, 1):
        sm = _COPY_SINKS.search(line)
        if not sm:
            continue
        sink_call = sm.group(1)

        for var in partial_vars:
            if var not in zeroed_vars and var in stack_structs:
                if re.search(rf"\b&?\s*{re.escape(var)}\b", line):
                    results.append(UninitLeak(
                        line=i,
                        description=(
                            f"stack struct `{var}` partially initialised "
                            f"(no memset/zero-init) then passed to "
                            f"`{sink_call}()` — potential info leak"
                        ),
                        struct_var=var,
                        sink_call=sink_call,
                        tier="regex",
                    ))

    return results


# ── Public API: CPG with regex fallback ───────────────────────────────

def detect_uninit_leak(
    source: str,
    function_name: str = "",
    joern_server: Any = None,
) -> list[UninitLeak]:
    """Detect uninit struct → copy sink.  CPG when available, else regex."""
    if not _COPY_SINKS.search(source):
        return []

    if joern_server is not None and function_name:
        try:
            cpg_results = detect_uninit_leak_cpg(function_name, joern_server)
            if cpg_results:
                return cpg_results
        except Exception:
            logger.debug(
                "uninit CPG query failed for %s, falling back to regex",
                function_name, exc_info=True,
            )

    return detect_uninit_leak_regex(source)
