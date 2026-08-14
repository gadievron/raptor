"""Callback-lifetime violation detector for /audit.

Detects patterns where a resource is freed while a registered callback
can still reference it (timer, workqueue, tasklet, hrtimer, waitqueue).

Tier 1: single-function fast-path (no Joern needed).
Tier 2: cross-function via Joern CPG query.
Sub-pattern 6c: kfree on RCU-dereferenced variable (should be kfree_rcu).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class CallbackLifetimeViolation:
    """One cross-function callback-lifetime violation."""

    register_func: str = ""
    register_line: int = 0
    free_func: str = ""
    free_line: int = 0
    callback: str = ""
    struct_member: str = ""
    reasoning: str = ""


@dataclass
class CallbackLifetimeResult:
    """Result of callback-lifetime analysis."""

    violation_found: bool = False
    register_line: int = 0
    free_line: int = 0
    cancel_missing: bool = False
    rcu_kfree_mismatch: bool = False
    violations: List[CallbackLifetimeViolation] = field(default_factory=list)
    reasoning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "violation_found": self.violation_found,
            "reasoning": self.reasoning,
        }
        if self.register_line:
            d["register_line"] = self.register_line
        if self.free_line:
            d["free_line"] = self.free_line
        if self.cancel_missing:
            d["cancel_missing"] = True
        if self.rcu_kfree_mismatch:
            d["rcu_kfree_mismatch"] = True
        if self.violations:
            d["violations"] = [
                {
                    "register_func": v.register_func,
                    "register_line": v.register_line,
                    "free_func": v.free_func,
                    "free_line": v.free_line,
                    "callback": v.callback,
                    "struct_member": v.struct_member,
                    "reasoning": v.reasoning,
                }
                for v in self.violations
            ]
        return d


_REGISTER_RE = re.compile(
    r"\b(timer_setup|setup_timer|INIT_WORK|INIT_DELAYED_WORK|"
    r"init_waitqueue_func_entry|tasklet_init|"
    r"hrtimer_init|mod_timer|add_timer|"
    r"schedule_work|schedule_delayed_work|queue_work)\s*\("
)

_CANCEL_RE = re.compile(
    r"\b(del_timer_sync|del_timer|timer_delete_sync|"
    r"cancel_work_sync|cancel_delayed_work_sync|flush_work|"
    r"flush_delayed_work|tasklet_kill|hrtimer_cancel|"
    r"cancel_work|remove_wait_queue)\s*\("
)

_FREE_RE = re.compile(
    r"\b(kfree|vfree|kvfree|kfree_rcu|kfree_sensitive|"
    r"free|devm_kfree)\s*\("
)

_RCU_DEREF_RE = re.compile(
    r"(\w+)\s*=\s*rcu_dereference\w*\s*\("
)

_KFREE_VAR_RE = re.compile(
    r"\bkfree\s*\(\s*(\w+)\s*\)"
)

_STRUCT_VAR_RE = re.compile(r"&(\w+)->")


def check_callback_lifetime_local(source: str) -> CallbackLifetimeResult:
    """Tier 1: detect free-without-cancel in a single function body."""
    from .safety_contract import assert_boost_only
    assert_boost_only("callback_lifetime")

    lines = source.split("\n")

    registrations: List[int] = []
    frees: List[int] = []
    cancels: set[int] = set()

    for i, line in enumerate(lines):
        if _REGISTER_RE.search(line):
            registrations.append(i)
        if _FREE_RE.search(line):
            frees.append(i)
        if _CANCEL_RE.search(line):
            cancels.add(i)

    for reg_line in registrations:
        for free_line in frees:
            if free_line <= reg_line:
                continue
            has_cancel = any(
                reg_line < c < free_line for c in cancels
            )
            if not has_cancel:
                return CallbackLifetimeResult(
                    violation_found=True,
                    register_line=reg_line + 1,
                    free_line=free_line + 1,
                    cancel_missing=True,
                    reasoning=(
                        f"callback registered at line {reg_line + 1}, "
                        f"containing struct freed at line {free_line + 1} "
                        f"without cancel/sync in between"
                    ),
                )

    rcu_result = _check_rcu_kfree(lines)
    if rcu_result is not None:
        return rcu_result

    return CallbackLifetimeResult(reasoning="no callback lifetime issues")


def _check_rcu_kfree(lines: List[str]) -> Optional[CallbackLifetimeResult]:
    """Sub-pattern 6c: kfree on RCU-dereferenced variable."""
    rcu_vars: Dict[str, int] = {}
    for i, line in enumerate(lines):
        m = _RCU_DEREF_RE.search(line)
        if m:
            rcu_vars[m.group(1)] = i

    if not rcu_vars:
        return None

    for i, line in enumerate(lines):
        m = _KFREE_VAR_RE.search(line)
        if m and m.group(1) in rcu_vars:
            deref_line = rcu_vars[m.group(1)]
            return CallbackLifetimeResult(
                violation_found=True,
                register_line=deref_line + 1,
                free_line=i + 1,
                rcu_kfree_mismatch=True,
                reasoning=(
                    f"variable '{m.group(1)}' obtained via rcu_dereference "
                    f"at line {deref_line + 1} freed with kfree at "
                    f"line {i + 1} — should use kfree_rcu"
                ),
            )

    return None


def _extract_struct_var(member_expr: str) -> Optional[str]:
    """Extract struct variable name from &foo->timer expression."""
    m = _STRUCT_VAR_RE.search(member_expr)
    return m.group(1) if m else None


def check_callback_lifetime_cross(
    joern: Any,
    file_path: str,
    func_name: str,
) -> CallbackLifetimeResult:
    """Tier 2: cross-function callback-lifetime check via Joern CPG."""
    from .safety_contract import assert_boost_only
    assert_boost_only("callback_lifetime")

    reg_names = (
        "timer_setup|setup_timer|INIT_WORK|INIT_DELAYED_WORK|"
        "tasklet_init|hrtimer_init|mod_timer|add_timer|"
        "schedule_work|schedule_delayed_work|queue_work"
    )
    cancel_names = (
        "del_timer_sync|del_timer|timer_delete_sync|"
        "cancel_work_sync|cancel_delayed_work_sync|flush_work|"
        "flush_delayed_work|tasklet_kill|hrtimer_cancel|"
        "cancel_work|remove_wait_queue"
    )
    free_names = "kfree|vfree|kvfree|kfree_sensitive|devm_kfree"

    escaped_file = file_path.replace("\\", "\\\\").replace('"', '\\"')

    reg_query = (
        f'cpg.call.name("{reg_names}")'
        f'.filter(_.file.name(".*{escaped_file}"))'
        f".map(c => (c.lineNumber.getOrElse(-1), "
        f"c.argument.order(0).headOption.map(_.code).getOrElse(\"\"), "
        f"c.argument.order(1).headOption.map(_.code).getOrElse(\"\"), "
        f"c.method.name)).l"
    )

    try:
        registrations = joern.query(reg_query)
    except Exception:
        logger.debug("callback_lifetime: Joern reg query failed", exc_info=True)
        return CallbackLifetimeResult(reasoning="Joern query failed")

    if not registrations:
        return CallbackLifetimeResult(reasoning="no callback registrations")

    violations: List[CallbackLifetimeViolation] = []
    for entry in registrations:
        if not isinstance(entry, (list, tuple)) or len(entry) < 4:
            continue
        reg_line, member_expr, callback_name, reg_func = entry[:4]

        struct_var = _extract_struct_var(str(member_expr))
        if not struct_var:
            continue

        escaped_var = struct_var.replace("\\", "\\\\").replace('"', '\\"')
        free_query = (
            f'cpg.call.name("{free_names}")'
            f'.filter(_.file.name(".*{escaped_file}"))'
            f'.filter(_.argument.order(0).code(".*{escaped_var}.*"))'
            f".map(c => (c.method.name, c.lineNumber.getOrElse(-1))).l"
        )

        try:
            free_sites = joern.query(free_query)
        except Exception:
            continue

        for free_entry in (free_sites or []):
            if not isinstance(free_entry, (list, tuple)) or len(free_entry) < 2:
                continue
            free_func, free_line = free_entry[:2]
            if free_func == reg_func:
                continue

            escaped_member = str(member_expr).replace("\\", "\\\\").replace('"', '\\"')
            cancel_query = (
                f'cpg.method.name("{free_func}")'
                f'.ast.isCall.name("{cancel_names}")'
                f'.filter(_.argument.order(0).code(".*{escaped_member}.*"))'
                f".l"
            )

            try:
                cancels = joern.query(cancel_query)
            except Exception:
                cancels = None

            if not cancels:
                violations.append(CallbackLifetimeViolation(
                    register_func=str(reg_func),
                    register_line=int(reg_line) if reg_line != -1 else 0,
                    free_func=str(free_func),
                    free_line=int(free_line) if free_line != -1 else 0,
                    callback=str(callback_name),
                    struct_member=str(member_expr),
                    reasoning=(
                        f"{reg_func} registers callback {callback_name} "
                        f"via {member_expr} at line {reg_line}; "
                        f"{free_func} frees {struct_var} at line "
                        f"{free_line} without cancelling the callback"
                    ),
                ))

    if violations:
        return CallbackLifetimeResult(
            violation_found=True,
            violations=violations,
            reasoning=(
                f"{len(violations)} cross-function callback-lifetime "
                f"violation(s) found"
            ),
        )

    return CallbackLifetimeResult(reasoning="no callback lifetime issues")
