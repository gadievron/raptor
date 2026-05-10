"""Stage C structural pre-checks via Coccinelle.

Runs a small set of cocci rules across the target ONCE, builds a
``PrereqFacts`` map (function defs + call sites), then evaluates each
finding against those facts. This is mechanical evidence the LLM
reasoning at Stage C/D consults — it does NOT decide finding status
on its own.

Skip-silently semantics match the ``/scan`` cocci leg:
  * spatch absent → no facts (skipped)
  * target has no C/C++ source → no facts (skipped)
  * shipped prereqs rules dir missing → no facts (skipped)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .runner import is_available as spatch_available
from .runner import run_rules as spatch_run_rules


# Re-exported for callers that want to skip prereqs on pure-Python /
# pure-JS targets without re-implementing the heuristic. Same set as
# the /scan cocci leg's ``_repo_has_c_cpp_source``.
_C_CPP_EXTS: Tuple[str, ...] = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh")


def _shipped_prereqs_rules_dir() -> Optional[Path]:
    """Resolve the in-tree shipped prereqs rules dir, or None if
    missing (minimal install / packaging strip)."""
    here = Path(__file__).resolve()
    # packages/coccinelle/prereqs.py → repo root → engine/coccinelle/prereqs/
    candidate = here.parents[2] / "engine" / "coccinelle" / "prereqs"
    return candidate if candidate.is_dir() else None


def _has_c_cpp_source(repo_path: Path, max_files: int = 200) -> bool:
    """Bounded heuristic: any C/C++ source under ``repo_path``?"""
    if not repo_path.is_dir():
        return False
    seen = 0
    for entry in repo_path.rglob("*"):
        if not entry.is_file():
            continue
        seen += 1
        if entry.suffix.lower() in _C_CPP_EXTS:
            return True
        if seen >= max_files:
            return False
    return False


@dataclass
class PrereqFacts:
    """Structural facts derived from the function-inventory rule.

    ``defs``: function name → set of (file, line) where defined.
    ``calls``: function name → set of (file, line) where called.

    Both maps key on the bare function name as it appears in source.
    Aliasing / renaming / pointer-call indirection is out of scope —
    cocci only sees the syntactic form.
    """

    defs: Dict[str, Set[Tuple[str, int]]] = field(default_factory=dict)
    calls: Dict[str, Set[Tuple[str, int]]] = field(default_factory=dict)
    skipped_reason: Optional[str] = None

    @property
    def is_skipped(self) -> bool:
        return self.skipped_reason is not None

    def function_exists(self, name: str) -> bool:
        return name in self.defs

    def function_has_callers(self, name: str) -> bool:
        return name in self.calls and len(self.calls[name]) > 0

    def callers_of(self, name: str) -> List[Tuple[str, int]]:
        return sorted(self.calls.get(name, set()))


def gather_prereqs(
    target: Path,
    rules_dir: Optional[Path] = None,
    timeout_per_rule: int = 300,
) -> PrereqFacts:
    """Run shipped prereq rules against ``target`` and build facts.

    Returns ``PrereqFacts`` with ``skipped_reason`` set when the run
    is skipped (caller treats this as "no structural evidence
    available"; it is NOT an error).
    """
    target = Path(target)

    if not spatch_available():
        return PrereqFacts(skipped_reason="spatch_not_available")
    if not _has_c_cpp_source(target):
        return PrereqFacts(skipped_reason="no_c_cpp_source")

    effective_rules_dir = rules_dir if rules_dir else _shipped_prereqs_rules_dir()
    if effective_rules_dir is None:
        return PrereqFacts(skipped_reason="rules_dir_missing")

    results = spatch_run_rules(
        target=target,
        rules_dir=effective_rules_dir,
        timeout_per_rule=timeout_per_rule,
        no_includes=True,  # operator targets are untrusted
    )

    facts = PrereqFacts()
    for r in results:
        for m in r.matches:
            msg = (m.message or "").strip()
            if msg.startswith("def:"):
                name = msg[4:].strip()
                facts.defs.setdefault(name, set()).add((m.file, int(m.line)))
            elif msg.startswith("call:"):
                name = msg[5:].strip()
                facts.calls.setdefault(name, set()).add((m.file, int(m.line)))
            # Other message shapes (future rule additions) are
            # ignored here — the consumer may grow checks; this
            # gather pass stays neutral.
    return facts


def evaluate_finding(
    finding: Dict[str, Any],
    facts: PrereqFacts,
) -> Dict[str, Any]:
    """Per-finding mechanical evaluation against the prereq facts.

    Returns a dict suitable for ``finding["cocci_prereqs"]``.

    Output shape:
      {
        "applicable": bool,    # False when prereqs were skipped
                               # OR finding's file isn't C/C++.
        "checks": {
          "function_exists": bool | null,
          "function_has_callers": bool | null,
        },
        "details": {           # only populated when checks ran
          "function": str,
          "callers_count": int,
        },
        "skipped_reason": str | null,
      }

    Stage C reasoning consults this; Stage D may use it as evidence
    in attack-tree disposition. Status of the finding is NEVER
    overwritten here — these are facts, not verdicts.
    """
    out: Dict[str, Any] = {
        "applicable": False,
        "checks": {
            "function_exists": None,
            "function_has_callers": None,
        },
        "details": {},
        "skipped_reason": None,
    }

    if facts.is_skipped:
        out["skipped_reason"] = facts.skipped_reason
        return out

    func_name = (finding.get("function") or "").strip()
    file_path = (finding.get("file") or "").strip()

    # Bail when there's nothing to check or the file isn't C-family.
    # Findings on .py / .js / .go are skipped (cocci is C-only).
    if not func_name:
        out["skipped_reason"] = "finding_missing_function"
        return out
    if file_path:
        ext = os.path.splitext(file_path)[1].lower()
        if ext and ext not in _C_CPP_EXTS:
            out["skipped_reason"] = "non_c_cpp_file"
            return out

    out["applicable"] = True
    exists = facts.function_exists(func_name)
    has_callers = facts.function_has_callers(func_name) if exists else None

    out["checks"]["function_exists"] = exists
    # function_has_callers is only meaningful if the function exists.
    # When the function isn't defined locally (e.g. libc symbol), we
    # leave the caller check as null rather than asserting False.
    out["checks"]["function_has_callers"] = has_callers

    out["details"]["function"] = func_name
    if exists:
        out["details"]["callers_count"] = len(facts.calls.get(func_name, set()))

    return out
