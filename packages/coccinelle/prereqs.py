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
  * every prereq rule errored → no facts (skipped: an errored sweep
    holds no absence evidence; ``rules_failed``, never an empty fact
    base that reads as "scanned and found nothing")
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .runner import is_available as spatch_available
from .runner import run_rules as spatch_run_rules

# Re-exported for callers that want to skip prereqs on pure-Python /
# pure-JS targets without re-implementing the heuristic. Same set as
# the /scan cocci leg's ``_repo_has_c_cpp_source``.
_C_CPP_EXTS: tuple[str, ...] = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh")

# Extensions the sweep's fact base NEVER covers: spatch parses C
# translation units only (the runner's directory walk enumerates
# ``*.c``/``*.h``, and spatch's C parser chokes on C++ constructs), so
# a function defined in a ``.cpp``/``.cc`` file cannot appear in
# ``defs`` no matter what — its absence is not evidence.
# ``evaluate_finding`` skips findings on these files entirely rather
# than minting ``function_exists=False`` for functions the sweep was
# structurally blind to.
_CPP_ONLY_EXTS: tuple[str, ...] = (".cc", ".cpp", ".cxx", ".hpp", ".hh")


def _shipped_prereqs_rules_dir() -> Path | None:
    """Resolve the in-tree shipped prereqs rules dir, or None if
    missing (minimal install / packaging strip)."""
    here = Path(__file__).resolve()
    # packages/coccinelle/prereqs.py → repo root → engine/coccinelle/prereqs/
    candidate = here.parents[2] / "engine" / "coccinelle" / "prereqs"
    return candidate if candidate.is_dir() else None


# Pruned from the bounded source walk: VCS internals are never target
# source, and .git alone routinely holds hundreds of loose object
# files — enough to exhaust the file cap before any source dir is
# reached (readdir order dependent).
_VCS_DIR_NAMES: frozenset[str] = frozenset({".git", ".hg", ".svn"})


def _has_c_cpp_source(repo_path: Path, max_files: int = 200) -> bool:
    """Bounded heuristic: any C/C++ source under ``repo_path``?

    Walks with VCS directories pruned so their internals don't count
    toward the cap — pre-fix ``rglob("*")`` enumerated ``.git/objects``
    too, and any repo whose walk order fronted 200 non-source files
    returned False even with C sources present.
    """
    if not repo_path.is_dir():
        return False
    seen = 0
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in _VCS_DIR_NAMES]
        for fname in filenames:
            seen += 1
            if os.path.splitext(fname)[1].lower() in _C_CPP_EXTS:
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

    defs: dict[str, set[tuple[str, int]]] = field(default_factory=dict)
    calls: dict[str, set[tuple[str, int]]] = field(default_factory=dict)
    skipped_reason: str | None = None
    # False when any prereq rule errored (nonzero rc / parse errors on
    # some files): the maps then hold PARTIAL evidence — positive
    # entries stand, but a name's ABSENCE proves nothing. Negative
    # consumers (``evaluate_finding``'s function_exists=False,
    # source_intel's dead-code / gated-path axes) must abstain when
    # this is False; asserting absence from an errored sweep is how
    # engine failure used to read as a mechanical refutation.
    complete: bool = True
    # False when the sweep ran with ``--no-includes`` (always, today:
    # gather_prereqs scans untrusted targets): header-defined
    # static/inline functions never enter ``defs``, so absence of a
    # name that would live in a header is not evidence either.
    headers_parsed: bool = False

    @property
    def is_skipped(self) -> bool:
        return self.skipped_reason is not None

    def function_exists(self, name: str) -> bool:
        return name in self.defs

    def function_has_callers(self, name: str) -> bool:
        return name in self.calls and len(self.calls[name]) > 0

    def callers_of(self, name: str) -> list[tuple[str, int]]:
        return sorted(self.calls.get(name, set()))


def gather_prereqs(
    target: Path,
    rules_dir: Path | None = None,
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

    effective_rules_dir = rules_dir or _shipped_prereqs_rules_dir()
    if effective_rules_dir is None:
        return PrereqFacts(skipped_reason="rules_dir_missing")

    results = spatch_run_rules(
        target=target,
        rules_dir=effective_rules_dir,
        timeout_per_rule=timeout_per_rule,
        no_includes=True,  # operator targets are untrusted
        # In-repo shipped prereqs rules (code trust) — their
        # @script:python reporting blocks are trusted.
        allow_scripting=True,
    )

    # Engine failure must never read as verified silence (the same
    # rc-synthesis doctrine the runner applies one layer down): a
    # sweep in which NO rule succeeded produced no absence evidence
    # at all — treat it exactly like the other skip cases rather
    # than returning an empty fact base that downstream negative
    # checks would read as "scanned, nothing defined".
    if not results or not any(r.ok for r in results):
        return PrereqFacts(skipped_reason="rules_failed")

    facts = PrereqFacts(
        # Any errored rule leaves the maps partial: keep the positive
        # evidence but mark the base incomplete so absence answers
        # abstain (see PrereqFacts.complete).
        complete=all(r.ok for r in results),
        # no_includes=True above: headers are never parsed.
        headers_parsed=False,
    )
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
    finding: dict[str, Any],
    facts: PrereqFacts,
) -> dict[str, Any]:
    """Per-finding mechanical evaluation against the prereq facts.

    Returns a dict suitable for ``finding["cocci_prereqs"]``.

    Output shape:
      {
        "applicable": bool,    # False when prereqs were skipped,
                               # the finding carries no function
                               # name, its file isn't C/C++, OR the
                               # fact base is structurally blind to
                               # the file (C++ TUs the C-only sweep
                               # never parses).
        "checks": {
          "function_exists": bool | null,
          "function_has_callers": bool | null,
        },
        "details": {           # only populated when checks ran;
          "function": str,     # "abstained" names why a check
          "callers_count": int,  # answered null instead of False
          "abstained": str,      # (partial sweep / unparsed headers)
        },
        "skipped_reason": str | null,
      }

    Condemn-toward-abstain: ``function_exists``/``function_has_callers``
    answer ``False`` only when the fact base could actually have seen
    the definition/callers (complete sweep; file class the walk
    covers). A partial sweep or an uncovered file class answers
    ``null`` — absence there is not evidence, and downstream
    refutation consumers accept only a positive absence witness.

    Stage C reasoning consults this; Stage D may use it as evidence
    in attack-tree disposition. Status of the finding is NEVER
    overwritten here — these are facts, not verdicts.
    """
    out: dict[str, Any] = {
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
    ext = ""
    if file_path:
        ext = os.path.splitext(file_path)[1].lower()
        if ext and ext not in _C_CPP_EXTS:
            out["skipped_reason"] = "non_c_cpp_file"
            return out
        if ext in _CPP_ONLY_EXTS:
            # The sweep parses C translation units only — a function
            # in a .cpp/.cc/.hpp file can never be in the fact base,
            # so neither its absence nor its callers say anything.
            out["skipped_reason"] = "ext_not_in_fact_base"
            return out

    out["applicable"] = True
    out["details"]["function"] = func_name

    if facts.function_exists(func_name):
        # Positive witness: stands even from a partial fact base.
        out["checks"]["function_exists"] = True
        out["details"]["callers_count"] = len(
            facts.calls.get(func_name, set()),
        )
        if facts.function_has_callers(func_name):
            out["checks"]["function_has_callers"] = True
        elif facts.complete:
            out["checks"]["function_has_callers"] = False
        else:
            # Partial sweep: the calls map may be missing exactly the
            # caller that exists — "no callers" is not evidence.
            out["checks"]["function_has_callers"] = None
            out["details"]["abstained"] = "sweep_partial"
        return out

    # Name absent from defs. Absence is a POSITIVE witness only when
    # the fact base could have seen the definition:
    #   * the sweep must be complete (no rule errored), and
    #   * the finding's file class must be one the walk parses —
    #     header findings under --no-includes never enter defs.
    if ext == ".h" and not facts.headers_parsed:
        out["checks"]["function_exists"] = None
        out["details"]["abstained"] = "headers_not_parsed"
    elif not facts.complete:
        out["checks"]["function_exists"] = None
        out["details"]["abstained"] = "sweep_partial"
    else:
        out["checks"]["function_exists"] = False
    # function_has_callers is only meaningful if the function exists.
    # When the function isn't defined locally (e.g. libc symbol), we
    # leave the caller check as null rather than asserting False.
    return out
