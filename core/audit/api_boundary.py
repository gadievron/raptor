"""Public-API-boundary guard channel.

Adjudicates caller-contract hypotheses — claims about the *obligations
of callers* of an exported function ("only reachable if an external
API consumer passes a NULL host", "requires a caller to pass negative
outl past bio_read_intern's guard"). Flow tools ask "is there an
in-tree triggering path?" and come back empty, so these hypotheses
died speculative; this channel asks the answerable question instead:
*do the in-repo call sites honour the asserted obligation?*

Verdict semantics:

* every in-repo call site guarded → ``refuted`` with per-site receipts
  (guard line / provably-safe argument);
* a concrete unguarded call site (e.g. a literal ``NULL`` where the
  contract forbids it, a possibly-negative argument with no dominating
  check) → ``confirmed`` with the site as receipt;
* no in-repo call sites (external-only consumers) → ``inconclusive``
  with the explicit "external-only callers" reason — never silently
  dropped;
* contracts about the kernel / peer / OS environment → ``inconclusive``
  with an explicit "external contract" receipt (not adjudicable from
  the source tree).

Mechanics: call sites come from the inventory call graph
(``core.analysis.reachability.callers_of``) when an inventory is
available, else from a bounded source scan; the asserted precondition
is bound to a parameter of the callee's declaration and each call
site's argument expression + dominating-guard window is checked
structurally. Only *literal* violations confirm; sites whose guard
state cannot be decided structurally stay ``undecided`` and gate the
outcome to inconclusive rather than guessing. No LLM calls.

Enumeration honesty: every result reports how the sites were found
and whether the enumeration was verified complete
(``enumeration_complete``). Completeness is earned only by an
uncapped textual tree scan whose address-taken sweep finds no
indirect-call escape of the callee — call-graph-driven enumerations
are never marked complete. The documented soundness bounds — the
file/site/match budgets, the byte cap, AND the argument-span bound
(a call-shaped match whose argument list stays unbalanced within
``_balanced_span``'s window cannot be parsed into a site) — each
set an honesty flag when hit; any of them vetoes completeness. Consumers that ACT on a ``refuted``
verdict (the caller-contract confidence-demotion gate) must require
completeness; a refutation over a possibly-partial caller list is a
hint, not a receipt.
"""

from __future__ import annotations

import bisect
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

RULE_ID = "api_boundary:caller-contract"

#: Evidence marker for a bounded-contract site whose argument is a
#: pinned integer literal — decidable in neither direction without
#: the numeric bound.  Consumers key aggregate prose off this string;
#: keep it in sync with the ``bounded`` branch of ``_check_site``.
BOUNDED_CONST_EVIDENCE_MARKER = "pinned to compile-time constant"

_IDENT = r"[A-Za-z_]\w*"

# Hypothesis shapes that assert caller/boundary obligations.
_CALLER_CONTRACT_RE = re.compile(
    r"(?:caller[s]?(?:\s+\w+){0,2}\s+"
    r"(?:must|never|always|would|should|need|pass|passes|passing|"
    r"supply|supplies|violat\w*|invoke[sd]?|bypass\w*|check\w*)"
    r"|external\s+(?:api|consumer|caller)"
    r"|api\s+consumer"
    r"|public\s+api"
    r"|only\s+reachable\s+from"
    r"|exported\s+(?:function|symbol)"
    r"|out-of-tree"
    r"|in-tree\s+caller"
    r"|caller-side"
    r"|calling\s+context"
    r"|caller\s+contract|contract\s+of\s+the\s+caller)",
    re.IGNORECASE,
)

# Obligations of the environment, not of in-repo code: kernel/peer/OS
# semantics can never be adjudicated from the source tree.
_EXTERNAL_ENV_RE = re.compile(
    r"\b(?:kernel|operating\s+system|\bOS\b|peer|remote\s+(?:end|side)|"
    r"network\s+stack|hardware|firmware)\b",
    re.IGNORECASE,
)

# Common C casts stripped when reducing an argument to its base
# identifier.
_CAST_RE = re.compile(
    r"\(\s*(?:const\s+)?(?:unsigned\s+|signed\s+)?"
    r"(?:size_t|ssize_t|u?int(?:8|16|32|64)?_t|int|long(?:\s+long)?"
    r"|short|char|void|off_t|ptrdiff_t)\s*\*?\s*\)",
)

_UNSIGNED_VALUED_RE = re.compile(
    r"\b(?:sizeof|strlen|strnlen|wcslen)\s*\(",
)

# Single-call contract shapes.  Deliberately CONDITIONAL: the phrasing
# must condition on a caller's behaviour ("double free if a caller
# invokes it twice", "crashes when called again"), or assert the
# single-call vocabulary directly ("must be called exactly once", "no
# idempotence guard").  Declarative in-body claims ("free(p) is called
# twice on the error path at lines 61 and 72") must NOT match — those
# describe a defect inside the reviewed function, and adjudicating the
# CALLERS of that function would test the wrong mechanism.  The
# idempotence vocabulary matches only in NEGATED form: "is idempotent"
# / "idempotency is guaranteed" are safety assertions, not contracts
# on the callers.
_SINGLE_CALL_RE = re.compile(
    r"(?:(?:if|when|unless|should)\s+(?:[\w'`*>-]+\s+){0,4}?"
    r"(?:call(?:s|ed)?|invoke[sd]?|re-?invoke[sd]?|frees?|freed|"
    r"releases?[d]?|destroy(?:s|ed)?)\s+(?:[\w'`*>-]+\s+){0,3}?"
    r"(?:twice|again|more\s+than\s+once|a\s+second\s+time|"
    r"multiple\s+times|repeatedly)"
    r"|exactly\s+once"
    r"|(?:\bno|\bnot|\blacks?|\blacking|\bmissing|\bwithout)\s+"
    r"(?:[\w'`-]+\s+){0,2}?idempoten(?:t|ce|cy))",
    re.IGNORECASE,
)

# The explicitly named target of an invoked-twice claim ("if a caller
# invokes bitmap_free twice").  Pronouns and generic nouns are not
# names.
_INVOKE_TARGET_RE = re.compile(
    r"(?:call(?:s|ed|ing)?|invoke[sd]?|invoking|re-?invoke[sd]?)\s+"
    r"([A-Za-z_]\w*)\s*(?:\(\s*\))?\s+"
    r"(?:twice|again|more\s+than\s+once|a\s+second\s+time|"
    r"multiple\s+times|repeatedly)",
    re.IGNORECASE,
)
_INVOKE_TARGET_STOPWORDS = frozenset({
    "it", "this", "that", "them", "itself", "him", "her", "us",
    "the", "a", "an", "is", "was", "be", "been", "being",
    "function", "method", "callback", "routine", "helper", "api",
})


def _named_invoke_target(hypothesis: str) -> str:
    """The function name a re-invocation claim explicitly targets, or
    "" when the claim uses a pronoun / generic noun."""
    m = _INVOKE_TARGET_RE.search(hypothesis or "")
    if not m:
        return ""
    name = m.group(1)
    if name.lower() in _INVOKE_TARGET_STOPWORDS:
        return ""
    return name

# Caller-conditional phrasing beyond the explicit contract shapes:
# the hypothesis blames a hypothetical caller behaviour rather than
# an in-body path ("if a caller passes...", "NULL when called before
# init").  Gates the widened CWE dispatch below.
_CALLER_CONDITIONAL_RE = re.compile(
    r"(?:(?:if|when|unless|until|before|because)\s+"
    r"(?:a|the|any|some|an?\s+future)\s+caller"
    r"|caller\s+(?:passes|invokes|calls|supplies|provides|frees|"
    r"reuses|forgets|fails|neglects|omits)"
    r"|(?:if|when)\s+(?:it\s+is\s+|this\s+(?:function\s+)?is\s+)?"
    r"(?:called|invoked)\s+(?:twice|again|before|after|without|"
    r"with|while|multiple|more|prior)"
    r")",
    re.IGNORECASE,
)


@dataclass
class Contract:
    """One asserted caller obligation, bound to a callee parameter."""

    # "null" | "negative" | "single_call" | "bounded" | "external"
    kind: str
    param: str = ""    # callee parameter name ("" for external)
    param_index: int = -1

    def describe(self) -> str:
        if self.kind == "external":
            return "external-environment contract"
        if self.kind == "null":
            return f"callers must not pass NULL {self.param}"
        if self.kind == "single_call":
            return (
                f"callers must not invoke again on the same "
                f"{self.param} (single-call contract)"
            )
        if self.kind == "bounded":
            return (
                f"callers must keep {self.param} within the bound "
                "the flagged arithmetic assumes"
            )
        return f"callers must not pass negative {self.param}"


@dataclass
class CallSiteCheck:
    """Per-call-site receipt.

    ``grade`` records how the verdict was earned: ``structural`` =
    decidable from the argument expression itself (literal NULL,
    address-of, unsigned cast — sound); ``lexical`` = a regex hit in
    the raw-text window above the call (no dominance/branch proof —
    may HINT, never refute).
    """

    file: str
    caller: str
    line: int
    code: str
    verdict: str       # guarded | unguarded | undecided
    evidence: str = ""
    argument: str = ""
    grade: str = "structural"

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "caller": self.caller,
            "line": self.line,
            "code": self.code,
            "verdict": self.verdict,
            "evidence": self.evidence,
            "argument": self.argument,
            "grade": self.grade,
        }


@dataclass
class ApiBoundaryResult:
    """Aggregate channel verdict for one caller-contract hypothesis.

    ``enumeration`` / ``enumeration_complete`` / ``enumeration_notes``
    describe how the caller list was produced and whether it was
    verified complete (uncapped tree scan, no address-taken escape of
    the callee).  A ``refuted`` outcome with ``enumeration_complete``
    False is a hint over a possibly-partial caller list — consumers
    that demote on refutation must require completeness.
    """

    outcome: str       # confirmed | refuted | inconclusive
    reason: str
    contract: str = ""
    sites: list[CallSiteCheck] = field(default_factory=list)
    rule_id: str = RULE_ID
    enumeration: str = ""            # "call-graph" | "tree-scan" | ""
    enumeration_complete: bool = False
    enumeration_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "reason": self.reason,
            "contract": self.contract,
            "rule_id": self.rule_id,
            "sites": [s.to_dict() for s in self.sites],
            "enumeration": self.enumeration,
            "enumeration_complete": self.enumeration_complete,
            "enumeration_notes": list(self.enumeration_notes),
        }


def is_caller_contract_hypothesis(text: str) -> bool:
    """True when the hypothesis asserts an obligation at the public-API
    / caller boundary rather than a defect inside the function body."""
    return bool(text) and bool(_CALLER_CONTRACT_RE.search(text))


def is_single_call_hypothesis(text: str) -> bool:
    """True when the hypothesis asserts a single-call contract on the
    callers ("double free if a caller invokes it twice", "must be
    called exactly once").  Declarative in-body double-call claims do
    not match — see ``_SINGLE_CALL_RE``."""
    return bool(text) and bool(_SINGLE_CALL_RE.search(text))


def is_caller_conditional_hypothesis(text: str) -> bool:
    """True when the hypothesis conditions on caller behaviour — the
    union of the contract-shape, single-call, and caller-conditional
    phrasing classifiers.  Gates the widened CWE dispatch and the
    post-review demotion gate's candidate selection."""
    return bool(text) and bool(
        _CALLER_CONTRACT_RE.search(text)
        or _SINGLE_CALL_RE.search(text)
        or _CALLER_CONDITIONAL_RE.search(text)
    )


# CWE families dispatched to this channel from the CWE fallback chain
# (orchestrator._cwe_fallback_chain), independent of hypothesis shape.
# CWE-345 (insufficient verification of data authenticity) is
# caller-obligation shaped: "the consumer must verify origin /
# signature / integrity before passing the data in" is exactly the
# asserted-obligation-at-call-sites question this channel answers.
API_BOUNDARY_CWES = frozenset({"CWE-345"})

# CWE families dispatched only when the hypothesis is itself
# caller-conditional: double free / use-after-free / NULL dereference
# claims are usually in-body defects (which belong to the SMT/cocci/
# flow chains), but the "dangerous-if-misused" variants — "double
# free if a caller invokes this twice", "NULL deref when called
# before init" — are caller obligations this channel adjudicates.
CALLER_CONDITIONAL_CWES = frozenset({"CWE-415", "CWE-416", "CWE-476"})


def api_boundary_applicable(cwe: str, hypothesis: str = "") -> bool:
    """True when the CWE belongs to the boundary-obligation family.

    CWE-345 dispatches unconditionally; the caller-conditional
    families (CWE-415/416/476) dispatch only when the hypothesis
    phrasing conditions on caller behaviour.
    """
    norm = (cwe or "").upper().strip()
    if norm and not norm.startswith("CWE-"):
        norm = f"CWE-{norm}"
    if norm in API_BOUNDARY_CWES:
        return True
    if norm in CALLER_CONDITIONAL_CWES:
        return is_caller_conditional_hypothesis(hypothesis)
    return False


# ── contract extraction ─────────────────────────────────────────────


def parse_param_names(defining_source: str, function_name: str) -> list[str]:
    """Parameter names of ``function_name``'s definition, in order.
    Empty list when the definition cannot be found/parsed."""
    pattern = re.compile(rf"\b{re.escape(function_name)}\s*\(")
    pos = 0
    while True:
        m = pattern.search(defining_source, pos)
        if not m:
            return []
        params_text, end = _balanced_span(defining_source, m.end() - 1)
        if params_text is None:
            # Unbalanced within the span bound (e.g. a planted
            # over-long argument list at a CALL of the name before
            # the definition) — skip this match and keep looking for
            # the real definition instead of going blind.  A
            # definition whose own parameter list overflows the span
            # binds nothing and the check abstains downstream.
            pos = m.end()
            continue
        # A definition is followed by `{` (possibly after a newline);
        # declarations end in `;`, call sites in anything else.
        if defining_source[end:end + 200].lstrip().startswith("{"):
            return _param_names_from_list(params_text)
        pos = end


def _balanced_span(text: str, open_pos: int) -> tuple[str | None, int]:
    """Return (inner_text, index_after_close) for the paren opening at
    ``open_pos``; (None, open_pos) when unbalanced within bounds."""
    depth = 0
    for i in range(open_pos, min(len(text), open_pos + 4000)):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_pos + 1:i], i + 1
    return None, open_pos


def _split_top_level(args_text: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in args_text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _param_names_from_list(params_text: str) -> list[str]:
    names: list[str] = []
    for param in _split_top_level(params_text):
        param = param.strip()
        if not param or param in ("void", "..."):
            continue
        # Drop array suffixes / function-pointer noise, keep the last
        # identifier as the name.
        param = re.sub(r"\[[^\]]*\]", "", param)
        idents = re.findall(_IDENT, param)
        if idents:
            names.append(idents[-1])
    return names


def extract_contract(
    hypothesis: str, param_names: list[str],
) -> Contract | None:
    """Bind the asserted obligation to a callee parameter.

    Recognised shapes (per observed field hypotheses): NULL-parameter
    contracts ("NULL host", "host == NULL", "passes a NULL host"),
    negative-value contracts ("negative outl", "outl < 0"), and
    single-call contracts ("double free if a caller invokes it
    twice") bound to the parameter the hypothesis names — or to the
    sole parameter; multi-parameter callees with no named parameter
    decline to bind rather than guess.  Kernel / peer / OS
    obligations return the explicit external contract."""
    if not hypothesis:
        return None
    if _EXTERNAL_ENV_RE.search(hypothesis) and not any(
        re.search(rf"\bNULL\s+{re.escape(p)}\b|negative\s+`?{re.escape(p)}`?",
                  hypothesis, re.IGNORECASE)
        for p in param_names
    ):
        return Contract(kind="external")

    for idx, param in enumerate(param_names):
        p = re.escape(param)
        if re.search(
            rf"(?:\bNULL\s+`?{p}`?\b|`?{p}`?\s*(?:==|=|is|being)\s*NULL"
            rf"|NULL\s+(?:for|as)\s+`?{p}`?\b)",
            hypothesis, re.IGNORECASE,
        ):
            return Contract(kind="null", param=param, param_index=idx)
        if re.search(
            rf"(?:negative\s+`?{p}`?\b|`?{p}`?\s*<\s*0"
            rf"|`?{p}`?\s+(?:is|goes|becomes)\s+negative)",
            hypothesis, re.IGNORECASE,
        ):
            return Contract(kind="negative", param=param, param_index=idx)

    if _SINGLE_CALL_RE.search(hypothesis):
        named = [
            p for p in param_names
            if re.search(rf"(?<![\w.>]){re.escape(p)}\b", hypothesis)
        ]
        if named:
            return Contract(
                kind="single_call", param=named[0],
                param_index=param_names.index(named[0]),
            )
        if len(param_names) == 1:
            return Contract(
                kind="single_call", param=param_names[0], param_index=0,
            )
    return None


# ── call-site enumeration ───────────────────────────────────────────

_SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx")
_MAX_SCAN_FILES = 4000
_MAX_FILE_BYTES = 2_000_000
_GUARD_WINDOW_LINES = 14
#: Fallback post-call window when the enclosing definition's extent
#: cannot be inferred (receipts from it grade lexical, never refute).
_AFTER_WINDOW_LINES = 14
#: Brace-matching bound when inferring a definition's extent.
_MAX_EXTENT_LINES = 2000
#: Char cap on stored per-site regions (pre-call and post-call) and
#: per-line render slices.  Truncated regions are flagged; a truncated
#: region can neither refute nor confirm.
_MAX_REGION_CHARS = 20_000
_MAX_WINDOW_LINE_CHARS = 2000
#: Total call sites the enumerator materializes before capping (site
#: analysis is O(region) per site — unbounded site counts on hostile
#: or generated files must not stall the review loop).  A capped
#: enumeration can still confirm on the sites it found but is never
#: complete (cannot refute-and-demote).
_MAX_SITES_ENUMERATED = 40
#: Call-shaped matches examined per file before giving up (a hostile
#: file can contain tens of thousands of prototype-shaped matches
#: that never become sites but each cost a balanced-span scan).
_MAX_MATCHES_EXAMINED = 2000


def _line_depths(view_lines: list[str]) -> tuple[list[int], bool]:
    """Absolute brace depth BEFORE each line (file scope = 0), plus a
    final entry for end-of-file, plus an anomaly flag.  Computed on
    the sanitized view, so braces in comments/strings do not skew the
    count.  ``anomaly`` is True when the balance ever goes negative or
    does not return to 0 at end of file (unbalanced braces under
    preprocessor conditionals, hostile skew): extent inference is then
    untrustworthy in BOTH directions and no structural region receipts
    may be issued for the file."""
    depths = [0] * (len(view_lines) + 1)
    d = 0
    anomaly = False
    for i, ln in enumerate(view_lines):
        depths[i] = d
        if d < 0:
            anomaly = True
        d += ln.count("{") - ln.count("}")
    depths[len(view_lines)] = d
    if d != 0 or min(depths) < 0:
        anomaly = True
    return depths, anomaly


def _definition_extents(
    view_lines: list[str],
    depths: list[int],
) -> list[tuple[int, int]]:
    """Top-level definition extents ``[(start_idx, end_idx)]``
    (0-based, inclusive), one forward pass over the file.

    A candidate start is a column-0 code line at absolute brace depth
    0 (a definition can only start at file scope — an
    attacker-formatted column-0 ``{`` inside a function body sits at
    depth >= 1 and is skipped).  The candidate becomes an extent only
    when a body brace opens before a file-scope ``;`` terminates it,
    the brace match closes within bounds, and the absolute depth
    returns to 0 after the close."""
    extents: list[tuple[int, int]] = []
    n = len(view_lines)
    i = 0
    while i < n:
        if depths[i] != 0 or not re.match(r"[A-Za-z_{]", view_lines[i] or ""):
            i += 1
            continue
        end_idx = None
        depth = 0
        opened = False
        aborted = False
        for j in range(i, min(n, i + _MAX_EXTENT_LINES)):
            for ch in view_lines[j]:
                if ch == "{":
                    depth += 1
                    opened = True
                elif ch == "}":
                    depth -= 1
                    if opened and depth <= 0:
                        end_idx = j
                        break
                elif ch == ";" and not opened:
                    aborted = True  # file-scope declaration/statement
                    break
            if end_idx is not None or aborted:
                break
        if end_idx is not None and (
            end_idx + 1 < len(depths) and depths[end_idx + 1] == 0
        ):
            extents.append((i, end_idx))
            i = end_idx + 1
        else:
            i += 1
    return extents


def _capped_join(head: str, lines: list[str]) -> tuple[str, bool]:
    """Join ``head`` + ``lines`` up to the region char cap.  Returns
    (text, truncated) — truncated regions can neither refute nor
    confirm, so consumers must check the flag."""
    truncated = False
    if len(head) > _MAX_REGION_CHARS:
        head = head[:_MAX_REGION_CHARS]
        truncated = True
    parts = [head] if head else []
    total = len(head)
    for ln in lines:
        if total >= _MAX_REGION_CHARS:
            truncated = True
            break
        if len(ln) > _MAX_REGION_CHARS:
            ln = ln[:_MAX_REGION_CHARS]
            truncated = True
        parts.append(ln)
        total += len(ln) + 1
    return "\n".join(parts).strip("\n"), truncated


def _site_regions(
    view_lines: list[str],
    extents: list[tuple[int, int]],
    extent_starts: list[int],
    anomaly: bool,
    line_no: int,
    tail: str,
    prefix: str,
) -> dict[str, Any]:
    """Pre-call and post-call regions for one call site.

    When the enclosing definition's extent is known (no brace-balance
    anomaly, extent contains the call): ``after_window`` covers
    through the extent end, ``before_body`` covers from the extent
    head (definition line, parameter list) through the text just
    before the call, and ``after_complete`` is True unless a region
    hit the char cap.  Otherwise ``after_window`` falls back to a
    bounded window, ``before_body`` is empty, and receipts grade
    lexical (hint, never refute)."""
    call_idx = line_no - 1
    extent = None
    if not anomaly and extents and 0 <= call_idx < len(view_lines):
        k = bisect.bisect_right(extent_starts, call_idx) - 1
        if k >= 0 and extents[k][0] <= call_idx <= extents[k][1]:
            extent = extents[k]
    if extent is not None:
        after, a_tr = _capped_join(
            tail, view_lines[call_idx + 1:extent[1] + 1],
        )
        pre_lines = view_lines[extent[0]:call_idx]
        pre_len = sum(len(ln) + 1 for ln in pre_lines) + len(prefix)
        if pre_len > _MAX_REGION_CHARS:
            # Oversized pre-call body: never materialize it — flag it
            # so the single-call checks decline (an alias created in
            # the invisible part must not be missed silently).
            before, b_tr = "", True
        else:
            before = "\n".join(pre_lines)
            if prefix:
                before = f"{before}\n{prefix}" if before else prefix
            b_tr = False
        return {
            "after_window": after,
            "after_truncated": a_tr,
            "after_complete": not a_tr,
            "before_body": before,
            "before_truncated": b_tr,
        }
    after, a_tr = _capped_join(
        tail, view_lines[call_idx + 1:call_idx + 1 + _AFTER_WINDOW_LINES],
    )
    return {
        "after_window": after,
        "after_truncated": a_tr,
        "after_complete": False,
        "before_body": "",
        "before_truncated": False,
    }


def _caller_files_from_inventory(
    inventory: dict[str, Any] | None,
    file_path: str,
    function_name: str,
) -> list[dict[str, Any]] | None:
    """1-hop callers via the inventory call graph, or None when the
    graph cannot answer (missing inventory / resolver error)."""
    if not inventory:
        return None
    try:
        from core.analysis.reachability import InternalFunction, callers_of

        target = InternalFunction(
            file_path=file_path, name=function_name, line=0,
        )
        result = callers_of(inventory, target, exclude_test_files=True)
        return [
            {"file": c.file_path, "name": c.name, "line": c.line}
            for c in result.all_callers
        ]
    except Exception:
        logger.debug(
            "api_boundary: callers_of failed for %s:%s",
            file_path, function_name, exc_info=True,
        )
        return None


# Statement keywords that precede *calls*, never declarations — the
# type-prefix filter must not swallow `return f(...)` / `case f(...)`.
_STMT_KEYWORDS = (
    r"return|goto|case|else|do|sizeof|switch|while|if|for|break|"
    r"continue|typedef"
)


def _looks_like_decl_or_def(line: str, function_name: str) -> bool:
    """Filter out prototypes/definitions when scanning for call sites."""
    return bool(re.match(
        rf"\s*(?:static\s+|extern\s+|inline\s+|const\s+)*"
        rf"(?!(?:{_STMT_KEYWORDS})\b)"
        rf"(?:{_IDENT}[\w\s\*]*[\s\*])\s*{re.escape(function_name)}\s*\(",
        line,
    )) or bool(re.match(rf"\s*#\s*define\s+{re.escape(function_name)}\b", line))


def _scan_file_for_calls(
    path: Path,
    rel: str,
    function_name: str,
    *,
    skip_span: tuple[int, int] | None = None,
    max_sites: int = _MAX_SITES_ENUMERATED,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Call sites of ``function_name`` in one file, plus a per-file
    report.

    Returns ``(sites, file_report)`` where sites are
    ``{file, line, code, args, window, after_window, after_complete,
    after_truncated, before_body, before_truncated}`` dicts and the
    report carries the honesty facts consumers must not lose:
    ``size_skipped`` (file over the byte cap — a caller may hide in
    it), ``site_capped`` (site or match budget exhausted),
    ``span_capped`` (a call-shaped match whose argument list stayed
    unbalanced within the span bound was dropped — a real call site
    may be hidden behind an over-long argument list),
    ``definitions`` (lines holding a DEFINITION of the name — used
    for cross-TU ambiguity detection), and ``alias_attr`` (an
    ``alias("name")`` attribute in the raw text — an indirect entry
    the sanitized view hides inside a string literal)."""
    freport: dict[str, Any] = {
        "size_skipped": False,
        "site_capped": False,
        "span_capped": False,
        "definitions": [],
        "alias_attr": False,
    }
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            freport["size_skipped"] = True
            return [], freport
        text = path.read_text(errors="replace")
    except OSError:
        return [], freport
    if function_name not in text:
        return [], freport
    # ``alias("name")`` attributes put the target name inside a string
    # literal, which the sanitized view blanks — detect on raw text.
    if re.search(
        rf'\balias\s*\(\s*"\s*{re.escape(function_name)}\s*"', text,
    ):
        freport["alias_attr"] = True
    # Matching, argument extraction and the guard window all run on
    # the sanitized view (comments/string literals blanked, offsets
    # preserved): a comment mentioning the callee is not a call site,
    # and comment text in the window must not read as a guard. Raw
    # lines feed only the human-facing ``code`` receipt field.
    from .source_view import sanitized_view
    view = sanitized_view(text, str(path))
    sites: list[dict[str, Any]] = []
    lines = text.splitlines()
    view_lines = view.splitlines()
    call_re = re.compile(rf"(?<![\w.>]){re.escape(function_name)}\s*\(")
    offset = 0
    line_starts: list[int] = []
    for ln in view_lines:
        line_starts.append(offset)
        offset += len(ln) + 1
    depths: list[int] | None = None
    anomaly = False
    extents: list[tuple[int, int]] = []
    extent_starts: list[int] = []
    examined = 0
    for m in call_re.finditer(view):
        examined += 1
        if examined > _MAX_MATCHES_EXAMINED or len(sites) >= max_sites:
            freport["site_capped"] = True
            break
        # Line number via binary search over line starts.
        line_no = bisect.bisect_right(line_starts, m.start())
        line_text = view_lines[line_no - 1]
        open_pos = view.index("(", m.start())
        args_text, _end = _balanced_span(view, open_pos)
        in_skip = bool(
            skip_span and skip_span[0] <= line_no <= skip_span[1],
        )
        # A body brace directly after the balanced paren marks a
        # DEFINITION — a call expression is never followed by `{`.
        # This catches K&R-style heads (return type on the previous
        # line) that escape the type-prefix filter, and feeds the
        # cross-TU ambiguity check: a same-name definition elsewhere
        # means these textual sites cannot be attributed to the
        # reviewed function.
        is_def_head = (
            args_text is not None
            and view[_end:_end + 200].lstrip().startswith("{")
        )
        if is_def_head:
            if not in_skip:
                freport["definitions"].append(line_no)
            continue
        if in_skip or _looks_like_decl_or_def(line_text, function_name):
            continue
        if args_text is None:
            # A call-shaped match whose argument list stays
            # unbalanced within the span bound cannot be parsed into
            # a site — but it may BE a real call site (one over-long
            # argument list is trivially plantable).  Dropping it
            # silently would let a partial site list pass for the
            # whole caller set; record the honesty event so
            # completeness claims and the caller-lock witness refuse.
            freport["span_capped"] = True
            continue
        window_start = max(0, line_no - 1 - _GUARD_WINDOW_LINES)
        window = "\n".join(
            ln[:_MAX_WINDOW_LINE_CHARS]
            for ln in view_lines[window_start:line_no - 1]
        )
        # Pre/post-call regions for reuse/re-pass/alias checks
        # (single-call contracts).  Extents are computed once per
        # file; regions are char-capped and flag truncation.
        if depths is None:
            depths, anomaly = _line_depths(view_lines)
            if not anomaly:
                extents = _definition_extents(view_lines, depths)
                extent_starts = [s for s, _ in extents]
        end_line_no = bisect.bisect_right(line_starts, max(_end - 1, 0))
        tail = ""
        if 1 <= end_line_no <= len(view_lines):
            tail_start = _end - line_starts[end_line_no - 1]
            tail = view_lines[end_line_no - 1][
                tail_start:tail_start + _MAX_REGION_CHARS
            ]
        col = m.start() - line_starts[line_no - 1]
        prefix = line_text[max(0, col - _MAX_WINDOW_LINE_CHARS):col]
        regions = _site_regions(
            view_lines, extents, extent_starts, anomaly,
            end_line_no, tail, prefix,
        )
        site: dict[str, Any] = {
            "file": rel,
            "line": line_no,
            "code": (lines[line_no - 1].strip()[:_MAX_WINDOW_LINE_CHARS]
                     if line_no <= len(lines)
                     else line_text.strip()[:_MAX_WINDOW_LINE_CHARS]),
            "args": _split_top_level(args_text),
            "window": window,
        }
        site.update(regions)
        sites.append(site)
    return sites, freport


def enumerate_call_sites_with_report(
    target_path: Path,
    function_name: str,
    *,
    def_file: str = "",
    def_span: tuple[int, int] | None = None,
    inventory: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """In-repo call sites of ``function_name``, plus how they were found.

    Prefers the inventory call graph to pick candidate files, falling
    back to a bounded scan of the tree. The defining span is excluded.

    The report describes the path that actually produced the sites —
    ``method`` is "call-graph" only when the graph both answered and
    yielded sites, "tree-scan" whenever the fallback ran (including a
    present-but-unresolving inventory) — plus the honesty facts a
    consumer needs before treating the list as exhaustive:
    ``scan_capped`` / ``scanned_files`` (bounded file walk),
    ``site_capped`` (per-run site/match budget hit), ``span_capped``
    (a call-shaped match dropped because its argument list stayed
    unbalanced within the span bound — a call site may be hidden),
    ``size_skipped`` (files over the byte cap that may hide callers),
    ``extra_definitions`` (same-name definitions OUTSIDE the reviewed
    definition's file — textual sites cannot be attributed to the
    reviewed function), and ``alias_attrs`` (``alias("name")``
    attributes — indirect entry points the sanitized view hides).
    """
    target_path = Path(target_path)
    report: dict[str, Any] = {
        "method": "tree-scan",
        "scan_capped": False,
        "scanned_files": 0,
        "site_capped": False,
        "span_capped": False,
        "size_skipped": 0,
        "extra_definitions": [],
        "alias_attrs": [],
    }

    def _fold(rel: str, freport: dict[str, Any]) -> None:
        if freport.get("size_skipped"):
            report["size_skipped"] += 1
        if freport.get("site_capped"):
            report["site_capped"] = True
        if freport.get("span_capped"):
            report["span_capped"] = True
        if freport.get("alias_attr"):
            report["alias_attrs"].append(rel)
        if rel != def_file:
            for ln in freport.get("definitions", []):
                report["extra_definitions"].append(f"{rel}:{ln}")

    callers = _caller_files_from_inventory(
        inventory, def_file, function_name,
    )
    sites: list[dict[str, Any]] = []
    if callers:
        seen_files: set[str] = set()
        for caller in callers:
            rel = caller.get("file", "")
            if not rel or rel in seen_files:
                continue
            seen_files.add(rel)
            path = target_path / rel
            skip = def_span if rel == def_file else None
            budget = _MAX_SITES_ENUMERATED - len(sites)
            if budget <= 0:
                report["site_capped"] = True
                break
            found, freport = _scan_file_for_calls(
                path, rel, function_name,
                skip_span=skip, max_sites=budget,
            )
            _fold(rel, freport)
            for site in found:
                site["caller"] = caller.get("name", "")
                sites.append(site)
        if sites:
            report["method"] = "call-graph"
            return sites, report

    # Fallback: bounded tree scan.
    scanned = 0
    for path in sorted(target_path.rglob("*")):
        if scanned >= _MAX_SCAN_FILES:
            report["scan_capped"] = True
            break
        if not path.is_file() or path.suffix.lower() not in _SOURCE_SUFFIXES:
            continue
        scanned += 1
        try:
            rel = str(path.relative_to(target_path))
        except ValueError:
            continue
        skip = def_span if rel == def_file else None
        budget = _MAX_SITES_ENUMERATED - len(sites)
        if budget <= 0:
            report["site_capped"] = True
            break
        found, freport = _scan_file_for_calls(
            path, rel, function_name, skip_span=skip, max_sites=budget,
        )
        _fold(rel, freport)
        sites.extend(found)
    report["scanned_files"] = scanned
    return sites, report


# ── per-site guard analysis ─────────────────────────────────────────


def _base_identifier(arg: str) -> str:
    """Reduce an argument expression to its base identifier."""
    arg = _CAST_RE.sub("", arg).strip()
    arg = arg.lstrip("&*(").strip()
    m = re.match(rf"({_IDENT})", arg)
    return m.group(1) if m else ""


def _check_site(
    contract: Contract,
    site: dict[str, Any],
    callee: str = "",
) -> CallSiteCheck:
    args = site.get("args") or []
    check = CallSiteCheck(
        file=site.get("file", ""),
        caller=site.get("caller", ""),
        line=site.get("line", 0),
        code=site.get("code", ""),
        verdict="undecided",
    )
    if contract.param_index >= len(args):
        check.evidence = (
            f"call passes {len(args)} argument(s); parameter "
            f"#{contract.param_index + 1} not present"
        )
        return check
    arg = args[contract.param_index].strip()
    check.argument = arg
    stripped = _CAST_RE.sub("", arg).strip()
    base = _base_identifier(arg)
    window = site.get("window", "")

    if contract.kind == "null":
        if re.fullmatch(r"(?:NULL|nullptr|0)", stripped):
            check.verdict = "unguarded"
            check.evidence = (
                "literal NULL passed where the contract forbids it"
            )
            return check
        if stripped.startswith(("&", '"')):
            check.verdict = "guarded"
            check.evidence = (
                "address-of / string-literal argument cannot be NULL"
            )
            return check
        if base:
            guard = re.search(
                rf"(?:if|while)\s*\([^)]*(?:!\s*{re.escape(base)}\b"
                rf"|{re.escape(base)}\s*[!=]=\s*NULL"
                rf"|NULL\s*[!=]=\s*{re.escape(base)}\b"
                rf"|\b{re.escape(base)}\b\s*(?:&&|\)))",
                window,
            )
            if guard:
                check.verdict = "guarded"
                check.grade = "lexical"
                check.evidence = (
                    f"NULL check in the window (lexical — no "
                    f"dominance proof): {guard.group(0).strip()}"
                )
                return check
        check.evidence = "no structural NULL guard found in the window"
        return check

    if contract.kind == "negative":
        if re.fullmatch(r"\d+[uUlL]*", stripped):
            check.verdict = "guarded"
            check.evidence = "non-negative integer literal"
            return check
        if re.fullmatch(r"-\s*\d+[uUlL]*", stripped):
            check.verdict = "unguarded"
            check.evidence = (
                "negative literal passed where the contract forbids it"
            )
            return check
        if _UNSIGNED_VALUED_RE.search(arg) or re.search(
            r"\(\s*(?:unsigned|size_t|uint\d+_t)\b", arg,
        ):
            check.verdict = "guarded"
            check.evidence = "unsigned-valued argument"
            return check
        if base:
            guard = re.search(
                rf"(?:if|while)\s*\([^)]*{re.escape(base)}\s*"
                rf"(?:<\s*0|<=\s*0|>=\s*0|>\s*0)",
                window,
            )
            if guard:
                check.verdict = "guarded"
                check.grade = "lexical"
                check.evidence = (
                    f"sign check in the window (lexical — no "
                    f"dominance proof): {guard.group(0).strip()}"
                )
                return check
        check.evidence = "no structural sign guard found in the window"
        return check

    if contract.kind == "single_call":
        return _check_single_call_site(site, check, base, callee, arg)

    if contract.kind == "bounded":
        # A bounded contract carries no concrete numeric bound (the
        # receipt that asserted it does not carry one across the
        # promotion boundary), so a pinned integer literal is
        # decidable in NEITHER direction: it cannot be judged
        # violating (no bound to exceed) and it must not be graded
        # upholding (the pinned value may itself exceed the bound the
        # flagged arithmetic assumes).  Literals stay "undecided"
        # with a constant-specific receipt, and the kind never
        # returns "unguarded" — the aggregate can refute
        # (sizeof-bounded sites) or decline, never confirm.
        if re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|\d+)[uUlL]*", stripped):
            check.evidence = (
                f"operand {BOUNDED_CONST_EVIDENCE_MARKER} {stripped} "
                "— no numeric bound available to adjudicate"
            )
            return check
        # Tested on the raw argument: the cast-stripper reads a
        # parenthesised type operand ("sizeof(int)") as a cast.
        if re.match(r"sizeof\s*\(", arg):
            check.verdict = "guarded"
            check.evidence = (
                "sizeof-valued argument — bounded by an in-repo "
                "object/type size"
            )
            return check
        if base:
            guard = re.search(
                rf"(?:if|while|assert\w*|BUG_ON|ASSERT|CHECK)\s*\("
                rf"[^;)]*\b{re.escape(base)}\b\s*(?:<=?|>=?|==)",
                window,
            )
            if guard:
                check.verdict = "guarded"
                check.grade = "lexical"
                check.evidence = (
                    f"range check in the window (lexical — no "
                    f"dominance proof): {guard.group(0).strip()}"
                )
                return check
        check.evidence = (
            "argument not provably bounded (no sizeof, no range "
            "check in the window)"
        )
        return check

    check.evidence = f"unsupported contract kind {contract.kind!r}"
    return check


# Anything that breaks straight-line reasoning between the call and a
# later occurrence of the argument: braces, ternaries, control-flow
# keywords, preprocessor lines.  A re-pass or reassignment separated
# from the call by any of these may sit on a different path — never
# decide structurally across it.
_BRANCH_TOKEN_RE = re.compile(
    r"[{}?#]|\b(?:if|else|switch|case|while|for|goto|return|break|"
    r"continue|do)\b",
)

# An intervening call between the original call and a re-pass: the
# callee may not return (exit/abort/longjmp) or may change the
# argument's state — a "literal double invocation" separated by
# another call is not literal.
_INTERVENING_CALL_RE = re.compile(r"[A-Za-z_]\w*\s*\(")

# A type-shaped token directly preceding an identifier: parameter or
# local declaration.  Deliberately keyword/`_t`/pointer-star based —
# generic `word ident` would misread expressions.
_DECL_TYPE_TOKENS = (
    r"struct|union|enum|const|unsigned|signed|register|volatile|"
    r"static|auto|char|short|int|long|float|double|void|size_t|"
    r"ssize_t|[A-Za-z_]\w*_t"
)


def _declared_locally(before_body: str, base: str) -> bool:
    """True when ``base`` is visibly a parameter or local of the
    enclosing definition (its declaration appears in the pre-call
    body, which includes the definition head).  A base with no
    visible declaration may be a global or file-static — freed from
    multiple callers in sequence, which no per-caller analysis can
    order — so refutation must decline."""
    b = re.escape(base)
    # A type token must precede the identifier: a bare-star
    # alternative made the deref-store `*g = x;` (assignment THROUGH
    # g, not a declaration OF g) read as a local declaration and
    # weakened this decline-to-refute rule. Pointer declarators are
    # already covered by the type branch (`char *p`, `int a, *p` —
    # the `[\s*]` tail matches the star).
    return bool(re.search(
        rf"\b(?:{_DECL_TYPE_TOKENS})\b[^;(){{}}=]*[\s*]"
        rf"{b}\s*[=;,)\[]",
        before_body,
    ))


def _single_call_precall_risk(
    site: dict[str, Any], base: str,
) -> str | None:
    """Pre-call conditions that forbid a guarded (refuting) receipt
    for a single-call contract, or None when none apply.

    * loop/goto: the call itself may execute more than once — a
      clean post-call region proves nothing;
    * pre-call aliasing (address-of, assignment to another lvalue):
      the resource stays reachable through names the post-call scan
      does not track;
    * no visible local/parameter declaration: the argument may be a
      global freed from multiple callers — cross-caller ordering is
      not per-site decidable;
    * truncated pre-call region: any of the above may hide in the
      invisible part.
    """
    before = site.get("before_body", "") or ""
    if site.get("before_truncated"):
        return (
            "pre-call region too large to adjudicate structurally"
        )
    after = site.get("after_window", "") or ""
    if re.search(r"\bgoto\b", before) or re.search(r"\bgoto\b", after):
        return (
            "goto in the enclosing definition — the call may execute "
            "more than once"
        )
    if re.search(r"\b(?:for|while|do)\b", before):
        return (
            "loop construct before the call — the call may execute "
            "more than once"
        )
    b = re.escape(base)
    if re.search(rf"&\s*{b}\b", before):
        return (
            f"address of {base} taken before the call — aliases may "
            "exist"
        )
    if re.search(rf"(?<![=!<>])=(?!=)[^;\n]*?(?<![\w.>&]){b}\b", before):
        return (
            f"{base} assigned to another lvalue before the call — "
            "aliases may exist"
        )
    if not _declared_locally(before, base):
        return (
            f"{base} is not provably local to the caller (no "
            "parameter/local declaration found) — cross-caller "
            "call ordering is not decidable per site"
        )
    return None


def _check_single_call_site(
    site: dict[str, Any],
    check: CallSiteCheck,
    base: str,
    callee: str,
    arg: str,
) -> CallSiteCheck:
    """Adjudicate a single-call contract at one call site.

    Confirm lane (a literal double invocation): the FULL argument
    expression — not just its base identifier — must be re-passed to
    the same callee, straight-line from the original call (no branch
    tokens, no intervening call that could not return).  Freeing two
    different fields (``f(s->a); f(s->b);``) or re-passing across an
    intervening call never confirms.

    Refute lane (guarded receipts): the argument's base identifier is
    never referenced again through the end of the enclosing
    definition (or is immediately reassigned, straight-line), AND the
    pre-call analysis finds no loop/goto, no pre-call alias of the
    argument, and a visible local/parameter declaration — otherwise
    the site stays undecided.  Window-bounded or truncated regions
    grade lexical / undecided and can never refute.
    """
    if not base:
        check.evidence = (
            "argument is not a simple identifier — post-call reuse "
            "cannot be traced structurally"
        )
        return check
    after = site.get("after_window", "") or ""
    complete = bool(site.get("after_complete"))

    # Confirm lane: exact-argument re-pass to the same callee.  Runs
    # on the visible (possibly truncated) prefix — a straight-line
    # re-pass found before any truncation point is real.
    arg_norm = re.sub(r"\s+", "", arg)
    if callee and arg_norm:
        for rm in re.finditer(
            rf"(?<![\w.>]){re.escape(callee)}\s*\(", after,
        ):
            op = after.index("(", rm.start())
            inner, _e = _balanced_span(after, op)
            if inner is None:
                continue
            re_args = [
                re.sub(r"\s+", "", a) for a in _split_top_level(inner)
            ]
            if arg_norm not in re_args:
                continue
            between = after[:rm.start()]
            if not _BRANCH_TOKEN_RE.search(between) and not (
                _INTERVENING_CALL_RE.search(between)
            ):
                check.verdict = "unguarded"
                check.evidence = (
                    f"{arg} re-passed to {callee} directly after the "
                    "call with no intervening statement — literal "
                    "double invocation"
                )
                return check
            check.evidence = (
                f"{arg} re-passed to {callee} later in the caller on "
                "a separated path — cannot decide structurally"
            )
            return check

    if site.get("after_truncated"):
        check.evidence = (
            "post-call region too large to adjudicate structurally"
        )
        return check

    occ = re.search(rf"(?<![\w.>]){re.escape(base)}\b", after)
    if occ is None:
        risk = _single_call_precall_risk(site, base) if complete else None
        if risk:
            check.evidence = risk
            return check
        check.verdict = "guarded"
        if complete:
            check.evidence = (
                f"{base} is not referenced again between the call and "
                "the end of the enclosing definition (last use), and "
                "the pre-call body shows no loop, alias, or "
                "non-local scope"
            )
        else:
            check.grade = "lexical"
            check.evidence = (
                f"no reuse of {base} within the "
                f"{_AFTER_WINDOW_LINES}-line post-call window "
                "(window-bounded — no extent proof)"
            )
        return check

    between = after[:occ.start()]
    if _BRANCH_TOKEN_RE.search(between):
        check.evidence = (
            f"{base} is referenced again after the call on a branched "
            "path — cannot decide structurally"
        )
        return check

    pre = between.rstrip()
    if pre.endswith(("*", "&")):
        check.evidence = (
            f"{base} is dereferenced or aliased after the call"
        )
        return check
    if pre.endswith(("(", ",")):
        check.evidence = (
            f"{base} passed to another function after the call"
        )
        return check
    occ_tail = after[occ.end():]
    assign = re.match(r"\s*=(?!=)\s*([^;,\n]*)", occ_tail)
    if assign:
        risk = _single_call_precall_risk(site, base) if complete else None
        if risk:
            check.evidence = risk
            return check
        rhs = assign.group(1).strip()
        check.verdict = "guarded"
        if not complete:
            check.grade = "lexical"
        if re.fullmatch(r"(?:NULL|nullptr|0)", rhs):
            check.evidence = (
                f"{base} nulled immediately after the call "
                f"({base} = {rhs})"
            )
        else:
            check.evidence = (
                f"{base} reassigned immediately after the call"
            )
        return check
    check.evidence = f"{base} reused after the call"
    return check


def _is_test_site(rel_path: str) -> bool:
    """The conventional test-file predicate the inventory call-graph
    path applies — reused so test-file call sites can be set aside.
    Tests exercise contracts deliberately (idempotence tests
    double-call teardown helpers on purpose; NULL-robustness tests
    pass literal NULL) — a "violation" there is not production caller
    evidence and must not confirm, and an upholding test site is not
    production reachability either.  False (keep the site) when the
    predicate is unavailable."""
    try:
        from core.analysis.reachability import _is_test_file

        return _is_test_file(rel_path)
    except Exception:
        return False


# ── enumeration-completeness verification ───────────────────────────

#: Cap on collected address-taken receipt locations.
_MAX_ADDRESS_TAKEN_RECEIPTS = 5


def address_taken_occurrences(
    target_path: Path,
    function_name: str,
    *,
    def_file: str = "",
    def_span: tuple[int, int] | None = None,
) -> tuple[list[str], bool, int]:
    """Locations where ``function_name`` appears WITHOUT a call — a
    function-pointer table entry, ``&fn`` escape, or macro alias.  Any
    hit means indirect callers are possible and a textual call-site
    enumeration cannot be trusted as complete.

    Returns ``(receipts, scan_capped, size_skipped)``: up to
    ``_MAX_ADDRESS_TAKEN_RECEIPTS`` ``file:line`` strings, whether the
    bounded walk hit its file cap, and how many source files were
    skipped for exceeding the byte cap.  A capped walk or any size
    skip means absence of receipts proves nothing.  Runs on the
    sanitized view — comment / string mentions do not count.
    """
    target_path = Path(target_path)
    name_re = re.compile(
        rf"(?<![\w.>]){re.escape(function_name)}\b(?!\s*\()",
    )
    receipts: list[str] = []
    scanned = 0
    capped = False
    size_skipped = 0
    from .source_view import sanitized_view
    for path in sorted(target_path.rglob("*")):
        if scanned >= _MAX_SCAN_FILES:
            capped = True
            break
        if not path.is_file() or path.suffix.lower() not in _SOURCE_SUFFIXES:
            continue
        scanned += 1
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                size_skipped += 1
                continue
            text = path.read_text(errors="replace")
        except OSError:
            continue
        if function_name not in text:
            continue
        try:
            rel = str(path.relative_to(target_path))
        except ValueError:
            continue
        view = sanitized_view(text, str(path))
        for line_no, line in enumerate(view.splitlines(), start=1):
            if (
                def_span
                and rel == def_file
                and def_span[0] <= line_no <= def_span[1]
            ):
                continue
            if name_re.search(line):
                receipts.append(f"{rel}:{line_no}")
                if len(receipts) >= _MAX_ADDRESS_TAKEN_RECEIPTS:
                    return receipts, capped, size_skipped
    return receipts, capped, size_skipped


# ── channel entry point ─────────────────────────────────────────────


def run_api_boundary_check(
    target_path: Path,
    file_path: str,
    function_name: str,
    hypothesis: str,
    *,
    inventory: dict[str, Any] | None = None,
    def_span: tuple[int, int] | None = None,
) -> ApiBoundaryResult:
    """Adjudicate one caller-contract hypothesis at the API boundary.
    See module docstring for verdict semantics."""
    target_path = Path(target_path)
    defining_source = ""
    try:
        p = target_path / file_path
        if p.is_file():
            defining_source = p.read_text(errors="replace")
    except OSError:
        pass

    # Wrong-target defence: a hypothesis that names its
    # invoked-twice/called-again target explicitly must name the
    # reviewed function — adjudicating the reviewed function's callers
    # against a claim about a DIFFERENT callee tests the wrong
    # mechanism.
    named_target = _named_invoke_target(hypothesis)
    if named_target and named_target != function_name:
        return ApiBoundaryResult(
            outcome="inconclusive",
            reason=(
                f"hypothesis names {named_target} as the "
                f"re-invoked callee, not {function_name} — the "
                "reviewed function's call sites cannot adjudicate it"
            ),
        )

    param_names = (
        parse_param_names(defining_source, function_name)
        if defining_source else []
    )
    contract = extract_contract(hypothesis, param_names)
    if contract is None:
        return ApiBoundaryResult(
            outcome="inconclusive",
            reason=(
                "could not bind the asserted obligation to a callee "
                "parameter (supported shapes: NULL-parameter, "
                "negative-value, and single-call contracts)"
            ),
        )
    if contract.kind == "external":
        return ApiBoundaryResult(
            outcome="inconclusive",
            reason=(
                "external contract — the obligation is on the kernel/"
                "peer/OS environment, not on in-repo callers; not "
                "adjudicable from the source tree"
            ),
            contract=contract.describe(),
        )

    return adjudicate_contract(
        target_path,
        file_path,
        function_name,
        contract,
        inventory=inventory,
        def_span=def_span,
    )


def adjudicate_contract(
    target_path: Path,
    file_path: str,
    function_name: str,
    contract: Contract,
    *,
    inventory: dict[str, Any] | None = None,
    def_span: tuple[int, int] | None = None,
) -> ApiBoundaryResult:
    """Adjudicate one already-bound caller obligation at the API
    boundary: enumerate in-repo call sites and grade each against the
    contract.  Shared tail of :func:`run_api_boundary_check` for
    callers that carry a :class:`Contract` directly (e.g. a
    precondition re-derived from a tool receipt) instead of a prose
    hypothesis; verdict and honesty semantics are identical (see
    module docstring)."""
    target_path = Path(target_path)
    sites, report = enumerate_call_sites_with_report(
        target_path,
        function_name,
        def_file=file_path,
        def_span=def_span,
        inventory=inventory,
    )
    method = str(report.get("method", "tree-scan"))
    notes: list[str] = []
    # Cross-TU ambiguity: a same-name definition OUTSIDE the reviewed
    # definition's file (a static in another TU, a same-name macro
    # body) means textual call sites cannot be attributed to the
    # reviewed function — neither a violation nor an upholding site is
    # evidence about it.
    extra_defs = report.get("extra_definitions") or []
    if extra_defs:
        return ApiBoundaryResult(
            outcome="inconclusive",
            reason=(
                f"{len(extra_defs)} additional definition(s) of "
                f"{function_name} in the tree "
                f"({', '.join(extra_defs[:3])}) — textual call sites "
                "cannot be attributed to the reviewed function"
            ),
            contract=contract.describe(),
            enumeration=method,
            enumeration_notes=[
                f"same-name definitions at {', '.join(extra_defs[:5])}"
            ],
        )
    if report.get("scan_capped"):
        notes.append(
            f"tree scan hit its {_MAX_SCAN_FILES}-file cap — "
            "enumeration incomplete"
        )
    if report.get("site_capped"):
        notes.append(
            "call-site budget exhausted before covering the tree — "
            "enumeration incomplete"
        )
    if report.get("span_capped"):
        notes.append(
            f"call-shaped match of {function_name} dropped because "
            "its argument list stayed unbalanced within the span "
            "bound — a call site may be hidden; enumeration "
            "incomplete"
        )
    if report.get("size_skipped"):
        notes.append(
            f"{report['size_skipped']} source file(s) exceeded the "
            "byte cap and were not scanned — callers may hide in "
            "them; enumeration incomplete"
        )
    for rel in report.get("alias_attrs") or []:
        notes.append(
            f"alias(\"{function_name}\") attribute in {rel} — an "
            "indirect entry point exists; enumeration incomplete"
        )
    kept = [s for s in sites if not _is_test_site(s.get("file", ""))]
    if len(kept) != len(sites):
        notes.append(
            f"{len(sites) - len(kept)} test-file call site(s) set "
            "aside (tests exercise contracts deliberately — neither "
            "a violation nor an upholding site there is production "
            "caller evidence)"
        )
        sites = kept
    if not sites:
        return ApiBoundaryResult(
            outcome="inconclusive",
            reason=(
                "external-only callers — no in-repo call sites of "
                f"{function_name}; the caller obligation cannot be "
                "adjudicated from this tree"
            ),
            contract=contract.describe(),
            enumeration=method,
            enumeration_notes=notes,
        )

    checks = [_check_site(contract, s, function_name) for s in sites]
    unguarded = [c for c in checks if c.verdict == "unguarded"]
    undecided = [c for c in checks if c.verdict == "undecided"]
    lexical = [
        c for c in checks
        if c.verdict == "guarded" and c.grade == "lexical"
    ]

    if unguarded:
        first = unguarded[0]
        return ApiBoundaryResult(
            outcome="confirmed",
            reason=(
                f"concrete unguarded call site: {first.file}:"
                f"{first.line} ({first.evidence})"
            ),
            contract=contract.describe(),
            sites=checks,
            enumeration=method,
            enumeration_notes=notes,
        )
    if not undecided:
        if lexical:
            # A window-regex guard hit carries no dominance/branch
            # proof (an if(!p) in a sibling branch that does not
            # dominate the call matches just the same) — a lexical
            # receipt may HINT, never refute.
            return ApiBoundaryResult(
                outcome="inconclusive",
                reason=(
                    f"{len(lexical)} of {len(checks)} guard receipt(s) "
                    "are lexical-grade (window regex, no dominance "
                    "proof) — cannot refute; sites need review"
                ),
                contract=contract.describe(),
                sites=checks,
                enumeration=method,
                enumeration_notes=notes,
            )
        # Refutation: verify enumeration completeness before consumers
        # act on it.  Only an uncapped, un-skipped textual tree scan
        # whose address-taken sweep finds no indirect-call escape
        # earns ``enumeration_complete`` — the call-graph path picks
        # candidate files from inventory edges and can silently miss
        # macro-wrapped or unindexed callers; oversized files and
        # capped budgets can hide violating callers; alias attributes
        # and cross-TU definitions break site attribution.
        complete = False
        if method != "tree-scan":
            notes.append(
                "call-graph-driven enumeration — not verified "
                "exhaustive; refutation is a hint only"
            )
        elif not (
            report.get("scan_capped")
            or report.get("site_capped")
            or report.get("span_capped")
            or report.get("size_skipped")
            or report.get("alias_attrs")
        ):
            taken, taken_capped, taken_skipped = (
                address_taken_occurrences(
                    target_path, function_name,
                    def_file=file_path, def_span=def_span,
                )
            )
            if taken:
                notes.append(
                    f"address of {function_name} taken at "
                    f"{', '.join(taken)} — indirect callers possible; "
                    "enumeration incomplete"
                )
            elif taken_capped or taken_skipped:
                notes.append(
                    "address-taken sweep capped or skipped oversized "
                    "files — enumeration completeness unverified"
                )
            else:
                complete = True
        return ApiBoundaryResult(
            outcome="refuted",
            reason=(
                f"all {len(checks)} in-repo call site(s) honour the "
                "contract (structural guard receipts per site)"
            ),
            contract=contract.describe(),
            sites=checks,
            enumeration=method,
            enumeration_complete=complete,
            enumeration_notes=notes,
        )
    return ApiBoundaryResult(
        outcome="inconclusive",
        reason=(
            f"{len(undecided)} of {len(checks)} call site(s) could "
            "not be structurally decided (no dominating guard found, "
            "argument not provably safe)"
        ),
        contract=contract.describe(),
        sites=checks,
        enumeration=method,
        enumeration_notes=notes,
    )
