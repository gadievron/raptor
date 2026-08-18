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


@dataclass
class Contract:
    """One asserted caller obligation, bound to a callee parameter."""

    kind: str          # "null" | "negative" | "external"
    param: str = ""    # callee parameter name ("" for external)
    param_index: int = -1

    def describe(self) -> str:
        if self.kind == "external":
            return "external-environment contract"
        if self.kind == "null":
            return f"callers must not pass NULL {self.param}"
        return f"callers must not pass negative {self.param}"


@dataclass
class CallSiteCheck:
    """Per-call-site receipt."""

    file: str
    caller: str
    line: int
    code: str
    verdict: str       # guarded | unguarded | undecided
    evidence: str = ""
    argument: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "caller": self.caller,
            "line": self.line,
            "code": self.code,
            "verdict": self.verdict,
            "evidence": self.evidence,
            "argument": self.argument,
        }


@dataclass
class ApiBoundaryResult:
    """Aggregate channel verdict for one caller-contract hypothesis."""

    outcome: str       # confirmed | refuted | inconclusive
    reason: str
    contract: str = ""
    sites: list[CallSiteCheck] = field(default_factory=list)
    rule_id: str = RULE_ID

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "reason": self.reason,
            "contract": self.contract,
            "rule_id": self.rule_id,
            "sites": [s.to_dict() for s in self.sites],
        }


def is_caller_contract_hypothesis(text: str) -> bool:
    """True when the hypothesis asserts an obligation at the public-API
    / caller boundary rather than a defect inside the function body."""
    return bool(text) and bool(_CALLER_CONTRACT_RE.search(text))


# CWE families dispatched to this channel from the CWE fallback chain
# (orchestrator._cwe_fallback_chain), independent of hypothesis shape.
# CWE-345 (insufficient verification of data authenticity) is
# caller-obligation shaped: "the consumer must verify origin /
# signature / integrity before passing the data in" is exactly the
# asserted-obligation-at-call-sites question this channel answers.
API_BOUNDARY_CWES = frozenset({"CWE-345"})


def api_boundary_applicable(cwe: str) -> bool:
    """True when the CWE belongs to the boundary-obligation family."""
    norm = (cwe or "").upper().strip()
    if norm and not norm.startswith("CWE-"):
        norm = f"CWE-{norm}"
    return norm in API_BOUNDARY_CWES


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
            return []
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
    contracts ("NULL host", "host == NULL", "passes a NULL host") and
    negative-value contracts ("negative outl", "outl < 0"). Kernel /
    peer / OS obligations return the explicit external contract."""
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
    return None


# ── call-site enumeration ───────────────────────────────────────────

_SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx")
_MAX_SCAN_FILES = 4000
_MAX_FILE_BYTES = 2_000_000
_GUARD_WINDOW_LINES = 14


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
) -> list[dict[str, Any]]:
    """Call sites of ``function_name`` in one file:
    {file, line, code, args, window} dicts."""
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return []
        text = path.read_text(errors="replace")
    except OSError:
        return []
    if function_name not in text:
        return []
    sites: list[dict[str, Any]] = []
    lines = text.splitlines()
    call_re = re.compile(rf"(?<![\w.>]){re.escape(function_name)}\s*\(")
    offset = 0
    line_starts: list[int] = []
    for ln in lines:
        line_starts.append(offset)
        offset += len(ln) + 1
    for m in call_re.finditer(text):
        # Line number via binary search over line starts.
        line_no = bisect.bisect_right(line_starts, m.start())
        if skip_span and skip_span[0] <= line_no <= skip_span[1]:
            continue
        line_text = lines[line_no - 1]
        if _looks_like_decl_or_def(line_text, function_name):
            continue
        open_pos = text.index("(", m.start())
        args_text, _end = _balanced_span(text, open_pos)
        if args_text is None:
            continue
        window_start = max(0, line_no - 1 - _GUARD_WINDOW_LINES)
        window = "\n".join(lines[window_start:line_no - 1])
        sites.append({
            "file": rel,
            "line": line_no,
            "code": line_text.strip(),
            "args": _split_top_level(args_text),
            "window": window,
        })
    return sites


def enumerate_call_sites(
    target_path: Path,
    function_name: str,
    *,
    def_file: str = "",
    def_span: tuple[int, int] | None = None,
    inventory: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """In-repo call sites of ``function_name``.

    Prefers the inventory call graph to pick candidate files, falling
    back to a bounded scan of the tree. The defining span is excluded.
    """
    target_path = Path(target_path)
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
            for site in _scan_file_for_calls(
                path, rel, function_name, skip_span=skip,
            ):
                site["caller"] = caller.get("name", "")
                sites.append(site)
        if sites:
            return sites

    # Fallback: bounded tree scan.
    scanned = 0
    for path in sorted(target_path.rglob("*")):
        if scanned >= _MAX_SCAN_FILES:
            break
        if not path.is_file() or path.suffix.lower() not in _SOURCE_SUFFIXES:
            continue
        scanned += 1
        try:
            rel = str(path.relative_to(target_path))
        except ValueError:
            continue
        skip = def_span if rel == def_file else None
        sites.extend(_scan_file_for_calls(
            path, rel, function_name, skip_span=skip,
        ))
    return sites


# ── per-site guard analysis ─────────────────────────────────────────


def _base_identifier(arg: str) -> str:
    """Reduce an argument expression to its base identifier."""
    arg = _CAST_RE.sub("", arg).strip()
    arg = arg.lstrip("&*(").strip()
    m = re.match(rf"({_IDENT})", arg)
    return m.group(1) if m else ""


def _check_site(contract: Contract, site: dict[str, Any]) -> CallSiteCheck:
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
                check.evidence = (
                    f"dominating NULL check: {guard.group(0).strip()}"
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
                check.evidence = (
                    f"dominating sign check: {guard.group(0).strip()}"
                )
                return check
        check.evidence = "no structural sign guard found in the window"
        return check

    check.evidence = f"unsupported contract kind {contract.kind!r}"
    return check


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
                "parameter (supported shapes: NULL-parameter and "
                "negative-value contracts)"
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

    sites = enumerate_call_sites(
        target_path,
        function_name,
        def_file=file_path,
        def_span=def_span,
        inventory=inventory,
    )
    if not sites:
        return ApiBoundaryResult(
            outcome="inconclusive",
            reason=(
                "external-only callers — no in-repo call sites of "
                f"{function_name}; the caller obligation cannot be "
                "adjudicated from this tree"
            ),
            contract=contract.describe(),
        )

    checks = [_check_site(contract, s) for s in sites]
    unguarded = [c for c in checks if c.verdict == "unguarded"]
    undecided = [c for c in checks if c.verdict == "undecided"]

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
        )
    if not undecided:
        return ApiBoundaryResult(
            outcome="refuted",
            reason=(
                f"all {len(checks)} in-repo call site(s) honour the "
                "contract (guard receipts per site)"
            ),
            contract=contract.describe(),
            sites=checks,
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
    )
