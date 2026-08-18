"""Flow-sensitive per-hypothesis Coccinelle rules for /audit.

Unlike the stock pattern-only templates, these SmPL rules use
``... when != <event>`` to encode *absence of an intervening event on
the actual control-flow path*:

* ``use_after_free``   — ``free(V); ... when != V = E``  then a deref
  of ``V`` (index / star / field), i.e. no reassignment between the
  free and the use.
* ``double_free``      — a second ``free(V)`` reachable from the first
  with no intervening reassignment of ``V``.
* ``double_fetch``     — two fetches from the same user pointer with
  no re-binding of the pointer in between (missing re-validation
  after fetch).
* ``unchecked_return`` — ``V = F(...)`` followed by a deref of ``V``
  with no ``if`` on ``V`` and no reassignment on the path.

Every rendered rule binds the hypothesis-named identifier literally
(the identifier-consistency negative control shared with the
per-hypothesis semgrep rules): when no identifier can be bound from
the hypothesis, no rule is produced and the outcome is inconclusive —
never a generic sweep dressed up as a verdict.

spatch failures and SmPL/target parse errors classify as ``error``,
never ``refuted`` (mirrors the landed semgrep semantics).

Security: the target repo is untrusted and nothing from it executes —
spatch only *parses* target C code, is invoked with list-based argv
and ``RaptorConfig.get_safe_env()`` by ``packages.coccinelle.runner``,
and every value interpolated into a rendered rule passes identifier
validation first (no repo-derived strings reach the rule text).

Template semantics were validated against spatch 1.3 fixtures — see
``core/audit/tests/fixtures/cocci_flow/`` and the guarded-fixture
tests proving each template does NOT match correctly-guarded code.
"""

from __future__ import annotations

import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from .sweep import SweepResult, _check_path_containment, _match_in_range

logger = logging.getLogger(__name__)

TOOL_NAME = "coccinelle_flow"

# Victim expressions: a bare identifier or a -> / . field path whose
# every segment is a valid identifier.  Regex-safe and SmPL-safe by
# construction (no quotes, spaces, or metacharacters admitted).
_VICTIM_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:(?:->|\.)[A-Za-z_][A-Za-z0-9_]*)*$"
)
_FUNC_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_FREE_FNS = ("kfree_sensitive", "devm_kfree", "kfree_rcu", "kvfree",
             "kfree", "vfree", "free")
_FETCH_FNS = ("__copy_from_user", "copy_from_user")

# Allocator/getter names accepted for unchecked_return when the
# hypothesis names the callee only via a backtick or "call to X".
_RETURNING_FNS_HINT = re.compile(
    r"\b(k?[mc]alloc|kzalloc|kcalloc|krealloc|realloc|strdup|kstrdup|"
    r"fopen|open|malloc|calloc)\b"
)


def victim_expr_valid(expr: str) -> bool:
    """True when *expr* is safe to interpolate into a rendered rule."""
    return bool(expr) and bool(_VICTIM_RE.match(expr))


# ── SmPL templates ───────────────────────────────────────────────────
#
# Notes earned against live spatch 1.3:
#   * the deref forms live in separate rules — a single-rule
#     disjunction misbehaves once positions attach at different
#     depths per branch;
#   * a line-leading ``*`` is the SmPL star-annotation operator, so
#     the pointer-deref pattern is indented one space;
#   * the ``when != V = E1`` exclusion needs a metavariable that is
#     NOT reused in the endpoint pattern, otherwise the shared
#     binding defeats the exclusion;
#   * ``V = F(...)`` is written without the trailing semicolon so the
#     ``decl_init`` isomorphism lets it match ``T V = F(...);``.

_SCRIPT_BLOCK = """\
@script:python@
p << {rule}.p;
@@
import json, sys
for _p in p:
    _m = {{"file": _p.file, "line": int(_p.line), "col": int(_p.column),
          "line_end": int(_p.line_end), "col_end": int(_p.column_end),
          "rule": "{rule_id}", "message": {message!r}}}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\\n")
"""

_UAF_TEMPLATE = """\
// flow-sensitive use-after-free: {free_fn}({victim}) followed by a
// deref of {victim} with no intervening reassignment on the path.
@uaf1 exists@
expression E1, E2;
position p;
@@

{free_fn}({victim});
... when != {victim} = E1
{victim}@p[E2]

@uaf2 exists@
expression E1;
position p;
@@

{free_fn}({victim});
... when != {victim} = E1
 *{victim}@p

@uaf3 exists@
expression E1;
identifier fld;
position p;
@@

{free_fn}({victim});
... when != {victim} = E1
{victim}@p->fld

{script1}
{script2}
{script3}
"""

_DOUBLE_FREE_TEMPLATE = """\
// flow-sensitive double-free: a second {free_fn}({victim}) reachable
// from the first with no intervening reassignment of {victim}.
@dfree exists@
expression E1;
position p;
@@

{free_fn}({victim});
... when != {victim} = E1
{free_fn}@p({victim});

{script1}
"""

_DOUBLE_FETCH_TEMPLATE = """\
// flow-sensitive double-fetch: two {fetch_fn} reads from the same
// user pointer {victim} with no re-binding of {victim} in between
// (the second read can observe different bytes than were validated).
@dfetch exists@
expression D1, D2, S1, S2, E1;
position p;
@@

{fetch_fn}(D1, {victim}, S1);
... when != {victim} = E1
{fetch_fn}@p(D2, {victim}, S2);

{script1}
"""

_UNCHECKED_RETURN_TEMPLATE = """\
// flow-sensitive unchecked return: V = {func}(...) then a deref of V
// with no if-test involving V and no reassignment on the path.
@ur1 exists@
identifier V;
expression E1, E2;
statement S1;
position p;
@@

V = {func}(...)
... when != if (<+... V ...+>) S1
    when != V = E1
V@p[E2]

@ur2 exists@
identifier V;
expression E1;
statement S1;
position p;
@@

V = {func}(...)
... when != if (<+... V ...+>) S1
    when != V = E1
 *V@p

@ur3 exists@
identifier V;
expression E1;
identifier fld;
statement S1;
position p;
@@

V = {func}(...)
... when != if (<+... V ...+>) S1
    when != V = E1
V@p->fld

{script1}
{script2}
{script3}
"""

FLOW_TEMPLATES = frozenset({
    "use_after_free", "double_free", "double_fetch", "unchecked_return",
})

# CWE routing for the fallback chain.
CWE_FLOW_TEMPLATES = {
    "CWE-416": "use_after_free",
    "CWE-415": "double_free",
    "CWE-252": "unchecked_return",
    "CWE-367": "double_fetch",
}


def _scripts(rule_names: list, rule_id: str, message: str) -> dict:
    out = {}
    for i, rule in enumerate(rule_names, start=1):
        out[f"script{i}"] = _SCRIPT_BLOCK.format(
            rule=rule, rule_id=rule_id, message=message,
        )
    return out


def render_flow_rule(
    template: str,
    *,
    victim: str | None = None,
    func: str | None = None,
    free_fn: str = "free",
    fetch_fn: str = "copy_from_user",
) -> str | None:
    """Render a flow-sensitive SmPL rule bound to hypothesis names.

    Returns the rule text, or None when the required binding is
    missing or fails validation (the caller must then decline a
    verdict rather than sweep with an unbound rule).
    """
    if template == "use_after_free":
        if not victim or not victim_expr_valid(victim) \
                or not _FUNC_RE.match(free_fn):
            return None
        rule_id = "flow_use_after_free"
        msg = f"use of {victim} after {free_fn} with no reassignment"
        return _UAF_TEMPLATE.format(
            victim=victim, free_fn=free_fn,
            **_scripts(["uaf1", "uaf2", "uaf3"], rule_id, msg),
        )

    if template == "double_free":
        if not victim or not victim_expr_valid(victim) \
                or not _FUNC_RE.match(free_fn):
            return None
        rule_id = "flow_double_free"
        msg = f"second {free_fn}({victim}) with no reassignment between"
        return _DOUBLE_FREE_TEMPLATE.format(
            victim=victim, free_fn=free_fn,
            **_scripts(["dfree"], rule_id, msg),
        )

    if template == "double_fetch":
        if not victim or not victim_expr_valid(victim) \
                or not _FUNC_RE.match(fetch_fn):
            return None
        rule_id = "flow_double_fetch"
        msg = f"second {fetch_fn} from {victim} without re-binding"
        return _DOUBLE_FETCH_TEMPLATE.format(
            victim=victim, fetch_fn=fetch_fn,
            **_scripts(["dfetch"], rule_id, msg),
        )

    if template == "unchecked_return":
        if not func or not _FUNC_RE.match(func):
            return None
        rule_id = "flow_unchecked_return"
        msg = f"return of {func}() dereferenced without a check"
        return _UNCHECKED_RETURN_TEMPLATE.format(
            func=func,
            **_scripts(["ur1", "ur2", "ur3"], rule_id, msg),
        )

    return None


# ── hypothesis dispatch + binding extraction ─────────────────────────

_TEMPLATE_KEYWORDS = (
    ("double_free", ("double free", "double-free", "freed twice",
                     "free twice", "frees the same")),
    ("double_fetch", ("double fetch", "double-fetch", "fetched twice",
                      "toctou fetch", "re-fetch", "refetch",
                      "fetched again")),
    ("use_after_free", ("use after free", "use-after-free",
                        "used after free", "used after it is freed",
                        "dangling pointer", "after being freed")),
    ("unchecked_return", ("unchecked return", "return value is not",
                          "without checking the return",
                          "return not checked",
                          "null check on the return")),
)


def flow_template_for_hypothesis(hypothesis: str) -> str | None:
    """Keyword-dispatch a hypothesis to a flow template, or None."""
    hyp = (hypothesis or "").lower()
    for template, keywords in _TEMPLATE_KEYWORDS:
        if any(kw in hyp for kw in keywords):
            return template
    return None


def flow_template_for_cwe(cwe: str) -> str | None:
    """CWE-dispatch to a flow template, or None."""
    normalized = (cwe or "").upper().strip()
    if normalized and not normalized.startswith("CWE-"):
        normalized = f"CWE-{normalized}"
    return CWE_FLOW_TEMPLATES.get(normalized)


_BACKTICK_EXPR_RE = re.compile(
    r"`([A-Za-z_][A-Za-z0-9_]*(?:(?:->|\.)[A-Za-z_][A-Za-z0-9_]*)*)`"
)

_VICTIM_PATTERNS = (
    # "use-after-free of conn->buf" / "double free of `ptr`"
    re.compile(
        r"(?:free(?:ing)?|fetch(?:es|ing)?)\s+(?:of\s+|from\s+)?"
        r"[`'\"]?([A-Za-z_][A-Za-z0-9_]*"
        r"(?:(?:->|\.)[A-Za-z_][A-Za-z0-9_]*)*)[`'\"]?",
        re.IGNORECASE,
    ),
    # "conn->buf is freed / fetched twice"
    re.compile(
        r"[`'\"]?([A-Za-z_][A-Za-z0-9_]*"
        r"(?:(?:->|\.)[A-Za-z_][A-Za-z0-9_]*)*)[`'\"]?\s+is\s+"
        r"(?:freed|fetched|used|read)",
        re.IGNORECASE,
    ),
    # "from `uptr`" (double-fetch phrasing)
    re.compile(
        r"from\s+[`'\"]?([A-Za-z_][A-Za-z0-9_]*"
        r"(?:(?:->|\.)[A-Za-z_][A-Za-z0-9_]*)*)[`'\"]?",
        re.IGNORECASE,
    ),
)

_RETURN_FN_PATTERNS = (
    # "return value of malloc" / "return of `kmalloc`"
    re.compile(
        r"return(?:\s+value)?\s+(?:of|from)\s+"
        r"[`'\"]?([A-Za-z_][A-Za-z0-9_]*)[`'\"]?",
        re.IGNORECASE,
    ),
    # "`fopen()` return is not checked"
    re.compile(r"[`'\"]?([A-Za-z_][A-Za-z0-9_]*)\(\)?[`'\"]?\s+return"),
)

_PROSE_VICTIMS = frozenset({
    "the", "a", "an", "it", "this", "that", "memory", "pointer",
    "buffer", "object", "value", "data", "user", "same", "twice",
    "userspace", "kernel", "function", "return", "from", "of", "to",
    "in", "on", "at", "into", "and", "then", "again", "by",
})


def _plausible_victim(name: str | None) -> str | None:
    if not name:
        return None
    if name.lower() in _PROSE_VICTIMS:
        return None
    if not victim_expr_valid(name):
        return None
    return name


def extract_flow_binding(
    template: str, hypothesis: str,
) -> dict | None:
    """Extract the render kwargs for *template* from *hypothesis*.

    Returns e.g. ``{"victim": "conn->buf", "free_fn": "kfree"}`` or
    None when the hypothesis names nothing bindable — the
    identifier-consistency negative control.
    """
    hyp = hypothesis or ""

    if template == "unchecked_return":
        func = None
        for pat in _RETURN_FN_PATTERNS:
            m = pat.search(hyp)
            if m and _FUNC_RE.match(m.group(1)) \
                    and m.group(1).lower() not in _PROSE_VICTIMS:
                func = m.group(1)
                break
        if func is None:
            m = _RETURNING_FNS_HINT.search(hyp)
            if m:
                func = m.group(1)
        if func is None:
            return None
        return {"func": func}

    victim = None
    for pat in _VICTIM_PATTERNS:
        m = pat.search(hyp)
        if m:
            victim = _plausible_victim(m.group(1))
            if victim:
                break
    if victim is None:
        for cand in _BACKTICK_EXPR_RE.findall(hyp):
            victim = _plausible_victim(cand)
            if victim:
                break
    if victim is None:
        return None

    binding: dict = {"victim": victim}
    if template in ("use_after_free", "double_free"):
        for fn in _FREE_FNS:
            if re.search(rf"\b{fn}\b", hyp):
                binding["free_fn"] = fn
                break
    elif template == "double_fetch":
        for fn in _FETCH_FNS:
            if re.search(rf"\b{fn}\b", hyp):
                binding["fetch_fn"] = fn
                break
    return binding


# ── sweep entry point ────────────────────────────────────────────────


def run_flow_cocci_sweep(
    *,
    target_path: Path,
    file_path: str,
    function_name: str,
    hypothesis: str,
    template: str | None = None,
    line_start: int | None = None,
    line_end: int | None = None,
    timeout: int = 120,
) -> SweepResult:
    """Run a flow-sensitive per-hypothesis Coccinelle rule on one file.

    Outcomes:
      * ``confirmed``    — the rendered rule matched inside the
        function range (matches carry line + bound-identifier message).
      * ``refuted``      — spatch ran cleanly and nothing matched.
      * ``inconclusive`` — no template applies or the hypothesis names
        no bindable identifier (negative control: no binding, no
        verdict).
      * ``error``        — spatch missing, SmPL/target parse errors,
        non-zero exit, or timeout.  Never ``refuted`` on failure.
    """
    escape = _check_path_containment(target_path, file_path, TOOL_NAME)
    if escape:
        return escape

    full_path = target_path / file_path
    if not full_path.exists():
        return SweepResult(
            tool=TOOL_NAME,
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[f"file not found: {full_path}"],
        )

    template = template or flow_template_for_hypothesis(hypothesis)
    if template not in FLOW_TEMPLATES:
        return SweepResult(
            tool=TOOL_NAME,
            file_path=file_path,
            function_name=function_name,
            outcome="inconclusive",
            details={"reason": "no flow-sensitive template applies"},
        )

    binding = extract_flow_binding(template, hypothesis)
    if binding is None:
        return SweepResult(
            tool=TOOL_NAME,
            file_path=file_path,
            function_name=function_name,
            outcome="inconclusive",
            rule_id=f"cocci-flow:{template}",
            details={
                "reason": (
                    "hypothesis names no bindable identifier "
                    "(identifier-consistency control)"
                ),
            },
        )

    rule_text = render_flow_rule(template, **binding)
    if rule_text is None:
        return SweepResult(
            tool=TOOL_NAME,
            file_path=file_path,
            function_name=function_name,
            outcome="inconclusive",
            rule_id=f"cocci-flow:{template}",
            details={"reason": "binding failed validation"},
        )

    try:
        from packages.coccinelle.runner import is_available, run_rule
    except ImportError:
        return SweepResult(
            tool=TOOL_NAME,
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=["coccinelle package not available"],
            rule_id=f"cocci-flow:{template}",
        )

    if not is_available():
        return SweepResult(
            tool=TOOL_NAME,
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=["coccinelle (spatch) not installed"],
            rule_id=f"cocci-flow:{template}",
        )

    fd, tmp_name = tempfile.mkstemp(
        suffix=".cocci", prefix="raptor-cocci-flow-",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(rule_text)

        try:
            result = run_rule(
                full_path,
                Path(tmp_name),
                no_includes=True,
                timeout=timeout,
                # In-repo flow templates (code trust) — their rendered
                # @script:python reporting blocks are trusted.
                allow_scripting=True,
            )
        except Exception as exc:  # noqa: BLE001 — degrade to outcome=error, never crash
            return SweepResult(
                tool=TOOL_NAME,
                file_path=file_path,
                function_name=function_name,
                outcome="error",
                errors=[str(exc)],
                rule_id=f"cocci-flow:{template}",
            )
    finally:
        try:
            Path(tmp_name).unlink()
        except OSError:
            pass

    # spatch failure / parse errors → error, never refuted (mirrors
    # the landed per-hypothesis semgrep semantics).
    if result.returncode != 0 or result.errors:
        return SweepResult(
            tool=TOOL_NAME,
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=list(result.errors)
            or [f"spatch exited with code {result.returncode}"],
            rule_id=f"cocci-flow:{template}",
        )

    matches: list = []
    for m in result.matches:
        matches.append(m.to_dict() if hasattr(m, "to_dict") else {"raw": str(m)})

    if line_start is not None and line_end is not None:
        matches = [
            m for m in matches if _match_in_range(m, line_start, line_end)
        ]

    if matches:
        return SweepResult(
            tool=TOOL_NAME,
            file_path=file_path,
            function_name=function_name,
            outcome="confirmed",
            matches=matches,
            rule_id=f"cocci-flow:{template}",
            details={"binding": binding},
        )

    return SweepResult(
        tool=TOOL_NAME,
        file_path=file_path,
        function_name=function_name,
        outcome="refuted",
        rule_id=f"cocci-flow:{template}",
        details={"binding": binding},
    )


def chain_entry_for_cwe(cwe: str) -> dict | None:
    """Tool-chain entry for the flow-cocci channel, or None."""
    template = flow_template_for_cwe(cwe)
    if template is None:
        return None
    return {"type": "coccinelle_flow", "config": {"template": template}}


__all__ = [
    "CWE_FLOW_TEMPLATES",
    "FLOW_TEMPLATES",
    "TOOL_NAME",
    "chain_entry_for_cwe",
    "extract_flow_binding",
    "flow_template_for_cwe",
    "flow_template_for_hypothesis",
    "render_flow_rule",
    "run_flow_cocci_sweep",
    "victim_expr_valid",
]

# Re-exported for type context in docstrings/tests.
_ = Any
