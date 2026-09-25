"""sanwit — witness-executed sanitizer-sufficiency checks.

The audit's witness class for the claim "sanitizer X does not
neutralize payload class Y in sink context Z": extract the ACTUAL
sanitizer chain from the target function (as written — refusing
whenever a pure straight-line chain cannot be isolated), synthesize
a minimal PHP probe from a fixed template, execute it in a sandboxed
interpreter against the sink context's breakout-payload corpus, and
adjudicate each output with the context's mechanical predicate.
Assertion by execution, never by model judgment.

Deterministic verdict vocabulary and its discipline:

* ``insufficient(payload)`` → outcome ``confirmed``, rule id
  ``sanwit:insufficient:<context>``. DETECTION-grade by policy
  (:func:`is_detection_rule_id` is True for every sanwit stamp):
  an executed breakout proves the DEFENSE does not defend that
  context — it does not prove reachability or the attack path, so
  it may corroborate and aggregate but never convict alone.
* ``sufficient`` → outcome ``inconclusive``, rule id
  ``sanwit:sufficient:<context>``. NEVER suppression-grade: the
  receipt is corpus-bounded, context-scoped and interpreter-scoped
  ("neutralized the tested corpus for context Z on PHP <ver>"; a
  chain sufficient for context Z says nothing about any other
  context). Inconclusive keeps the item dark/dispatched — it never
  counts as refuted and never resolves clean; the channel is also
  deliberately absent from ``tool_coverage._CWE_TOOL_MAP``.
* ``not-executable(reason)`` → outcome ``skipped``. Absent
  capability or refused extraction is stated in the receipt, never
  silently dropped; ``skipped`` keeps it out of refuted counters
  and dispatch records (did not look).

Every verdict binds to (extracted chain, payload corpus, context id,
interpreter version) — all recorded in the receipt — and there is NO
refuted outcome in this module: no sanwit result can demote,
suppress, or clean-resolve an item. No verdict without an executed,
token-authenticated receipt.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._extract import (
    ExtractionRefusal,
    extract_chain,
)
from ._families import (
    FAMILY_HTML,
    FAMILY_SANITIZERS,
    FAMILY_SHELL,
    SINK_CONTEXTS,
    SinkContext,
)
from ._probe import (
    ProbeRun,
    generate_probe,
    parse_probe_output,
    payloads_document,
)

__all__ = [
    "SANWIT_CWES",
    "SanwitResult",
    "is_detection_rule_id",
    "is_sanwit_hypothesis",
    "run_sanwit_check",
    "sanwit_can_adjudicate",
    "sanwit_cwe_applicable",
    "sanwit_language_permitted",
]

#: CWE classes the channel joins via the CWE fallback chain (the
#: fail_open_verify.FAIL_OPEN_CWES precedent: channel CWE sets live
#: with the channel). Shell family: 78/77/88; HTML family: 79/116.
SANWIT_CWES: frozenset[str] = frozenset({
    "CWE-78", "CWE-77", "CWE-88", "CWE-79", "CWE-116",
})

#: Chain-length ceiling. Real sanitizer chains are a handful of
#: steps; a longer extraction is almost certainly a mis-anchored
#: walk and would bloat probe/receipts. Larger admits stranger
#: chains at receipt-size cost; smaller starts refusing real
#: multi-step rewrites.
MAX_CHAIN_STEPS = 12

# Receipt caps (exhibits are target/interpreter-derived text).
_EXHIBIT_OUTPUT_CAP = 256
_CHAIN_TEMPLATE_CAP = 200


def _escape(text: str, cap: int) -> str:
    from core.security.log_sanitisation import escape_nonprintable

    if len(text) > cap:
        text = text[:cap] + "…[capped]"
    return escape_nonprintable(text)


# ── hypothesis-side classification ───────────────────────────────────

_ALL_SANITIZERS: tuple[str, ...] = tuple(
    name for names in FAMILY_SANITIZERS.values() for name in names
)

_SANITIZER_RE = re.compile(
    r"\b(" + "|".join(_ALL_SANITIZERS) + r")\b", re.IGNORECASE,
)

# Insufficiency-direction cues. Anchored on the sanitizer-name
# requirement above, so breadth here costs at most one witness
# execution, never a verdict. Gaps bounded per the hypothesis-regex
# doctrine.
_CUE_RE = re.compile(
    r"insufficien|not\s+sufficient|"
    r"does\s?n[o']?t\s+(?:neutrali|escape|quote|protect|prevent|stop)|"
    r"despite|bypass|breaks?\s?out|survive|"
    r"passes?\s+through|still\s+(?:injectable|exploitable|vulnerable)|"
    r"escapes?\s+only|argument\s+inject|option\s+inject|quot",
    re.IGNORECASE,
)


def mentioned_sanitizers(hypothesis: str) -> tuple[str, ...]:
    """Family sanitizer names the hypothesis cites (lowercased,
    order kept, deduplicated)."""
    return tuple(dict.fromkeys(
        m.group(1).lower()
        for m in _SANITIZER_RE.finditer(hypothesis or "")
    ))


def _family_of(names: tuple[str, ...]) -> str | None:
    families = {
        fam for fam, members in FAMILY_SANITIZERS.items()
        for n in names if n in members
    }
    if len(families) == 1:
        return next(iter(families))
    return None


def is_sanwit_hypothesis(hypothesis: str) -> bool:
    """Keyword classifier for the string-matched chain hook: the
    hypothesis must NAME a family sanitizer (extraction cannot anchor
    otherwise) and carry an insufficiency-direction cue."""
    text = hypothesis or ""
    return bool(mentioned_sanitizers(text)) and bool(_CUE_RE.search(text))


def sanwit_language_permitted(
    file_path: str, language: str | None = None,
) -> bool:
    """Chain-BUILD language gate (both orchestrator hooks call it).

    The substrate seam already skips non-PHP files pre-dispatch, but
    a chain leg's mere EXISTENCE is consulted by the empty-dispatch
    synthesis fallback — an always-appended sanwit leg would silently
    remove that routing for sanitizer-named hypotheses on non-PHP
    files (PHP-builtin names appear in other-language trees, e.g. a C
    reimplementation of the same API). Mirrors the curated-semgrep
    leg's gate: mapped ``.php`` extensions pass; unmapped extensions
    pass on a php content-probe hint; no file context fails CLOSED
    (the joern_langs precedent).
    """
    from core.audit.hypothesis_mapping import (
        semgrep_language_for,
        semgrep_probed_language,
    )

    if semgrep_language_for(file_path or "") == "php":
        return True
    return semgrep_probed_language(file_path or "", language) == "php"


def sanwit_cwe_applicable(cwe: str, hypothesis: str = "") -> bool:
    """CWE fallback-chain gate. Requires BOTH the class and a named
    family sanitizer — a nameless dispatch could only mint
    not-executable noise."""
    normalized = (cwe or "").upper().strip()
    if normalized and not normalized.startswith("CWE-"):
        normalized = f"CWE-{normalized}"
    if normalized not in SANWIT_CWES:
        return False
    return bool(mentioned_sanitizers(hypothesis or ""))


# ── context resolution ───────────────────────────────────────────────

_CWE_FAMILY: dict[str, str] = {
    "CWE-78": FAMILY_SHELL, "CWE-77": FAMILY_SHELL,
    "CWE-88": FAMILY_SHELL,
    "CWE-79": FAMILY_HTML, "CWE-116": FAMILY_HTML,
}

_SQUOTE_RE = re.compile(r"single[\s-]?quot|\bsquote\b", re.IGNORECASE)
_DQUOTE_RE = re.compile(r"double[\s-]?quot|\bdquote\b", re.IGNORECASE)
_UNQUOTED_ATTR_RE = re.compile(
    r"unquoted\s{0,3}attribut", re.IGNORECASE,
)
_HTML_TEXT_RE = re.compile(
    r"element\s{0,3}(?:content|context|body)|text\s{0,3}(?:node|context)|"
    r"tag\s{0,3}body|between\s{0,3}tags|html\s{0,3}body",
    re.IGNORECASE,
)
_ENT_RESIDUAL_RE = re.compile(
    r"ent_quotes|ent_compat|ent_noquotes", re.IGNORECASE,
)
# Sink-attachment patterns for shell quote contexts: the quote phrase
# must attach to the SINK EMBEDDING, not to the sanitizer's own
# behaviour ("escapeshellarg wraps the value in single quotes" is how
# hypotheses describe the sanitizer ITSELF — pinning shell-squote on
# it would auto-confirm a false insufficiency on every escapeshellarg
# function, since its output always carries quotes). Two accepted
# shapes: an embedding verb governing the quote phrase, or the quote
# phrase modifying a part-of-the-command noun. Gaps bounded.
_SHELL_EMBED_RE = re.compile(
    r"(?:embedd\w{0,4}|placed|inserted|interpolat\w{0,4}|"
    r"concatenat\w{0,4}|lands?|appears?|sits|ends?\s{1,3}up)"
    r"[\s\w]{0,30}?(?:in|inside|within|into)\s{1,3}"
    r"(?:a\s{1,3}|the\s{1,3})?(?:single|double)[\s-]?quot"
    r"|(?:single|double)[\s-]?quot\w{0,4}\s{1,3}"
    r"(?:part|portion|context|region|segment|section|string)\s{1,3}of",
    re.IGNORECASE,
)
_ATTR_RE = re.compile(r"attribut", re.IGNORECASE)
# Hybrid guard: a sanitizer-behaviour verb (wraps/quotes/escapes/…)
# governing the SAME CLAUSE as the quote phrase means the quotes are
# the sanitizer's own ("escapeshellarg wraps the input so it lands
# inside single quotes") — an embedding verb later in that clause
# must not rescue the pin. Clause = no [.;:!?] between the verb and
# the quote phrase; gaps bounded.
# The (?!-) keeps participial value descriptions out: in "the
# escapeshellarg-escaped value lands inside single quotes" the
# hyphen-attached participle identifies the VALUE, not a behaviour
# claim — the phrase is genuine sink-embedding and must keep its pin.
_SANITIZER_BEHAVIOR_QUOTE_RE = re.compile(
    r"\b(?:" + "|".join(_ALL_SANITIZERS) + r")\b(?!-)"
    r"[^.;:!?]{0,40}?\b(?:wrap|quot|escap|enclos|surround|put|add)\w{0,4}\b"
    r"[^.;:!?]{0,80}?(?:single|double)[\s-]?quot",
    re.IGNORECASE,
)


def resolve_context(
    hypothesis: str, cwe: str = "",
) -> tuple[SinkContext | None, str]:
    """Pin (family, ONE context id) from the hypothesis + CWE.

    Returns ``(context, "")`` or ``(None, reason)``. Ambiguity
    REFUSES with the candidates named — testing every candidate
    context could mint a breakout in a context the real sink is not
    in (a false insufficiency), so the conservative direction is a
    reasoned refusal.
    """
    text = hypothesis or ""
    names = mentioned_sanitizers(text)
    if not names:
        return None, "no family sanitizer named in the hypothesis"
    family = _family_of(names)
    if family is None:
        normalized = (cwe or "").upper().strip()
        if normalized and not normalized.startswith("CWE-"):
            normalized = f"CWE-{normalized}"
        family = _CWE_FAMILY.get(normalized)
    if family is None:
        return None, (
            "sanitizer families are mixed and the CWE does not pin "
            "one — sink context class not determinable"
        )
    if family == FAMILY_SHELL:
        squote = bool(_SQUOTE_RE.search(text))
        dquote = bool(_DQUOTE_RE.search(text))
        if squote or dquote:
            # Quote-embedded shell contexts require SINK-ATTACHED
            # quote phrasing: hypotheses routinely describe
            # escapeshellarg's own quoting, and pinning an embedding
            # context from that phrasing would mint a breakout the
            # real sink never has (the sanitizer's output ALWAYS
            # carries quotes). A sanitizer-behaviour verb governing
            # the same clause as the quote phrase overrides any
            # embedding verb in it — the hybrid "wraps … so it lands
            # inside single quotes" is still about the sanitizer.
            if _SANITIZER_BEHAVIOR_QUOTE_RE.search(text):
                return None, (
                    "quote phrasing is governed by a sanitizer-"
                    "behaviour verb in the same clause (the quotes "
                    "described are the sanitizer's own) — candidates "
                    "shell-command / shell-squote / shell-dquote; "
                    "state the sink embedding in its own clause"
                )
            if _SHELL_EMBED_RE.search(text):
                ctx = "shell-squote" if squote else "shell-dquote"
                return SINK_CONTEXTS[ctx], ""
            return None, (
                "quote phrasing does not attach to the sink "
                "embedding (it may describe the sanitizer itself) — "
                "candidates shell-command / shell-squote / "
                "shell-dquote; state that the output is embedded "
                "inside quotes in the command string, or drop the "
                "quote phrasing for command position"
            )
        # Family default: escapeshellarg/escapeshellcmd output in
        # command/argument position is the sanitizers' contractual
        # context; quote-embedded sinks require sink-attached quote
        # phrasing.
        return SINK_CONTEXTS["shell-command"], ""
    # HTML family: the quote kind must be pinned for attribute
    # contexts — the breakout character differs per kind — and quote
    # phrasing must co-occur with the attribute context (bare
    # "leaves single quotes unescaped" describes the sanitizer, not
    # the sink).
    if _UNQUOTED_ATTR_RE.search(text):
        return SINK_CONTEXTS["html-attr-unquoted"], ""
    attr = bool(_ATTR_RE.search(text))
    if attr and _SQUOTE_RE.search(text):
        return SINK_CONTEXTS["html-attr-squote"], ""
    if attr and _DQUOTE_RE.search(text):
        return SINK_CONTEXTS["html-attr-dquote"], ""
    if _HTML_TEXT_RE.search(text):
        return SINK_CONTEXTS["html-text"], ""
    if attr:
        if _ENT_RESIDUAL_RE.search(text):
            # The ENT-flag residual is definitionally the
            # single-quote survival class (ENT_COMPAT escapes the
            # double quote; ENT_NOQUOTES leaves both and the single
            # quote is a sound representative).
            return SINK_CONTEXTS["html-attr-squote"], ""
        return None, (
            "attribute context named without its quote kind — "
            "candidates html-attr-squote / html-attr-dquote / "
            "html-attr-unquoted; the hypothesis must pin one"
        )
    if _SQUOTE_RE.search(text) or _DQUOTE_RE.search(text):
        return None, (
            "quote phrasing without an attribute or element "
            "context — candidates html-attr-squote / "
            "html-attr-dquote / html-text; the hypothesis must pin "
            "the sink context"
        )
    return None, (
        "sink context class not determinable from the hypothesis "
        "(no attribute/element/quote phrasing)"
    )


# ── result type ──────────────────────────────────────────────────────


@dataclass
class SanwitResult:
    """One sanitizer-sufficiency witness outcome (receipt-bearing)."""

    tool: str
    file_path: str
    function_name: str
    outcome: str  # confirmed | inconclusive | skipped | error
    verdict: str  # insufficient | sufficient | not-executable | error
    rule_id: str
    reason: str
    context_id: str = ""
    family: str = ""
    chain: list[str] = field(default_factory=list)
    subject_var: str = ""
    interpreter: dict[str, str] = field(default_factory=dict)
    corpus_size: int = 0
    exhibits: list[dict[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    details: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "tool": self.tool,
            "outcome": self.outcome,
            "verdict": self.verdict,
            "rule_id": self.rule_id,
            "reason": self.reason,
        }
        for key in ("context_id", "family", "subject_var"):
            value = getattr(self, key)
            if value:
                d[key] = value
        if self.chain:
            d["chain"] = list(self.chain)
        if self.interpreter:
            d["interpreter"] = dict(self.interpreter)
        if self.corpus_size:
            d["corpus_size"] = self.corpus_size
        if self.exhibits:
            d["exhibits"] = [dict(e) for e in self.exhibits]
        if self.errors:
            d["errors"] = list(self.errors)
        return d


def sanwit_can_adjudicate(
    target_path: Path | str,
    file_path: str,
    hypothesis: str,
    *,
    source: str = "",
    cwe: str = "",
) -> bool:
    """Static precheck: would :func:`run_sanwit_check` reach
    execution, or refuse (not-executable)?

    Mirrors the refusal ladder — context resolution, chain
    extraction, chain-length ceiling, file-binding hazard,
    interpreter availability — WITHOUT executing anything (the
    interpreter probe is memoized per process). Chain-existence
    consumers (the empty-dispatch synthesis routing) call this so a
    sanwit-only chain whose leg would refuse counts as NO dispatch:
    the leg only counts when it can actually run.
    """
    ctx, _ = resolve_context(hypothesis, cwe)
    if ctx is None:
        return False
    extraction = extract_chain(source or "", mentioned_sanitizers(hypothesis))
    if isinstance(extraction, ExtractionRefusal):
        return False
    if len(extraction.steps) > MAX_CHAIN_STEPS:
        return False
    if _file_binding_hazard(target_path, file_path):
        return False
    from ._execute import RuntimeUnavailable, resolve_php_runtime

    return not isinstance(resolve_php_runtime(), RuntimeUnavailable)


def is_detection_rule_id(rule_id: str) -> bool:
    """Every sanwit stamp is detection-grade in this cut: an executed
    breakout adjudicates the DEFENSE-insufficiency premise, not the
    attack path — it corroborates and aggregates (the two-namespace
    Bayesian seam), never convicts alone."""
    return (rule_id or "").startswith("sanwit:")


# ── the check ────────────────────────────────────────────────────────


def _base(
    file_path: str, function_name: str,
) -> dict[str, str]:
    return {"tool": "sanwit", "file_path": file_path,
            "function_name": function_name}


def _not_executable(
    file_path: str, function_name: str, reason: str, **extra: Any,
) -> SanwitResult:
    return SanwitResult(
        outcome="skipped", verdict="not-executable",
        rule_id="sanwit:not-executable",
        reason=reason, **_base(file_path, function_name), **extra,
    )


# Namespace / import declarations change what an unqualified builtin
# name binds to (a namespaced file can shadow htmlspecialchars,
# escapeshellarg, even ENT_QUOTES; `use function` / `use const`
# import shadows into non-namespaced files too) — the probe runs in
# the global namespace, so its binding would diverge from the
# target's in BOTH directions (a do-nothing shadow reads sufficient;
# a stricter shadow reads insufficient). Extraction cannot see this
# from the function source alone, so the FILE is scanned. The scan
# is code-aware (HTML prologue, comments, string literals and
# heredoc/nowdoc bodies are blanked first — a fixed-size head read
# was defeated by comment padding pushing the declaration past the
# head) and FAIL-CLOSED: a file larger than the scan budget refuses
# with the bound stamped rather than guessing.
# PHP keywords are case-insensitive: `NameSpace App;` and
# `USE FUNCTION strrev as htmlspecialchars;` are legal shadowing
# spellings, so both regexes must be too.
_NAMESPACE_DECL_RE = re.compile(
    r"(?:^|[;{}\s])namespace\s+[A-Za-z_\\][\w\\]{0,200}\s*[;{]",
    re.IGNORECASE,
)
_USE_IMPORT_RE = re.compile(
    r"(?:^|[;{}\s])use\s+(?:function|const)\s",
    re.IGNORECASE,
)

#: Binding-scan budget (bytes). PHP requires ``namespace`` to be the
#: first statement, but ``use function``/``use const`` may appear
#: between any top-level statements, so the whole file is scanned.
#: Larger admits bigger legitimate files at scan-time cost; smaller
#: refuses more of them (fail-closed, reason names the bound). 1 MiB
#: covers ordinary PHP sources with a wide margin.
_BINDING_SCAN_BUDGET = 1024 * 1024


def _blank_php_noncode(text: str) -> str:
    """Blank everything that is not live PHP code: the HTML prologue
    and inter-tag text, ``//``/``#``/``/* */`` comments, single- and
    double-quoted string contents, and heredoc/nowdoc bodies. The
    binding regexes then cannot match inside data, and a declaration
    buried behind ANY amount of comment padding is still seen."""
    out = list(text)
    i, n = 0, len(text)
    mode = "html"  # html | php | sq | dq | line | block
    while i < n:
        ch = text[i]
        if mode == "html":
            if ch == "<" and text[i:i + 5].lower() == "<?php":
                mode = "php"
                i += 5
                continue
            if ch == "<" and text[i:i + 2] == "<?":
                # Short / echo open tags.
                mode = "php"
                i += 2
                continue
            out[i] = " "
            i += 1
            continue
        if mode == "php":
            if ch == "?" and text[i:i + 2] == "?>":
                mode = "html"
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if ch in ("'", '"'):
                mode = "sq" if ch == "'" else "dq"
                i += 1
                continue
            if ch == "/" and text[i:i + 2] == "//":
                mode = "line"
                out[i] = " "
                i += 1
                continue
            if ch == "#":
                mode = "line"
                out[i] = " "
                i += 1
                continue
            if ch == "/" and text[i:i + 2] == "/*":
                mode = "block"
                out[i] = out[i + 1] = " "
                i += 2
                continue
            if ch == "<" and text[i:i + 3] == "<<<":
                # Heredoc/nowdoc: read the (optionally quoted)
                # identifier, then blank until a line starting
                # (after optional indent) with that identifier.
                j = i + 3
                while j < n and text[j] in " \t":
                    j += 1
                quote = ""
                if j < n and text[j] in ("'", '"'):
                    quote = text[j]
                    j += 1
                start_id = j
                while j < n and (text[j].isalnum() or text[j] == "_"):
                    j += 1
                ident = text[start_id:j]
                if quote and j < n and text[j] == quote:
                    j += 1
                if not ident:
                    # Malformed — blank the rest (fail closed).
                    for k in range(i, n):
                        out[k] = " "
                    return "".join(out)
                for k in range(i, j):
                    out[k] = " "
                end_re = re.compile(
                    r"^[ \t]*" + re.escape(ident) + r"\b", re.MULTILINE,
                )
                m = end_re.search(text, j)
                end = m.end() if m else n
                for k in range(j, end):
                    if text[k] != "\n":
                        out[k] = " "
                i = end
                continue
            i += 1
            continue
        if mode in ("sq", "dq"):
            if ch == "\\":
                out[i] = " "
                if i + 1 < n:
                    out[i + 1] = " "
                i += 2
                continue
            if (mode == "sq" and ch == "'") or (mode == "dq" and ch == '"'):
                mode = "php"
            else:
                out[i] = " "
            i += 1
            continue
        if mode == "line":
            if ch == "\n":
                mode = "php"
            else:
                out[i] = " "
            i += 1
            continue
        # block comment
        if ch == "*" and text[i:i + 2] == "*/":
            out[i] = out[i + 1] = " "
            mode = "php"
            i += 2
            continue
        if ch != "\n":
            out[i] = " "
        i += 1
    return "".join(out)


def _file_binding_hazard(target_path: Path | str, file_path: str) -> str:
    """Refusal reason when the target FILE declares a namespace or
    imports functions/constants, else ''.

    A missing/unreadable file (source-only callers, tests) yields ''
    — that residual is stated in the receipt policy rather than
    silently guessed. A file over the scan budget refuses (fail
    closed) with the bound named.
    """
    base = Path(target_path)
    full = base / file_path
    try:
        if not str(full.resolve()).startswith(str(base.resolve())):
            return ""
        with open(full, "rb") as fh:
            raw = fh.read(_BINDING_SCAN_BUDGET + 1)
    except (OSError, ValueError):
        return ""
    if len(raw) > _BINDING_SCAN_BUDGET:
        return (
            f"target file exceeds the {_BINDING_SCAN_BUDGET}-byte "
            "binding-scan budget — namespace/import declarations "
            "cannot be ruled out (fail closed)"
        )
    code = _blank_php_noncode(raw.decode("utf-8", errors="replace"))
    if _NAMESPACE_DECL_RE.search(code):
        return (
            "target file declares a namespace — unqualified builtin "
            "names (functions and constants) may bind to "
            "namespace-local shadows, so the probe's global binding "
            "is not verifiably the target's"
        )
    if _USE_IMPORT_RE.search(code):
        return (
            "target file imports functions or constants (use "
            "function / use const) — unqualified builtin names may "
            "bind to the import, so the probe's global binding is "
            "not verifiably the target's"
        )
    return ""


def run_sanwit_check(
    target_path: Path | str,
    file_path: str,
    function_name: str,
    hypothesis: str,
    *,
    source: str = "",
    cwe: str = "",
    audit_run_dir: Path | None = None,
) -> SanwitResult:
    """Execute the sanitizer-sufficiency witness for one hypothesis.

    ``target_path`` feeds exactly one read: a bounded head check of
    the target FILE for namespace / use-function declarations (the
    binding-divergence refusal) — nothing else from the tree is read
    or executed. Source-only callers (no readable file) skip that
    check; the residual is stated in the module docs.
    """
    ctx, why = resolve_context(hypothesis, cwe)
    if ctx is None:
        return _not_executable(file_path, function_name, why)

    names = mentioned_sanitizers(hypothesis)
    extraction = extract_chain(source or "", names)
    if isinstance(extraction, ExtractionRefusal):
        return _not_executable(
            file_path, function_name,
            f"extraction refused: {extraction.reason}",
            context_id=ctx.context_id, family=ctx.family,
        )
    hazard = _file_binding_hazard(target_path, file_path)
    if hazard:
        return _not_executable(
            file_path, function_name, hazard,
            context_id=ctx.context_id, family=ctx.family,
        )
    if len(extraction.steps) > MAX_CHAIN_STEPS:
        return _not_executable(
            file_path, function_name,
            f"extracted chain has {len(extraction.steps)} steps — "
            f"over the {MAX_CHAIN_STEPS}-step ceiling",
            context_id=ctx.context_id, family=ctx.family,
        )
    chain_templates = [
        _escape(step.template(), _CHAIN_TEMPLATE_CAP)
        for step in extraction.steps
    ]

    from ._execute import (
        RuntimeUnavailable,
        execute_probe,
        resolve_php_runtime,
    )

    runtime = resolve_php_runtime()
    if isinstance(runtime, RuntimeUnavailable):
        return _not_executable(
            file_path, function_name, runtime.reason,
            context_id=ctx.context_id, family=ctx.family,
            chain=chain_templates, subject_var=extraction.subject_var,
        )

    token = secrets.token_hex(8)
    probe_src = generate_probe(extraction.steps, token)
    exec_outcome = execute_probe(
        runtime, probe_src, payloads_document(ctx.corpus),
        audit_run_dir=audit_run_dir,
    )
    common: dict[str, Any] = {
        "context_id": ctx.context_id, "family": ctx.family,
        "chain": chain_templates,
        "subject_var": extraction.subject_var,
        "interpreter": runtime.describe(),
        "corpus_size": len(ctx.corpus),
    }
    if exec_outcome.floor_refusal:
        return _not_executable(
            file_path, function_name,
            f"sandbox floor: {exec_outcome.reason}", **common,
        )
    if not exec_outcome.ok:
        return SanwitResult(
            outcome="error", verdict="error",
            rule_id="sanwit:error", reason=exec_outcome.reason,
            errors=[exec_outcome.reason],
            **_base(file_path, function_name), **common,
        )

    run = parse_probe_output(exec_outcome.stdout, token)
    if isinstance(run, str):
        return SanwitResult(
            outcome="error", verdict="error",
            rule_id="sanwit:error",
            reason=f"unauthenticated/unparseable probe output: {run}",
            errors=[run],
            **_base(file_path, function_name), **common,
        )
    if run.php_version:
        common["interpreter"] = {
            **common["interpreter"], "version": run.php_version,
        }
    return _adjudicate(
        ctx, run, file_path, function_name, common,
    )


def _adjudicate(
    ctx: SinkContext,
    run: ProbeRun,
    file_path: str,
    function_name: str,
    common: dict[str, Any],
) -> SanwitResult:
    """Fold per-payload predicate results into the channel verdict.

    A breakout is an existential claim — one authenticated exhibit
    carries it even when other payloads errored. Sufficiency is a
    universal claim over the corpus — any errored, truncated or
    missing payload poisons it (outcome ``error``, never
    "sufficient").
    """
    exhibits: list[dict[str, str]] = []
    indeterminate: list[str] = []
    for payload_id, payload in ctx.corpus:
        if payload_id in run.errors:
            indeterminate.append(
                f"{payload_id}: {_escape(run.errors[payload_id], 200)}",
            )
            continue
        if payload_id not in run.outputs:
            indeterminate.append(f"{payload_id}: no output")
            continue
        if run.truncated.get(payload_id):
            indeterminate.append(f"{payload_id}: output truncated")
            continue
        output = run.outputs[payload_id]
        check = ctx.predicate(output)
        if check.breakout:
            exhibits.append({
                "payload_id": payload_id,
                "payload": _escape(payload, 64),
                "output": _escape(output, _EXHIBIT_OUTPUT_CAP),
                "detail": check.detail,
            })
    if exhibits:
        first = exhibits[0]
        return SanwitResult(
            outcome="confirmed", verdict="insufficient",
            rule_id=f"sanwit:insufficient:{ctx.context_id}",
            reason=(
                f"executed chain does not neutralize the "
                f"{ctx.context_id} breakout class: payload "
                f"{first['payload_id']!r} — {first['detail']}"
            ),
            exhibits=exhibits[:4],
            errors=indeterminate,
            **_base(file_path, function_name), **common,
        )
    if indeterminate:
        return SanwitResult(
            outcome="error", verdict="error",
            rule_id="sanwit:error",
            reason=(
                "chain execution indeterminate for "
                f"{len(indeterminate)}/{len(ctx.corpus)} payloads — "
                "sufficiency cannot be adjudicated"
            ),
            errors=indeterminate,
            **_base(file_path, function_name), **common,
        )
    version = common.get("interpreter", {}).get("version", "?")
    return SanwitResult(
        outcome="inconclusive", verdict="sufficient",
        rule_id=f"sanwit:sufficient:{ctx.context_id}",
        reason=(
            f"executed chain neutralized the tested breakout corpus "
            f"({len(ctx.corpus)} payloads) for context "
            f"{ctx.context_id} on PHP {version} — corpus-bounded and "
            "context-scoped; says nothing about other contexts and "
            "is not a clean verdict"
        ),
        **_base(file_path, function_name), **common,
    )
