"""Coccinelle (spatch) dispatch for /understand --hunt — C/C++ targets.

Implements the same ``HuntDispatchFn`` shape as
``hunt_dispatch.default_hunt_dispatch`` so the substrate (multi-model
orchestrator + ``VariantAdapter``) treats it as a drop-in alternative
backend. The difference is what does the work:

  default_hunt_dispatch  → LLM with sandboxed Read/Grep/Glob tools
                          (works on any language, but text-grep
                          precision on C is poor; one variant search
                          is N LLM tool-call rounds)
  cocci_hunt_dispatch    → 1 LLM call to translate the natural-language
                          pattern into a Coccinelle semantic patch
                          (.cocci rule), then ``spatch`` does the
                          AST-level matching deterministically

Cocci is C/C++-only. For other-language targets the dispatch returns
an error variant the substrate filters cleanly into ``failed_models``,
matching how other-shape failures (provider-construction error, bad
repo path) surface today.

Cost / latency profile:
  * 1 LLM round-trip per call, output capped to a small .cocci file
    (~200 tokens). Compares to the LLM-grep dispatch's typical 10-30
    Read/Grep tool rounds plus a final analysis turn.
  * spatch wall-clock dominates: 5-30s on a typical kernel-sized
    subdirectory, deterministic regardless of model temperature.
  * Result quality: AST-level matches, no false hits from text-pattern
    coincidence. Trade-off: pattern must be expressible in SmPL —
    structural patterns work cleanly, semantic ones (data-flow
    properties) need to defer to other tools (CodeQL / IRIS) or fall
    back to the LLM dispatch.

This dispatch is opt-in via ``--hunt-tool=cocci`` on the /understand
CLI. ``--hunt-tool=auto`` (the default once wired) picks cocci when:
  (a) ``spatch`` is on PATH (``packages.coccinelle.runner.is_available``)
  (b) repo contains C/C++ source files (heuristic: any .c/.h/.cpp/.hpp)
otherwise falls through to the default LLM dispatch.
"""

from __future__ import annotations

import logging
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from core.llm.config import ModelConfig
from core.llm.providers import create_provider
from packages.coccinelle.models import SpatchResult
from packages.coccinelle.runner import is_available as spatch_is_available
from packages.coccinelle.runner import run_rule as spatch_run_rule

logger = logging.getLogger(__name__)


# Per-call wall-clock + spatch-execution caps. spatch's own --timeout
# applies per-rule on the spatch side; these are the dispatch-level
# safety nets.
DEFAULT_RULE_TIMEOUT_S = 120
# Rule-translation LLM call has tiny output (the rule text); this is
# a rough cap for the model-side budget. Caller can override.
DEFAULT_RULE_GEN_MAX_COST_USD = 0.05


# Heuristic: does this repo look like C/C++? Used by `--hunt-tool=auto`
# to decide whether to route through cocci. Exposed as a function so
# the caller can short-circuit the dispatch entirely (saves the
# spatch_is_available probe + LLM rule-gen call) for non-C targets.
_C_FILE_EXTS: tuple[str, ...] = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh")


def repo_looks_c_cpp(repo_path: str, max_files_to_check: int = 200) -> bool:
    """Heuristic check that the repo has C/C++ source. Bounded scan
    so giant repos don't pay a rglob walk to discover the obvious."""
    p = Path(repo_path)
    if not p.is_dir():
        return False
    seen = 0
    for entry in p.rglob("*"):
        if not entry.is_file():
            continue
        seen += 1
        if entry.suffix.lower() in _C_FILE_EXTS:
            return True
        if seen >= max_files_to_check:
            return False
    return False


# ---------------------------------------------------------------------
# Pattern → Coccinelle rule
# ---------------------------------------------------------------------


_RULE_GEN_SYSTEM = """\
You are a Coccinelle (spatch) rule writer. Your sole job is to translate
a natural-language description of a vulnerability/code pattern into a
Coccinelle semantic patch (.cocci rule) that finds instances of that
pattern in C source code.

Output format: ONLY the rule text, between ```cocci and ``` fences.
No prose, no preamble.

Rule shape — follow this template exactly:

    @r@
    <metavariable declarations, e.g. "expression e1, e2;">
    position p;
    @@
    <pattern with @p attached to the syntax-element you want to flag>

Hard requirements:
  * Exactly ONE named rule block named ``@r@``.
  * The rule MUST declare a ``position p;`` metavariable and attach
    ``@p`` to the construct you want flagged
    (e.g. ``strcpy@p(e1, e2)`` or ``foo@p(...)``).
  * NO ``script:python`` or ``script:ocaml`` blocks. The dispatcher
    auto-injects a Python reporting harness that reads ``r.p`` and
    emits the structured output the parser expects. Adding your own
    script block prevents the harness from being injected and the
    matches won't be parsed.
  * NO transformations (no ``+`` / ``-`` lines that would rewrite
    code). Matching only.
  * Prefer false negatives over false positives. If the pattern is
    ambiguous, encode the strictest reading.
  * Use ``<+...+>`` only when the body is intended to be flexible.

If the pattern needs information that is not structurally available
in C (e.g. taint flow, runtime values, "is this attacker-controlled"),
output exactly:

    UNTRANSLATABLE: <one-sentence reason>

The dispatcher surfaces that and the operator can fall back to the
LLM-grep hunt or use a dataflow tool (CodeQL / IRIS).

Example (for "find all strcpy calls"):

    @r@
    expression e1, e2;
    position p;
    @@
    strcpy@p(e1, e2)
"""


_RULE_FENCE_RE = re.compile(
    r"```cocci\s*\n(.*?)```",
    re.DOTALL | re.IGNORECASE,
)


def _strip_fences(text: str) -> str:
    """Pull the rule text out of ```cocci ... ``` fences. If the model
    returned plain text without fences, take the whole thing."""
    m = _RULE_FENCE_RE.search(text)
    if m:
        return m.group(1).strip()
    return text.strip()


_POS_DECL_RE = re.compile(r"position\s+(\w+)\s*;")
_RULE_HEAD_RE = re.compile(r"@(\w+)@")


def _inject_reporter_harness(rule_text: str) -> str:
    """Append a ``script:python`` block that emits one ``COCCIRESULT:``
    JSON line per matched position. Mirrors what
    ``packages.coccinelle.runner._inject_harness`` does — but pre-
    inject here so the runner's broken stdin-rule codepath
    (``--sp-file -`` not supported by some spatch builds) is
    avoided. The runner sees a rule that already has
    ``script:python``, leaves it alone, and runs from the file path.

    If the rule already has a script block (e.g. operator-authored
    or LLM that ignored the system-prompt rules), pass it through
    unchanged. Same applies if there's no ``position`` metavariable
    declared — without one, the harness can't bind anything to
    report.
    """
    if "script:python" in rule_text or "script:ocaml" in rule_text:
        return rule_text
    pos_match = _POS_DECL_RE.search(rule_text)
    if not pos_match:
        return rule_text
    rule_names = _RULE_HEAD_RE.findall(rule_text)
    if not rule_names:
        return rule_text
    pos_var = pos_match.group(1)
    rule_id = rule_names[0]
    # Output goes to stderr so the runner's _parse_results can find
    # it (the runner reads both stdout and stderr).
    harness = (
        f"\n\n@script:python@\n"
        f"{pos_var} << {rule_id}.{pos_var};\n"
        f"@@\n"
        f"\n"
        f"import json, sys\n"
        f"for _p in {pos_var}:\n"
        f'    _m = {{"file": _p.file, "line": int(_p.line), '
        f'"col": int(_p.column), '
        f'"line_end": int(_p.line_end), '
        f'"col_end": int(_p.column_end), '
        f'"rule": "understand-hunt-cocci"}}\n'
        f'    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\\n")\n'
    )
    return rule_text + harness


def translate_pattern_to_cocci_rule(
    pattern: str,
    *,
    model: ModelConfig,
    max_cost_usd: float = DEFAULT_RULE_GEN_MAX_COST_USD,
) -> "Optional[str]":
    """Single-turn LLM call: pattern → cocci rule text. Returns None
    when the model declared the pattern UNTRANSLATABLE (caller falls
    back to LLM-grep hunt or surfaces the reason)."""
    provider = create_provider(model)

    # Single-turn — no tool use, no agentic loop. ``LLMProvider.generate``
    # is the canonical text-only interface every provider implements
    # (see core/llm/providers.py:143). Falling back to a manual
    # turn-loop would be over-engineering for a one-shot call.
    user_message = (
        f"Translate this pattern into a Coccinelle .cocci rule:\n\n"
        f"{pattern}\n"
    )
    response = provider.generate(
        prompt=user_message,
        system_prompt=_RULE_GEN_SYSTEM,
        max_tokens=600,
    )
    text = (getattr(response, "content", "") or "").strip()
    if not text:
        return None
    if text.upper().startswith("UNTRANSLATABLE"):
        logger.info(
            "cocci_hunt: pattern declared untranslatable: %s",
            text.split(":", 1)[-1].strip()[:200],
        )
        return None
    rule_text = _strip_fences(text)
    if not rule_text:
        return None
    return rule_text


# ---------------------------------------------------------------------
# Spatch result → variant dicts
# ---------------------------------------------------------------------


def _spatch_matches_to_variants(
    result: SpatchResult,
    repo_path: str,
) -> List[Dict[str, Any]]:
    """Translate ``SpatchResult.matches`` into the variant-dict shape
    that ``VariantAdapter`` expects: file (relative to repo), line,
    function (best-effort empty unless the rule emitted it), snippet
    (the rule's emitted message), confidence."""
    repo = Path(repo_path).resolve()
    out: List[Dict[str, Any]] = []
    for m in result.matches:
        # Normalize file paths to repo-relative when we can. The
        # VariantAdapter's dedup key includes the file path; an
        # absolute spatch-emitted path would bucket separately
        # from the repo-relative path the LLM dispatch emits.
        file_rel = m.file
        try:
            mp = Path(m.file)
            if mp.is_absolute():
                file_rel = str(mp.resolve().relative_to(repo))
        except (ValueError, OSError):
            pass  # leave as-is; cross-FS or non-repo file
        out.append({
            "file": file_rel,
            "line": int(m.line) if m.line else 0,
            "function": "",  # spatch's COCCIRESULT format doesn't
                             # include enclosing function by default;
                             # a future enhancement could add it
                             # via metavariable capture.
            "snippet": m.message or "",
            "confidence": "high",  # AST-level match — high signal
            "tool": "coccinelle",
        })
    return out


# ---------------------------------------------------------------------
# Dispatch entry point
# ---------------------------------------------------------------------


def cocci_hunt_dispatch(
    model: ModelConfig,
    pattern: str,
    repo_path: str,
    *,
    rule_timeout_s: int = DEFAULT_RULE_TIMEOUT_S,
    rule_gen_max_cost_usd: float = DEFAULT_RULE_GEN_MAX_COST_USD,
    spatch_runner: Optional[Callable] = None,
    sandbox: bool = True,
) -> List[Dict[str, Any]]:
    """``HuntDispatchFn`` implementation backed by Coccinelle.

    Same call shape as ``default_hunt_dispatch`` so the substrate's
    ``hunt(...)`` orchestrator treats it as a drop-in alternative.
    Errors are returned as a single-element list with an ``"error"``
    key — substrate convention for ``failed_models`` capture.

    ``sandbox`` (default True) runs spatch through ``core.sandbox.run``
    via ``make_sandbox_runner``. Critical: cocci rules CAN embed
    ``script:python`` blocks that execute as part of the spatch
    process. The dispatch's rule text is LLM-emitted, and the LLM's
    pattern input is operator-influenced — combined, that's
    arbitrary-code-exec inside the process invoking spatch. The
    sandbox locks reads to ``target``, blocks network, and uses a
    fake $HOME so even a compromised rule can't exfiltrate. Tests
    pass ``sandbox=False`` for speed; production callers should
    take the default. Falls back to plain ``subprocess.run`` on
    hosts where the sandbox isn't available (non-Linux/macOS,
    minimal containers) — degrade-not-fail. ``spatch_runner``
    overrides everything (lets tests inject a fully-stubbed runner).
    """
    if not isinstance(pattern, str) or not pattern.strip():
        return [{"error": "pattern must be a non-empty string"}]
    pattern = pattern.strip()

    if not Path(repo_path).is_dir():
        return [{"error": f"invalid repo_path: {repo_path!r} is not a directory"}]

    if not spatch_is_available():
        return [{"error": (
            "coccinelle (spatch) is not installed; install via your "
            "package manager (e.g. apt install coccinelle) or use "
            "--hunt-tool=llm to fall back to the LLM-grep dispatch"
        )}]

    if not repo_looks_c_cpp(repo_path):
        return [{"error": (
            "target repo has no C/C++ source files; coccinelle is "
            "C/C++-only — use --hunt-tool=llm or --hunt-tool=auto "
            "for other-language targets"
        )}]

    # Step 1: translate the pattern into a cocci rule via 1 LLM call.
    try:
        rule_text = translate_pattern_to_cocci_rule(
            pattern, model=model,
            max_cost_usd=rule_gen_max_cost_usd,
        )
    except Exception as exc:  # noqa: BLE001 - any provider failure
        logger.warning(
            "cocci_hunt: rule-gen call failed for model %s: %s",
            getattr(model, "model_name", "?"), exc,
        )
        return [{"error": (
            f"rule-gen LLM call failed: {type(exc).__name__}: {exc}"
        )}]
    if rule_text is None:
        return [{"error": (
            "pattern declared UNTRANSLATABLE by the rule-gen model "
            "(or model returned empty) — fall back to --hunt-tool=llm "
            "for natural-language pattern hunting, or use a dataflow "
            "tool (CodeQL / IRIS) for taint-shaped patterns"
        )}]

    # Step 2: pre-inject a reporting harness so the rule emits
    # ``COCCIRESULT:`` JSON on each match (the format
    # ``packages.coccinelle.runner._parse_results`` reads). The
    # runner has its own auto-injection codepath but it routes
    # through ``spatch --sp-file -`` (stdin), which fails with
    # ``Sys_error("-: No such file or directory")`` on the spatch
    # version we use today. Pre-injecting here keeps the runner
    # on its file-path codepath. Follow-up: fix the auto-injection
    # path in the runner.
    rule_text = _inject_reporter_harness(rule_text)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".cocci", delete=False,
    ) as fh:
        fh.write(rule_text)
        rule_path = Path(fh.name)

    # Sandbox spatch by default — see docstring. Caller's explicit
    # ``spatch_runner=`` wins (used by tests to inject mocks).
    effective_runner = spatch_runner
    if effective_runner is None and sandbox:
        try:
            from packages.hypothesis_validation.adapters.base import (
                make_sandbox_runner,
            )
            effective_runner = make_sandbox_runner(
                target=Path(repo_path),
                caller_label="understand-hunt-cocci",
            )
        except ImportError:
            # hypothesis_validation isn't a hard dependency of
            # /understand. If it's missing, fall back to unsandboxed
            # plain subprocess.run via the runner's default. Log so
            # operators can audit.
            logger.warning(
                "cocci_hunt: make_sandbox_runner unavailable; "
                "spatch will run unsandboxed",
            )

    try:
        result: SpatchResult = spatch_run_rule(
            target=Path(repo_path),
            rule=rule_path,
            timeout=rule_timeout_s,
            no_includes=True,  # operator targets are untrusted
            subprocess_runner=effective_runner,
        )
    except Exception as exc:  # noqa: BLE001 - spatch wrapper failure
        return [{"error": (
            f"spatch invocation failed: {type(exc).__name__}: {exc}"
        )}]
    finally:
        try:
            rule_path.unlink()
        except OSError:
            pass

    if not result.ok and not result.matches:
        # Nothing matched AND spatch reported errors — surface the
        # error so the operator can refine the pattern. (Empty
        # matches with rc=0 is a legitimate "no variants found"
        # answer — return [] in that case.)
        err = "; ".join(result.errors)[:500] if result.errors else (
            f"spatch returncode {result.returncode}"
        )
        return [{"error": f"cocci rule did not execute cleanly: {err}"}]

    return _spatch_matches_to_variants(result, repo_path)
