"""Coccinelle adapter — hypothesis validation via SmPL semantic patches.

Coccinelle is the right tool when the hypothesis is about C-level patterns,
inconsistencies across callers, or control-flow shape (lock balance, NULL
checks, error paths). The LLM-generated rule is written in SmPL.

Security: SmPL supports `@script:python@`, `@script:ocaml@`, `@finalize:`,
and `@initialize:` blocks that execute code in the spatch process. An
LLM-generated rule containing such blocks could exfiltrate data, fork
shells, or otherwise abuse host privileges. This adapter REJECTS any
rule containing these annotations. The COCCIRESULT extraction harness
is injected by packages/coccinelle.runner._inject_harness — LLM-supplied
rules must contain only declarative SmPL patterns.
"""

import re
from pathlib import Path
from tempfile import NamedTemporaryFile

from packages import coccinelle as coccinelle_pkg

from .base import ToolAdapter, ToolCapability, ToolEvidence, make_sandbox_runner


# Annotations that introduce code execution into SmPL. Any of these in a
# rule body (after the `@`) means the LLM is trying to run code, not match
# patterns. We refuse such rules outright rather than try to neutralise.
_FORBIDDEN_ANNOTATION_RE = re.compile(
    r"@\s*(script\s*:|finalize\s*:|initialize\s*:)",
    re.IGNORECASE,
)


def _contains_forbidden_blocks(rule: str) -> bool:
    """Return True when the rule has @script:, @finalize:, or @initialize:.

    Comments are not stripped first — SmPL `//` comments don't span `@` lines
    in practice, and being conservative (rejecting commented-out script
    blocks too) is acceptable. It does mean prose mentioning the literal
    annotations trips the gate, so the shipped syntax example (the text
    the LLM mirrors) deliberately avoids spelling them out. See
    _FORBIDDEN_ANNOTATION_RE for the matched syntax.
    """
    return bool(_FORBIDDEN_ANNOTATION_RE.search(rule))


# Tokens that packages/coccinelle's runner keys its COCCIRESULT
# extraction-harness injection on (raw substring checks over the whole
# rule text, comments included). A rule carrying either token would run
# WITHOUT the harness, emit no COCCIRESULT lines, and read as a clean
# "no matches" — silently turning a rule that actually matched into a
# refutation. Reject such rules up front: an LLM-generated declarative
# rule never legitimately contains them (RAPTOR injects the result
# scripting itself).
_HARNESS_SUPPRESSING_TOKENS = ("script:python", "COCCIRESULT:")


def _contains_harness_suppressors(rule: str) -> bool:
    """True when the rule text would disable result-harness injection."""
    return any(tok in rule for tok in _HARNESS_SUPPRESSING_TOKENS)


_SYNTAX_EXAMPLE = """\
// Find malloc() return values used without a NULL check.
// Write the matching pattern only — RAPTOR injects the result-extraction
// script automatically. Rules that carry their own script, finalize, or
// initialize annotations are rejected.
@unchecked@
expression E;
position p;
identifier fld;
@@

* E@p = malloc(...);
... when != \\(E == NULL\\|!E\\|IS_ERR(E)\\)
* E->fld
"""


class CoccinelleAdapter(ToolAdapter):
    """Adapter wrapping packages/coccinelle/ for hypothesis validation.

    Args:
        sandbox: When True (default), run spatch in a network-blocked
            sandbox via core.sandbox.run. Falls back gracefully to
            subprocess.run when the sandbox isn't available on the host.
            Set False for tests or trusted environments.
    """

    def __init__(self, *, sandbox: bool = True) -> None:
        self._sandbox = sandbox

    @property
    def name(self) -> str:
        return "coccinelle"

    def is_available(self) -> bool:
        return coccinelle_pkg.is_available()

    def describe(self) -> ToolCapability:
        return ToolCapability(
            name=self.name,
            good_for=[
                "Inconsistency detection across callers (e.g. 'find callers that don't check the return of foo')",
                "Lock/unlock symmetry, refcount balance, error-path cleanup",
                "NULL-check enforcement after allocation",
                "Pattern matching with control-flow awareness via the ... operator",
                "C and C++ source",
            ],
            bad_for=[
                "Inter-procedural dataflow tracking — use codeql instead",
                "Path satisfiability / concrete value reasoning — use smt instead",
                "Languages other than C/C++",
                "Pure regex matching with no semantic content — use semgrep",
            ],
            syntax_example=_SYNTAX_EXAMPLE,
            languages=["c", "cpp"],
        )

    def run(
        self,
        rule: str,
        target: Path,
        *,
        timeout: int = 300,
        env: dict[str, str] | None = None,
    ) -> ToolEvidence:
        if not self.is_available():
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error="spatch is not installed",
            )

        if not rule or not rule.strip():
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error="empty rule",
            )

        if _contains_forbidden_blocks(rule):
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error=(
                    "rule contains @script:, @finalize:, or @initialize: "
                    "blocks; LLM-generated rules must contain only "
                    "declarative SmPL — RAPTOR injects the result-extraction "
                    "scripting itself"
                ),
            )

        if _contains_harness_suppressors(rule):
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error=(
                    "rule contains text ('script:python' or 'COCCIRESULT:') "
                    "that would disable RAPTOR's result-extraction harness "
                    "and make every run read as 'no matches'; remove it — "
                    "RAPTOR injects the result scripting itself"
                ),
            )

        if env is None:
            from core.config import RaptorConfig
            env = RaptorConfig.get_safe_env()

        # spatch needs the rule as a file. Write to temp then run.
        rule_file: Path | None = None
        try:
            with NamedTemporaryFile(
                prefix="cocci_hv_", suffix=".cocci",
                mode="w", delete=False,
            ) as tmp:
                # Record the path before writing so the finally-unlink
                # below also covers a failed write — delete=False files
                # otherwise leak on ENOSPC/EIO.
                rule_file = Path(tmp.name)
                tmp.write(rule)

            subprocess_runner = (
                make_sandbox_runner(target=target) if self._sandbox else None
            )
            result = coccinelle_pkg.run_rule(
                target=target,
                rule=rule_file,
                timeout=timeout,
                env=env,
                subprocess_runner=subprocess_runner,
            )
        except OSError as e:
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error=f"failed to invoke spatch: {e}",
            )
        finally:
            if rule_file is not None:
                try:
                    rule_file.unlink()
                except OSError:
                    pass

        if not result.ok:
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error="; ".join(result.errors) or f"spatch returned {result.returncode}",
            )

        matches = [m.to_dict() for m in result.matches]
        n = len(matches)
        files = sorted({m["file"] for m in matches if m.get("file")})
        if n:
            summary = f"{n} match{'es' if n != 1 else ''} in {len(files)} file{'s' if len(files) != 1 else ''}"
        else:
            summary = "no matches"

        return ToolEvidence(
            tool=self.name,
            rule=rule,
            success=True,
            matches=matches,
            summary=summary,
        )
