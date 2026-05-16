"""Semgrep adapter — hypothesis validation via Semgrep YAML rules.

Semgrep is the right tool when the hypothesis is a syntactic or local-flow
pattern that crosses many languages, or when the LLM has identified a
specific construct to find across the codebase. The LLM-generated rule is
written in Semgrep YAML.
"""

from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Dict, Optional

from packages import semgrep as semgrep_pkg

from .base import ToolAdapter, ToolCapability, ToolEvidence, make_sandbox_runner


_SYNTAX_EXAMPLE = """\
rules:
  - id: hardcoded-secret
    message: Hardcoded credential assigned to $VAR
    severity: WARNING
    languages: [python, javascript]
    pattern-either:
      - pattern: $VAR = "..."
      - pattern: $VAR = '...'
    pattern-where:
      - metavariable-regex:
          metavariable: $VAR
          regex: (?i)(password|secret|token|api[_-]?key)
"""


class SemgrepAdapter(ToolAdapter):
    """Adapter wrapping packages/semgrep/ for hypothesis validation.

    Args:
        sandbox: When True (default), run semgrep in a network-blocked
            sandbox via core.sandbox.run. Falls back gracefully to
            subprocess.run when the sandbox isn't available on the host.
            Set False for tests or trusted environments.
    """

    def __init__(self, *, sandbox: bool = True):
        self._sandbox = sandbox

    @property
    def name(self) -> str:
        return "semgrep"

    def is_available(self) -> bool:
        return semgrep_pkg.is_available()

    def describe(self) -> ToolCapability:
        return ToolCapability(
            name=self.name,
            good_for=[
                "Syntactic pattern matching across many languages",
                "Metavariable patterns ($X, $FUNC) with type/regex constraints",
                "Local-flow patterns (taint mode) within a function",
                "Multi-language scans where the same pattern applies broadly",
                "Quick checks that don't require full control-flow analysis",
            ],
            bad_for=[
                "Inter-procedural dataflow — use codeql instead",
                "Control-flow-sensitive C-specific patterns (locks, error paths) — use coccinelle",
                "Path satisfiability / concrete trigger inputs — use smt",
                "Semantic equivalence (different code shapes meaning the same thing)",
            ],
            syntax_example=_SYNTAX_EXAMPLE,
            languages=["python", "javascript", "typescript", "java", "go", "ruby", "c", "cpp", "rust"],
        )

    def run(
        self,
        rule: str,
        target: Path,
        *,
        timeout: int = 300,
        env: Optional[Dict[str, str]] = None,
    ) -> ToolEvidence:
        if not self.is_available():
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error="semgrep is not installed",
            )

        if not rule or not rule.strip():
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error="empty rule",
            )

        if env is None:
            from core.config import RaptorConfig
            env = RaptorConfig.get_safe_env()

        rule_file: Optional[Path] = None
        try:
            tmp = NamedTemporaryFile(
                prefix="semgrep_hv_", suffix=".yaml",
                mode="w", delete=False,
            )
            tmp.write(rule)
            tmp.close()
            rule_file = Path(tmp.name)

            subprocess_runner = (
                make_sandbox_runner(target=target) if self._sandbox else None
            )
            result = semgrep_pkg.run_rule(
                target=target,
                config=str(rule_file),
                timeout=timeout,
                env=env,
                subprocess_runner=subprocess_runner,
            )
        except OSError as e:
            return ToolEvidence(
                tool=self.name, rule=rule, success=False,
                error=f"failed to invoke semgrep: {e}",
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
                error="; ".join(result.errors) or f"semgrep returned {result.returncode}",
            )

        matches = [f.to_dict() for f in result.findings]
        n = len(matches)
        files = sorted({m["file"] for m in matches if m.get("file")})
        if n:
            summary = f"{n} finding{'s' if n != 1 else ''} in {len(files)} file{'s' if len(files) != 1 else ''}"
        else:
            summary = "no findings"

        return ToolEvidence(
            tool=self.name,
            rule=rule,
            success=True,
            matches=matches,
            summary=summary,
        )
