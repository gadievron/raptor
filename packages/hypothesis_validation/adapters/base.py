"""Tool adapter protocol — the contract every adapter implements.

The runner depends only on this interface. Adapters wrap concrete tools
(Coccinelle, Semgrep, CodeQL, SMT) and expose a uniform run-a-rule
operation plus a self-describing capability summary the runner uses to
build the LLM prompt.

Sandboxing: by default, all subprocess-based adapters (Coccinelle,
Semgrep, CodeQL) engage core.sandbox.run with block_network=True so an
LLM-generated rule cannot exfiltrate data over the network. Callers
that need to disable the sandbox (tests, trusted environments where
performance dominates) construct adapters with sandbox=False. The SMT
adapter is sandbox-free because it never spawns a subprocess.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


@dataclass
class ToolCapability:
    """Self-description of what a tool is good (and bad) at.

    The runner concatenates these into the LLM's system prompt so the
    LLM picks the right tool for each hypothesis. The descriptions are
    written for an LLM audience: concise, honest about limitations, with
    one syntax example so the LLM can mirror the style.

    Attributes:
        name: Stable identifier (e.g. "coccinelle"). Used in prompts and
            in Evidence.tool. Must match the registered adapter name.
        good_for: Bullet-list strings describing what hypotheses this tool
            can validate well.
        bad_for: Bullet-list strings describing classes of hypothesis that
            this tool will not handle — steers the LLM to a different tool.
        syntax_example: A minimal worked example of a rule the LLM can
            mirror. Should illustrate the most important construct (e.g.
            position metavariables for Coccinelle, pattern syntax for
            Semgrep).
        languages: Languages this tool supports. Empty means language-agnostic
            or determined by rules; runner displays it as informational.
    """

    name: str
    good_for: List[str] = field(default_factory=list)
    bad_for: List[str] = field(default_factory=list)
    syntax_example: str = ""
    languages: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "good_for": list(self.good_for),
            "bad_for": list(self.bad_for),
            "syntax_example": self.syntax_example,
            "languages": list(self.languages),
        }

    def render_for_prompt(self) -> str:
        """Format the capability as plain text for the LLM system prompt."""
        lines = [f"## {self.name}"]
        if self.languages:
            lines.append(f"Languages: {', '.join(self.languages)}")
        if self.good_for:
            lines.append("Good for:")
            for item in self.good_for:
                lines.append(f"  - {item}")
        if self.bad_for:
            lines.append("Not for:")
            for item in self.bad_for:
                lines.append(f"  - {item}")
        if self.syntax_example:
            lines.append("Example:")
            lines.append("```")
            lines.append(self.syntax_example.strip())
            lines.append("```")
        return "\n".join(lines)


@dataclass
class ToolInvocation:
    """Record of a single tool run — the auditable command trail.

    The runner attaches this to evidence so a human reviewer can re-run
    any invocation. Stores the exact rule text the LLM generated, the
    target, and any tool-specific args.
    """

    tool: str
    rule: str
    target: str
    args: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "rule": self.rule,
            "target": self.target,
            "args": dict(self.args),
        }


@dataclass
class ToolEvidence:
    """Result of running a tool with one rule.

    Adapters build this from their tool-specific result objects. The
    runner converts ToolEvidence → Evidence (in result.py) when assembling
    the final ValidationResult.
    """

    tool: str
    rule: str
    success: bool
    matches: List[Dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    error: str = ""

    @property
    def confirms(self) -> bool:
        """True when the tool ran cleanly and produced matches."""
        return self.success and bool(self.matches)

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "rule": self.rule,
            "success": self.success,
            "matches": list(self.matches),
            "summary": self.summary,
            "error": self.error,
        }


def make_sandbox_runner(
    *,
    target: Path,
    output: Optional[Path] = None,
    block_network: bool = True,
    caller_label: str = "hypothesis-validation",
) -> Callable:
    """Build a subprocess-runner-shaped callable that wraps core.sandbox.run.

    The returned callable has the same signature as subprocess.run for the
    kwargs the runners actually use (capture_output, text, timeout, env,
    input). Suitable to pass as `subprocess_runner=` to
    packages/coccinelle and packages/semgrep run_rule.

    Falls back to subprocess.run when core.sandbox is unavailable
    (non-Linux/macOS hosts) — the underlying runners still get the safe
    env from the adapter's run() method, so this is degrade-not-fail.

    Args:
        target: Scan target path. Used by the sandbox to set Landlock
            read access; LLM-generated rule scans the target only.
        output: Optional output dir for Landlock writable scope. When
            None, the sandbox restricts writes to /tmp only.
        block_network: True (default) blocks all network access. None of
            our four tools need network for hypothesis validation —
            registry packs are pre-resolved, queries run locally.
        caller_label: Tag for sandbox event logs.

    Returns:
        Callable usable as subprocess_runner.
    """
    import subprocess

    try:
        from core.sandbox import run as sandbox_run  # type: ignore
    except Exception:
        # Sandbox unavailable on this platform / install. Fall back to
        # subprocess.run; the safe env from the adapter still applies.
        return subprocess.run

    def _runner(cmd, **kwargs):
        sandbox_kwargs = {
            "block_network": block_network,
            "target": str(target),
            "caller_label": caller_label,
        }
        if output is not None:
            sandbox_kwargs["output"] = str(output)
        sandbox_kwargs.update({k: v for k, v in kwargs.items() if k != "shell"})
        return sandbox_run(cmd, **sandbox_kwargs)

    return _runner


class ToolAdapter(ABC):
    """Abstract base for security-tool adapters.

    Concrete subclasses wrap a security tool and expose the run-a-rule
    operation. Subclasses must be importable without their underlying
    tool installed — describe() and the adapter constructor must NOT
    raise when the tool binary is absent. Use is_available() to gate
    actual invocation.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Stable identifier for this adapter (e.g. "coccinelle")."""

    @abstractmethod
    def describe(self) -> ToolCapability:
        """Return the capability description for the LLM system prompt."""

    @abstractmethod
    def is_available(self) -> bool:
        """Whether the underlying tool is installed and runnable."""

    @abstractmethod
    def run(
        self,
        rule: str,
        target: Path,
        *,
        timeout: int = 300,
        env: Optional[Dict[str, str]] = None,
    ) -> ToolEvidence:
        """Run a rule against a target and return evidence.

        Args:
            rule: Tool-native rule text generated by the LLM.
            target: File or directory to scan.
            timeout: Per-rule timeout in seconds.
            env: Subprocess environment. Untrusted-target callers should
                pass RaptorConfig.get_safe_env().

        Returns:
            ToolEvidence with success/matches/summary populated. Adapters
            MUST NOT raise — return ToolEvidence(success=False, error=...)
            for any failure mode (parse error, timeout, OSError, missing
            binary).
        """
