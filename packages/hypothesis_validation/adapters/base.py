"""Tool adapter protocol — the contract every adapter implements.

The runner depends only on this interface. Adapters wrap concrete tools
(Coccinelle, Semgrep, CodeQL, SMT) and expose a uniform run-a-rule
operation plus a self-describing capability summary the runner uses to
build the LLM prompt.

Sandboxing: by default, all subprocess-based adapters (Coccinelle,
Semgrep, CodeQL) engage core.sandbox.run with block_network=True so an
LLM-generated rule cannot exfiltrate data over the network, plus
restrict_reads=True and a fake HOME so a hostile rule cannot pull
credentials or dotfiles into its match output either. Callers
that need to disable the sandbox (tests, trusted environments where
performance dominates) construct adapters with sandbox=False. The SMT
adapter is sandbox-free because it never spawns a subprocess.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from collections.abc import Callable


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
    good_for: list[str] = field(default_factory=list)
    bad_for: list[str] = field(default_factory=list)
    syntax_example: str = ""
    languages: list[str] = field(default_factory=list)

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
            lines.extend(f"  - {item}" for item in self.good_for)
        if self.bad_for:
            lines.append("Not for:")
            lines.extend(f"  - {item}" for item in self.bad_for)
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
    args: dict[str, Any] = field(default_factory=dict)

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
    matches: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    error: str = ""

    empty_matches_conclusive: bool = False
    """True when the adapter asserts that a clean run with NO matches is
    itself a definitive tool result rather than mere absence of evidence.
    Example: an SMT ``unsat`` proves the constraints are mutually
    exclusive — for a hypothesis phrased as "this path is infeasible"
    that is CONFIRMING proof despite the empty match list. The verdict
    ladder consults this flag before downgrading a confirmed claim with
    no matches to refuted."""

    @property
    def confirms(self) -> bool:
        """True when the tool ran cleanly and produced matches."""
        return self.success and bool(self.matches)

    def to_dict(self) -> dict:
        d = {
            "tool": self.tool,
            "rule": self.rule,
            "success": self.success,
            "matches": list(self.matches),
            "summary": self.summary,
            "error": self.error,
        }
        # Only emit the flag when set so the legacy serialized shape
        # stays untouched for the common case.
        if self.empty_matches_conclusive:
            d["empty_matches_conclusive"] = True
        return d


def _toolchain_read_dirs(cmd: list[str]) -> list[str]:
    """Read-allowlist directories for the executable being sandboxed.

    Under ``restrict_reads=True`` only the system dirs, target, output,
    and the sandbox /tmp stay readable — a tool installed under $HOME
    (pip --user semgrep, opam spatch, a downloaded codeql dist) would
    fail to load. Cover the executable's own directory, its
    symlink-resolved location (a ``~/.local/bin`` shim often points at
    a dist elsewhere), and the install layout around it:

    - a virtualenv (``pyvenv.cfg`` beside ``bin/``) is self-contained,
      so the venv ROOT is the right — and precisely-scoped — grant
      (the interpreter resolves site-packages via that pyvenv.cfg);
    - other ``bin/``-rooted layouts get the sibling ``lib``/``share``
      trees where packages and tool data files live. Deliberately NOT
      the whole prefix: granting e.g. all of ``~/.local`` would expose
      unrelated per-user state.
    """
    dirs: list[str] = []
    exe = cmd[0] if cmd else ""
    if not exe or not Path(exe).is_absolute():
        return dirs
    for p in (Path(exe), Path(exe).resolve()):
        parent = p.parent
        candidates = [parent]
        if (parent.parent / "pyvenv.cfg").is_file():
            candidates.append(parent.parent)
        elif parent.name == "bin":
            candidates.extend([parent.parent / "lib", parent.parent / "share"])
        for c in candidates:
            s = str(c)
            if s not in dirs and c.is_dir():
                dirs.append(s)
    return dirs


# Shared tempdir roots: granting one of these WHOLESALE would defeat
# the sandbox's private-/tmp isolation, so file grants under them stay
# file-granular.
_SHARED_TMP_ROOTS = ("/tmp", "/var/tmp")


def _cmd_file_grants(
    cmd: list[str], *, skip_prefixes: tuple[str, ...],
) -> list[str]:
    """Read grants for the files named as command arguments.

    The rule runners materialise per-invocation inputs under the host
    tempdir (the semgrep YAML rule, spatch's harnessed .cocci copy,
    the temp CodeQL query pack) and name them on the command line. The
    mount-ns sandbox gives the child a PRIVATE /tmp, so a host-/tmp
    file is invisible unless explicitly bound — the tool then fails,
    or worse, runs with no rules and reads back as a clean "no
    matches". The command line here is RAPTOR-constructed (never
    attacker-chosen), so every file it names is one the tool is meant
    to read.

    Grants the argument's parent directory (a temp query pack needs
    its sibling qlpack.yml visible too) unless the parent is a shared
    tempdir root, in which case the grant stays file-granular. Paths
    under ``skip_prefixes`` (target/output — already bound) are left
    alone. EMPTY files are skipped: the binds are read-only, and an
    empty file named on a RAPTOR-built command line is a pre-created
    OUTPUT placeholder (e.g. semgrep's --json-output tempfile) — a
    read-only bind over it would make the tool's own write fail.
    Every genuine input (rule/config/query) has content.
    """
    grants: list[str] = []
    for arg in cmd[1:]:
        if not isinstance(arg, str) or not arg.startswith("/"):
            continue
        if any(
            arg == pref or arg.startswith(pref.rstrip("/") + "/")
            for pref in skip_prefixes
        ):
            continue
        p = Path(arg)
        try:
            if not p.is_file() or p.stat().st_size == 0:
                continue
        except OSError:
            continue
        parent = str(p.parent)
        grant = arg if parent in _SHARED_TMP_ROOTS else parent
        if grant not in grants:
            grants.append(grant)
    return grants


def make_sandbox_runner(
    *,
    target: Path,
    output: Path | None = None,
    block_network: bool = True,
    restrict_reads: bool = True,
    fake_home: bool = True,
    readable_paths: list[str] | None = None,
    caller_label: str = "hypothesis-validation",
) -> Callable:
    """Build a subprocess-runner-shaped callable that wraps core.sandbox.run.

    The returned callable has the same signature as subprocess.run for the
    kwargs the runners actually use (capture_output, text, timeout, env,
    input). Suitable to pass as `subprocess_runner=` to
    packages/coccinelle and packages/semgrep run_rule.

    Fail-closed when core.sandbox is unavailable: raises
    ``core.run.sandbox_policy.SandboxUnavailableError`` naming the
    remedy. Hosts that genuinely lack sandbox support can explicitly
    opt into a bare-subprocess fallback with
    ``RAPTOR_ALLOW_UNSANDBOXED_TOOLS=1`` (loud warning + security
    event); the underlying runners still get the safe env from the
    adapter's run() method in that degraded mode.

    Args:
        target: Scan target path. Used by the sandbox to set Landlock
            read access; LLM-generated rule scans the target only.
        output: Optional output dir for Landlock writable scope. When
            None, the sandbox restricts writes to /tmp only (plus a
            scratch dir materialised for the fake HOME — see fake_home).
        block_network: True (default) blocks all network access. None of
            our four tools need network for hypothesis validation —
            registry packs are pre-resolved, queries run locally.
        restrict_reads: True (default) flips Landlock from read-wide to
            a read allowlist (system dirs + target + output + /tmp +
            the toolchain dirs derived from the command). Second-layer
            defence for LLM-generated rules: even with script blocks
            rejected up front, a hostile rule's match output must not
            be able to carry the contents of $HOME dotfiles back into
            LLM context and reports.
        fake_home: True (default) points HOME / XDG_*_HOME at an empty
            directory so a hostile rule finds no dotfiles to read even
            by path guess (ENOENT rather than EACCES, which brittle
            tools handle better). Requires a writable dir: when
            ``output`` is None a scratch dir is created under the
            system tempdir — writes there are already inside the
            sandbox's default writable surface, so this grants no
            extra write authority.
        readable_paths: Extra read-allowed paths for tools with per-user
            state the sandbox must keep visible (e.g. codeql's pack
            cache). Only meaningful with restrict_reads.
        caller_label: Tag for sandbox event logs.

    Returns:
        Callable usable as subprocess_runner.
    """
    import subprocess

    try:
        from core.sandbox import run as sandbox_run  # type: ignore[import-not-found]
    except Exception as exc:  # noqa: BLE001 — any import failure means no isolation
        # Fail-closed: no silent bare-subprocess fallback. The tools
        # this runner feeds (semgrep / coccinelle / codeql on
        # LLM-generated rules over untrusted targets) are exactly the
        # ones that must not run unisolated. Explicit dev-host opt-in
        # via RAPTOR_ALLOW_UNSANDBOXED_TOOLS=1 (loud warning +
        # security event) is the only degraded path.
        from core.run.sandbox_policy import require_sandbox_or_optout
        require_sandbox_or_optout(
            f"{caller_label} (make_sandbox_runner)", exc,
        )
        return subprocess.run

    scratch = None
    effective_output = output
    if fake_home and effective_output is None:
        # The sandbox materialises the fake HOME under ``output``; give
        # it a scratch dir when the caller has none. Held by the runner
        # closure so TemporaryDirectory's finalizer cleans it up when
        # the runner is collected.
        import tempfile
        scratch = tempfile.TemporaryDirectory(prefix="hv_sandbox_")
        effective_output = Path(scratch.name)

    def _runner(cmd, **kwargs):
        _ = scratch  # keep the fake-HOME scratch dir alive with the closure
        sandbox_kwargs: dict[str, Any] = {
            "block_network": block_network,
            "target": str(target),
            "restrict_reads": restrict_reads,
            "fake_home": fake_home,
            "caller_label": caller_label,
            "env_caller_filtered": True,
        }
        if effective_output is not None:
            sandbox_kwargs["output"] = str(effective_output)
        if readable_paths:
            sandbox_kwargs["readable_paths"] = list(readable_paths)
        # tool_paths feeds BOTH the Landlock read allowlist and the
        # mount-ns bind set, so it is the channel that makes the
        # toolchain dirs and command-named files actually visible.
        tool_dirs = _toolchain_read_dirs(cmd)
        skip = tuple(
            s for s in (str(target),
                        str(effective_output) if effective_output else "")
            if s
        )
        for extra in _cmd_file_grants(cmd, skip_prefixes=skip):
            if extra not in tool_dirs:
                tool_dirs.append(extra)
        if tool_dirs:
            sandbox_kwargs["tool_paths"] = tool_dirs
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
        env: dict[str, str] | None = None,
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
