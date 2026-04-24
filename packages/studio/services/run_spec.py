"""Build raptor subprocess invocations for UI-triggered runs.

Only raptor commands that have a pure-Python entry point are supported here.
Claude-Code-only commands (``/understand``, ``/validate``, ``/oss-forensics``,
``/crash-analysis``) can't be kicked off without a Claude Code session, so
the UI falls back to showing the CLI command for those.

Schema reference: docs/PYTHON_CLI.md + docs/ARCHITECTURE.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


class UnsupportedKind(ValueError):
    """Raised for kinds that don't have a pure-Python entry point."""


@dataclass
class FormField:
    name: str
    label: str
    kind: str = "text"   # text | select | checkbox | number
    required: bool = False
    default: str = ""
    placeholder: str = ""
    help: str = ""
    options: list[str] = None  # for select


@dataclass
class RunnableKind:
    kind: str
    label: str
    description: str
    script: str           # path relative to RAPTOR_HOME, or "" for Claude-backed
    target_arg: str       # --repo / --binary / --target / ""
    fields: list[FormField]
    requires_claude: bool = False  # If True, wrap as `claude -p <slash-command>`
    slash_command: str = ""        # The /slash-command invoked under Claude Code


# Kinds that can be executed as pure Python (no Claude Code needed).
RUNNABLE_KINDS: dict[str, RunnableKind] = {
    "agentic": RunnableKind(
        kind="agentic",
        label="Agentic (full workflow)",
        description="Scan + validate + exploit + patch in one pass. Highest coverage, highest cost.",
        script="raptor_agentic.py",
        target_arg="--repo",
        fields=[
            FormField("policy_groups", "Policy groups", kind="text", default="all",
                      placeholder="all | secrets,owasp | secrets,crypto",
                      help="Comma-separated Semgrep packs; 'all' uses everything."),
            FormField("max_findings", "Max findings to process", kind="number", default="20"),
            FormField("mode", "Mode", kind="select", default="thorough",
                      options=["fast", "thorough"]),
            FormField("no_exploits", "Skip exploit generation", kind="checkbox"),
            FormField("no_patches", "Skip patch generation", kind="checkbox"),
        ],
    ),
    "scan": RunnableKind(
        kind="scan",
        label="Scan (Semgrep only)",
        description="Semgrep static analysis; no CodeQL, no LLM, no exploits. Fast.",
        script="raptor_agentic.py",
        target_arg="--repo",
        fields=[
            FormField("policy_groups", "Policy groups", kind="text", default="owasp,secrets",
                      placeholder="owasp,secrets",
                      help="Comma-separated Semgrep packs."),
        ],
    ),
    "codeql": RunnableKind(
        kind="codeql",
        label="CodeQL (deep dataflow)",
        description="CodeQL with SMT path pre-screening. Slow but catches what Semgrep misses.",
        script="raptor_codeql.py",
        target_arg="--repo",
        fields=[
            FormField("language", "Language", kind="select", default="",
                      options=["", "python", "java", "javascript", "cpp", "go", "ruby", "csharp"],
                      help="Leave blank to auto-detect."),
            FormField("validate_dataflow", "Validate dataflow paths", kind="checkbox", default="on"),
            FormField("visualize", "Emit Mermaid diagrams", kind="checkbox", default="on"),
            FormField("analyze", "Run LLM exploitability analysis", kind="checkbox"),
        ],
    ),
    "fuzz": RunnableKind(
        kind="fuzz",
        label="Fuzz (AFL++)",
        description="Coverage-guided fuzzing of a compiled binary with autonomous corpus.",
        script="raptor_fuzzing.py",
        target_arg="--binary",
        fields=[
            FormField("duration", "Duration (seconds)", kind="number", default="300", required=True),
            FormField("parallel", "Parallel AFL instances", kind="number", default="1"),
            FormField("max_crashes", "Max crashes to analyse", kind="number", default="10"),
            FormField("autonomous", "Autonomous corpus", kind="checkbox", default="on",
                      help="Let raptor generate intelligent seeds from the binary strings."),
            FormField("goal", "Goal", kind="text",
                      placeholder="find heap overflow | find parser bugs | find RCE",
                      help="Optional goal-directed seed generation."),
            FormField("corpus", "Corpus dir", kind="text",
                      placeholder="/path/to/seeds",
                      help="Optional — mutually exclusive with autonomous."),
        ],
    ),
    # --- Claude-backed kinds (shell out to `claude -p`) ------------------
    "understand": RunnableKind(
        kind="understand",
        label="Understand (attack surface map)",
        description="Map attack surface, trace data flows, hunt variants. Runs under Claude Code.",
        script="", target_arg="",
        fields=[
            FormField("mode", "Mode", kind="select", default="map",
                      options=["map", "variants", "dataflow"],
                      help="Which understand sub-task to run."),
        ],
        requires_claude=True, slash_command="/understand",
    ),
    "validate": RunnableKind(
        kind="validate",
        label="Validate (Stages A–F)",
        description="Multi-stage exploitability validation on existing findings. Runs under Claude Code.",
        script="", target_arg="",
        fields=[
            FormField("binary", "Binary", kind="text",
                      placeholder="/path/to/binary (optional — enables Stage E feasibility)",
                      help="If provided, Stage E binary feasibility runs."),
            FormField("vuln_type", "Vuln type filter", kind="text",
                      placeholder="command_injection | buffer_overflow | …",
                      help="Optional — restrict validation to one vuln class."),
        ],
        requires_claude=True, slash_command="/validate",
    ),
    "oss-forensics": RunnableKind(
        kind="oss-forensics",
        label="OSS forensics",
        description="Evidence-backed GitHub investigation. Requires GOOGLE_APPLICATION_CREDENTIALS for GH Archive.",
        script="", target_arg="",
        fields=[
            FormField("focus", "Focus / research question", kind="text",
                      placeholder='e.g. "July 13 incident"',
                      help="The investigation prompt passed to /oss-forensics."),
            FormField("max_followups", "Max evidence rounds", kind="number", default="3"),
            FormField("max_retries", "Max hypothesis retries", kind="number", default="3"),
        ],
        requires_claude=True, slash_command="/oss-forensics",
    ),
    "crash-analysis": RunnableKind(
        kind="crash-analysis",
        label="Crash analysis (rr + GDB)",
        description="Autonomous root-cause analysis for C/C++ crashes. Linux x86_64 only.",
        script="", target_arg="",
        fields=[
            FormField("bug_url", "Bug tracker URL", kind="text",
                      placeholder="https://trac.ffmpeg.org/ticket/12345",
                      required=True),
            FormField("repo_url", "Git repo URL", kind="text",
                      placeholder="https://github.com/FFmpeg/FFmpeg.git",
                      required=True),
        ],
        requires_claude=True, slash_command="/crash-analysis",
    ),
}


# Legacy alias — kept so other code that referenced this still compiles.
CLAUDE_ONLY_KINDS: dict[str, str] = {}


def is_runnable(kind: str) -> bool:
    return kind in RUNNABLE_KINDS


def build_command(
    kind: str,
    target: str,
    raptor_home: Path,
    form_values: dict[str, str] | None = None,
    project_name: str = "",
) -> list[str]:
    """Translate (kind, target, form_values) into an argv for subprocess.Popen.

    For Python-entry-point kinds, returns ``["python3", script, ...]``.
    For Claude-backed kinds (requires_claude=True), returns a shell
    invocation that activates the project with raptor's CLI then passes
    a slash-command prompt to ``claude -p``.

    Raises UnsupportedKind if the kind is unknown.
    Raises ValueError on missing required fields.
    """
    if kind not in RUNNABLE_KINDS:
        raise UnsupportedKind(f"Kind '{kind}' is not runnable from the UI.")
    spec = RUNNABLE_KINDS[kind]
    values = form_values or {}

    if spec.requires_claude:
        return _build_claude_command(spec, target, raptor_home, values, project_name)

    argv = ["python3", str(raptor_home / spec.script), spec.target_arg, target]

    # Append kind-specific args, matching what raptor expects.
    if kind == "agentic":
        if values.get("policy_groups"):
            argv += ["--policy-groups", values["policy_groups"]]
        if values.get("max_findings"):
            argv += ["--max-findings", str(values["max_findings"])]
        if values.get("mode"):
            argv += ["--mode", values["mode"]]
        if values.get("no_exploits"):
            argv += ["--no-exploits"]
        if values.get("no_patches"):
            argv += ["--no-patches"]
    elif kind == "scan":
        if values.get("policy_groups"):
            argv += ["--policy-groups", values["policy_groups"]]
        argv += ["--mode", "fast", "--no-exploits", "--no-patches"]
    elif kind == "codeql":
        if values.get("language"):
            argv += ["--language", values["language"]]
        if values.get("validate_dataflow"):
            argv += ["--validate-dataflow"]
        if values.get("visualize"):
            argv += ["--visualize"]
        if values.get("analyze"):
            argv += ["--analyze"]
    elif kind == "fuzz":
        if not values.get("duration"):
            raise ValueError("Duration is required for fuzzing.")
        argv += ["--duration", str(values["duration"])]
        if values.get("parallel"):
            argv += ["--parallel", str(values["parallel"])]
        if values.get("max_crashes"):
            argv += ["--max-crashes", str(values["max_crashes"])]
        if values.get("autonomous"):
            argv += ["--autonomous"]
        if values.get("goal"):
            argv += ["--goal", values["goal"]]
        if values.get("corpus"):
            argv += ["--corpus", values["corpus"]]

    return argv


def claude_cli_hint(kind: str, target: str, project_name: str) -> Optional[str]:
    """Return a CLI cheat-sheet for a Claude-backed kind (read-only path).

    The actual subprocess path is handled by ``build_command`` which wraps
    the same invocation for the worker to run. This helper is for UI copy.
    """
    spec = RUNNABLE_KINDS.get(kind)
    if not spec or not spec.requires_claude:
        return None
    slash = _compose_slash_command(spec, target, {}, project_name)
    return f"cd $RAPTOR_HOME\nraptor project use {project_name}\nclaude -p '{slash}'"


def _compose_slash_command(
    spec: RunnableKind, target: str, values: dict, project_name: str
) -> str:
    """Compose the slash-command string passed to ``claude -p``."""
    parts = [spec.slash_command]

    if spec.kind == "understand":
        mode = values.get("mode") or "map"
        parts.append(f"--{mode}")
        if target:
            parts.append(target)
    elif spec.kind == "validate":
        if target:
            parts.append(target)
        if values.get("binary"):
            parts += ["--binary", values["binary"]]
        if values.get("vuln_type"):
            parts += ["--vuln-type", values["vuln_type"]]
    elif spec.kind == "oss-forensics":
        focus = values.get("focus") or ""
        vendor = values.get("vendor_report_url") or ""
        url = target
        prompt_bits = [url]
        if focus:
            prompt_bits.append(focus)
        if vendor:
            prompt_bits.append(f"validate claims in {vendor}")
        if len(prompt_bits) > 1:
            parts.append('"' + " — ".join(prompt_bits) + '"')
        else:
            parts.append(url)
        if values.get("max_followups"):
            parts += ["--max-followups", str(values["max_followups"])]
        if values.get("max_retries"):
            parts += ["--max-retries", str(values["max_retries"])]
    elif spec.kind == "crash-analysis":
        bug_url = values.get("bug_url") or ""
        repo_url = values.get("repo_url") or ""
        if not bug_url or not repo_url:
            raise ValueError("crash-analysis requires both bug_url and repo_url.")
        parts += [bug_url, repo_url]

    return " ".join(parts)


def _build_claude_command(
    spec: RunnableKind, target: str, raptor_home: Path, values: dict, project_name: str
) -> list[str]:
    """Wrap a Claude-backed kind into a `bash -c` invocation.

    Activates the project with ``raptor project use`` first (pure Python
    subcommand, cheap), then runs ``claude -p`` with the slash-command prompt.
    """
    import shlex

    slash = _compose_slash_command(spec, target, values, project_name)

    raptor_bin = raptor_home / "bin" / "raptor"
    parts: list[str] = []
    if project_name:
        parts.append(
            f"bash {shlex.quote(str(raptor_bin))} project use {shlex.quote(project_name)}"
        )
    parts.append(f"claude -p {shlex.quote(slash)}")

    return ["bash", "-c", " && ".join(parts)]
