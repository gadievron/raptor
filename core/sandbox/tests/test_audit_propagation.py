"""Audit-flag propagation across subprocess boundaries.

Discovered by full agentic E2E against /tmp/vulns: `python raptor.py
agentic --audit` set audit mode in the agentic process, but the
actual sandbox-using subprocesses (scanner.py, codeql/agent.py)
inherited nothing because subprocess.Popen was invoked without
forwarding `--audit` and codeql/agent.py didn't even register the
flag in its argparse. Net: zero audit signal in run dirs despite
--audit being passed by the operator.

These tests are structural-drift defenses — source-greps that fail
loudly if anyone undoes the wiring. They don't actually exercise the
subprocess-spawn path (no need; the unit tests already cover what
happens once the flag arrives).

Why source-grep over functional spawn:
- A functional test would need to fake subprocess.Popen + observe
  the constructed argv. That's brittle and slow.
- A source-grep test captures the contract we actually care about
  ("the flag IS forwarded") in a single line per subprocess site.
- Any future entry point that adds a sandbox-using subprocess should
  add a corresponding assertion here, making the requirement
  visible to contributors.
"""

from __future__ import annotations

from pathlib import Path



REPO_ROOT = Path(__file__).resolve().parents[3]


class TestAgenticPropagatesSandboxFlags:
    """raptor_agentic.py must forward --audit and --audit-verbose into
    the scanner.py and codeql/agent.py subprocess invocations. Without
    this, audit mode dies at the agentic-process boundary."""

    def test_agentic_source_builds_passthrough_list(self):
        src = (REPO_ROOT / "raptor_agentic.py").read_text()
        # Pin the contract: the four canonical sandbox flags are
        # checked on `args` and forwarded.
        assert "sandbox_passthrough" in src, (
            "raptor_agentic.py must build a sandbox_passthrough list "
            "to forward --sandbox / --audit / --audit-verbose to "
            "scanner subprocesses; without it, audit dies at the "
            "process boundary"
        )
        for flag, attr in [
            ("--sandbox", "sandbox"),
            ("--no-sandbox", "no_sandbox"),
            ("--audit", "audit"),
            ("--audit-verbose", "audit_verbose"),
        ]:
            assert flag in src, f"raptor_agentic.py missing {flag} forward"
            assert f'getattr(args, "{attr}"' in src, (
                f"raptor_agentic.py must read args.{attr} to forward "
                f"{flag} (use getattr to avoid AttributeError if the "
                f"sandbox CLI surface drifts)"
            )

    def test_agentic_includes_passthrough_in_semgrep_cmd(self):
        src = (REPO_ROOT / "raptor_agentic.py").read_text()
        # The semgrep_cmd construction must splat the passthrough list.
        # Without this, scanner.py spawns without --audit and never
        # engages audit mode regardless of what the operator passed.
        assert "*sandbox_passthrough" in src, (
            "raptor_agentic.py must splat *sandbox_passthrough into "
            "the scanner subprocess argv"
        )
        # Crude but effective: count occurrences. Two subprocess
        # invocations (semgrep, codeql) → expect at least two splats.
        assert src.count("*sandbox_passthrough") >= 2, (
            "raptor_agentic.py spawns at least two sandbox-using "
            "subprocesses (semgrep, codeql); each must splat the "
            "passthrough list"
        )


class TestCodeqlAgentRegistersSandboxArgs:
    """packages/codeql/agent.py must register the sandbox CLI flags
    on its argparse so the agentic-driven invocation can pass them."""

    def test_codeql_agent_imports_add_cli_args(self):
        src = (REPO_ROOT / "packages" / "codeql" / "agent.py").read_text()
        assert "from core.sandbox import add_cli_args" in src, (
            "packages/codeql/agent.py must import add_cli_args / "
            "apply_cli_args from core.sandbox so it can parse "
            "--sandbox / --audit / --audit-verbose. Without this, "
            "raptor_agentic.py forwarding the flags would error "
            "out as 'unrecognized argument' in the codeql subprocess."
        )

    def test_codeql_agent_calls_apply_cli_args(self):
        src = (REPO_ROOT / "packages" / "codeql" / "agent.py").read_text()
        assert "apply_cli_args(args" in src, (
            "packages/codeql/agent.py must call apply_cli_args after "
            "parse_args so state._cli_sandbox_audit etc. are set."
        )

    def test_codeql_agent_help_lists_audit_flags(self, capsys):
        # End-to-end probe: --help must list --audit / --audit-verbose.
        # Catches the case where someone removes the import but leaves
        # the rest of the wiring (the source-grep tests above would
        # still pass on a half-edit).
        import sys
        agent_path = REPO_ROOT / "packages" / "codeql" / "agent.py"
        # Use subprocess to avoid main()'s sys.exit / global state.
        import subprocess
        result = subprocess.run(
            [sys.executable, str(agent_path), "--help"],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, (
            f"codeql agent --help failed: {result.stderr!r}"
        )
        assert "--audit" in result.stdout, (
            f"codeql agent --help does not list --audit:\n"
            f"{result.stdout}"
        )
        assert "--audit-verbose" in result.stdout, (
            f"codeql agent --help does not list --audit-verbose:\n"
            f"{result.stdout}"
        )
