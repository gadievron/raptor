#!/usr/bin/env python3
"""PreToolUse hook: enforce a per-agent Bash command allowlist.

Wired via the ``hooks:`` frontmatter of individual agent definitions
(.claude/agents/*.md) so the restriction is scoped to one agent, not
the whole session. The harness's declarative ``Bash(prefix *)``
permission rules are settings-scope (session-wide) only, and the
agent-frontmatter ``tools:`` field accepts bare tool names — qualified
entries like ``Bash(libexec/raptor-bq-query *)`` are not resolvable
there and would stop the agent from launching. Per-agent
``PreToolUse`` hooks are the documented mechanism for per-agent tool
narrowing (same pattern as webfetch-domain-allowlist.py).

Usage (in agent frontmatter):

    hooks:
      PreToolUse:
        - matcher: Bash
          hooks:
            - type: command
              command: "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/bash-command-allowlist.py libexec/raptor-bq-query 'python3 some/script.py'"

Arguments are the allowed command prefixes. A command is allowed when,
after leading-whitespace stripping, it equals a prefix or starts with
``<prefix> `` (prefix followed by a space). Multi-word prefixes are
passed as single (quoted) arguments.

Compound-command hardening: shell metacharacters that could chain a
second command or substitute one inside an allowed invocation
(newline, ``;``, ``&``, ``|``, backticks, ``$(``, ``<(``, ``>(``,
``>``, ``<``) are rejected outright — the allowed surface is plain
single invocations. Output capture belongs in the tool's own flags
(e.g. ``raptor-bq-query --output rows.json``), not shell redirects.

Contract (Claude Code PreToolUse hooks):
  stdin  — JSON with ``tool_name`` and ``tool_input`` (``command`` key).
  exit 0 — allow the call.
  exit 2 — block the call; stderr is fed back to the agent.

Fail-closed: unparseable input or a missing command is blocked.
"""

import json
import sys

_FORBIDDEN_SUBSTRINGS = ("\n", ";", "&", "|", "`", "$(", "<(", ">(", ">", "<")


def main(argv: list[str]) -> int:
    prefixes = [a for a in argv if a]

    try:
        payload = json.load(sys.stdin)
    except ValueError:
        sys.stderr.write(
            "bash-command-allowlist: unparseable hook input; "
            "blocking the Bash call (fail-closed).\n"
        )
        return 2

    tool_input = payload.get("tool_input")
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str) or not command.strip():
        sys.stderr.write(
            "bash-command-allowlist: no command in tool input; "
            "blocking the Bash call (fail-closed).\n"
        )
        return 2

    command = command.strip()

    for token in _FORBIDDEN_SUBSTRINGS:
        if token in command:
            sys.stderr.write(
                f"bash-command-allowlist: {token!r} is not allowed — this "
                "agent may only run plain single invocations of its "
                "allowlisted tools (no pipes, chaining, substitution, or "
                "redirects). SQL containing operators like < > & belongs "
                "in a file: Write it, then pass --query-file; capture "
                "results with --output, not shell redirects.\n"
            )
            return 2

    for prefix in prefixes:
        if command == prefix or command.startswith(prefix + " "):
            return 0

    sys.stderr.write(
        "bash-command-allowlist: command not in this agent's allowlist "
        f"({', '.join(prefixes)}). The call was blocked. If the "
        "investigation genuinely requires another tool, report that to "
        "the orchestrator/operator instead of retrying.\n"
    )
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
