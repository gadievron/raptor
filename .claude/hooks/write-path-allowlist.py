#!/usr/bin/env python3
"""PreToolUse hook: enforce a per-agent Write/Edit path allowlist.

Wired via the ``hooks:`` frontmatter of individual agent definitions
(.claude/agents/*.md) so the restriction is scoped to one agent, not
the whole session — the same per-agent narrowing pattern as
webfetch-domain-allowlist.py and bash-command-allowlist.py.

Why it exists: an agent whose prose says "Write exactly ONE artifact"
still holds an unrestricted Write grant, and for agents that read
hostile content (the crash-report-fetcher is the pipeline's
designated prompt-injection victim) that grant is an escape hatch —
a steered agent can rewrite the very anchor file that mechanically
constrains its own WebFetch. Prose is not a boundary; this hook is.

Usage (in agent frontmatter):

    hooks:
      PreToolUse:
        - matcher: Write
          hooks:
            - type: command
              command: "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/write-path-allowlist.py bug-report.json"

Arguments are the allowed file BASENAMES. A write is allowed only
when the target path's final component exactly matches one of them
and no path component is ``..``. Everything else — most importantly
anything under ``.claude/`` (hooks, anchors, settings, agent
definitions), including case-insensitive variants (``.CLAUDE``) and
symbolic links pointing into ``.claude/`` — is blocked.

Contract (Claude Code PreToolUse hooks):
  stdin  — JSON with ``tool_name`` and ``tool_input`` (``file_path``).
  exit 0 — allow the call.
  exit 2 — block the call; stderr is fed back to the agent.

Fail-closed: unparseable input, a missing path, a ``..`` component,
a backslash separator, a symlink target/ancestor, or a ``.claude``
component is blocked regardless of basename.
"""

import json
import sys
from pathlib import Path, PurePosixPath


def _has_forbidden_component(parts: tuple[str, ...]) -> bool:
    for part in parts:
        lower = part.lower()
        if part == ".." or lower == ".claude":
            return True
    return False


def _has_symlink_or_resolved_claude(file_path: str) -> bool:
    try:
        candidate = Path(file_path)
        # Walk existing path and ancestors to reject symlinks outright
        cur = candidate
        while True:
            if cur.is_symlink():
                return True
            if cur.parent == cur:
                break
            cur = cur.parent
        resolved = candidate.resolve(strict=False)
        if _has_forbidden_component(resolved.parts):
            return True
    except OSError:
        return True
    return False


def main(argv: list[str]) -> int:
    allowed = {a for a in argv if a}

    try:
        payload = json.load(sys.stdin)
    except ValueError:
        sys.stderr.write(
            "write-path-allowlist: unparseable hook input; "
            "blocking the write (fail-closed).\n"
        )
        return 2

    tool_input = payload.get("tool_input")
    file_path = (
        tool_input.get("file_path") if isinstance(tool_input, dict) else None
    )
    if not isinstance(file_path, str) or not file_path.strip():
        sys.stderr.write(
            "write-path-allowlist: no file_path in tool input; "
            "blocking the write (fail-closed).\n"
        )
        return 2

    if "\\" in file_path or "\x00" in file_path:
        sys.stderr.write(
            "write-path-allowlist: refusing backslash or NUL in "
            f"path: {file_path!r}\n"
        )
        return 2

    parts = PurePosixPath(file_path).parts
    if _has_forbidden_component(parts) or _has_symlink_or_resolved_claude(file_path):
        sys.stderr.write(
            "write-path-allowlist: refusing traversal, symlink, or .claude/ "
            f"writes: {file_path!r}\n"
        )
        return 2

    name = parts[-1] if parts else ""
    if name not in allowed:
        sys.stderr.write(
            f"write-path-allowlist: {name!r} is not an allowed artifact "
            f"for this agent (allowed: {sorted(allowed)}); blocking the "
            "write. Report content that belongs elsewhere to the "
            "orchestrator instead.\n"
        )
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
