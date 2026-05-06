"""Shared tool specifications for hunt and trace dispatchers.

Both modes expose the same Read/Grep/Glob handlers — only the terminal
tool differs (submit_variants for hunt, submit_verdicts for trace). Keep
descriptions and schemas in one place so the model's prompt context is
identical for the shared tools across both modes.
"""

from __future__ import annotations

from typing import List

from core.llm.tool_use import ToolDef

from packages.code_understanding.dispatch.tools import SandboxedTools


READ_FILE_DESCRIPTION = (
    "Read a file under the target repository. Path must be repo-relative "
    "(no leading slash, no '..' escaping). Returns JSON: "
    "{path, content, truncated, byte_cap}."
)

GREP_DESCRIPTION = (
    "Search for ``pattern`` across files in the repo. ``path`` narrows to "
    "a directory subtree (must be a directory, not a file — use read_file "
    "for single files). ``regex=true`` enables Python regex; default is "
    "literal substring. Output is sorted by (file, line)."
)

GLOB_DESCRIPTION = (
    "List files matching a glob pattern. Uses Python ``fnmatch`` (``*`` "
    "matches any character including ``/``); ``**`` is NOT shell-style "
    "recursive — for that, use grep with ``path=``."
)


def build_shared_tools(sandbox: SandboxedTools) -> List[ToolDef]:
    """Read/Grep/Glob tools, identical between hunt and trace.

    Each ToolDef carries (name, description, input_schema, handler).
    Handlers receive a dict of validated inputs and return a JSON string.
    """
    return [
        ToolDef(
            name="read_file",
            description=READ_FILE_DESCRIPTION,
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "max_lines": {"type": "integer"},
                },
                "required": ["path"],
            },
            handler=lambda args: sandbox.read_file(
                args["path"],
                max_lines=args.get("max_lines"),
            ),
        ),
        ToolDef(
            name="grep",
            description=GREP_DESCRIPTION,
            input_schema={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                    "path": {"type": "string"},
                    "regex": {"type": "boolean"},
                    "case_sensitive": {"type": "boolean"},
                },
                "required": ["pattern"],
            },
            handler=lambda args: sandbox.grep(
                args["pattern"],
                path=args.get("path"),
                regex=bool(args.get("regex", False)),
                case_sensitive=bool(args.get("case_sensitive", True)),
            ),
        ),
        ToolDef(
            name="glob_files",
            description=GLOB_DESCRIPTION,
            input_schema={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                },
                "required": ["pattern"],
            },
            handler=lambda args: sandbox.glob_files(args["pattern"]),
        ),
    ]
