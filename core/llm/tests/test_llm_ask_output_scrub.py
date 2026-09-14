"""raptor-llm-ask free-text emission must be terminal-scrubbed.

The model can be induced — e.g. by ``--file`` context it is asked to
echo — to emit terminal escape sequences; one echoed OSC sequence
rewrites the operator's terminal title/clipboard. The JSON lane is
safe (``dumps_display`` escapes control characters); the free-text
lane must route through ``escape_nonprintable``.

The report-writer audit cannot see this site (``content`` is not an
LLM-derived key there, and ``escape_nonprintable`` is deliberately not
one of its markdown-report sanitisers — this is a terminal surface,
not a markdown report), and exercising the lane end-to-end needs a
live provider, so the emission contract is pinned structurally here:
the AST must show ``response.content`` reaching ``print`` only through
``escape_nonprintable``.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
LLM_ASK = REPO_ROOT / "libexec" / "raptor-llm-ask"


def _print_calls(tree: ast.AST):
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "print"):
            yield node


def _mentions_response_content(node: ast.AST) -> bool:
    return any(
        isinstance(sub, ast.Attribute) and sub.attr == "content"
        and isinstance(sub.value, ast.Name) and sub.value.id == "response"
        for sub in ast.walk(node)
    )


def test_response_content_never_printed_raw():
    tree = ast.parse(LLM_ASK.read_text(encoding="utf-8"))
    offenders = []
    scrubbed = 0
    for call in _print_calls(tree):
        for arg in call.args:
            if not _mentions_response_content(arg):
                continue
            if (isinstance(arg, ast.Call)
                    and isinstance(arg.func, ast.Name)
                    and arg.func.id == "escape_nonprintable"):
                scrubbed += 1
            else:
                offenders.append(ast.dump(arg)[:120])
    assert not offenders, (
        "response.content reaches print() unscrubbed: "
        f"{offenders}"
    )
    # The free-text lane exists and is scrubbed (guards against the
    # print being deleted while the raw emission moves elsewhere).
    assert scrubbed >= 1
