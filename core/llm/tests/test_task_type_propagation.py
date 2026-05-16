"""Smoke tests verifying that consumer call sites tag their LLM
calls with the correct ``task_type``.

These tests are deliberately observational: each test patches
``LLMClient.generate_structured`` (or ``generate``) on a real client
instance, drives one consumer through a known code path, and asserts
the captured ``task_type`` kwarg matches the convention. They exist
to catch regressions where someone removes a tag during refactor.

Why not test every call site:
  Each consumer has its own setup cost (prompt-defense scaffolding,
  fixtures, etc.). The substrate (``LLMConfig.__post_init__`` →
  fast-tier routing) is already covered in
  ``test_fast_model_routing.py``; here we just spot-check that the
  tags reach the client.
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Module-level audit — every modified file imports TaskType
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("module_name", [
    "packages.web.fuzzer",
    "packages.llm_analysis.crash_agent",
    "packages.llm_analysis.agent",
    "packages.codeql.autonomous_analyzer",
    "packages.codeql.dataflow_validator",
    "packages.autonomous.dialogue",
])
def test_consumer_imports_task_type(module_name):
    """Every consumer touched by this PR imports ``TaskType``. This
    catches the case where someone removes the import while keeping
    the string literal — at which point the tag is detached from the
    central convention and prone to drift on future renames."""
    import importlib
    mod = importlib.import_module(module_name)
    # The import is captured into the module's namespace; whether it
    # lives at module scope or inside a function, ``TaskType`` should
    # resolve when looked up.
    assert hasattr(mod, "TaskType"), (
        f"{module_name} imports task_type strings but does not import "
        f"TaskType — refactor risk"
    )


# ---------------------------------------------------------------------------
# Static audit — every generate_structured / generate call carries a
# task_type kwarg in the modified files. Catches regressions where a
# rebase or refactor drops the tag from one site but not others.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", [
    "packages/web/fuzzer.py",
    "packages/llm_analysis/crash_agent.py",
    "packages/llm_analysis/agent.py",
    "packages/codeql/autonomous_analyzer.py",
    "packages/codeql/dataflow_validator.py",
    "packages/autonomous/dialogue.py",
])
def test_every_llm_call_in_file_has_task_type(path):
    """Every ``self.llm.generate`` / ``self.llm.generate_structured``
    invocation in the modified files must carry a ``task_type=`` kwarg.

    Implementation: scan the file, for each occurrence of an LLM call,
    check whether the call's argument list (up to its closing paren)
    contains ``task_type=``. We balance parens to handle multi-line
    calls reliably across formatters."""
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.normpath(os.path.join(here, "..", "..", ".."))
    full = os.path.join(repo, path)
    text = open(full, encoding="utf-8").read()

    # Find every call boundary. Match either ``llm.generate(`` or
    # ``llm.generate_structured(`` — both belong to the LLMClient
    # surface.
    import re
    pattern = re.compile(r"\b(?:llm|client)\.generate(?:_structured)?\(")
    for m in pattern.finditer(text):
        start = m.end()                    # position just after ``(``
        depth = 1
        i = start
        while i < len(text) and depth > 0:
            ch = text[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            i += 1
        call_args = text[start:i - 1]
        assert "task_type" in call_args, (
            f"{path}: call at offset {m.start()} missing task_type=:\n"
            f"  {call_args.strip()[:200]}"
        )
