"""Tool adapters — wrap each security tool for hypothesis validation.

Adapters expose a uniform interface so the runner can offer the LLM a
consistent set of tools without leaking each tool's invocation idioms
into the prompt. Each adapter knows how to:

  - describe() its capabilities (what it's good for, syntax examples)
  - run() a rule string against a target and return ToolEvidence

Concrete adapters:
    CoccinelleAdapter   — wraps packages/coccinelle/ (LLM-authored SmPL)
    SemgrepAdapter      — wraps packages/semgrep/
    CodeQLAdapter       — runs LLM-generated .ql against a pre-built database
    SMTAdapter          — wraps packages/codeql/smt_path_validator.py
    SourceIntelAdapter  — pre-computed cocci KB from packages/source_intel/
                          (different shape: JSON query into shipped rules,
                          not LLM-authored SmPL)
"""

from .base import ToolAdapter, ToolCapability, ToolEvidence, ToolInvocation
from .coccinelle import CoccinelleAdapter
from .semgrep import SemgrepAdapter
from .codeql import CodeQLAdapter
from .smt import SMTAdapter
from .source_intel import SourceIntelAdapter

__all__ = [
    "ToolAdapter",
    "ToolCapability",
    "ToolEvidence",
    "ToolInvocation",
    "CoccinelleAdapter",
    "SemgrepAdapter",
    "CodeQLAdapter",
    "SMTAdapter",
    "SourceIntelAdapter",
]
