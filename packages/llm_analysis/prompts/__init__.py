"""Shared prompt builders for LLM analysis.

Used by both agent.py (sequential) and orchestrator.py (parallel dispatch).
"""

from .analysis import (
    build_analysis_prompt,
    build_analysis_prompt_from_finding,
    build_analysis_schema,
    ANALYSIS_SYSTEM_PROMPT,
)
from .exploit import (
    build_exploit_prompt,
    build_exploit_prompt_from_finding,
    EXPLOIT_SYSTEM_PROMPT,
)
from .patch import (
    build_patch_prompt,
    build_patch_prompt_from_finding,
    PATCH_SYSTEM_PROMPT,
)
from .schemas import (
    ANALYSIS_SCHEMA,
    DATAFLOW_SCHEMA_FIELDS,
    FINDING_RESULT_SCHEMA,
)
