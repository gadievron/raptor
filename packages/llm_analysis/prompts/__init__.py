"""Shared prompt builders for LLM analysis.

Used by both agent.py (sequential) and orchestrator.py (parallel dispatch).
All builders return PromptBundle (system + user message parts) — see
core.security.prompt_envelope. Call sites pass `bundle.messages` to the
LLM client by role.
"""

from .analysis import (
    ANALYSIS_SYSTEM_PROMPT,
    ANALYSIS_TASK_INSTRUCTIONS,
    DATAFLOW_VALIDATION_SYSTEM_PROMPT,
    DATAFLOW_VALIDATION_TASK,
    build_analysis_prompt_bundle,
    build_analysis_prompt_bundle_from_finding,
    build_analysis_schema,
    build_dataflow_validation_bundle,
)
from .exploit import (
    EXPLOIT_SYSTEM_PROMPT,
    EXPLOIT_TASK_INSTRUCTIONS,
    SCA_EXPLOIT_TASK_INSTRUCTIONS,
    build_exploit_prompt_bundle,
    build_exploit_prompt_bundle_from_finding,
    build_sca_exploit_prompt_bundle,
)
from .patch import (
    PATCH_SYSTEM_PROMPT,
    PATCH_TASK_INSTRUCTIONS,
    SCA_PATCH_SYSTEM_PROMPT,
    build_patch_prompt_bundle,
    build_patch_prompt_bundle_from_finding,
    build_sca_patch_prompt_bundle,
)
from .schemas import (
    ANALYSIS_SCHEMA,
    DATAFLOW_SCHEMA_FIELDS,
    DATAFLOW_VALIDATION_SCHEMA,
    FINDING_RESULT_SCHEMA,
)
