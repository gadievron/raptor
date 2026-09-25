"""OpenAnt integration package for Raptor.

Self-contained bridge between Raptor's finding pipeline and OpenAnt's
source-code vulnerability scanner. No cross-package imports within Raptor.

Usage:
    from packages.openant import run_openant_scan, is_available
    from packages.openant.translator import translate_pipeline_output, deduplicate_with_sarif
    from packages.openant.config import OpenAntConfig, get_config
"""

from .config import OpenAntConfig, get_config, is_available
from .recovery import RECOVERED_TIER, recover_dropped_verdicts
from .scanner import run_openant_scan
from .translator import translate_pipeline_output, deduplicate_with_sarif

__all__ = [
    "OpenAntConfig",
    "RECOVERED_TIER",
    "get_config",
    "is_available",
    "recover_dropped_verdicts",
    "run_openant_scan",
    "translate_pipeline_output",
    "deduplicate_with_sarif",
]
