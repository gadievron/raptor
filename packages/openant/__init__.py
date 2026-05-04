"""OpenAnt integration package for Raptor.

Self-contained bridge between Raptor's finding pipeline and OpenAnt's
source-code vulnerability scanner. No cross-package imports within Raptor.

Usage:
    from packages.openant import run_openant_scan, is_available
    from packages.openant.translator import translate_pipeline_output, deduplicate_with_sarif
    from packages.openant.config import OpenAntConfig, get_config
"""

from .config import OpenAntConfig, get_config, is_available
from .scanner import run_openant_scan
from .translator import translate_pipeline_output, deduplicate_with_sarif

__all__ = [
    "OpenAntConfig",
    "get_config",
    "is_available",
    "run_openant_scan",
    "translate_pipeline_output",
    "deduplicate_with_sarif",
]
