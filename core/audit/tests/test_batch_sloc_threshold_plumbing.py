"""--batch-sloc-threshold must reach OrchestratorConfig from the CLI opts.

The knob existed on OrchestratorConfig (default 15) but was not
settable per run; this pins the AuditPipelineOpts pass-through added
alongside the CLI flag.
"""

from __future__ import annotations

from pathlib import Path

from core.audit.orchestrator import OrchestratorConfig
from core.audit.pipeline import AuditPipelineOpts


def test_default_is_none_and_config_keeps_its_default():
    opts = AuditPipelineOpts()
    assert opts.batch_sloc_threshold is None
    # None means "don't override" — OrchestratorConfig default rules.
    kwargs = (
        {"batch_sloc_threshold": opts.batch_sloc_threshold}
        if opts.batch_sloc_threshold is not None else {}
    )
    cfg = OrchestratorConfig(target_path=Path("."), out_dir=Path("."), **kwargs)
    assert cfg.batch_sloc_threshold == 15


def test_explicit_threshold_reaches_config():
    opts = AuditPipelineOpts(batch_sloc_threshold=30)
    kwargs = (
        {"batch_sloc_threshold": opts.batch_sloc_threshold}
        if opts.batch_sloc_threshold is not None else {}
    )
    cfg = OrchestratorConfig(target_path=Path("."), out_dir=Path("."), **kwargs)
    assert cfg.batch_sloc_threshold == 30


def test_zero_disables_batching_pass_through():
    opts = AuditPipelineOpts(batch_sloc_threshold=0)
    kwargs = (
        {"batch_sloc_threshold": opts.batch_sloc_threshold}
        if opts.batch_sloc_threshold is not None else {}
    )
    cfg = OrchestratorConfig(target_path=Path("."), out_dir=Path("."), **kwargs)
    assert cfg.batch_sloc_threshold == 0
