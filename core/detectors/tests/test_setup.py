"""Preparation ownership must be explicit and confined to one run."""
from pathlib import Path

from core.audit.run_memo import BoundedMemo
from core.detectors.setup import AnalysisSetup


def test_setup_is_lazy_and_fresh(monkeypatch):
    monkeypatch.setattr('core.audit.compiler_sweep._derive_include_dirs',
                        lambda *a: (_ for _ in ()).throw(AssertionError('eager discovery')))
    first, second = AnalysisSetup(), AnalysisSetup()
    assert first.preprocessed_views is None and second.preprocessed_views is None
    assert first.include_dirs_memo is not second.include_dirs_memo
    assert len(first.include_dirs_memo) == len(second.include_dirs_memo) == 0
    assert first.include_dirs_memo._max_entries == 64


def test_audit_adopts_existing_or_explicitly_shared_setup():
    from core.audit.orchestrator import OrchestratorConfig
    memo = BoundedMemo(2)
    config = OrchestratorConfig(target_path=Path('/target'), out_dir=Path('/output'),
                                include_dirs_memo=memo)
    assert config.analysis_setup.include_dirs_memo is memo
    shared = AnalysisSetup(include_dirs_memo=memo)
    other = OrchestratorConfig(target_path=Path('/target'), out_dir=Path('/output'),
                               analysis_setup=shared)
    assert other.analysis_setup is shared and other.include_dirs_memo is memo
