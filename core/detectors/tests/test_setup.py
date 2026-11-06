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


def test_rejected_views_do_not_walk_source_maps(monkeypatch):
    import sys
    from core.audit.preprocessor_view import ExpandedView
    from core.detectors.setup import PreparedViews

    view = ExpandedView(ok=True, file_path="a.c", text="int a;",
                        line_map=(("a.c", 1),) * 1000)
    full = PreparedViews()
    for number in range(32):
        assert full.put((number,), view)
    duplicate = PreparedViews()
    assert duplicate.put(("same",), view)
    original_size = sys.getsizeof
    visited = []

    def measured_size(value):
        if value is view.line_map or value is view.line_map[0]:
            visited.append(value)
        return original_size(value)

    monkeypatch.setattr(sys, "getsizeof", measured_size)
    assert not full.put(("new",), view)
    assert not duplicate.put(("same",), view)
    assert not PreparedViews(max_bytes=1).put(("tiny",), view)
    large = ExpandedView(ok=True, file_path="a.c", text="x" * (2 * 1024 * 1024),
                         line_map=view.line_map)
    assert not PreparedViews().put(("large",), large)
    assert not visited


def test_concurrent_view_admission_respects_shared_budget():
    from concurrent.futures import ThreadPoolExecutor
    import threading
    from core.audit.preprocessor_view import ExpandedView
    from core.detectors.setup import PreparedViews

    view = ExpandedView(ok=True, file_path="a.c", text="int a;")
    probe = PreparedViews()
    assert probe.put((0,), view)
    cache = PreparedViews(max_bytes=probe.retained_bytes)
    start = threading.Barrier(8)

    def admit(number):
        start.wait(timeout=5)
        return cache.put((number,), view)

    with ThreadPoolExecutor(max_workers=8) as pool:
        admitted = list(pool.map(admit, range(8)))
    assert sum(admitted) == 1
    assert cache.retained_bytes == probe.retained_bytes
    for number, accepted in enumerate(admitted):
        assert (cache.get((number,)) is not None) == accepted


def test_source_map_sizing_stops_when_remaining_budget_is_exceeded(monkeypatch):
    import sys
    from core.audit.preprocessor_view import ExpandedView
    from core.detectors.setup import PreparedViews

    pair = ("a.c", 1)
    view = ExpandedView(ok=True, file_path="a.c", text="int a;",
                        line_map=(pair,) * 1000)
    full = PreparedViews()
    assert full.put((0,), view)
    cache = PreparedViews(max_bytes=full.retained_bytes // 2)
    original_size = sys.getsizeof
    visits = 0

    def measured_size(value):
        nonlocal visits
        if value is pair:
            visits += 1
        return original_size(value)

    monkeypatch.setattr(sys, "getsizeof", measured_size)
    assert not cache.put((0,), view)
    assert 0 < visits < len(view.line_map)
    assert cache.retained_bytes == 0
    assert cache.get((0,)) is None
