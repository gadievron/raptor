"""Cross-library callee-summary attachment requires dependency context.

The summary cache holds pre-computed contracts for many libraries. The
callee enrichment used to attach the FIRST bare function-name match
across every cached library — a summary from a library the target does
not even depend on then drove contract-violation evidence. Attachment
now requires the target's dependency manifests to name the library at
the cached version.
"""

from __future__ import annotations


class TestTargetLibraryVersion:
    def test_detected_version_returned(self, tmp_path):
        from core.audit.orchestrator import (
            _target_lib_version_memo,
            _target_library_version,
        )

        _target_lib_version_memo.clear()
        (tmp_path / "requirements.txt").write_text("flask==2.3.1\n")
        assert _target_library_version(tmp_path, "flask") == "2.3.1"

    def test_undetected_library_returns_none(self, tmp_path):
        from core.audit.orchestrator import (
            _target_lib_version_memo,
            _target_library_version,
        )

        _target_lib_version_memo.clear()
        (tmp_path / "requirements.txt").write_text("flask==2.3.1\n")
        assert _target_library_version(tmp_path, "django") is None

    def test_memoised_per_target_and_library(self, tmp_path):
        from core.audit.orchestrator import (
            _target_lib_version_memo,
            _target_library_version,
        )

        _target_lib_version_memo.clear()
        (tmp_path / "requirements.txt").write_text("flask==2.3.1\n")
        assert _target_library_version(tmp_path, "flask") == "2.3.1"
        # Manifest change is NOT picked up (memoised) — the audit run
        # resolves dependencies once, deterministically.
        (tmp_path / "requirements.txt").write_text("flask==9.9.9\n")
        assert _target_library_version(tmp_path, "flask") == "2.3.1"
        assert (str(tmp_path), "flask") in _target_lib_version_memo


class TestDependencyGateWiring:
    """The enrichment loop must gate on _target_library_version.

    Source-level wiring check (established pattern for the heavy
    review_one_function scaffolding): the cached-library scan inside
    the callee-summary enrichment must consult the dependency gate
    before summary_cache.lookup.
    """

    def test_summary_cache_scan_is_dependency_gated(self):
        import inspect

        import core.audit.orchestrator as orch

        src = inspect.getsource(orch.review_one_function)
        idx = src.find("available_libraries()")
        assert idx >= 0, "cached-library scan not found"
        lookup_idx = src.find("summary_cache.lookup", idx)
        assert lookup_idx >= 0, "summary_cache.lookup not found"
        gate_idx = src.find("_target_library_version", idx)
        assert 0 <= gate_idx < lookup_idx, (
            "cached cross-library summaries must pass the dependency-"
            "context gate before attaching as callee evidence"
        )
