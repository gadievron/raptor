"""Proportionate CPG-build failure: one retry at derived-max limits
on large scopes, and a run-report record of the channel outcome —
channel loss must never live only in a mid-run log line."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import core.audit.joern_backend as jb
from core.audit.joern_backend import (
    JOERN_CPG_STATUS_FILENAME,
    _CPG_RETRY_MIN_SLOC,
    _derived_max_retry_limits,
    load_cpg_build_status,
)


def _patch_sizing(monkeypatch, *, sloc: int, max_heap: int = 65536):
    import core.tuning as tuning
    import packages.joern.runner as runner
    monkeypatch.setattr(
        runner, "estimate_in_scope_sloc",
        lambda target, exclude_dirs=(): sloc,
    )
    monkeypatch.setattr(
        tuning, "derived_max_joern_heap_mb", lambda: max_heap,
    )


class TestRetryArming:
    def test_below_threshold_not_armed(self, monkeypatch, tmp_path):
        _patch_sizing(monkeypatch, sloc=_CPG_RETRY_MIN_SLOC - 1)
        assert _derived_max_retry_limits(
            tmp_path, (), None, False, 300) is None

    def test_large_scope_armed_with_raised_limits(self, monkeypatch, tmp_path):
        _patch_sizing(monkeypatch, sloc=3_000_000)
        got = _derived_max_retry_limits(tmp_path, (), 16384, True, 300)
        assert got is not None
        heap, timeout, sloc = got
        assert heap == 65536  # derived heap raises to the ceiling
        assert timeout >= 2 * 2849  # SLOC curve with slack
        assert sloc == 3_000_000

    def test_already_at_derived_max_not_armed(self, monkeypatch, tmp_path):
        _patch_sizing(monkeypatch, sloc=3_000_000, max_heap=65536)
        from core.tuning import derive_joern_cpg_timeout_s
        at_max_timeout = derive_joern_cpg_timeout_s(3_000_000)
        assert _derived_max_retry_limits(
            tmp_path, (), 65536, True, at_max_timeout,
        ) is None

    def test_operator_heap_above_ceiling_never_lowered(
        self, monkeypatch, tmp_path,
    ):
        _patch_sizing(monkeypatch, sloc=3_000_000, max_heap=65536)
        got = _derived_max_retry_limits(
            tmp_path, (), 131072, False, 300)
        assert got is not None
        heap, _timeout, _sloc = got
        assert heap == 131072

    def test_explicit_heap_never_raised(self, monkeypatch, tmp_path):
        # An explicit operator heap is an assertion, honored both
        # directions: the retry keeps it exactly and may only
        # extend the timeout.
        _patch_sizing(monkeypatch, sloc=3_000_000, max_heap=65536)
        got = _derived_max_retry_limits(
            tmp_path, (), 16384, False, 300)
        assert got is not None
        heap, timeout, _sloc = got
        assert heap == 16384
        assert timeout >= 2 * 2849

    def test_absent_heap_raises_to_ceiling(self, monkeypatch, tmp_path):
        _patch_sizing(monkeypatch, sloc=3_000_000, max_heap=65536)
        got = _derived_max_retry_limits(
            tmp_path, (), None, False, 300)
        assert got is not None
        heap, _timeout, _sloc = got
        assert heap == 65536

    def test_estimate_failure_not_armed(self, monkeypatch, tmp_path):
        import packages.joern.runner as runner

        def boom(target, exclude_dirs=()):
            raise OSError("walk failed")

        monkeypatch.setattr(runner, "estimate_in_scope_sloc", boom)
        assert _derived_max_retry_limits(
            tmp_path, (), None, False, 300) is None


class TestEnsureCpgLoadedRetry:
    def _isolate_home(self, monkeypatch, tmp_path: Path) -> None:
        # _ensure_cpg_loaded mkdirs its cache under Path.home() —
        # keep the test's writes inside its own tmp tree.
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

    def _fake_cpg(self, tmp_path: Path, *, failed: bool):
        p = tmp_path / "cpg.bin"
        p.write_bytes(b"x")
        return SimpleNamespace(
            path=p, exists=lambda: not failed, build_failed=failed,
        )

    def test_retry_rescues_and_records(self, monkeypatch, tmp_path):
        import packages.joern.runner as runner
        self._isolate_home(monkeypatch, tmp_path)
        _patch_sizing(monkeypatch, sloc=3_000_000)
        out = tmp_path / "run"
        out.mkdir()
        calls: list[dict] = []
        fake_results = [
            self._fake_cpg(tmp_path, failed=True),
            self._fake_cpg(tmp_path, failed=False),
        ]

        def fake_build(target, cache_dir, **kwargs):
            calls.append(kwargs)
            return fake_results[len(calls) - 1]

        monkeypatch.setattr(runner, "build_cpg_cached", fake_build)
        imported: list = []
        srv = SimpleNamespace(
            _cpg_loaded=False,
            import_cpg=lambda path, timeout=None: imported.append(path),
        )
        ok = jb._ensure_cpg_loaded(
            srv, tmp_path,
            tunables=SimpleNamespace(
                cpg_timeout_s=300, import_timeout_s=900, heap_mb=16384,
                cpg_timeout_auto=False, heap_is_derived=True,
            ),
            out_dir=out,
        )
        assert ok is True
        assert len(calls) == 2
        assert calls[1]["heap_mb"] == 65536
        assert calls[1]["timeout"] >= 2 * 2849
        assert imported  # the rescued graph was imported
        record = load_cpg_build_status(out)
        assert record is not None
        assert record["failed"] is False
        assert record["retried"] is True
        assert record["retry_heap_mb"] == 65536

    def test_channel_loss_recorded_after_failed_retry(
        self, monkeypatch, tmp_path,
    ):
        import packages.joern.runner as runner
        self._isolate_home(monkeypatch, tmp_path)
        _patch_sizing(monkeypatch, sloc=3_000_000)
        out = tmp_path / "run"
        out.mkdir()
        calls: list[dict] = []

        def fake_build(target, cache_dir, **kwargs):
            calls.append(kwargs)
            return self._fake_cpg(tmp_path, failed=True)

        monkeypatch.setattr(runner, "build_cpg_cached", fake_build)
        srv = SimpleNamespace(_cpg_loaded=False)
        ok = jb._ensure_cpg_loaded(srv, tmp_path, out_dir=out)
        assert ok is False
        assert len(calls) == 2  # exactly one retry, never more
        record = load_cpg_build_status(out)
        assert record is not None
        assert record["failed"] is True
        assert record["retried"] is True

    def test_small_scope_fails_without_retry(self, monkeypatch, tmp_path):
        import packages.joern.runner as runner
        self._isolate_home(monkeypatch, tmp_path)
        _patch_sizing(monkeypatch, sloc=10_000)
        out = tmp_path / "run"
        out.mkdir()
        calls: list[dict] = []

        def fake_build(target, cache_dir, **kwargs):
            calls.append(kwargs)
            return self._fake_cpg(tmp_path, failed=True)

        monkeypatch.setattr(runner, "build_cpg_cached", fake_build)
        srv = SimpleNamespace(_cpg_loaded=False)
        ok = jb._ensure_cpg_loaded(srv, tmp_path, out_dir=out)
        assert ok is False
        assert len(calls) == 1
        record = load_cpg_build_status(out)
        assert record is not None
        assert record["failed"] is True
        assert record["retried"] is False

    def test_import_failure_is_channel_loss_not_rescue(
        self, monkeypatch, tmp_path,
    ):
        # A rescued BUILD whose import then fails must record a
        # failure, never a rescue the server cannot serve.
        import packages.joern.runner as runner
        _patch_sizing(monkeypatch, sloc=3_000_000)
        self._isolate_home(monkeypatch, tmp_path)
        out = tmp_path / "run"
        out.mkdir()
        results = [
            self._fake_cpg(tmp_path, failed=True),
            self._fake_cpg(tmp_path, failed=False),
        ]
        calls: list[dict] = []

        def fake_build(target, cache_dir, **kwargs):
            calls.append(kwargs)
            return results[len(calls) - 1]

        monkeypatch.setattr(runner, "build_cpg_cached", fake_build)

        def broken_import(path, timeout=None):
            raise RuntimeError("import transport died")

        srv = SimpleNamespace(_cpg_loaded=False, import_cpg=broken_import)
        ok = jb._ensure_cpg_loaded(srv, tmp_path, out_dir=out)
        assert ok is False
        record = load_cpg_build_status(out)
        assert record is not None
        assert record["failed"] is True
        assert record["retried"] is True
        assert record["phase"] == "import"

    def test_build_exception_records_channel_loss(
        self, monkeypatch, tmp_path,
    ):
        import packages.joern.runner as runner
        self._isolate_home(monkeypatch, tmp_path)
        out = tmp_path / "run"
        out.mkdir()

        def exploding_build(target, cache_dir, **kwargs):
            raise OSError("no space left on device")

        monkeypatch.setattr(runner, "build_cpg_cached", exploding_build)
        srv = SimpleNamespace(_cpg_loaded=False)
        ok = jb._ensure_cpg_loaded(srv, tmp_path, out_dir=out)
        assert ok is False
        record = load_cpg_build_status(out)
        assert record is not None
        assert record["failed"] is True
        assert record["phase"] == "build"

    def test_success_writes_truthful_record(self, monkeypatch, tmp_path):
        # Contract change (stale-record fix): a plain success now
        # writes a failed=False, retried=False record — the write is
        # what retires a stale failure record from an earlier segment
        # sharing the out dir. The report prints nothing for it (the
        # rescue line keys on retried).
        import packages.joern.runner as runner
        self._isolate_home(monkeypatch, tmp_path)
        out = tmp_path / "run"
        out.mkdir()
        monkeypatch.setattr(
            runner, "build_cpg_cached",
            lambda target, cache_dir, **kw: self._fake_cpg(
                tmp_path, failed=False),
        )
        srv = SimpleNamespace(
            _cpg_loaded=False,
            import_cpg=lambda path, timeout=None: None,
        )
        assert jb._ensure_cpg_loaded(srv, tmp_path, out_dir=out) is True
        record = load_cpg_build_status(out)
        assert record is not None
        assert record["failed"] is False
        assert record["retried"] is False
        assert record["phase"] == "complete"


class TestReportSurfacing:
    def test_channel_loss_named_in_report(self, tmp_path):
        from core.json import save_json
        save_json(tmp_path / JOERN_CPG_STATUS_FILENAME, {
            "target": "/t", "failed": True, "retried": True,
            "first_heap_mb": 16384, "first_timeout_s": 300,
            "retry_heap_mb": 65536, "retry_timeout_s": 5700,
            "estimated_sloc": 3_000_000, "scope_excluded_dirs": 4,
        })
        from core.audit.report import generate_report
        report = generate_report(tmp_path)
        assert report["joern_cpg_build"]["failed"] is True
        assert "Joern channel lost" in report["summary"]
        assert "joern_heap_ceiling_mb" in report["summary"]

    def test_rescue_named_in_report(self, tmp_path):
        from core.json import save_json
        save_json(tmp_path / JOERN_CPG_STATUS_FILENAME, {
            "target": "/t", "failed": False, "retried": True,
            "first_heap_mb": None, "first_timeout_s": 300,
            "retry_heap_mb": 65536, "retry_timeout_s": 5700,
            "estimated_sloc": 3_000_000, "scope_excluded_dirs": 0,
        })
        from core.audit.report import generate_report
        report = generate_report(tmp_path)
        assert report["joern_cpg_build"]["retried"] is True
        assert "derived-max retry" in report["summary"]
        assert "Joern channel lost" not in report["summary"]

    def test_import_failure_named_in_report(self, tmp_path):
        from core.json import save_json
        save_json(tmp_path / JOERN_CPG_STATUS_FILENAME, {
            "target": "/t", "failed": True, "retried": True,
            "phase": "import",
            "first_heap_mb": 16384, "first_timeout_s": 300,
            "retry_heap_mb": 65536, "retry_timeout_s": 5700,
            "estimated_sloc": 3_000_000, "scope_excluded_dirs": 0,
        })
        from core.audit.report import generate_report
        report = generate_report(tmp_path)
        assert "Joern channel lost" in report["summary"]
        assert "failed to import" in report["summary"]

    def test_no_artifact_no_report_entry(self, tmp_path):
        from core.audit.report import generate_report
        report = generate_report(tmp_path)
        assert "joern_cpg_build" not in report


class TestPlainSuccessRetiresStaleRecord:
    _isolate_home = TestEnsureCpgLoadedRetry._isolate_home
    _fake_cpg = TestEnsureCpgLoadedRetry._fake_cpg

    def test_plain_success_overwrites_prior_failure(
        self, monkeypatch, tmp_path,
    ):
        # Segment 1 failed and recorded the loss; segment 2's build
        # succeeds WITHOUT the retry (cache warm / tuning raised). The
        # success must retire the stale failed record — otherwise the
        # report claims a channel loss beside real joern receipts.
        import packages.joern.runner as runner
        self._isolate_home(monkeypatch, tmp_path)
        _patch_sizing(monkeypatch, sloc=10_000)
        out = tmp_path / "run"
        out.mkdir()
        from core.json import save_json
        save_json(out / jb.JOERN_CPG_STATUS_FILENAME, {
            "target": str(tmp_path), "failed": True, "phase": "build",
            "retried": False, "ts": "2026-09-25T00:00:00+00:00",
        })

        monkeypatch.setattr(
            runner, "build_cpg_cached",
            lambda target, cache_dir, **kw: self._fake_cpg(
                tmp_path, failed=False),
        )
        srv = SimpleNamespace(
            _cpg_loaded=False,
            import_cpg=lambda path, timeout=None: None,
        )
        ok = jb._ensure_cpg_loaded(srv, tmp_path, out_dir=out)
        assert ok is True
        record = load_cpg_build_status(out)
        assert record is not None
        assert record["failed"] is False
        assert record["retried"] is False
        assert record["phase"] == "complete"

    def test_plain_success_record_renders_silently(self, tmp_path):
        # The truthful plain-success record (stale-record fix) must
        # not borrow the rescue line — nothing to say, say nothing.
        from core.json import save_json
        save_json(tmp_path / JOERN_CPG_STATUS_FILENAME, {
            "target": "/t", "failed": False, "retried": False,
            "first_heap_mb": 16384, "first_timeout_s": 300,
            "retry_heap_mb": 65536, "retry_timeout_s": 5700,
            "estimated_sloc": 10_000, "scope_excluded_dirs": 0,
        })
        from core.audit.report import generate_report
        report = generate_report(tmp_path)
        assert report["joern_cpg_build"]["failed"] is False
        assert "derived-max retry" not in report["summary"]
        assert "Joern channel lost" not in report["summary"]
