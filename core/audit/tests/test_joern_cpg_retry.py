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
            import_cpg=lambda path, timeout=None: imported.append(path) or True,
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
            import_cpg=lambda path, timeout=None: True,
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
            import_cpg=lambda path, timeout=None: True,
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


class TestImportResultHonesty:
    """import_cpg reports handled failures by RETURNING False (server
    died mid-import, malformed response) — segment-shape: a kernel
    CPG import killing the server minted a fake success (CPG-less
    server read as loaded, false failed=False record, unrecoverable
    pre-sweep). The result must be checked, retried once against a
    restarted server, and recorded truthfully."""

    _isolate_home = TestEnsureCpgLoadedRetry._isolate_home
    _fake_cpg = TestEnsureCpgLoadedRetry._fake_cpg

    def _setup(self, monkeypatch, tmp_path):
        import packages.joern.runner as runner
        self._isolate_home(monkeypatch, tmp_path)
        _patch_sizing(monkeypatch, sloc=10_000)
        out = tmp_path / "run"
        out.mkdir()
        monkeypatch.setattr(
            runner, "build_cpg_cached",
            lambda target, cache_dir, **kw: self._fake_cpg(
                tmp_path, failed=False),
        )
        return out

    def test_false_import_is_channel_loss_not_success(
            self, monkeypatch, tmp_path):
        out = self._setup(monkeypatch, tmp_path)
        calls: list = []
        srv = SimpleNamespace(
            _cpg_loaded=False,
            import_cpg=lambda path, timeout=None: calls.append(
                timeout) or False,
            restart=lambda: False,  # restart fails too
        )
        assert jb._ensure_cpg_loaded(srv, tmp_path, out_dir=out) is False
        assert len(calls) == 1  # failed restart => no second import
        record = load_cpg_build_status(out)
        assert record is not None
        assert record["failed"] is True
        assert record["phase"] == "import"

    def test_import_retry_after_restart_rescues(
            self, monkeypatch, tmp_path):
        out = self._setup(monkeypatch, tmp_path)
        imports: list = []
        restarts: list = []

        def fake_import(path, timeout=None):
            imports.append(timeout)
            return len(imports) > 1  # first fails, retry succeeds

        srv = SimpleNamespace(
            _cpg_loaded=False,
            import_cpg=fake_import,
            restart=lambda: restarts.append(1) or True,
        )
        assert jb._ensure_cpg_loaded(srv, tmp_path, out_dir=out) is True
        assert len(imports) == 2 and len(restarts) == 1
        # Retry timeout: doubled with a 30-min floor.
        assert imports[1] >= 1800
        record = load_cpg_build_status(out)
        assert record is not None
        assert record["failed"] is False

    def test_no_restart_api_degrades_without_retry(
            self, monkeypatch, tmp_path):
        out = self._setup(monkeypatch, tmp_path)
        imports: list = []
        srv = SimpleNamespace(
            _cpg_loaded=False,
            import_cpg=lambda path, timeout=None: imports.append(
                1) or False,
        )
        assert jb._ensure_cpg_loaded(srv, tmp_path, out_dir=out) is False
        assert len(imports) == 1
        record = load_cpg_build_status(out)
        assert record["failed"] is True

    def test_orchestrator_passes_out_dir(self):
        # Wiring pin: the audit's own server start must hand out_dir
        # through, or every record write above is a silent no-op on
        # the main path (the segment-6 observability gap).
        import inspect
        import core.audit.orchestrator as orch
        src = inspect.getsource(orch)
        idx = src.find("_start_joern_server_raw(\n")
        assert idx != -1
        call = src[idx:idx + 800]
        assert "out_dir=config.out_dir" in call

    def test_report_names_the_record_target(self, tmp_path):
        from core.json import save_json
        save_json(tmp_path / JOERN_CPG_STATUS_FILENAME, {
            "target": "/t/narrowed-root", "failed": True,
            "retried": False, "phase": "import",
            "first_heap_mb": 16384, "first_timeout_s": 300,
            "retry_heap_mb": 65536, "retry_timeout_s": 5700,
            "estimated_sloc": 3_000_000, "scope_excluded_dirs": 4,
        })
        from core.audit.report import generate_report
        report = generate_report(tmp_path)
        assert "Joern channel lost" in report["summary"]
        assert "/t/narrowed-root" in report["summary"]

    def test_record_fields_never_clobber_build_retry(
            self, monkeypatch, tmp_path):
        # The import retry must record its own fields — rebinding the
        # build retry's closure variable fabricated retry_timeout_s
        # (report printed 1800 where the derived-max build retry ran
        # 5700).
        import packages.joern.runner as runner
        self._isolate_home(monkeypatch, tmp_path)
        _patch_sizing(monkeypatch, sloc=3_000_000)
        out = tmp_path / "run"
        out.mkdir()
        builds: list = []
        fake_results = [
            self._fake_cpg(tmp_path, failed=True),
            self._fake_cpg(tmp_path, failed=False),
        ]

        def fake_build(target, cache_dir, **kwargs):
            builds.append(kwargs)
            return fake_results[min(len(builds), 2) - 1]

        monkeypatch.setattr(runner, "build_cpg_cached", fake_build)
        imports: list = []
        srv = SimpleNamespace(
            _cpg_loaded=False,
            import_cpg=lambda path, timeout=None: imports.append(
                timeout) or len(imports) > 1,
            restart=lambda: True,
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
        record = load_cpg_build_status(out)
        assert record["retried"] is True          # build retry ran
        assert record["retry_timeout_s"] >= 2 * 2849  # NOT clobbered
        assert record["import_retried"] is True
        assert record["import_retry_timeout_s"] == 1800

    def test_report_names_the_import_rescue(self, tmp_path):
        from core.json import save_json
        save_json(tmp_path / JOERN_CPG_STATUS_FILENAME, {
            "target": "/t", "failed": False, "retried": False,
            "phase": "complete", "import_retried": True,
            "import_retry_timeout_s": 1800,
            "first_heap_mb": 16384, "first_timeout_s": 300,
            "retry_heap_mb": None, "retry_timeout_s": 5700,
            "estimated_sloc": 10_000, "scope_excluded_dirs": 0,
        })
        from core.audit.report import generate_report
        report = generate_report(tmp_path)
        assert "rescued by a retry against" in report["summary"]
        assert "Joern channel lost" not in report["summary"]
        assert "derived-max retry" not in report["summary"]


class TestImportFailureHonesty:
    """The status record must say WHY a channel was lost (which
    ceiling bound, what operation died) — the before-shape was a
    failed record beside a bare log line. And a timeout-class first
    failure must never retry at the same budget: the first timeout
    proved that wall insufficient (an idle-but-slow client-side
    deserialise), so the retry raises bounded or fails fast."""

    _isolate_home = TestEnsureCpgLoadedRetry._isolate_home
    _fake_cpg = TestEnsureCpgLoadedRetry._fake_cpg

    _MIB = 1024 * 1024

    def _setup(self, monkeypatch, tmp_path, *, cpg_bytes: int = 1):
        import packages.joern.runner as runner
        self._isolate_home(monkeypatch, tmp_path)
        _patch_sizing(monkeypatch, sloc=10_000)
        out = tmp_path / "run"
        out.mkdir()
        p = tmp_path / "cpg.bin"
        with p.open("wb") as f:
            f.truncate(cpg_bytes)  # sparse: size without the bytes
        cpg = SimpleNamespace(
            path=p, exists=lambda: True, build_failed=False,
        )
        monkeypatch.setattr(
            runner, "build_cpg_cached",
            lambda target, cache_dir, **kw: cpg,
        )
        return out

    def _tunables(self, import_timeout_s: int, *, auto: bool = False):
        return SimpleNamespace(
            cpg_timeout_s=300, import_timeout_s=import_timeout_s,
            heap_mb=None, cpg_timeout_auto=False,
            import_timeout_auto=auto, heap_is_derived=False,
        )

    def test_timeout_at_ceiling_fails_fast_without_retry(
            self, monkeypatch, tmp_path):
        # No larger retry budget exists above the derivation ceiling:
        # re-running the SAME wall is guaranteed waste, so the channel
        # fails fast with an honest reason instead of burning a second
        # ceiling-length wall.
        from core.tuning import derived_max_joern_import_timeout_s
        cap = derived_max_joern_import_timeout_s()
        out = self._setup(monkeypatch, tmp_path)
        imports: list = []
        restarts: list = []
        srv = SimpleNamespace(
            _cpg_loaded=False,
            _last_post_error=f"query timed out after {cap}s",
            import_cpg=lambda path, timeout=None: imports.append(
                timeout) or False,
            restart=lambda: restarts.append(1) or True,
        )
        ok = jb._ensure_cpg_loaded(
            srv, tmp_path, tunables=self._tunables(cap), out_dir=out,
        )
        assert ok is False
        assert len(imports) == 1 and not restarts
        record = load_cpg_build_status(out)
        assert record["failed"] is True
        assert record["phase"] == "import"
        assert record["reason"] == "import_timeout"
        assert record["import_timeout_s"] == cap
        assert record["cpg_bytes"] == 1

    def test_timeout_below_ceiling_retries_at_raised_budget(
            self, monkeypatch, tmp_path):
        out = self._setup(monkeypatch, tmp_path)
        imports: list = []
        srv = SimpleNamespace(
            _cpg_loaded=False,
            _last_post_error="query timed out after 3800s",
            import_cpg=lambda path, timeout=None: imports.append(
                timeout) or len(imports) > 1,
            restart=lambda: True,
        )
        ok = jb._ensure_cpg_loaded(
            srv, tmp_path, tunables=self._tunables(3800), out_dir=out,
        )
        assert ok is True
        # The retry budget RAISED (doubled), never the same wall.
        assert imports == [3800, 7600]
        record = load_cpg_build_status(out)
        assert record["failed"] is False
        assert record["import_retried"] is True
        assert record["import_retry_timeout_s"] == 7600
        assert record["reason"] is None

    def test_retry_budget_clamps_at_derivation_ceiling(
            self, monkeypatch, tmp_path):
        from core.tuning import derived_max_joern_import_timeout_s
        cap = derived_max_joern_import_timeout_s()
        out = self._setup(monkeypatch, tmp_path)
        imports: list = []
        srv = SimpleNamespace(
            _cpg_loaded=False,
            _last_post_error="query timed out after 7000s",
            import_cpg=lambda path, timeout=None: imports.append(
                timeout) or len(imports) > 1,
            restart=lambda: True,
        )
        ok = jb._ensure_cpg_loaded(
            srv, tmp_path, tunables=self._tunables(7000), out_dir=out,
        )
        assert ok is True
        assert imports == [7000, cap]  # 2x would be 14000 — clamped

    def test_crash_class_records_connection_reason(
            self, monkeypatch, tmp_path):
        out = self._setup(monkeypatch, tmp_path)
        imports: list = []
        srv = SimpleNamespace(
            _cpg_loaded=False,
            _last_post_error="connection failed: [Errno 104] reset",
            import_cpg=lambda path, timeout=None: imports.append(
                timeout) or False,
            restart=lambda: True,
        )
        ok = jb._ensure_cpg_loaded(
            srv, tmp_path, tunables=self._tunables(900), out_dir=out,
        )
        assert ok is False
        assert len(imports) == 2  # crash class still gets its retry
        record = load_cpg_build_status(out)
        assert record["reason"] == "import_connection_lost"

    def test_handled_failure_without_detail_records_generic_reason(
            self, monkeypatch, tmp_path):
        # Injected doubles and handled non-transport failures carry no
        # post classification — the reason degrades to the generic
        # class, never to a crash or a fabricated ceiling claim.
        out = self._setup(monkeypatch, tmp_path)
        srv = SimpleNamespace(
            _cpg_loaded=False,
            import_cpg=lambda path, timeout=None: False,
            restart=lambda: True,
        )
        assert jb._ensure_cpg_loaded(srv, tmp_path, out_dir=out) is False
        record = load_cpg_build_status(out)
        assert record["reason"] == "import_failed"

    def test_auto_import_budget_scales_with_cpg_size(
            self, monkeypatch, tmp_path):
        # The kernel-scale shape: a ~190 MiB serialized CPG must get
        # an import wall that clears the fixed window it died under.
        out = self._setup(monkeypatch, tmp_path, cpg_bytes=190 * self._MIB)
        imports: list = []
        srv = SimpleNamespace(
            _cpg_loaded=False,
            import_cpg=lambda path, timeout=None: imports.append(
                timeout) or True,
        )
        ok = jb._ensure_cpg_loaded(
            srv, tmp_path,
            tunables=self._tunables(900, auto=True), out_dir=out,
        )
        assert ok is True
        assert imports[0] > 1800  # clears the old fixed retry window
        assert imports[0] <= 10800
        record = load_cpg_build_status(out)
        assert record["cpg_bytes"] == 190 * self._MIB
        assert record["import_timeout_s"] == imports[0]

    def test_build_failure_reasons_recorded(self, monkeypatch, tmp_path):
        import packages.joern.runner as runner
        self._isolate_home(monkeypatch, tmp_path)
        _patch_sizing(monkeypatch, sloc=10_000)
        out = tmp_path / "run"
        out.mkdir()
        monkeypatch.setattr(
            runner, "build_cpg_cached",
            lambda target, cache_dir, **kw: self._fake_cpg(
                tmp_path, failed=True),
        )
        srv = SimpleNamespace(_cpg_loaded=False)
        assert jb._ensure_cpg_loaded(srv, tmp_path, out_dir=out) is False
        assert load_cpg_build_status(out)["reason"] == "build_failed"

        def exploding(target, cache_dir, **kw):
            raise OSError("no space left on device")

        monkeypatch.setattr(runner, "build_cpg_cached", exploding)
        assert jb._ensure_cpg_loaded(srv, tmp_path, out_dir=out) is False
        assert load_cpg_build_status(out)["reason"] == "build_error"

    def test_success_record_reason_is_none(self, monkeypatch, tmp_path):
        out = self._setup(monkeypatch, tmp_path)
        srv = SimpleNamespace(
            _cpg_loaded=False,
            import_cpg=lambda path, timeout=None: True,
        )
        assert jb._ensure_cpg_loaded(srv, tmp_path, out_dir=out) is True
        record = load_cpg_build_status(out)
        assert record["reason"] is None
        assert record["cpg_bytes"] == 1
