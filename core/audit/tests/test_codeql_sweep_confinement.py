"""Filesystem-confinement fences for the sweep's codeql invocations.

The codeql JVM analyzes a database extracted from the scanned repo —
attacker-shaped bytes — so its sandboxed run must carry REAL
filesystem confinement on both sides:

* reads: ``restrict_reads=True`` plus an enumerated grant (query pack
  roots, the installed-pack home) — without the flag the substrate
  discards ``readable_paths`` outright and the Landlock tier leaves
  reads host-wide;
* writes: the database dir only — the durable pack trees stay
  read-only so a compromised JVM cannot poison compiled-query caches,
  with the compilation cache redirected into the database dir.

Most fences are hermetic kwarg recorders (no codeql CLI, no network).
Kwarg recorders alone stay green while the substrate ignores a kwarg,
so one fence (:class:`TestLiveConfinement`) goes through the real
``core.sandbox`` substrate and is skipped only when no
filesystem-confinement lane can engage on the host.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import core.audit.sweep as sweep_mod
from core.audit.run_memo import BoundedMemo
from core.audit.sweep import (
    _codeql_pack_root,
    _sandboxed_codeql_runner,
    run_codeql_sweep,
    warm_codeql_memo,
)
from core.sandbox.errors import SandboxSetupError


@pytest.fixture(autouse=True)
def _fresh_memo():
    sweep_mod._reset_codeql_memo()
    yield
    sweep_mod._reset_codeql_memo()


_FAKE_CODEQL = "/home/testuser/.local/bin/codeql"


@pytest.fixture
def hermetic_codeql_cli(monkeypatch):
    """Both dispatch paths resolve the codeql CLI in the caller env —
    pin a fake home-rooted install so tests never depend on, or vary
    with, the host's codeql. Not autouse: the live-substrate fence
    needs the real ``shutil.which`` (the sandbox resolves its probe
    argv through it)."""
    import shutil

    monkeypatch.setattr(
        shutil, "which",
        lambda name, *a, **k: _FAKE_CODEQL if name == "codeql" else None,
    )


class _RecordingSandboxRun:
    """Stand-in for ``core.sandbox.run`` capturing every call."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, cmd: list[str], **kwargs: Any):
        record = dict(kwargs)
        record["cmd"] = list(cmd)
        # Existence is a call-time property (scratch dirs are deleted
        # on exit) — capture it now, not at assert time.
        out = kwargs.get("output")
        record["output_existed"] = bool(out) and os.path.isdir(out)
        self.calls.append(record)
        return SimpleNamespace(returncode=0, stdout="", stderr="")


@pytest.fixture
def sandbox_recorder(monkeypatch) -> _RecordingSandboxRun:
    import core.sandbox as _sb

    rec = _RecordingSandboxRun()
    monkeypatch.setattr(_sb, "run", rec)
    return rec


def _make_pack_query(tmp_path: Path) -> tuple[Path, Path]:
    """A query file inside a qlpack (manifest at the pack root)."""
    pack = tmp_path / "pack"
    (pack / "queries").mkdir(parents=True)
    (pack / "qlpack.yml").write_text("name: test/pack\n", encoding="utf-8")
    query = pack / "queries" / "q.ql"
    query.write_text("/** @id cpp/test-q */\nselect 1", encoding="utf-8")
    return query, pack


class TestPackRoot:
    def test_ascends_to_qlpack_manifest(self, tmp_path: Path):
        query, pack = _make_pack_query(tmp_path)
        assert _codeql_pack_root(query) == pack.resolve()

    def test_codeql_pack_yml_also_matches(self, tmp_path: Path):
        pack = tmp_path / "pack"
        pack.mkdir()
        (pack / "codeql-pack.yml").write_text("name: t/p\n", encoding="utf-8")
        query = pack / "q.ql"
        query.write_text("select 1", encoding="utf-8")
        assert _codeql_pack_root(query) == pack.resolve()

    def test_falls_back_to_query_dir_without_manifest(self, tmp_path: Path):
        query = tmp_path / "bare" / "q.ql"
        query.parent.mkdir()
        query.write_text("select 1", encoding="utf-8")
        assert _codeql_pack_root(query) == (tmp_path / "bare").resolve()

    def test_deep_pack_within_bound_still_resolves(self, tmp_path: Path):
        """The deepest standard-pack layout (3 levels of nesting)
        sits well inside the ascent bound."""
        pack = tmp_path / "pack"
        deep = pack / "Security" / "CWE" / "CWE-120"
        deep.mkdir(parents=True)
        (pack / "qlpack.yml").write_text("name: t/p\n", encoding="utf-8")
        query = deep / "q.ql"
        query.write_text("select 1", encoding="utf-8")
        assert _codeql_pack_root(query) == pack.resolve()

    def test_manifest_beyond_bound_falls_back_loudly(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ):
        """A manifest deeper than the ascent bound cannot widen the
        read grant — the lookup falls back to the query dir and the
        unusable shape is diagnosed at WARNING, not left as a silent
        per-hypothesis analyze error."""
        root = tmp_path / "far"
        deep = root / "a" / "b" / "c" / "d" / "e" / "f" / "g"
        deep.mkdir(parents=True)
        (root / "qlpack.yml").write_text("name: t/p\n", encoding="utf-8")
        query = deep / "q.ql"
        query.write_text("select 1", encoding="utf-8")
        with caplog.at_level(logging.WARNING, logger="core.audit.sweep"):
            assert _codeql_pack_root(query) == deep.resolve()
        warned = [
            r for r in caplog.records
            if "outside the bounded read grant" in r.getMessage()
        ]
        assert len(warned) == 1

    def test_home_directory_never_accepted_as_pack_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        """A manifest planted in $HOME would convert the lookup into a
        home-wide read grant — the ascent stops before examining it."""
        home = tmp_path / "home"
        sub = home / "sub"
        sub.mkdir(parents=True)
        (home / "qlpack.yml").write_text("name: t/p\n", encoding="utf-8")
        monkeypatch.setenv("HOME", str(home))
        query = sub / "q.ql"
        query.write_text("select 1", encoding="utf-8")
        assert _codeql_pack_root(query) == sub.resolve()


class TestCacheArgs:
    def test_redirects_cache_into_database_dir(self, tmp_path: Path):
        db = tmp_path / "db"
        db.mkdir()
        args = sweep_mod._codeql_cache_args(db)
        cache = db / "raptor-compile-cache"
        assert cache.is_dir()
        assert f"--compilation-cache={cache}" in args
        assert "--no-default-compilation-cache" in args

    def test_unmakeable_cache_dir_still_disables_default_caches(
        self, tmp_path: Path,
    ):
        """The default-cache deny is the write-protection half — it
        must ride even when the redirect dir cannot be created (the
        CLI surfaces the unwritable database itself)."""
        db = tmp_path / "missing" / "db"
        args = sweep_mod._codeql_cache_args(db)
        assert "--no-default-compilation-cache" in args


class TestRunnerConfinement:
    def _runner_kwargs(
        self, tmp_path: Path, sandbox_recorder: _RecordingSandboxRun,
    ) -> dict[str, Any]:
        query, pack = _make_pack_query(tmp_path)
        db = tmp_path / "db"
        db.mkdir()
        scratch = tmp_path / "scratch"
        scratch.mkdir()
        runner = _sandboxed_codeql_runner(
            ["/opt/codeql"],
            database_dir=db,
            query_paths=[str(query)],
            scratch_dir=scratch,
        )
        runner(
            ["codeql", "database", "analyze", str(db)],
            capture_output=True, text=True, timeout=5, check=False,
            env={"INJECTED": "1"},
        )
        assert len(sandbox_recorder.calls) == 1
        return sandbox_recorder.calls[0]

    def test_passes_fs_confinement(
        self, tmp_path: Path, sandbox_recorder: _RecordingSandboxRun,
        monkeypatch,
    ):
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        kwargs = self._runner_kwargs(tmp_path, sandbox_recorder)
        assert kwargs["output"] == str(tmp_path / "scratch")
        # restrict_reads is what makes readable_paths REAL: without it
        # the substrate discards the read grant and the Landlock tier
        # leaves reads host-wide.
        assert kwargs["restrict_reads"] is True
        assert str((tmp_path / "pack").resolve()) in kwargs["readable_paths"]
        # Write surface is the database dir ONLY — no pack tree, no
        # package home, nothing a poisoned compile cache could ride.
        assert kwargs["writable_paths"] == [str(tmp_path / "db")]
        assert kwargs["block_network"] is True
        assert kwargs["tool_paths"] == ["/opt/codeql"]

    def test_caller_env_is_dropped(
        self, tmp_path: Path, sandbox_recorder: _RecordingSandboxRun,
        monkeypatch,
    ):
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        kwargs = self._runner_kwargs(tmp_path, sandbox_recorder)
        assert "env" not in kwargs
        # subprocess-shaped kwargs still ride through.
        assert kwargs["timeout"] == 5
        assert kwargs["capture_output"] is True

    def test_codeql_home_granted_read_only_when_present(
        self, tmp_path: Path, sandbox_recorder: _RecordingSandboxRun,
        monkeypatch,
    ):
        home = tmp_path / "home"
        (home / ".codeql").mkdir(parents=True)
        monkeypatch.setenv("HOME", str(home))
        kwargs = self._runner_kwargs(tmp_path, sandbox_recorder)
        assert str(home / ".codeql") in kwargs["readable_paths"]
        # Never writable: installed packs are durable state every
        # future sweep executes.
        assert str(home / ".codeql") not in kwargs["writable_paths"]

    def test_absent_codeql_home_not_granted(
        self, tmp_path: Path, sandbox_recorder: _RecordingSandboxRun,
        monkeypatch,
    ):
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        kwargs = self._runner_kwargs(tmp_path, sandbox_recorder)
        assert str(home / ".codeql") not in kwargs["readable_paths"]
        assert str(home / ".codeql") not in kwargs["writable_paths"]


class TestRunnerSeamPin:
    """A caller-supplied ``sandbox_run`` pin owns the spawn seam.

    The whole-run warm-up fires the adapter on a daemon thread that
    outlives its launcher, so the launcher resolves
    ``core.sandbox.run`` in its own context and passes it down; the
    adapter must use that pin — not whatever the module attribute
    holds at spawn time — while omitting the pin must keep the
    pre-existing call-time resolution for same-thread callers."""

    def _built_runner_call(self, tmp_path: Path, **builder_kwargs: Any):
        query, _pack = _make_pack_query(tmp_path)
        db = tmp_path / "db"
        db.mkdir()
        scratch = tmp_path / "scratch"
        scratch.mkdir()
        runner = _sandboxed_codeql_runner(
            ["/opt/codeql"],
            database_dir=db,
            query_paths=[str(query)],
            scratch_dir=scratch,
            **builder_kwargs,
        )
        runner(
            ["codeql", "database", "analyze", str(db)],
            capture_output=True, text=True, timeout=5, check=False,
            env={"INJECTED": "1"},
        )

    def test_pinned_spawn_callable_wins_over_the_live_seam(
        self, tmp_path: Path, sandbox_recorder: _RecordingSandboxRun,
    ):
        pin = _RecordingSandboxRun()
        self._built_runner_call(tmp_path, sandbox_run=pin)
        assert sandbox_recorder.calls == []
        assert len(pin.calls) == 1
        # The pin changes WHO spawns, never WHAT rides the spawn: the
        # confinement kwargs and the env scrub are intact.
        kwargs = pin.calls[0]
        assert kwargs["block_network"] is True
        assert kwargs["restrict_reads"] is True
        assert kwargs["writable_paths"] == [str(tmp_path / "db")]
        assert "env" not in kwargs

    def test_omitted_pin_keeps_call_time_resolution(
        self, tmp_path: Path, sandbox_recorder: _RecordingSandboxRun,
    ):
        self._built_runner_call(tmp_path)
        assert len(sandbox_recorder.calls) == 1

    @pytest.mark.usefixtures("hermetic_codeql_cli")
    def test_warm_codeql_memo_threads_the_pin(
        self, tmp_path: Path, monkeypatch,
        sandbox_recorder: _RecordingSandboxRun,
    ):
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        db = _make_db(tmp_path)
        query, _pack = _make_pack_query(tmp_path)
        calls: list[dict[str, Any]] = []
        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", _recording_analyze(calls))

        pin = _RecordingSandboxRun()
        stats = warm_codeql_memo(
            str(db), [str(query)], BoundedMemo(8), sandbox_run=pin,
        )

        assert stats is not None
        assert len(calls) == 1
        assert sandbox_recorder.calls == []
        assert len(pin.calls) == 1
        assert pin.calls[0]["block_network"] is True


def _make_db(tmp_path: Path) -> Path:
    db = tmp_path / "codeql-db"
    db.mkdir(exist_ok=True)
    (db / "codeql-database.yml").write_text(
        "sourceLocationPrefix: /src\n", encoding="utf-8")
    import zipfile

    with zipfile.ZipFile(db / "src.zip", "w") as zf:
        zf.writestr("src/a.c", "int x;\n")
    return db


def _recording_analyze(calls: list[dict[str, Any]],
                       results: list[dict] | None = None):
    """Stand-in for codeql_augmented_run.analyze recording each call
    (including the runner, codeql_bin, and extra_args the sweep hands
    it)."""

    def fake(db_path, queries, output_path, *, extension_pack=None,
             codeql_bin="codeql", timeout_seconds=0, runner=None,
             extra_args=()):
        calls.append({
            "db": db_path, "queries": tuple(queries),
            "codeql_bin": codeql_bin, "runner": runner,
            "extra_args": tuple(extra_args),
        })
        if runner is not None:
            # Drive the adapter exactly as the real analyze() would.
            runner([str(codeql_bin), "database", "analyze", str(db_path)],
                   capture_output=True, text=True,
                   timeout=timeout_seconds, check=False,
                   env={"CALLER": "env"})
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps({"runs": [{"results": results or []}]}),
            encoding="utf-8",
        )
        return SimpleNamespace(
            sarif_path=output_path, queries=tuple(queries),
            extension_pack=extension_pack, elapsed_seconds=0.0,
        )

    return fake


def _assert_cache_redirect(extra_args: tuple[str, ...], db: Path) -> None:
    """The compile cache is redirected INTO the database dir and the
    default (pack-tree) cache locations are disabled."""
    assert "--no-default-compilation-cache" in extra_args
    redirects = [
        a for a in extra_args if a.startswith("--compilation-cache=")
    ]
    assert len(redirects) == 1
    assert redirects[0].split("=", 1)[1] == str(db / "raptor-compile-cache")


@pytest.mark.usefixtures("hermetic_codeql_cli")
class TestDispatchConfinement:
    """The per-hypothesis dispatch path routes analyze through the
    confined sandbox adapter."""

    def test_dispatch_analyze_gets_confined_runner(
        self, tmp_path: Path, monkeypatch,
        sandbox_recorder: _RecordingSandboxRun,
    ):
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        db = _make_db(tmp_path)
        query, pack = _make_pack_query(tmp_path)
        calls: list[dict[str, Any]] = []
        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", _recording_analyze(calls))

        result = run_codeql_sweep(
            target_path=tmp_path, file_path="a.c", function_name="foo",
            query_path=str(query), database_path=str(db),
            line_start=1, line_end=5,
        )

        assert result.outcome in ("confirmed", "refuted")
        assert len(calls) == 1
        assert calls[0]["runner"] is not None
        assert calls[0]["codeql_bin"] == os.path.realpath(_FAKE_CODEQL)
        _assert_cache_redirect(calls[0]["extra_args"], db)
        # The adapter carried the confinement into the sandbox call.
        [sb] = sandbox_recorder.calls
        assert sb["restrict_reads"] is True
        assert sb["writable_paths"] == [str(db)]
        assert str(pack.resolve()) in sb["readable_paths"]
        assert sb["output"]  # the invocation scratch dir
        assert sb["output_existed"] is True
        assert sb["block_network"] is True
        assert "env" not in sb
        assert sb["tool_paths"] == [
            str(Path(os.path.realpath(_FAKE_CODEQL)).parent)]

    def test_missing_cli_keeps_bare_analyze(
        self, tmp_path: Path, monkeypatch,
        sandbox_recorder: _RecordingSandboxRun,
    ):
        """No CLI on PATH: nothing can execute on either lane, so the
        dispatch keeps the plain analyze() call (missing-tool
        FileNotFoundError contract) instead of a dead sandbox hop."""
        import shutil

        monkeypatch.setattr(shutil, "which", lambda *a, **k: None)
        db = _make_db(tmp_path)
        query, _pack = _make_pack_query(tmp_path)
        calls: list[dict[str, Any]] = []
        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", _recording_analyze(calls))

        run_codeql_sweep(
            target_path=tmp_path, file_path="a.c", function_name="foo",
            query_path=str(query), database_path=str(db),
            line_start=1, line_end=5,
        )

        assert len(calls) == 1
        assert calls[0]["runner"] is None
        assert calls[0]["extra_args"] == ()
        assert sandbox_recorder.calls == []


@pytest.mark.usefixtures("hermetic_codeql_cli")
class TestWarmupConfinement:
    """The whole-run warm-up analyze routes through the same confined
    adapter."""

    def test_warmup_analyze_gets_confined_runner(
        self, tmp_path: Path, monkeypatch,
        sandbox_recorder: _RecordingSandboxRun,
    ):
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        db = _make_db(tmp_path)
        query, pack = _make_pack_query(tmp_path)
        calls: list[dict[str, Any]] = []
        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(car, "analyze", _recording_analyze(calls))

        memo: BoundedMemo = BoundedMemo(8)
        stats = warm_codeql_memo(str(db), [str(query)], memo)

        assert stats is not None
        assert len(calls) == 1
        assert calls[0]["runner"] is not None
        assert calls[0]["codeql_bin"] == os.path.realpath(_FAKE_CODEQL)
        _assert_cache_redirect(calls[0]["extra_args"], db)
        [sb] = sandbox_recorder.calls
        assert sb["restrict_reads"] is True
        assert sb["writable_paths"] == [str(db)]
        assert str(pack.resolve()) in sb["readable_paths"]
        assert sb["output"]
        assert sb["output_existed"] is True
        assert sb["block_network"] is True
        assert "env" not in sb


def _raising_analyze(exc_for_call: dict[int, BaseException]):
    """Stand-in for analyze that raises per call index, else succeeds
    with an empty result set."""
    state = {"n": 0}

    def fake(db_path, queries, output_path, **kwargs):
        idx = state["n"]
        state["n"] += 1
        exc = exc_for_call.get(idx)
        if exc is not None:
            raise exc
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps({"runs": [{"results": []}]}), encoding="utf-8",
        )
        return SimpleNamespace(sarif_path=output_path)

    return fake


def _make_queries(tmp_path: Path, count: int) -> list[Path]:
    """Distinct query files (distinct content → distinct memo keys)."""
    out = []
    for i in range(count):
        q = tmp_path / f"q{i}.ql"
        q.write_text(f"/** @id cpp/test-q{i} */\nselect {i}",
                     encoding="utf-8")
        out.append(q)
    return out


@pytest.mark.usefixtures("hermetic_codeql_cli")
class TestChannelWarnings:
    """Systematic dispatch failure must surface at WARNING (once per
    process), never only in per-hypothesis DEBUG records."""

    @pytest.fixture(autouse=True)
    def _armed_channel(self):
        sweep_mod._reset_codeql_channel_state()
        yield
        sweep_mod._reset_codeql_channel_state()

    def _dispatch(self, tmp_path: Path, db: Path, query: Path):
        return run_codeql_sweep(
            target_path=tmp_path, file_path="a.c", function_name="foo",
            query_path=str(query), database_path=str(db),
            line_start=1, line_end=5,
        )

    @staticmethod
    def _systematic_warnings(
        caplog: pytest.LogCaptureFixture,
    ) -> list[logging.LogRecord]:
        return [
            r for r in caplog.records
            if r.levelno == logging.WARNING
            and "failing systematically" in r.getMessage()
        ]

    def test_error_streak_warns_once_at_threshold(
        self, tmp_path: Path, monkeypatch,
        caplog: pytest.LogCaptureFixture,
    ):
        db = _make_db(tmp_path)
        queries = _make_queries(tmp_path, 4)
        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(
            car, "analyze",
            _raising_analyze({i: RuntimeError("boom") for i in range(4)}),
        )
        with caplog.at_level(logging.WARNING, logger="core.audit.sweep"):
            for i, q in enumerate(queries):
                result = self._dispatch(tmp_path, db, q)
                assert result.outcome == "error"
                warned = self._systematic_warnings(caplog)
                if i + 1 < sweep_mod._CODEQL_ERROR_STREAK_WARN:
                    assert warned == []
                else:
                    # Fires AT the threshold, once per process.
                    assert len(warned) == 1

    def test_successful_dispatch_resets_the_streak(
        self, tmp_path: Path, monkeypatch,
        caplog: pytest.LogCaptureFixture,
    ):
        db = _make_db(tmp_path)
        queries = _make_queries(tmp_path, 5)
        import core.dataflow.codeql_augmented_run as car
        # fail, fail, succeed, fail, fail — no run of 3.
        monkeypatch.setattr(
            car, "analyze",
            _raising_analyze(
                {i: RuntimeError("boom") for i in (0, 1, 3, 4)},
            ),
        )
        with caplog.at_level(logging.WARNING, logger="core.audit.sweep"):
            for q in queries:
                self._dispatch(tmp_path, db, q)
        assert self._systematic_warnings(caplog) == []

    def test_sandbox_refusal_warns_once_and_propagates(
        self, tmp_path: Path, monkeypatch,
        caplog: pytest.LogCaptureFixture,
    ):
        """SandboxSetupError is BaseException by design — the dispatch
        must warn (host posture is systematic) and re-raise, never
        convert the refusal into a quiet per-hypothesis error."""
        db = _make_db(tmp_path)
        q1, q2 = _make_queries(tmp_path, 2)
        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(
            car, "analyze",
            _raising_analyze({
                0: SandboxSetupError("floor refused"),
                1: SandboxSetupError("floor refused"),
            }),
        )
        with caplog.at_level(logging.WARNING, logger="core.audit.sweep"):
            with pytest.raises(SandboxSetupError):
                self._dispatch(tmp_path, db, q1)
            with pytest.raises(SandboxSetupError):
                self._dispatch(tmp_path, db, q2)
        assert len(self._systematic_warnings(caplog)) == 1


@pytest.mark.usefixtures("hermetic_codeql_cli")
class TestWarmupFailureWarning:
    """The warm-up is best-effort (background thread, caller
    debug-swallows) but must not fail silently."""

    @pytest.fixture(autouse=True)
    def _armed_channel(self):
        sweep_mod._reset_codeql_channel_state()
        yield
        sweep_mod._reset_codeql_channel_state()

    def test_warmup_failure_warns_once(
        self, tmp_path: Path, monkeypatch,
        caplog: pytest.LogCaptureFixture,
    ):
        db = _make_db(tmp_path)
        query, _pack = _make_pack_query(tmp_path)
        import core.dataflow.codeql_augmented_run as car
        monkeypatch.setattr(
            car, "analyze",
            _raising_analyze({0: RuntimeError("boom"),
                              1: RuntimeError("boom")}),
        )
        with caplog.at_level(logging.WARNING, logger="core.audit.sweep"):
            assert warm_codeql_memo(
                str(db), [str(query)], BoundedMemo(8)) is None
            assert warm_codeql_memo(
                str(db), [str(query)], BoundedMemo(8)) is None
        warned = [
            r for r in caplog.records
            if r.levelno == logging.WARNING
            and "warm-up analyze failed" in r.getMessage()
        ]
        assert len(warned) == 1
        assert "RuntimeError" in warned[0].getMessage()


class TestLiveConfinement:
    """One fence through the REAL substrate: the recorder fences above
    prove the kwargs; this proves the substrate enforces them (a
    discarded read grant keeps every recorder green)."""

    def test_pack_readable_outside_denied(self, tmp_path: Path):
        import shutil
        import tempfile

        query, pack = _make_pack_query(tmp_path)
        # The database must live OUTSIDE the host temp tree, like the
        # production run dirs do: on the mount-ns lane a writable
        # grant under host /tmp counts as in-view (the per-sandbox
        # tmpfs) and is not carried into the view as a bind, so a
        # /tmp-resident db would be invisible to the child.
        try:
            db_holder = tempfile.mkdtemp(
                prefix="sweepconf-live-db-", dir="/var/tmp")
        except OSError as exc:
            pytest.skip(f"/var/tmp not usable on this host: {exc}")
        try:
            db = Path(db_holder) / "db"
            db.mkdir()
            scratch = tmp_path / "scratch"
            scratch.mkdir()
            outside = tmp_path / "outside" / "canary.txt"
            outside.parent.mkdir()
            outside.write_text("LIVE-CANARY\n", encoding="utf-8")

            runner = _sandboxed_codeql_runner(
                ["/usr/bin"],
                database_dir=db,
                query_paths=[str(query)],
                scratch_dir=scratch,
                caller_label="sweepconf-live-fence",
            )

            try:
                probe = runner(["true"], capture_output=True, text=True,
                               timeout=60, check=False)
            except SandboxSetupError as exc:
                pytest.skip(f"sandbox cannot engage on this host: {exc}")
            if probe.returncode != 0:
                pytest.skip(
                    "sandbox probe failed on this host "
                    f"(rc={probe.returncode})",
                )
            info = getattr(probe, "sandbox_info", None) or {}
            fs_layer = bool(info.get("mount_ns_active")) or (
                "landlock" in str(info.get("backend", ""))
            )
            if not fs_layer:
                pytest.skip(
                    "no filesystem-confinement lane engaged on this "
                    f"host (sandbox_info={info!r})",
                )

            # Read grant honoured: the query resolves through its
            # pack.
            inside = runner(["cat", str(query)], capture_output=True,
                            text=True, timeout=60, check=False)
            assert inside.returncode == 0
            assert "cpp/test-q" in inside.stdout

            # Read deny outside every grant.
            denied = runner(["cat", str(outside)], capture_output=True,
                            text=True, timeout=60, check=False)
            assert denied.returncode != 0
            assert "LIVE-CANARY" not in (denied.stdout or "")

            # Write allow on the database dir; write deny on the pack
            # tree (the compiled-query poisoning surface).
            db_write = runner(["touch", str(db / "live-write")],
                              capture_output=True, text=True,
                              timeout=60, check=False)
            assert db_write.returncode == 0
            pack_write = runner(["touch", str(pack / "live-canary")],
                                capture_output=True, text=True,
                                timeout=60, check=False)
            assert pack_write.returncode != 0
            assert not (pack / "live-canary").exists()
        finally:
            shutil.rmtree(db_holder, ignore_errors=True)
