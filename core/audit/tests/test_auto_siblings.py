"""Auto-siblings composition — binary /audit runs seed themselves.

Composition-unit coverage of ``core.audit.auto_siblings`` plus the
pipeline seam (``core.audit.pipeline._maybe_auto_siblings``) and the
CLI wiring: a binary target with a mapped sibling run gets the REAL
siblings engine run over it and the produced seeds captured into the
audit run dir where the landed intake ingests them (merging with
operator ``--hypothesis-seeds`` files under the intake's shared
caps); every non-captured outcome degrades loudly to today's
unseeded behaviour; source targets are byte-identical (the pass is
never entered).
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

import pytest

from core.audit.auto_siblings import (
    RECEIPT_FILENAME,
    run_auto_siblings,
)
from core.audit.hypothesis_intake import (
    MAX_SEED_RECORDS,
    SEED_PRIORITY_BOOST,
    SEEDS_FILENAME,
    apply_hypothesis_seeds,
)
from core.json import load_json, save_json

_ANCHOR = "ab" * 8
_MEMBERS = ["parse_a", "parse_b", "parse_c", "parse_d"]

_BODY_CHECKED = (
    "int {name}(char *p, uint n) {{ "
    "if (p == (char *)0x0) return -1; "
    "if (n < 0x100) {{ memcpy(dst, p, n); }} return 0; }}"
)
_BODY_UNCHECKED = (
    "int {name}(char *p, uint n) {{ memcpy(dst, p, n); return 0; }}"
)


@pytest.fixture(autouse=True)
def _no_session_ledger(monkeypatch):
    # run_discovery tier 0 reads the live session's run ledger —
    # hermetic tests must not see this machine's real runs.
    import core.project.sessions as sessions
    monkeypatch.setattr(sessions, "ledger_runs", lambda: [])


@pytest.fixture(autouse=True)
def _no_global_out(tmp_path, monkeypatch):
    # The global out/ fallback must not scan this machine's real runs.
    root = tmp_path / "global-out"
    root.mkdir()
    from core.config import RaptorConfig
    monkeypatch.setattr(RaptorConfig, "get_out_dir",
                        classmethod(lambda cls: root))


def _fid(rel: int) -> str:
    return f"{_ANCHOR}:{rel:#x}"


def _make_binary(tmp: Path) -> tuple[Path, str]:
    binary = tmp / "acmed"
    binary.write_bytes(b"\x7fELF-not-really-" + b"x" * 64)
    return binary, hashlib.sha256(binary.read_bytes()).hexdigest()


def _addr(i: int) -> int:
    return 0x401000 + i * 0x100


def _write_map_run(
    tmp: Path,
    binary: Path,
    sha: str,
    *,
    name: str = "map-run",
    run_meta: bool = True,
) -> Path:
    """A mapped sibling run dir the REAL siblings engine can consume:
    manifest + context map + hunt family + decompilations + a
    re-database whose call xrefs reproduce the engine's own test
    topology (parse_d skips check_len; emit is a hub)."""
    run_dir = tmp / name
    run_dir.mkdir(exist_ok=True)
    save_json(run_dir / "binary-manifest.json", {
        "schema_version": 1,
        "binary_path": str(binary),
        "binary_sha256": sha,
        "size_bytes": 128,
        "executable": True,
        "target_kind": "binary",
        "arch": "x86",
        "bits": 64,
        "binary_format": "elf",
        "build_id": _ANCHOR,
        "image_base": 0x400000,
    })
    functions = [
        {
            "id": f"BFN-{_addr(i):x}",
            "name": name_,
            "address": hex(_addr(i)),
            "size": 64,
            "fid": _fid(0x1000 + i * 0x100),
            "is_exported": True,
        }
        for i, name_ in enumerate(_MEMBERS)
    ]
    save_json(run_dir / "binary-context-map.json", {
        "interesting_functions": functions,
    })
    save_json(run_dir / "binary-hunt-anchor-frame.json", {
        "schema_version": 1,
        "mode": "anchor",
        "families": [{
            "id": "BHUNTFAM-feed01",
            "members": [
                {"name": name_, "fid": _fid(0x1000 + i * 0x100),
                 "address": hex(_addr(i))}
                for i, name_ in enumerate(_MEMBERS)
            ],
            "sample_strings": ["frame %d truncated"],
        }],
    })
    save_json(run_dir / "binary-decompilations.json", {
        "coverage": {},
        "functions": [
            {
                "name": name_,
                "address": hex(_addr(i)),
                "body": (
                    _BODY_UNCHECKED if name_ == "parse_d"
                    else _BODY_CHECKED
                ).format(name=name_),
            }
            for i, name_ in enumerate(_MEMBERS)
        ],
    })
    # Re-database: the engine's call-graph substrate (no radare2 in
    # tests). parse_a..c call check_len + emit; parse_d only emit;
    # 20 noise callers make emit a hub; extra_caller keeps check_len
    # distinctive (2..hub-max callers).
    fns = [
        {"name": name_, "address": _addr(i), "size": 64,
         "fid": _fid(0x1000 + i * 0x100)}
        for i, name_ in enumerate(_MEMBERS)
    ]
    fns.append({"name": "check_len", "address": 0x402000, "size": 32,
                "fid": _fid(0x2000)})
    fns.append({"name": "emit", "address": 0x403000, "size": 32})
    fns.append({"name": "extra_caller", "address": 0x404000,
                "size": 32})
    for i in range(20):
        fns.append({"name": f"noise_{i:02d}",
                    "address": 0x410000 + i * 0x100, "size": 32})
    xrefs = []
    for i, name_ in enumerate(_MEMBERS):
        if name_ != "parse_d":
            xrefs.append({"from_addr": _addr(i) + 4,
                          "to_addr": 0x402000, "kind": "call"})
        xrefs.append({"from_addr": _addr(i) + 8,
                      "to_addr": 0x403000, "kind": "call"})
    xrefs.append({"from_addr": 0x404000 + 4, "to_addr": 0x402000,
                  "kind": "call"})
    for i in range(20):
        xrefs.append({"from_addr": 0x410000 + i * 0x100 + 4,
                      "to_addr": 0x403000, "kind": "call"})
    save_json(run_dir / "re-database.json", {
        "source_tool": "test",
        "binary_path": str(binary),
        "functions": fns,
        "xrefs": xrefs,
        "metadata": {"binary_sha256": sha},
    })
    if run_meta:
        save_json(run_dir / ".raptor-run.json", {
            "version": 2,
            "command": "binary",
            "status": "completed",
            "target_path": str(binary),
        })
    return run_dir


def _audit_dir(tmp: Path) -> Path:
    out = tmp / "audit-run"
    out.mkdir(exist_ok=True)
    return out


class TestCapture:
    def test_real_engine_runs_and_seeds_are_captured(self, tmp_path):
        binary, sha = _make_binary(tmp_path)
        _write_map_run(tmp_path, binary, sha)
        out_dir = _audit_dir(tmp_path)

        receipt = run_auto_siblings(out_dir, binary)

        assert receipt["status"] == "captured"
        assert receipt["provenance"] == "computed"
        assert "map-run" in receipt["map_run_dir"]
        assert receipt["seeds_emitted"] >= 1
        captured = out_dir / SEEDS_FILENAME
        assert captured.is_file()
        doc = load_json(captured)
        assert doc["producer"] == "binary-siblings"
        names = {s.get("function") for s in doc["seeds"]}
        assert "parse_d" in names
        # Receipt persisted for the report's degradation surface.
        on_disk = load_json(out_dir / RECEIPT_FILENAME)
        assert on_disk["status"] == "captured"

    def test_existing_map_artifact_is_captured_verbatim(
        self, tmp_path,
    ):
        """A map run that already holds sibling-hypotheses.json (a
        prior hand-run, possibly operator-adjudicated) is captured
        AS-IS: the engine must not re-run — it is not
        bit-deterministic across substrate state and would silently
        replace the reviewed artifact."""
        binary, sha = _make_binary(tmp_path)
        map_dir = _write_map_run(tmp_path, binary, sha)
        adjudicated = {
            "schema_version": 1,
            "producer": "binary-siblings",
            "seeds": [
                {"file": "binary:acmed", "function": "parse_d",
                 "claim": "hand-adjudicated outlier row"},
                {"file": "binary:acmed", "function": "parse_b",
                 "claim": "second adjudicated row"},
            ],
        }
        save_json(map_dir / SEEDS_FILENAME, adjudicated)
        artifact_bytes = (map_dir / SEEDS_FILENAME).read_bytes()
        out_dir = _audit_dir(tmp_path)

        def _boom(*_a, **_k):
            raise AssertionError(
                "engine must not re-run over an existing artifact")

        receipt = run_auto_siblings(out_dir, binary, engine=_boom)

        assert receipt["status"] == "captured"
        assert receipt["provenance"] == "captured_existing"
        assert receipt["seeds_emitted"] == 2
        assert (out_dir / SEEDS_FILENAME).read_bytes() == artifact_bytes

    def test_captured_seeds_ingest_through_the_normal_intake(
        self, tmp_path,
    ):
        binary, sha = _make_binary(tmp_path)
        _write_map_run(tmp_path, binary, sha)
        out_dir = _audit_dir(tmp_path)
        run_auto_siblings(out_dir, binary)

        gap = {
            "file": "binary:acmed", "name": "parse_d",
            "metadata": {"address": _addr(3)},
            "priority_score": 0,
        }
        summary = apply_hypothesis_seeds([gap], out_dir)

        assert summary is not None
        assert summary["loaded"] >= 1
        assert summary["matched"] >= 1
        assert gap["priority_score"] == SEED_PRIORITY_BOOST
        assert gap["seed_hypotheses"]
        # Per-source provenance: the captured file is a named source.
        assert any(
            s["path"].endswith(SEEDS_FILENAME)
            for s in summary["sources"]
        )

    def test_existing_co_located_file_is_reused_never_overwritten(
        self, tmp_path,
    ):
        binary, sha = _make_binary(tmp_path)
        _write_map_run(tmp_path, binary, sha)
        out_dir = _audit_dir(tmp_path)
        ferried = {"schema_version": 1, "producer": "operator",
                   "seeds": []}
        save_json(out_dir / SEEDS_FILENAME, ferried)

        def _boom(*_a, **_k):
            raise AssertionError("engine must not run")

        receipt = run_auto_siblings(out_dir, binary, engine=_boom)

        assert receipt["status"] == "reused"
        assert load_json(out_dir / SEEDS_FILENAME) == ferried

    def test_merges_with_operator_seeds_under_the_shared_cap(
        self, tmp_path,
    ):
        binary, sha = _make_binary(tmp_path)
        map_dir = _write_map_run(tmp_path, binary, sha)
        out_dir = _audit_dir(tmp_path)

        def _engine(run_dir, *, auto):
            assert auto is True
            save_json(Path(run_dir) / SEEDS_FILENAME, {
                "schema_version": 1,
                "producer": "binary-siblings",
                "seeds": [
                    {"file": "binary:acmed", "function": f"auto_{i}",
                     "claim": f"auto claim {i}"}
                    for i in range(MAX_SEED_RECORDS - 10)
                ],
            })
            return {"hypothesis_seeds_emitted": MAX_SEED_RECORDS - 10}

        receipt = run_auto_siblings(out_dir, binary, engine=_engine)
        assert receipt["status"] == "captured"
        assert receipt["map_run_dir"].endswith(map_dir.name)

        operator = tmp_path / "operator-seeds.json"
        save_json(operator, {
            "seeds": [
                {"file": "binary:acmed", "function": f"op_{i}",
                 "claim": f"operator claim {i}"}
                for i in range(20)
            ],
        })
        summary = apply_hypothesis_seeds([], out_dir, [operator])

        # Both sources load through the intake's one multi-source
        # path; the record cap holds ACROSS sources (auto seeds fill
        # 190 slots, the operator file gets 10, the rest are counted).
        assert len(summary["sources"]) == 2
        assert summary["loaded"] == MAX_SEED_RECORDS
        assert summary["skipped"].get("over_cap") == 10


class TestDegrade:
    def test_no_mapped_run_degrades_loudly(self, tmp_path, caplog):
        binary, _sha = _make_binary(tmp_path)
        out_dir = _audit_dir(tmp_path)

        with caplog.at_level(logging.WARNING,
                             logger="core.audit.auto_siblings"):
            receipt = run_auto_siblings(out_dir, binary)

        assert receipt["status"] == "degraded"
        assert receipt["reason"] == "no_mapped_run"
        assert not (out_dir / SEEDS_FILENAME).exists()
        on_disk = load_json(out_dir / RECEIPT_FILENAME)
        assert on_disk["status"] == "degraded"
        warnings = [r for r in caplog.records
                    if r.levelno == logging.WARNING]
        assert len(warnings) == 1
        assert "auto-siblings skipped" in warnings[0].getMessage()

    def test_different_build_is_refused(self, tmp_path):
        binary, _sha = _make_binary(tmp_path)
        _write_map_run(tmp_path, binary, "ff" * 32)
        out_dir = _audit_dir(tmp_path)

        def _boom(*_a, **_k):
            raise AssertionError("engine must not run on a mismatch")

        receipt = run_auto_siblings(out_dir, binary, engine=_boom)

        assert receipt["status"] == "degraded"
        assert receipt["reason"] == "build_mismatch"
        assert not (out_dir / SEEDS_FILENAME).exists()

    def test_existing_artifact_of_wrong_build_is_refused(
        self, tmp_path,
    ):
        """The identity gate precedes the existing-artifact fast
        path: a stale map's adjudicated artifact for ANOTHER build
        is refused, never captured."""
        binary, _sha = _make_binary(tmp_path)
        map_dir = _write_map_run(tmp_path, binary, "ff" * 32)
        save_json(map_dir / SEEDS_FILENAME, {
            "schema_version": 1, "producer": "binary-siblings",
            "seeds": [{"file": "binary:acmed", "function": "parse_d",
                       "claim": "stale-build row"}],
        })
        out_dir = _audit_dir(tmp_path)

        receipt = run_auto_siblings(out_dir, binary)

        assert receipt["status"] == "degraded"
        assert receipt["reason"] == "build_mismatch"
        assert not (out_dir / SEEDS_FILENAME).exists()

    def test_unstamped_manifest_identity_is_refused(self, tmp_path):
        """FAIL-CLOSED identity: a map manifest without a
        binary_sha256 stamp refuses (the RAPTOR producer always
        stamps — a stripped manifest must not become the route by
        which a rebuilt binary's stale map seeds the audit)."""
        binary, _sha = _make_binary(tmp_path)
        map_dir = _write_map_run(tmp_path, binary, "unused")
        manifest = load_json(map_dir / "binary-manifest.json")
        manifest["binary_sha256"] = ""
        save_json(map_dir / "binary-manifest.json", manifest)
        out_dir = _audit_dir(tmp_path)

        def _boom(*_a, **_k):
            raise AssertionError(
                "engine must not run on unverified identity")

        receipt = run_auto_siblings(out_dir, binary, engine=_boom)

        assert receipt["status"] == "degraded"
        assert receipt["reason"] == "identity_unverified"
        assert not (out_dir / SEEDS_FILENAME).exists()

    def test_engine_timeout_degrades(
        self, tmp_path, monkeypatch, caplog,
    ):
        """The compute leg is wall-bounded: a wedged engine (untimed
        lock, pathological substrate) degrades to engine_timeout
        instead of pinning audit start."""
        import time

        import core.audit.auto_siblings as mod
        binary, sha = _make_binary(tmp_path)
        _write_map_run(tmp_path, binary, sha)
        out_dir = _audit_dir(tmp_path)
        monkeypatch.setattr(mod, "ENGINE_WALL_S", 0.2)

        def _wedged(*_a, **_k):
            time.sleep(1.0)
            return {"hypothesis_seeds_emitted": 1}

        with caplog.at_level(logging.WARNING,
                             logger="core.audit.auto_siblings"):
            receipt = run_auto_siblings(out_dir, binary, engine=_wedged)

        assert receipt["status"] == "degraded"
        assert receipt["reason"] == "engine_timeout"
        assert not (out_dir / SEEDS_FILENAME).exists()
        assert any("auto-siblings skipped" in r.getMessage()
                   for r in caplog.records)

    def test_over_budget_produced_file_degrades(self, tmp_path):
        """Capture bounds: a produced seed file over the intake's
        read budget is not captured (a truncated JSON capture would
        be silently unreadable at intake time)."""
        from core.audit.hypothesis_intake import MAX_SEED_FILE_BYTES
        binary, sha = _make_binary(tmp_path)
        map_dir = _write_map_run(tmp_path, binary, sha)
        out_dir = _audit_dir(tmp_path)

        def _engine(run_dir, *, auto):
            del auto
            (Path(run_dir) / SEEDS_FILENAME).write_bytes(
                b'{"seeds": ["' + b"x" * MAX_SEED_FILE_BYTES + b'"]}',
            )
            return {"hypothesis_seeds_emitted": 1}

        receipt = run_auto_siblings(out_dir, binary, engine=_engine)

        assert receipt["status"] == "degraded"
        assert receipt["reason"] == "capture_failed"
        assert not (out_dir / SEEDS_FILENAME).exists()
        # The over-budget artifact stays in the MAP dir untouched.
        assert (map_dir / SEEDS_FILENAME).is_file()

    def test_engine_failure_degrades_with_escaped_detail(
        self, tmp_path, caplog,
    ):
        binary, sha = _make_binary(tmp_path)
        _write_map_run(tmp_path, binary, sha)
        out_dir = _audit_dir(tmp_path)

        def _engine(*_a, **_k):
            raise RuntimeError("no substrate \x1b]0;pwn\x07 here")

        with caplog.at_level(logging.WARNING,
                             logger="core.audit.auto_siblings"):
            receipt = run_auto_siblings(out_dir, binary, engine=_engine)

        assert receipt["status"] == "degraded"
        assert receipt["reason"] == "siblings_failed"
        # Target-derived error text is escaped before any surface.
        assert "\x1b" not in receipt["detail"]
        assert "\\x1b" in receipt["detail"]
        assert not (out_dir / SEEDS_FILENAME).exists()
        assert any("auto-siblings skipped" in r.getMessage()
                   for r in caplog.records)

    def test_wrong_target_sibling_never_seeds(self, tmp_path):
        # A mapped run for a DIFFERENT binary in the same parent dir:
        # the recorded-target gate must exclude it.
        binary, _sha = _make_binary(tmp_path)
        other = tmp_path / "otherd"
        other.write_bytes(b"other binary")
        other_sha = hashlib.sha256(other.read_bytes()).hexdigest()
        _write_map_run(tmp_path, other, other_sha)
        out_dir = _audit_dir(tmp_path)

        receipt = run_auto_siblings(out_dir, binary)

        assert receipt["status"] == "degraded"
        assert receipt["reason"] == "no_mapped_run"


class TestPipelineSeam:
    def _opts(self, tmp_path, inventory, **kw):
        from core.audit.pipeline import AuditPipelineOpts
        return AuditPipelineOpts(
            target_path=tmp_path / "t",
            out_dir=tmp_path / "o",
            inventory=inventory,
            **kw,
        )

    def _record_calls(self, monkeypatch):
        import core.audit.auto_siblings as mod
        calls: list = []
        monkeypatch.setattr(
            mod, "run_auto_siblings",
            lambda out_dir, target_path, **kw: calls.append(
                (out_dir, target_path)),
        )
        return calls

    def test_binary_inventory_enters_the_pass(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.pipeline import _maybe_auto_siblings
        calls = self._record_calls(monkeypatch)
        opts = self._opts(tmp_path, {"target_kind": "binary"})
        _maybe_auto_siblings(opts)
        assert calls == [(opts.out_dir, opts.target_path)]

    def test_source_target_is_byte_identical(
        self, tmp_path, monkeypatch,
    ):
        """Source targets never enter the pass: no discovery, no
        receipt, no log — the composition is binary-lane only."""
        from core.audit.pipeline import _maybe_auto_siblings
        calls = self._record_calls(monkeypatch)
        for inventory in (
            {"target_kind": "source"},
            {"files": []},
            None,
        ):
            _maybe_auto_siblings(self._opts(tmp_path, inventory))
        assert calls == []

    def test_opt_out_flag_skips_the_pass(self, tmp_path, monkeypatch):
        from core.audit.pipeline import _maybe_auto_siblings
        calls = self._record_calls(monkeypatch)
        opts = self._opts(
            tmp_path, {"target_kind": "binary"}, auto_siblings=False,
        )
        _maybe_auto_siblings(opts)
        assert calls == []

    def test_default_is_on(self, tmp_path):
        from core.audit.pipeline import AuditPipelineOpts
        assert AuditPipelineOpts().auto_siblings is True

    def test_pass_failure_never_blocks_the_pipeline(
        self, tmp_path, monkeypatch, caplog,
    ):
        from core.audit.pipeline import _maybe_auto_siblings
        import core.audit.auto_siblings as mod

        def _boom(*_a, **_k):
            raise RuntimeError("composition exploded")

        monkeypatch.setattr(mod, "run_auto_siblings", _boom)
        opts = self._opts(tmp_path, {"target_kind": "binary"})
        with caplog.at_level(logging.WARNING,
                             logger="core.audit.pipeline"):
            _maybe_auto_siblings(opts)  # must not raise
        assert any("auto-siblings" in r.getMessage()
                   for r in caplog.records)


class TestReportSurface:
    def test_degraded_receipt_reaches_the_report(self, tmp_path):
        out_dir = _audit_dir(tmp_path)
        save_json(out_dir / RECEIPT_FILENAME, {
            "schema_version": 1,
            "status": "degraded",
            "reason": "no_mapped_run",
            "detail": "no mapped binary run dir found",
        })
        from core.audit.report import generate_report
        report = generate_report(out_dir)
        assert report["auto_siblings"]["reason"] == "no_mapped_run"
        assert "Auto-siblings pass skipped" in report["summary"]

    def test_captured_receipt_is_not_a_warning(self, tmp_path):
        out_dir = _audit_dir(tmp_path)
        save_json(out_dir / RECEIPT_FILENAME, {
            "schema_version": 1,
            "status": "captured",
            "map_run_dir": "x",
            "seeds_emitted": 3,
            "captured": "y",
        })
        from core.audit.report import generate_report
        report = generate_report(out_dir)
        assert "auto_siblings" not in report
        assert "Auto-siblings pass skipped" not in report["summary"]


_SCRIPT = (
    Path(__file__).resolve().parents[3] / "libexec" / "raptor-audit"
)


@pytest.fixture(scope="module")
def audit_cli():
    """Import the raptor-audit script as a module (trust marker set)."""
    import importlib.machinery
    import importlib.util
    import os
    import sys

    prior = os.environ.get("_RAPTOR_TRUSTED")
    os.environ["_RAPTOR_TRUSTED"] = "1"
    try:
        spec = importlib.util.spec_from_loader(
            "raptor_audit_cli_auto_siblings",
            importlib.machinery.SourceFileLoader(
                "raptor_audit_cli_auto_siblings", str(_SCRIPT),
            ),
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["raptor_audit_cli_auto_siblings"] = mod
        spec.loader.exec_module(mod)
        yield mod
    finally:
        sys.modules.pop("raptor_audit_cli_auto_siblings", None)
        if prior is None:
            os.environ.pop("_RAPTOR_TRUSTED", None)
        else:
            os.environ["_RAPTOR_TRUSTED"] = prior


class TestCliWiring:
    @staticmethod
    def _namespace(**overrides):
        import argparse
        base = {
            "scope": None, "scope_floor": True, "pin": None,
            "strategy": None, "budget": None, "model": None,
            "max_cost": None, "max_time": None, "review_passes": 1,
            "batch_sloc_threshold": None, "include_kinds": None,
            "adversarial": False, "rank_gaps": False, "edges": False,
            "max_propagation_depth": None, "subsystem_depth": 0,
            "no_validate": False, "no_binary_oracle": False,
            "annotations_dir": None, "codeql_db": None,
            "dynamic": False, "no_dynamic": False,
            "no_verdict_reuse": False, "pre_scan": False,
            "no_caller_contract_context": False,
            "no_caller_contract_demotion": False,
            "schedule": "cost", "no_on_demand_synthesis": False,
            "no_vendored_triage": False,
            "probe_determine_value": False,
            "no_environment_breaker": False, "deepen_reserve": None,
            "prior_journal": None, "prior_claims": 3,
            "hypothesis_seeds": None, "max_workers": 0,
        }
        base.update(overrides)
        return argparse.Namespace(**base)

    def test_run_config_persists_the_opt_out(self, audit_cli):
        args = self._namespace(no_auto_siblings=True)
        cfg = audit_cli._run_config_from_args(args, Path("/tmp/x"))
        assert cfg["no_auto_siblings"] is True

    def test_run_config_tolerates_absent_attr(self, audit_cli):
        args = self._namespace()
        assert not hasattr(args, "no_auto_siblings")
        cfg = audit_cli._run_config_from_args(args, Path("/tmp/x"))
        assert cfg["no_auto_siblings"] is False

    def test_resume_precedence_helper(self, audit_cli):
        import argparse
        ns = lambda v: argparse.Namespace(no_auto_siblings=v)  # noqa: E731
        helper = audit_cli._resume_auto_siblings
        # Default on; either side's opt-out sticks; no turn-back-on.
        assert helper(ns(False), {}) is True
        assert helper(ns(True), {}) is False
        assert helper(ns(False), {"no_auto_siblings": True}) is False
        assert helper(ns(True), {"no_auto_siblings": True}) is False
        # Legacy run config without the key: default on.
        assert helper(argparse.Namespace(), {}) is True

    def test_run_and_resume_parsers_accept_the_flag(
        self, audit_cli, monkeypatch, capsys,
    ):
        # The parser is built inside main(); probe it with a known
        # flag plus a sentinel-unknown flag — argparse exits 2 naming
        # ONLY the unrecognized argument, so the known flag's absence
        # from the error proves both subparsers accept it.
        import sys
        for argv in (
            ["raptor-audit", "run", "/tmp/x", "--no-auto-siblings",
             "--definitely-not-a-flag"],
            ["raptor-audit", "resume", "/tmp/x", "--no-auto-siblings",
             "--definitely-not-a-flag"],
        ):
            monkeypatch.setattr(sys, "argv", argv)
            with pytest.raises(SystemExit) as exc:
                audit_cli.main()
            assert exc.value.code == 2
            err = capsys.readouterr().err
            assert "--definitely-not-a-flag" in err
            assert "--no-auto-siblings" not in err
