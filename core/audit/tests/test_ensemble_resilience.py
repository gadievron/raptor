"""Tests for ensemble resilience: checkpointing, parallel passes, shared infra.

Covers:
- _checkpoint_write / _checkpoint_read round-trip and atomicity
- _run_ensemble_audit checkpoint resume (skip completed passes)
- max_workers halving propagation
- Shared Joern server lifecycle (caller-owned vs self-owned)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from core.audit.corpus.run_corpus import (
    _checkpoint_read,
    _checkpoint_write,
)

# ── Checkpoint round-trip ──────────────────────────────────────────


class TestCheckpointIO:
    def test_round_trip(self, tmp_path):
        p = tmp_path / "ckpt.json"
        data = [{"function_id": "a.c:foo", "actual": "finding", "match": True}]
        _checkpoint_write(p, data)
        loaded = _checkpoint_read(p)
        assert loaded == data

    def test_read_missing_returns_none(self, tmp_path):
        assert _checkpoint_read(tmp_path / "nope.json") is None

    def test_read_corrupt_returns_none(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{broken")
        assert _checkpoint_read(p) is None

    def test_atomic_write(self, tmp_path):
        """No .tmp file left behind after successful write."""
        p = tmp_path / "ckpt.json"
        _checkpoint_write(p, {"ok": True})
        assert p.exists()
        assert not p.with_suffix(".tmp").exists()

    def test_overwrite(self, tmp_path):
        p = tmp_path / "ckpt.json"
        _checkpoint_write(p, {"v": 1})
        _checkpoint_write(p, {"v": 2})
        assert _checkpoint_read(p) == {"v": 2}


# ── _run_audit joern_server pass-through ───────────────────────────


class TestRunAuditJoernOwnership:
    """Verify _run_audit skips Joern start/stop when a server is passed in."""

    @patch("core.audit.corpus.run_corpus._stop_shared_joern")
    @patch("core.audit.corpus.run_corpus._start_shared_joern")
    @patch("core.audit.corpus.run_corpus._run_audit_on_target")
    def test_caller_owned_joern_not_started(
        self, mock_target, mock_start, mock_stop,
    ):
        from core.audit.corpus.run_corpus import _run_audit

        mock_target.return_value = ({}, {}, None)
        external_srv = MagicMock(name="external_joern")

        with patch("core.audit.corpus.run_corpus.FunctionLabel",
                    create=True):
            _run_audit(
                [], {"repo": Path("/tmp/r")},
                joern_server=external_srv,
            )

        mock_start.assert_not_called()
        mock_stop.assert_not_called()

    @patch("core.audit.corpus.run_corpus._stop_shared_joern")
    @patch("core.audit.corpus.run_corpus._start_shared_joern",
           return_value=None)
    @patch("core.audit.corpus.run_corpus._run_audit_on_target")
    def test_self_owned_joern_started_and_stopped(
        self, mock_target, mock_start, mock_stop,
    ):
        from core.audit.corpus.run_corpus import _run_audit

        mock_target.return_value = ({}, {}, None)

        _run_audit([], {"repo": Path("/tmp/r")})

        mock_start.assert_called_once()
        mock_stop.assert_called_once()


# ── max_workers propagation ────────────────────────────────────────


class TestMaxWorkersPropagation:
    """Verify max_workers flows from _run_audit → _run_audit_on_target → pipeline."""

    @patch("core.audit.corpus.run_corpus._stop_shared_joern")
    @patch("core.audit.corpus.run_corpus._start_shared_joern",
           return_value=None)
    @patch("core.audit.corpus.run_corpus._run_audit_on_target")
    def test_max_workers_passed_to_target(
        self, mock_target, mock_start, mock_stop, tmp_path,
    ):
        from core.audit.corpus.run_corpus import _run_audit

        mock_target.return_value = ({}, {}, None)

        label = MagicMock()
        label.source.repo = "repo"
        label.function_id = "a.c:foo"

        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()

        _run_audit(
            [label],
            {"repo": repo_dir},
            max_workers=8,
        )

        mock_target.assert_called_once()
        _, kwargs = mock_target.call_args
        assert kwargs["max_workers"] == 8


# ── Ensemble checkpoint resume ─────────────────────────────────────


class TestEnsembleCheckpointResume:
    """Verify ensemble skips completed passes when checkpoints exist."""

    def _fake_results(self, mode: str) -> list[dict[str, Any]]:
        return [{
            "function_id": "a.c:foo",
            "bug_class": "integer",
            "expected": "finding",
            "actual": "finding" if mode == "security" else "clean",
            "match": mode == "security",
            "hypothesis": f"{mode} hyp",
            "evidence_tool": "semgrep",
            "model": "test",
            "cost_usd": 1.0,
            "duration_s": 5.0,
        }]

    @patch("core.audit.corpus.run_corpus._stop_shared_joern")
    @patch("core.audit.corpus.run_corpus._start_shared_joern",
           return_value=None)
    @patch("core.audit.corpus.run_corpus._run_audit")
    @patch("core.llm.concurrency.derive_max_workers",
           return_value=16)
    # Phase-2 classification is a REAL paid LLM pass; the cached fake
    # results contain a finding, which reaches it. Stub it — the leak
    # was caught by the run-end paid-call attribution.
    @patch("core.audit.corpus.run_corpus._run_phase2_classify",
           return_value=0.0)
    def test_both_cached_skips_passes(
        self, mock_phase2, mock_derive, mock_audit, mock_start, mock_stop,
        tmp_path,
    ):
        from core.audit.corpus.run_corpus import _run_ensemble_audit

        base = tmp_path / "ensemble"
        base.mkdir()
        sec_ckpt = base / "checkpoint-sec.json"
        bf_ckpt = base / "checkpoint-bf.json"
        _checkpoint_write(sec_ckpt, self._fake_results("security"))
        _checkpoint_write(bf_ckpt, self._fake_results("bug_first"))

        results, _dirs = _run_ensemble_audit(
            [], {}, out_dir=base,
        )

        mock_audit.assert_not_called()
        assert len(results) == 1
        assert results[0]["actual"] == "finding"

    @patch("core.audit.corpus.run_corpus._stop_shared_joern")
    @patch("core.audit.corpus.run_corpus._start_shared_joern",
           return_value=None)
    @patch("core.audit.corpus.run_corpus._run_audit")
    @patch("core.llm.concurrency.derive_max_workers",
           return_value=16)
    # Phase-2 classification is a REAL paid LLM pass; the cached fake
    # results contain a finding, which reaches it. Stub it — the leak
    # was caught by the run-end paid-call attribution.
    @patch("core.audit.corpus.run_corpus._run_phase2_classify",
           return_value=0.0)
    def test_one_cached_runs_only_missing(
        self, mock_phase2, mock_derive, mock_audit, mock_start, mock_stop,
        tmp_path,
    ):
        from core.audit.corpus.run_corpus import _run_ensemble_audit

        base = tmp_path / "ensemble"
        base.mkdir()
        sec_ckpt = base / "checkpoint-sec.json"
        _checkpoint_write(sec_ckpt, self._fake_results("security"))

        bf_out = Path(str(base) + "-bf")
        mock_audit.return_value = (self._fake_results("bug_first"), [bf_out])

        _results, _dirs = _run_ensemble_audit(
            [], {}, out_dir=base,
        )

        mock_audit.assert_called_once()
        _, kwargs = mock_audit.call_args
        assert kwargs["mode"] == "bug_first"


# ── Worker halving ─────────────────────────────────────────────────


class TestWorkerHalving:
    @patch("core.audit.corpus.run_corpus._stop_shared_joern")
    @patch("core.audit.corpus.run_corpus._start_shared_joern",
           return_value=None)
    @patch("core.audit.corpus.run_corpus._run_audit")
    @patch("core.llm.concurrency.derive_max_workers",
           return_value=20)
    def test_workers_full_for_sequential_passes(
        self, mock_derive, mock_audit, mock_start, mock_stop, tmp_path,
    ):
        from core.audit.corpus.run_corpus import _run_ensemble_audit

        base = tmp_path / "ensemble"
        mock_audit.return_value = ([], [])

        _run_ensemble_audit([], {}, out_dir=base)

        # Pass 1 always runs; pass 2 skipped when pass 1 returns no
        # functions needing review (empty results → nothing to pass 2).
        assert mock_audit.call_count >= 1
        for c in mock_audit.call_args_list:
            assert c[1]["max_workers"] == 20

    @patch("core.audit.corpus.run_corpus._stop_shared_joern")
    @patch("core.audit.corpus.run_corpus._start_shared_joern",
           return_value=None)
    @patch("core.audit.corpus.run_corpus._run_audit")
    @patch("core.llm.concurrency.derive_max_workers",
           return_value=1)
    def test_workers_floor_at_one(
        self, mock_derive, mock_audit, mock_start, mock_stop, tmp_path,
    ):
        from core.audit.corpus.run_corpus import _run_ensemble_audit

        base = tmp_path / "ensemble"
        mock_audit.return_value = ([], [])

        _run_ensemble_audit([], {}, out_dir=base)

        for c in mock_audit.call_args_list:
            assert c[1]["max_workers"] == 1

    @patch("core.audit.corpus.run_corpus._stop_shared_joern")
    @patch("core.audit.corpus.run_corpus._start_shared_joern",
           return_value=None)
    @patch("core.audit.corpus.run_corpus._run_audit")
    @patch("core.llm.concurrency.derive_max_workers",
           return_value=10)
    def test_pass2_skipped_when_all_clean(
        self, mock_derive, mock_audit, mock_start, mock_stop, tmp_path,
    ):
        from core.audit.corpus.run_corpus import _run_ensemble_audit

        base = tmp_path / "ensemble"
        mock_audit.return_value = ([
            {"function_id": "a.c:foo", "actual": "clean",
             "expected": "clean", "evidence_tool": "",
             "counter_hypothesis": "", "hypothesis": "",
             "match": True, "skipped": False, "bug_class": "test",
             "model": "", "cost_usd": 0.0, "duration_s": 0.0},
        ], [])

        _run_ensemble_audit([], {}, out_dir=base)

        assert mock_audit.call_count == 1


# ── Shared Joern in ensemble ──────────────────────────────────────


class TestEnsembleSharedJoern:
    @patch("core.audit.corpus.run_corpus._stop_shared_joern")
    @patch("core.audit.corpus.run_corpus._start_shared_joern")
    @patch("core.audit.corpus.run_corpus._run_audit")
    @patch("core.llm.concurrency.derive_max_workers",
           return_value=8)
    def test_joern_started_once_passed_to_both(
        self, mock_derive, mock_audit, mock_start, mock_stop, tmp_path,
    ):
        from core.audit.corpus.run_corpus import _run_ensemble_audit

        sentinel = MagicMock(name="shared_joern")
        mock_start.return_value = sentinel
        mock_audit.return_value = ([], [])

        base = tmp_path / "ensemble"
        _run_ensemble_audit(
            [], {"repo": Path("/tmp/r")}, out_dir=base,
        )

        mock_start.assert_called_once()
        mock_stop.assert_called_once_with(sentinel)
        assert mock_audit.call_count >= 1
        for c in mock_audit.call_args_list:
            assert c[1]["joern_server"] is sentinel
