"""Phase 6 tests — audit JSONL schema upgrade.

The chokepoint records every Phase 4 verdict the suppressor reaches,
so operators can grep / jq the trail of decisions:

* ``VERDICT_SUPPRESS`` → ``verdict="sanitizer_dominated"``,
  ``dropped=true``, ``bindings`` carries the value-bound witness.
* ``VERDICT_CANDIDATE_ONLY`` → ``verdict="sanitizer_candidate"``,
  ``dropped=false``, ``catalog_matches`` carries the full match set,
  ``bindings`` is empty.
* ``VERDICT_NO_SUPPRESS`` → no record (control-flow cut failed,
  nothing the gate saw is worth flagging).

The new ``dropped`` and ``extra`` kwargs on ``record_suppression``
are back-compat: binary-oracle calls take the defaults and produce a
record with ``dropped=true`` and no extra fields beyond the legacy
schema.
"""
from __future__ import annotations

import json
from pathlib import Path

from core.inventory.cfg_builder import PyCFGNode, build_python_cfg
from core.inventory.reach_chokepoint import record_suppression
from core.inventory.sanitizer_cut import (
    VERDICT_SANITIZER_CANDIDATE,
    VERDICT_SANITIZER_DOMINATED,
    evaluate_finding,
    record_sanitizer_cut_suppression,
)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _cfg(src: str, func: str = "handle"):
    cfg = build_python_cfg(src, func)
    assert cfg is not None
    return cfg


def _node_with_call(cfg, call_name):
    return next(
        n for n in cfg.nodes()
        if isinstance(n, PyCFGNode) and call_name in n.calls
    )


def _read_jsonl(out_dir: Path) -> list:
    f = out_dir / "suppressions.jsonl"
    if not f.exists():
        return []
    return [json.loads(line) for line in f.read_text().splitlines() if line]


def _finding() -> dict:
    return {
        "finding_id": "F1",
        "rule_id": "py/xss",
        "file_path": "src/handler.py",
        "line": 3,
        "function": "handle",
    }


# ---------------------------------------------------------------------------
# record_suppression — back-compat for binary-oracle
# ---------------------------------------------------------------------------


class TestBinaryOracleBackCompat:
    def test_legacy_call_writes_dropped_true_by_default(self, tmp_path: Path):
        """A binary-oracle-style call (no dropped, no extra) writes
        ``dropped: true`` and only the legacy fields plus the new
        ``dropped`` key. Existing readers ignore unknown keys."""
        record_suppression(
            tmp_path,
            finding=_finding(),
            verdict="binary_oracle_absent",
            reason="dead function",
        )
        records = _read_jsonl(tmp_path)
        assert len(records) == 1
        r = records[0]
        assert r["verdict"] == "binary_oracle_absent"
        assert r["dropped"] is True
        # Legacy field shape preserved.
        for k in ("finding_id", "rule_id", "file_path", "line",
                  "function", "reason"):
            assert k in r

    def test_explicit_dropped_false_lands_in_record(self, tmp_path: Path):
        record_suppression(
            tmp_path,
            finding=_finding(),
            verdict="some_verdict",
            reason="hint only",
            dropped=False,
        )
        records = _read_jsonl(tmp_path)
        assert records[0]["dropped"] is False

    def test_extra_fields_merged_into_record(self, tmp_path: Path):
        record_suppression(
            tmp_path,
            finding=_finding(),
            verdict="some_verdict",
            reason="x",
            extra={"sink_arg": "user", "witness_lines": [3, 5]},
        )
        records = _read_jsonl(tmp_path)
        r = records[0]
        assert r["sink_arg"] == "user"
        assert r["witness_lines"] == [3, 5]


# ---------------------------------------------------------------------------
# sanitizer-cut suppress records
# ---------------------------------------------------------------------------


class TestSuppressRecord:
    def test_suppress_writes_sanitizer_dominated_with_bindings(
        self, tmp_path: Path,
    ):
        src = (
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    render(y)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
            source_symbols={"x"},
            sink_arg="y",
        )
        record_sanitizer_cut_suppression(tmp_path, _finding(), result)
        records = _read_jsonl(tmp_path)
        assert len(records) == 1
        r = records[0]
        assert r["verdict"] == VERDICT_SANITIZER_DOMINATED
        assert r["dropped"] is True
        assert r["sink_arg"] == "y"
        # One value-bound binding witnessing the suppression.
        assert len(r["bindings"]) == 1
        b = r["bindings"][0]
        assert b["callable"] == "html.escape"
        assert b["input_symbols"] == ["x"]
        assert b["output_symbols"] == ["y"]
        assert b["lineno"] == 2
        # catalog_matches mirrors bindings when all catalog matches
        # are value-bound (the common straight-line case).
        assert len(r["catalog_matches"]) == 1
        # witness_lines is the deduped sorted set of line numbers.
        assert r["witness_lines"] == [2]

    def test_symmetric_sanitize_records_both_bindings(self, tmp_path: Path):
        """When both branches sanitise, both bindings are witnesses
        and both lines appear in the audit record."""
        src = (
            "def handle(user):\n"
            "    if user.is_admin:\n"
            "        safe = html.escape(user.name)\n"
            "    else:\n"
            "        safe = html.escape(user.name)\n"
            "    render(safe)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
            source_symbols={"user"},
            sink_arg="safe",
        )
        record_sanitizer_cut_suppression(tmp_path, _finding(), result)
        records = _read_jsonl(tmp_path)
        r = records[0]
        assert r["verdict"] == VERDICT_SANITIZER_DOMINATED
        assert len(r["bindings"]) == 2
        # Bindings are stable-sorted by (lineno, callable).
        linenos = [b["lineno"] for b in r["bindings"]]
        assert linenos == sorted(linenos)
        # Both lines appear in the witness_lines summary.
        assert r["witness_lines"] == sorted(linenos)


# ---------------------------------------------------------------------------
# candidate_only records — the Phase 6 addition
# ---------------------------------------------------------------------------


class TestCandidateOnlyRecord:
    def test_wrong_variable_case_emits_candidate_only_record(
        self, tmp_path: Path,
    ):
        """The canonical wrong-variable case lands ``candidate_only``
        (Phase 4) and the record persists it with
        ``dropped: false``. Operators can ``jq 'select(.dropped ==
        false)'`` to see exactly what survived the value-bound gate
        but the control-flow gate flagged."""
        src = (
            "def handle(user, other):\n"
            "    safe_other = html.escape(other)\n"
            "    render(user.name)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
            source_symbols={"user", "other"},
            sink_arg="user",
        )
        record_sanitizer_cut_suppression(tmp_path, _finding(), result)
        records = _read_jsonl(tmp_path)
        assert len(records) == 1
        r = records[0]
        assert r["verdict"] == VERDICT_SANITIZER_CANDIDATE
        assert r["dropped"] is False
        assert r["sink_arg"] == "user"
        # No value-bound bindings — that's why we landed candidate_only.
        assert r["bindings"] == []
        # But the catalog match IS recorded so operators can see what
        # was tried.
        assert len(r["catalog_matches"]) == 1
        cm = r["catalog_matches"][0]
        assert cm["callable"] == "html.escape"
        assert cm["input_symbols"] == ["other"]
        assert cm["output_symbols"] == ["safe_other"]


# ---------------------------------------------------------------------------
# no_suppress — no record
# ---------------------------------------------------------------------------


class TestNoSuppressNoRecord:
    def test_bypass_case_writes_no_record(self, tmp_path: Path):
        """When the control-flow cut fails entirely (bypass exists),
        the chokepoint records nothing — the LLM gets the finding
        with no audit trail from the suppressor."""
        src = (
            "def handle(user):\n"
            "    if user.is_admin:\n"
            "        safe = html.escape(user.name)\n"
            "    else:\n"
            "        safe = user.name\n"
            "    render(safe)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
            source_symbols={"user"},
            sink_arg="safe",
        )
        record_sanitizer_cut_suppression(tmp_path, _finding(), result)
        assert _read_jsonl(tmp_path) == []


# ---------------------------------------------------------------------------
# Coexistence — binary-oracle + sanitizer-cut share the file cleanly
# ---------------------------------------------------------------------------


class TestCoexistence:
    def test_binary_oracle_and_sanitizer_cut_records_share_file(
        self, tmp_path: Path,
    ):
        """Both producers append to the same suppressions.jsonl.
        Records are individually parseable; consumers tolerant of
        unknown keys can read both shapes uniformly."""
        # Binary-oracle-style record (no extra, dropped defaults true).
        record_suppression(
            tmp_path,
            finding={"finding_id": "FA", "rule_id": "cpp/buffer-overflow"},
            verdict="binary_oracle_absent",
            reason="dead function",
        )
        # Sanitizer-cut suppress record.
        src = (
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    render(y)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
            source_symbols={"x"},
            sink_arg="y",
        )
        record_sanitizer_cut_suppression(
            tmp_path, {"finding_id": "FB"}, result,
        )
        records = _read_jsonl(tmp_path)
        assert len(records) == 2
        # Both have a ``dropped`` key after Phase 6.
        assert all("dropped" in r for r in records)
        verdicts = {r["verdict"] for r in records}
        assert verdicts == {
            "binary_oracle_absent", VERDICT_SANITIZER_DOMINATED,
        }
        # Binary-oracle record has no ``bindings`` key — sanitizer-cut
        # specific. Consumers tolerant of missing keys are fine.
        bo = next(r for r in records if r["verdict"] == "binary_oracle_absent")
        sc = next(r for r in records if r["verdict"] != "binary_oracle_absent")
        assert "bindings" not in bo
        assert "bindings" in sc


# ---------------------------------------------------------------------------
# Phase 7 legacy path — no value context, suppression still recorded
# ---------------------------------------------------------------------------


class TestLegacyPath:
    def test_legacy_suppress_writes_record_without_bindings(
        self, tmp_path: Path,
    ):
        """Phase 7 callers that omit value context still produce a
        valid suppression record — just without the new binding /
        witness fields populated (empty lists / strings). Back-compat
        for callers that haven't been taught about value binding."""
        src = (
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    render(y)\n"
        )
        cfg = _cfg(src)
        sink = _node_with_call(cfg, "render")
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink,
            cwe="CWE-79", language="python",
            # No source_symbols / sink_arg.
        )
        record_sanitizer_cut_suppression(tmp_path, _finding(), result)
        records = _read_jsonl(tmp_path)
        assert len(records) == 1
        r = records[0]
        assert r["verdict"] == VERDICT_SANITIZER_DOMINATED
        assert r["dropped"] is True
        # Legacy path didn't populate the witness fields.
        assert r["sink_arg"] == ""
        assert r["bindings"] == []
        # ``catalog_matches`` and ``witness_lines`` are also empty.
        assert r["catalog_matches"] == []
        assert r["witness_lines"] == []
