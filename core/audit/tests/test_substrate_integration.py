"""Integration: PHP-dominant tree with one stray C file.

The motivating shape for the substrate seam, run through the real
orchestrator loop with a stub transport (canned review responses
keyed by function — one tool-chain-eligible hypothesis per checklist
function on both the PHP and C sides). spatch is stubbed at the
runner boundary: available, runs clean, matches nothing — so every
C-family dispatch mints a genuine refutation while PHP dispatches
must skip BEFORE the runner is reached.

Pinned: zero coccinelle refutations on PHP functions (and zero
runner invocations against PHP paths), the C file still gets a real
coccinelle verdict (anti-over-skip inside the same run), PHP
outcomes carry coccinelle in tools_skipped and never in
tools_dispatched, no tool-backed tier on a skips-only dispatch
record, the substrate_skip journal rows, the report honesty block,
and — per the sarif_cache phantom-coverage caveat — that the run
held no SARIF cache content at all.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.audit.orchestrator as orch
import packages.coccinelle.runner as cocci_runner
from core.audit.orchestrator import (
    OrchestratorConfig,
    ReviewOutcome,
    run_orchestrator,
)
from core.audit.report import generate_report
from core.audit.substrate import _reset_substrate_caches
from core.audit.sweep import SweepResult

_PHP_FN = "handle_request"
_PHP_FN2 = "render_page"
_C_FN = "parse_legacy"

# One tool-chain-eligible hypothesis per function: "missing null
# check" maps to the coccinelle missing_null_check rule in the chain
# builder, on the PHP and C sides alike.
_HYPOTHESES = {
    _PHP_FN: (
        "missing null check on `req` before dereference in "
        "handle_request"
    ),
    _PHP_FN2: (
        "missing null check on `tpl` before dereference in render_page"
    ),
    _C_FN: (
        "missing null check on `buf` before dereference in parse_legacy"
    ),
}


def _write_target(tmp_path: Path) -> tuple[Path, Path]:
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "app.php").write_text(
        "<?php\n"
        "function handle_request($req) {\n"
        "    return $req->param('id');\n"
        "}\n"
        "function render_page($tpl) {\n"
        "    return $tpl->render();\n"
        "}\n",
    )
    (target / "src" / "legacy.c").write_text(
        "int parse_legacy(char *buf) {\n"
        "    return buf[0];\n"
        "}\n",
    )
    out = tmp_path / "out"
    out.mkdir()
    checklist = {
        "files": [
            {
                "path": "src/app.php",
                "language": "php",
                "items": [
                    {"name": _PHP_FN, "line_start": 2, "line_end": 4},
                    {"name": _PHP_FN2, "line_start": 5, "line_end": 7},
                ],
            },
            {
                "path": "src/legacy.c",
                "language": "c",
                "items": [
                    {"name": _C_FN, "line_start": 1, "line_end": 3},
                ],
            },
        ],
    }
    (out / "checklist.json").write_text(json.dumps(checklist))
    (out / "context-map.json").write_text(json.dumps({
        "entry_points": [
            {"file": "src/app.php", "name": _PHP_FN},
            {"file": "src/app.php", "name": _PHP_FN2},
            {"file": "src/legacy.c", "name": _C_FN},
        ],
        "sinks": [],
        "trust_boundaries": [],
        "unchecked_flows": [],
    }))
    return target, out


def _review_fn(ctx, config):
    """Stub transport: canned responses keyed by function."""
    fn = ctx["function"]
    hypothesis = _HYPOTHESES.get(fn, "")
    return ReviewOutcome(
        file=ctx["file"],
        function=fn,
        status="finding",
        body=f"possible null deref in {fn}",
        hypothesis=hypothesis,
        line=ctx.get("line_start", 1) or 1,
        model="stub-transport",
    )


@pytest.mark.slow
class TestPhpTreeWithStrayCFile:

    @pytest.fixture()
    def run(self, tmp_path, monkeypatch):
        _reset_substrate_caches()
        target, out = _write_target(tmp_path)

        spatch_targets: list[str] = []
        monkeypatch.setattr(cocci_runner, "is_available", lambda: True)

        def _run_rule(path, rule, **kw):
            spatch_targets.append(str(path))
            return SimpleNamespace(matches=[], errors=[], returncode=0)

        monkeypatch.setattr(cocci_runner, "run_rule", _run_rule)

        # No live Joern: a fresh server start plus CPG build is a
        # minutes-long, machine-dependent path (and a healthy leftover
        # server changes gate-resolution activation between hosts).
        monkeypatch.setattr(
            orch, "_start_joern_server_raw", lambda *a, **kw: None,
        )

        # Neutralize the lanes that are not under test so the run is
        # hermetic: no real semgrep subprocess, no prefilter stamping
        # (a correlated prefilter hit would end validation before the
        # tool chain dispatches).
        monkeypatch.setattr(
            orch, "run_prefilter",
            lambda **kw: SimpleNamespace(
                hits=[], skip_llm=False, skip_reason="",
                language="", sloc=10,
            ),
        )
        # One function (render_page) gets a SKIPS-ONLY dispatch
        # record: every channel that would otherwise dispatch for it
        # returns skipped (the substrate seam already skips its
        # coccinelle/codeql/joern legs), so the no-tool-backed-tier
        # assertion below is exercised by a record that actually
        # exists. The other functions keep dispatching channels.
        def _keyed(tool: str):
            def _stub(**kw) -> SweepResult:
                outcome = (
                    "skipped" if kw["function_name"] == _PHP_FN2
                    else "inconclusive"
                )
                return SweepResult(
                    tool=tool, file_path=kw["file_path"],
                    function_name=kw["function_name"],
                    outcome=outcome,
                )
            return _stub

        monkeypatch.setattr(orch, "run_semgrep_sweep", _keyed("semgrep"))
        monkeypatch.setattr(orch, "run_smt_verb_direct", _keyed("smt"))
        import core.audit.compiler_sweep as compiler_mod
        monkeypatch.setattr(
            compiler_mod, "run_compiler_analyzer_sweep",
            _keyed("compiler"),
        )

        checklist = json.loads((out / "checklist.json").read_text())
        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            inventory=checklist,
            # Every function takes the full review path — the trivial
            # glance batch would bypass the per-function stub
            # transport this fixture keys its hypotheses on.
            batch_sloc_threshold=0,
        )
        result = run_orchestrator(config, _review_fn)
        return result, out, spatch_targets

    def test_php_functions_get_zero_coccinelle_refutations(self, run):
        result, _out, spatch_targets = run
        tc = result.tier_counters["coccinelle"]
        # The only refutation is the C file's; both PHP dispatches
        # substrate-skip.
        assert tc.refuted == 1
        assert tc.skipped_substrate == 2
        assert tc.substrate_skip_languages == {"php": 2}
        # The runner was never even invoked against PHP source.
        assert spatch_targets, "the C dispatch must reach spatch"
        assert all("legacy.c" in t for t in spatch_targets)

    def test_dispatch_records_split_by_substrate(self, run):
        result, _out, _spatch = run
        by_fn = {o.function: o for o in result.outcomes}
        for fn in (_PHP_FN, _PHP_FN2):
            o = by_fn[fn]
            assert "coccinelle" in (o.tools_skipped or set())
            assert "coccinelle" not in (o.tools_dispatched or set())
        c_outcome = by_fn[_C_FN]
        assert "coccinelle" in (c_outcome.tools_dispatched or set())
        assert "coccinelle" not in (c_outcome.tools_skipped or set())

    def test_no_tool_backed_tier_on_skips_only_record(self, run):
        result, _out, _spatch = run
        skips_only = [
            o for o in result.outcomes
            if not (o.tools_dispatched or set())
            and (o.tools_skipped or set())
        ]
        # Non-vacuous by construction: render_page's every channel
        # skips (see the fixture), so a skips-only record exists.
        assert _PHP_FN2 in {o.function for o in skips_only}
        for o in skips_only:
            assert o.verification_tier != "tool_backed"

    def test_substrate_skip_journal_rows(self, run):
        _result, out, _spatch = run
        rows = [
            json.loads(line)
            for line in (out / ".audit-log.jsonl")
            .read_text().splitlines()
        ]
        skips = [r for r in rows if r.get("action") == "substrate_skip"]
        cocci_skips = [r for r in skips if r.get("tool") == "coccinelle"]
        assert {r["file"] for r in cocci_skips} == {"src/app.php"}
        assert {r["function"] for r in cocci_skips} == {_PHP_FN, _PHP_FN2}
        assert all("php" in r["reason"] for r in cocci_skips)

    def test_report_honesty_block_names_the_tier(self, run):
        _result, out, _spatch = run
        report = generate_report(out)
        assert report["substrate_skips"]["coccinelle"]["count"] == 2
        summary = report["summary"]
        assert "Substrate skips" in summary
        assert "coccinelle: 2 check(s) skipped" in summary
        assert "`php`" in summary

    def test_sarif_cache_pinned_empty(self, run):
        # The gate-resolution sarif_cache alias credits class coverage
        # from file-level SARIF presence, bypassing the dispatch
        # record; the phantom-coverage assertions above are decidable
        # only because this run held no SARIF at all.
        _result, out, _spatch = run
        assert not list(out.rglob("*.sarif"))
