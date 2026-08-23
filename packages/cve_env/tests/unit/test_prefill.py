"""/cve-diff pre-fill consumption: CLI flags, prompt block, provenance.

The pre-fill is hints-with-provenance, never a gate: the PREFILL block
tells the agent to trust the verified facts over re-research but to
follow runtime evidence on contradiction, and the outcome JSON carries
the provenance (additive key — facade-contract safe).
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from cve_env.models import CveRecord, HostInfo

CVE = "CVE-2021-41773"

_POINTER = {
    "cve_id": CVE,
    "repository_url": "https://github.com/apache/httpd",
    "fix_commit": "a" * 40,
    "commit_before": "b" * 40,
    "diff_shape": "source",
    "consensus_verdict": "agree",
    "files_changed": 3,
    "source_run": "/tmp/out/cve-diff_run",
}


def _host() -> HostInfo:
    return HostInfo(arch="x86_64", os="linux")


class TestArgparse:
    def test_defaults_off(self):
        from cve_env.cli import _build_argparser

        args = _build_argparser().parse_args(["build", CVE])
        # None = unset: the facade treats it as off; the RAPTOR dispatch
        # distinguishes it from an EXPLICIT off when defaulting to auto.
        assert args.prefill is None
        assert args.prefill_from is None

    def test_accepts_auto_and_from(self):
        from cve_env.cli import _build_argparser

        args = _build_argparser().parse_args(
            ["build", CVE, "--prefill", "auto",
             "--prefill-from", "/tmp/somewhere"])
        assert args.prefill == "auto"
        assert args.prefill_from == "/tmp/somewhere"


class TestPromptBlock:
    def test_block_rendered_with_pointer(self):
        from cve_env.agent.prompts import render_user_prompt

        text = render_user_prompt(
            CveRecord(cve_id=CVE), _host(), prefill=_POINTER)
        assert "# Verified discovery (from /cve-diff)" in text
        assert "https://github.com/apache/httpd" in text
        assert "a" * 40 in text
        assert ("pre-patch commit (the vulnerable boundary): "
                + "b" * 40) in text
        assert "consensus: agree" in text
        assert "/tmp/out/cve-diff_run" in text
        # Hints-not-gates language must be present.
        assert "follow the evidence" in text

    def test_absent_without_pointer(self):
        from cve_env.agent.prompts import render_user_prompt

        text = render_user_prompt(CveRecord(cve_id=CVE), _host())
        assert "Verified discovery" not in text

    def test_mirror_shape_carries_warning(self):
        from cve_env.agent.prompts import render_user_prompt

        ptr = dict(_POINTER, diff_shape="packaging_only",
                   consensus_verdict="")
        text = render_user_prompt(
            CveRecord(cve_id=CVE), _host(), prefill=ptr)
        assert "downstream mirror" in text
        assert "packaging_only" in text

    def test_incomplete_pointer_renders_nothing(self):
        from cve_env.agent.prompts import render_user_prompt

        ptr = dict(_POINTER, fix_commit="")
        text = render_user_prompt(
            CveRecord(cve_id=CVE), _host(), prefill=ptr)
        assert "Verified discovery" not in text


def _build_args(**over) -> SimpleNamespace:
    base = dict(
        cve_id=CVE, product=None, version=None, description=None,
        max_turns=5, max_cost_usd=0.5, audit_root=None, silent=True,
        prefill=None, prefill_from=None,
    )
    base.update(over)
    return SimpleNamespace(**base)


def _fake_outcome():
    out = MagicMock()
    out.cve_id = CVE
    out.status = "success"
    out.verify_passed = True
    out.give_up_reason = None
    out.give_up_detail = None
    out.num_turns = 1
    out.total_cost_usd = 0.01
    out.stop_reason = "end_turn"
    out.reason = ""
    out.tool_names_called = []
    out.final_text = ""
    out.audit_path = None
    out.refusals = 0
    out.daemon_corruption = False
    out.stage_costs = {}
    out.stage_calls = {}
    out.over_budget_stages_list = []
    return out


class TestCliWiring:
    def _run_build(self, tmp_path, capsys, args):
        import cve_env.cli as cli_mod

        with patch.object(cli_mod, "build_core",
                          return_value=_fake_outcome()) as core, \
             patch("cve_env.agent.health_constraints.probe_for_constraints",
                   return_value=[]), \
             patch("cve_env.utils.lifecycle.acquire_lock",
                   return_value=tmp_path / "lock"), \
             patch("cve_env.utils.lifecycle.release_lock"):
            rc = cli_mod._cmd_build(args)
        return rc, core, capsys.readouterr()

    def test_auto_prefill_threads_pointer_and_outcome(
            self, tmp_path, capsys):
        args = _build_args(prefill="auto", audit_root=str(tmp_path))
        with patch("core.orchestration.cvediff_bridge.find_fix_pointer") \
                as find:
            find.return_value = SimpleNamespace(
                to_dict=lambda: dict(_POINTER),
                source_run=_POINTER["source_run"])
            rc, core, captured = self._run_build(tmp_path, capsys, args)
        assert rc == 0
        assert core.call_args.kwargs["prefill"] == _POINTER
        out = json.loads(captured.out)
        assert out["prefill"] == _POINTER
        assert "prefill: using /cve-diff discovery" in captured.err

    def test_auto_prefill_miss_reports_hint(self, tmp_path, capsys):
        args = _build_args(prefill="auto", audit_root=str(tmp_path))
        with patch("core.orchestration.cvediff_bridge.find_fix_pointer",
                   return_value=None):
            rc, core, captured = self._run_build(tmp_path, capsys, args)
        assert rc == 0
        assert core.call_args.kwargs["prefill"] is None
        assert json.loads(captured.out)["prefill"] is None
        assert f"/cve-diff run {CVE}" in captured.err

    def test_off_never_searches(self, tmp_path, capsys):
        args = _build_args(audit_root=str(tmp_path))
        with patch("core.orchestration.cvediff_bridge.find_fix_pointer") \
                as find:
            rc, core, captured = self._run_build(tmp_path, capsys, args)
        assert rc == 0
        find.assert_not_called()
        assert core.call_args.kwargs["prefill"] is None
        assert "prefill" not in captured.err

    def test_prefill_from_passes_explicit_dir(self, tmp_path, capsys):
        args = _build_args(prefill_from="/tmp/explicit",
                           audit_root=str(tmp_path))
        with patch("core.orchestration.cvediff_bridge.find_fix_pointer",
                   return_value=None) as find:
            self._run_build(tmp_path, capsys, args)
        assert find.call_args.kwargs["out_dir"] == "/tmp/explicit"
