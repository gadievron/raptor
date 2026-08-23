"""Replay-spec recording and rediscovery (S5.1 spec-store replay).

A successful build records the proven environment as a ``core.env``
spec (``environment-spec.json`` next to the outcome sidecar); the next
build of the same CVE provisions + verifies it at $0 before falling
back to the agent. Recording is conservative: only source kinds the
provisioner can consume (image, dockerfile) are recorded, and replay
failure of any kind falls through to the normal build.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

from cve_env.infra.spec_record import (
    derive_replay_spec,
    find_replayable_spec,
    record_run_spec,
)

CVE = "CVE-2018-7600"

_VERIFY_PLAN = [
    {"type": "http_check", "url": "/", "expect_status": 200},
    {"type": "exec_check", "command": "drush --version"},
]


def _uses(image: str = "drupal:8.5.0", *, with_build: bool = False,
          dockerfile_text: str = "", with_run: bool = True,
          with_verify: bool = True) -> list[dict]:
    uses: list[dict] = [
        {"name": "nvd_lookup", "input": {"cve_id": CVE}},
    ]
    if with_build:
        build_input: dict = {"context_dir": "/tmp/ctx", "image_tag": image}
        if dockerfile_text:
            build_input["dockerfile_text"] = dockerfile_text
        uses.append({"name": "docker_build", "input": build_input})
    if with_run:
        uses.append({"name": "docker_run", "input": {
            "image": image, "container_port": 80,
            "run_id": "r", "cve_id": CVE}})
    if with_verify:
        uses.append({"name": "verify", "input": {
            "container_id": "c1", "host_ip": "127.0.0.1",
            "host_port": 32768, "plan": _VERIFY_PLAN}})
    return uses


class TestDerive:
    def test_registry_image_records_image_spec(self):
        spec = derive_replay_spec(CVE, "8.5.0", _uses())
        assert spec is not None
        assert spec.source.kind == "image"
        assert spec.source.image_ref == "drupal:8.5.0"
        assert spec.cve_id == CVE
        assert spec.version == "8.5.0"
        assert spec.run.port == 80
        assert spec.verify_plan == _VERIFY_PLAN
        assert spec.markers["origin"]["verified"] is True

    def test_session_built_image_with_dockerfile_records_dockerfile(self):
        spec = derive_replay_spec(
            CVE, "", _uses(image="cve-env-local:build", with_build=True,
                           dockerfile_text="FROM drupal:8.5.0\n"))
        assert spec is not None
        assert spec.source.kind == "dockerfile"
        assert spec.source.dockerfile == "FROM drupal:8.5.0\n"

    def test_session_built_image_without_dockerfile_not_recorded(self):
        spec = derive_replay_spec(
            CVE, "", _uses(image="cve-env-local:build", with_build=True))
        assert spec is None

    def test_local_tag_prefix_without_build_call_not_recorded(self):
        # A local tag with no recoverable Dockerfile dies with the image
        # cache — recording it would produce a spec that cannot replay.
        spec = derive_replay_spec(CVE, "", _uses(image="cve-env-local:x"))
        assert spec is None

    def test_no_docker_run_means_not_recorded(self):
        spec = derive_replay_spec(CVE, "", _uses(with_run=False))
        assert spec is None

    def test_no_verify_means_not_recorded(self):
        spec = derive_replay_spec(CVE, "", _uses(with_verify=False))
        assert spec is None


class TestRecordAndFind:
    def test_record_writes_run_spec(self, tmp_path):
        path = record_run_spec(CVE, "8.5.0", _uses(), tmp_path)
        assert path is not None and path.is_file()
        data = json.loads(path.read_text())
        assert data["cve_id"] == CVE

    def test_record_unrecordable_returns_none(self, tmp_path):
        assert record_run_spec(
            CVE, "", _uses(with_run=False), tmp_path) is None

    def test_find_in_explicit_dir(self, tmp_path):
        record_run_spec(CVE, "8.5.0", _uses(), tmp_path)
        spec = find_replayable_spec(CVE, out_dir=tmp_path)
        assert spec is not None
        assert spec.markers["origin"]["source_run"] == str(tmp_path)

    def test_find_ignores_other_cves(self, tmp_path):
        record_run_spec(CVE, "8.5.0", _uses(), tmp_path)
        assert find_replayable_spec(
            "CVE-1999-0001", out_dir=tmp_path) is None

    def test_find_ignores_unverified_marker(self, tmp_path):
        record_run_spec(CVE, "8.5.0", _uses(), tmp_path)
        # recording writes the canonical file AND the per-id twin —
        # the unverified marker must gate BOTH lookups
        for path in tmp_path.glob("environment-spec*.json"):
            data = json.loads(path.read_text())
            data["markers"]["origin"]["verified"] = False
            path.write_text(json.dumps(data))
        assert find_replayable_spec(CVE, out_dir=tmp_path) is None

    def test_shared_dir_overwrite_survives_via_id_twin(self, tmp_path):
        """The facade's shared audit root: a later build of a DIFFERENT
        id overwrites the canonical environment-spec.json; the earlier
        id's replay must survive through its per-id twin."""
        record_run_spec(CVE, "8.5.0", _uses(), tmp_path)
        other = "CVE-2020-1234"
        record_run_spec(other, "2.0",
                        [{"name": "docker_run",
                          "input": {"image": "other:2.0",
                                    "container_port": 80}},
                         {"name": "verify", "input": {"plan": _VERIFY_PLAN}}],
                        tmp_path)
        first = find_replayable_spec(CVE, out_dir=tmp_path)
        second = find_replayable_spec(other, out_dir=tmp_path)
        assert first is not None and first.source.image_ref == "drupal:8.5.0"
        assert second is not None and second.source.image_ref == "other:2.0"

    def test_find_newest_across_project_runs(self, tmp_path):
        import os
        old = tmp_path / "run_old"
        new = tmp_path / "run_new"
        old.mkdir(), new.mkdir()
        p_old = record_run_spec(CVE, "1.0", _uses(image="app:1.0"), old)
        record_run_spec(CVE, "2.0", _uses(image="app:2.0"), new)
        os.utime(p_old, ns=(1, 1))
        spec = find_replayable_spec(CVE, project_dir=tmp_path)
        assert spec is not None
        assert spec.source.image_ref == "app:2.0"


def _fake_outcome():
    from unittest.mock import MagicMock

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


class TestCliReplay:
    def _args(self, tmp_path, **over):
        base = dict(
            cve_id=CVE, product=None, version=None, description=None,
            max_turns=5, max_cost_usd=0.5, audit_root=str(tmp_path),
            silent=True, prefill="auto", prefill_from=None,
        )
        base.update(over)
        return SimpleNamespace(**base)

    def _run(self, tmp_path, capsys, args, *, find_ret, provision_ret,
             build_ret=None):
        import cve_env.cli as cli_mod

        with patch("cve_env.infra.spec_record.find_replayable_spec",
                   return_value=find_ret), \
             patch("core.env.provision.provision",
                   return_value=provision_ret) as prov, \
             patch("core.orchestration.cvediff_bridge.find_fix_pointer",
                   return_value=None), \
             patch.object(cli_mod, "build_core",
                          return_value=build_ret or _fake_outcome()) as core, \
             patch("cve_env.agent.health_constraints.probe_for_constraints",
                   return_value=[]), \
             patch("cve_env.utils.lifecycle.acquire_lock",
                   return_value=tmp_path / "lock"), \
             patch("cve_env.utils.lifecycle.release_lock"):
            rc = cli_mod._cmd_build(args)
        return rc, core, prov, capsys.readouterr()

    def _spec(self):
        return derive_replay_spec(CVE, "8.5.0", _uses())

    def test_verified_replay_skips_agent(self, tmp_path, capsys):
        env = SimpleNamespace(
            verified=lambda: True, verify_result={"passed": True},
            provision_id="tok123", teardown=lambda: None)
        prov_ret = SimpleNamespace(ok=True, environment=env, reason="")
        rc, core, prov, captured = self._run(
            tmp_path, capsys, self._args(tmp_path),
            find_ret=self._spec(), provision_ret=prov_ret)
        assert rc == 0
        core.assert_not_called()
        prov.assert_called_once()
        out = json.loads(captured.out)
        assert out["status"] == "success"
        assert out["stop_reason"] == "replay"
        assert "agent build skipped" in captured.err

    def test_failed_replay_falls_through_to_agent(self, tmp_path, capsys):
        prov_ret = SimpleNamespace(
            ok=False, environment=None, reason="verify_failed")
        rc, core, _prov, captured = self._run(
            tmp_path, capsys, self._args(tmp_path),
            find_ret=self._spec(), provision_ret=prov_ret)
        assert rc == 0
        core.assert_called_once()
        assert "falling through" in captured.err

    def test_no_spec_goes_straight_to_agent(self, tmp_path, capsys):
        rc, core, prov, captured = self._run(
            tmp_path, capsys, self._args(tmp_path),
            find_ret=None, provision_ret=None)
        assert rc == 0
        core.assert_called_once()
        prov.assert_not_called()

    def test_prefill_off_never_replays(self, tmp_path, capsys):
        import cve_env.cli as cli_mod

        args = self._args(tmp_path, prefill=None)
        with patch("cve_env.infra.spec_record.find_replayable_spec") \
                as find, \
             patch.object(cli_mod, "build_core",
                          return_value=_fake_outcome()), \
             patch("cve_env.agent.health_constraints.probe_for_constraints",
                   return_value=[]), \
             patch("cve_env.utils.lifecycle.acquire_lock",
                   return_value=tmp_path / "lock"), \
             patch("cve_env.utils.lifecycle.release_lock"):
            rc = cli_mod._cmd_build(args)
        assert rc == 0
        find.assert_not_called()


class TestBuildCoreRecords:
    def test_success_records_spec_next_to_sidecar(self, tmp_path):
        """End-to-end through build_core's fake-provider harness: a
        passing verify records environment-spec.json in audit_root."""
        from core.llm.tool_use.types import (
            StopReason,
            TextBlock,
            ToolCall,
            ToolDef,
            TurnResponse,
        )

        import importlib.util
        from pathlib import Path as _P

        # Load the sibling harness by file path — the `tests` package
        # name collides across the repo, so a package import misroutes.
        _path = _P(__file__).with_name("test_agent_backend.py")
        _spec = importlib.util.spec_from_file_location(
            "cve_env_agent_backend_harness", _path)
        _harness = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_harness)
        _run_core = _harness._run_core

        verify_payload = {
            "passed": True,
            "results": [
                {"type": "container_status", "passed": True, "details": {}},
                {"type": "exec_check", "passed": True,
                 "details": {"command": "drush --version",
                             "expected_stdout_contains": "8.5.0"}},
                {"type": "http_check", "passed": True,
                 "details": {"url": "/", "content_check_performed": True}},
            ],
        }
        schema = {"type": "object", "properties": {}, "required": []}
        tools = [
            ToolDef(name="docker_run", description="run", input_schema=schema,
                    handler=lambda args: json.dumps(
                        {"ok": True, "container_id": "c1",
                         "host_port": 32768})),
            ToolDef(name="verify", description="verify", input_schema=schema,
                    handler=lambda args: json.dumps(verify_payload)),
            ToolDef(name="give_up", description="terminal",
                    input_schema=schema,
                    handler=lambda args: json.dumps({"terminal": True})),
        ]
        responses = [
            TurnResponse(
                content=[ToolCall(id="t1", name="docker_run",
                                  input={"image": "drupal:8.5.0",
                                         "container_port": 80,
                                         "run_id": "r", "cve_id": CVE})],
                stop_reason=StopReason.NEEDS_TOOL_CALL,
                input_tokens=10, output_tokens=5,
            ),
            TurnResponse(
                content=[ToolCall(id="t2", name="verify",
                                  input={"container_id": "c1",
                                         "host_ip": "127.0.0.1",
                                         "host_port": 32768,
                                         "plan": _VERIFY_PLAN})],
                stop_reason=StopReason.NEEDS_TOOL_CALL,
                input_tokens=10, output_tokens=5,
            ),
            TurnResponse(
                content=[TextBlock(text="environment verified")],
                stop_reason=StopReason.COMPLETE,
                input_tokens=10, output_tokens=5,
            ),
        ]
        out = _run_core(responses, tmp_path, tools=tools)
        spec_path = tmp_path / "environment-spec.json"
        if out.status == "success":
            assert spec_path.is_file()
            data = json.loads(spec_path.read_text())
            assert data["cve_id"] == CVE
            assert data["source"]["image_ref"] == "drupal:8.5.0"
        else:
            # Classifier demoted the run (e.g. verified_partial) — the
            # recording contract is success-only, so nothing on disk.
            assert out.verify_passed is True
            assert not spec_path.exists()
