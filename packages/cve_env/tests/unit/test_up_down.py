"""`cve-env up/down`: re-provision a recorded environment spec as a
live test target for exploit/PoC work, and label-scoped teardown.

The endpoint hand-off is gated on the verify plan by default — `up`
never yields an unverified lookalike unless --no-verify says so — and
the printed down_token maps to the provision's OWNER_LABEL value so
`down` removes exactly that provision's containers/images.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

from cve_env.cli import (
    _build_argparser,
    _cmd_down,
    _cmd_up,
    _describe_record,
)


def _spec(source_run="/runs/a"):
    return SimpleNamespace(
        markers={"origin": {"source_run": source_run}},
        verify_plan=[{"type": "container_status"}])


def _env(endpoint=("127.0.0.1", 32801), verified=True):
    handle = SimpleNamespace(endpoint=lambda: endpoint, tier="docker")
    return SimpleNamespace(
        handle=handle, image_ref="nginx:1.18.0", tier="docker",
        provision_id="abc123def456",
        verified=lambda: verified,
    )


def _args(**over):
    base = dict(env_id="DESC-aaaabbbbcccc", from_dir=None, no_verify=False,
                allow_egress=False, describe="nginx 1.18",
                product=None, version=None)
    base.update(over)
    return SimpleNamespace(**base)


class TestUp:
    def test_happy_path_prints_endpoint_and_token(self, capsys):
        outcome = SimpleNamespace(ok=True, environment=_env(),
                                  reason="", detail="")
        with patch("cve_env.infra.spec_record.find_replayable_spec",
                   return_value=_spec()), \
             patch("core.env.provision.provision",
                   return_value=outcome) as prov:
            rc = _cmd_up(_args())
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["endpoint"] == {"host": "127.0.0.1", "port": 32801}
        assert payload["down_token"] == "abc123def456"
        assert payload["verify_passed"] is True
        # verify is ON by default and refusal-gated
        assert prov.call_args.kwargs["verify"] is True
        assert prov.call_args.kwargs["fail_on_verify"] is True

    def test_no_spec_is_a_clear_failure(self, capsys):
        with patch("cve_env.infra.spec_record.find_replayable_spec",
                   return_value=None):
            rc = _cmd_up(_args())
        assert rc == 1
        assert "no recorded environment spec" in capsys.readouterr().err

    def test_verify_failure_refuses_the_endpoint(self, capsys):
        outcome = SimpleNamespace(ok=False, environment=None,
                                  reason="verify_failed", detail="probe")
        with patch("cve_env.infra.spec_record.find_replayable_spec",
                   return_value=_spec()), \
             patch("core.env.provision.provision", return_value=outcome):
            rc = _cmd_up(_args())
        assert rc == 1
        captured = capsys.readouterr()
        assert "verify_failed" in captured.err
        assert captured.out == ""  # no endpoint payload on failure

    def test_no_verify_flag_passes_through(self, capsys):
        outcome = SimpleNamespace(ok=True, environment=_env(),
                                  reason="", detail="")
        with patch("cve_env.infra.spec_record.find_replayable_spec",
                   return_value=_spec()), \
             patch("core.env.provision.provision",
                   return_value=outcome) as prov:
            rc = _cmd_up(_args(no_verify=True))
        assert rc == 0
        assert prov.call_args.kwargs["verify"] is False
        assert json.loads(capsys.readouterr().out)["verify_passed"] is None

    def test_endpointless_tier_still_reports_token(self, capsys):
        outcome = SimpleNamespace(
            ok=True, environment=_env(endpoint=None), reason="", detail="")
        with patch("cve_env.infra.spec_record.find_replayable_spec",
                   return_value=_spec()), \
             patch("core.env.provision.provision", return_value=outcome):
            rc = _cmd_up(_args())
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["endpoint"] is None
        assert payload["down_token"] == "abc123def456"


class TestDown:
    def test_down_is_label_scoped_on_the_token(self, capsys):
        with patch("core.container.lifecycle.remove_labeled_containers",
                   return_value=2) as rc_mock, \
             patch("core.container.lifecycle.remove_labeled_images",
                   return_value=1) as ri_mock:
            rc = _cmd_down(SimpleNamespace(token="abc123def456"))
        assert rc == 0
        from core.env.provision import OWNER_LABEL
        assert rc_mock.call_args.args[:2] == (OWNER_LABEL, "abc123def456")
        assert ri_mock.call_args.args[:2] == (OWNER_LABEL, "abc123def456")
        payload = json.loads(capsys.readouterr().out)
        assert payload["removed_containers"] == 2


class TestArgparseSurface:
    def test_up_and_down_parse(self):
        parser = _build_argparser()
        ns = parser.parse_args(["up", "DESC-aaaabbbbcccc",
                                "--from", "/runs/x", "--no-verify"])
        assert ns.env_id == "DESC-aaaabbbbcccc"
        assert ns.from_dir == "/runs/x"
        assert ns.no_verify is True
        ns2 = parser.parse_args(["down", "abc123def456"])
        assert ns2.token == "abc123def456"


class TestPortablePlanRecording:
    """Recorded verify plans must not bake the original run's ephemeral
    host port into tcp probes — a replay/up publishes a fresh port and
    the recorded one can never match again (live failure: 'connection
    refused' on every up of a freshly recorded spec)."""

    def test_tcp_probe_coordinates_stripped(self):
        from cve_env.infra.spec_record import derive_replay_spec
        tool_uses = [
            {"name": "docker_run",
             "input": {"image": "nginx:1.18.0", "container_port": 80}},
            {"name": "verify", "input": {"plan": [
                {"type": "container_status"},
                {"type": "tcp_probe_check", "host_port": 32813,
                 "host_ip": "127.0.0.1",
                 "send_text": "HEAD / HTTP/1.0\r\n\r\n",
                 "expected_response_contains": "nginx"},
                {"type": "http_check", "path": "/",
                 "expected_status": [200]},
            ]}},
        ]
        spec = derive_replay_spec("DESC-aaaabbbbcccc", "1.18.0", tool_uses)
        assert spec is not None
        tcp = [s for s in spec.verify_plan
               if s["type"] == "tcp_probe_check"][0]
        assert "host_port" not in tcp
        assert "host_ip" not in tcp
        # the probe semantics survive
        assert tcp["expected_response_contains"] == "nginx"
        # non-tcp steps untouched
        assert {"type": "http_check", "path": "/",
                "expected_status": [200]} in spec.verify_plan


class TestReviewRemediations:
    def test_replay_success_tears_down(self, capsys):
        from cve_env.cli import _attempt_replay
        from cve_env.models import CveRecord
        torn = {}
        env = SimpleNamespace(
            verified=lambda: True, verify_result={"passed": True},
            provision_id="tok123",
            teardown=lambda: torn.setdefault("yes", True))
        outcome = SimpleNamespace(ok=True, environment=env,
                                  reason="", detail="")
        with patch("cve_env.infra.spec_record.find_replayable_spec",
                   return_value=_spec()), \
             patch("core.env.provision.provision", return_value=outcome):
            result = _attempt_replay(
                CveRecord(cve_id="DESC-aaaabbbbcccc"), None)
        assert result is not None and result.status == "success"
        assert torn.get("yes") is True
        assert "torn down" in capsys.readouterr().err

    def test_up_refuses_empty_verify_plan(self, capsys):
        spec = SimpleNamespace(
            markers={"origin": {"source_run": "/runs/a"}},
            verify_plan=[])
        with patch("cve_env.infra.spec_record.find_replayable_spec",
                   return_value=spec):
            rc = _cmd_up(_args())
        assert rc == 1
        assert "no verify plan" in capsys.readouterr().err

    def test_up_no_verify_bypasses_empty_plan_gate(self, capsys):
        spec = SimpleNamespace(
            markers={"origin": {"source_run": "/runs/a"}},
            verify_plan=[])
        outcome = SimpleNamespace(ok=True, environment=_env(),
                                  reason="", detail="")
        with patch("cve_env.infra.spec_record.find_replayable_spec",
                   return_value=spec), \
             patch("core.env.provision.provision", return_value=outcome):
            rc = _cmd_up(_args(no_verify=True))
        assert rc == 0

    def test_portable_plan_strips_host_alias(self):
        from cve_env.infra.spec_record import _portable_plan
        out = _portable_plan([{"type": "tcp_probe_check",
                               "host": "127.0.0.1", "port": 32813,
                               "send_text": "x"}])
        assert out == [{"type": "tcp_probe_check", "send_text": "x"}]


class TestPs:
    def test_ps_parses_docker_rows(self, capsys):
        from types import SimpleNamespace as NS

        from cve_env.cli import _cmd_ps
        out = ('tok123\traptor-env-abc\t127.0.0.1:32816->80/tcp\t'
               'nginx:1.18.0\t5 minutes ago\n')
        with patch("core.container.proc.run_cli",
                   return_value=NS(returncode=0, stdout=out, stderr="")):
            rc = _cmd_ps(NS())
        assert rc == 0
        rows = json.loads(capsys.readouterr().out)
        assert rows == [{"down_token": "tok123", "name": "raptor-env-abc",
                         "endpoint": {"host": "127.0.0.1", "port": 32816},
                         "image": "nginx:1.18.0",
                         "running_for": "5 minutes ago"}]

    def test_ps_empty_is_clean(self, capsys):
        from types import SimpleNamespace as NS

        from cve_env.cli import _cmd_ps
        with patch("core.container.proc.run_cli",
                   return_value=NS(returncode=0, stdout="", stderr="")):
            rc = _cmd_ps(NS())
        assert rc == 0
        assert json.loads(capsys.readouterr().out) == []


class TestEgressPolicy:
    def test_up_default_is_isolated(self, capsys):
        seen = {}

        def fake_provision(spec, **kw):
            seen["mode"] = getattr(getattr(spec, "network", None),
                                   "mode", "isolated")
            return SimpleNamespace(ok=True, environment=_env(),
                                   reason="", detail="")

        spec = _spec()
        spec.network = SimpleNamespace(mode="isolated", egress_hosts=())
        with patch("cve_env.infra.spec_record.find_replayable_spec",
                   return_value=spec), \
             patch("core.env.provision.provision", fake_provision):
            rc = _cmd_up(_args())
        assert rc == 0
        assert seen["mode"] == "isolated"
        assert "egress ALLOWED" not in capsys.readouterr().err

    def test_allow_egress_flag_sets_unrestricted_and_warns(self, capsys):
        spec = _spec()
        spec.network = SimpleNamespace(mode="isolated", egress_hosts=())
        outcome = SimpleNamespace(ok=True, environment=_env(),
                                  reason="", detail="")
        with patch("cve_env.infra.spec_record.find_replayable_spec",
                   return_value=spec), \
             patch("core.env.provision.provision", return_value=outcome):
            rc = _cmd_up(_args(allow_egress=True))
        assert rc == 0
        assert spec.network.mode == "unrestricted"
        assert "egress ALLOWED" in capsys.readouterr().err

    def test_isolated_verify_failure_names_the_out(self, capsys):
        spec = _spec()
        spec.network = SimpleNamespace(mode="isolated", egress_hosts=())
        outcome = SimpleNamespace(ok=False, environment=None,
                                  reason="verify_failed", detail="probe")
        with patch("cve_env.infra.spec_record.find_replayable_spec",
                   return_value=spec), \
             patch("core.env.provision.provision", return_value=outcome):
            rc = _cmd_up(_args())
        assert rc == 1
        assert "--allow-egress" in capsys.readouterr().err


class TestDescribeTruncationWarning:
    def test_long_description_warns(self, capsys):
        _describe_record(_args(describe="x" * 4500))
        assert "embeds the first ~4000" in capsys.readouterr().err

    def test_short_description_silent(self, capsys):
        _describe_record(_args(describe="nginx 1.18"))
        assert "embeds the first" not in capsys.readouterr().err


class TestScorecardSegregation:
    def test_desc_id_routes_to_described_class(self):
        from unittest.mock import MagicMock

        from cve_env.infra.scorecard import (
            DECISION_CLASS,
            DECISION_CLASS_DESCRIBED,
            record_build_outcome,
        )
        sc = MagicMock()
        assert record_build_outcome("m1", "DESC-aaaabbbbcccc", "success",
                                    scorecard=sc)
        assert sc.record_event.call_args.args[0] == DECISION_CLASS_DESCRIBED
        sc2 = MagicMock()
        assert record_build_outcome("m1", "CVE-2018-7600", "success",
                                    scorecard=sc2)
        assert sc2.record_event.call_args.args[0] == DECISION_CLASS
