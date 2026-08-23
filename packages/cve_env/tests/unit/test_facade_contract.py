"""FACADE CONTRACT — the user-facing behaviour of ``cve-env`` that the
integration work must preserve.

Design record: ``~/design/cve-env-integration-2026-08-20.md`` §4.3. The
integration replaces the machinery behind ``bin/cve-env`` (runtime,
agent stack, substrates) in stages; these tests are the ratchet that
guarantees consumer (a) — the operator who runs ``cve-env build`` and
wants a compatible Docker environment — keeps getting exactly the
original contract:

  * CLI grammar and defaults (``build`` / ``doctor`` and every flag),
  * the outcome JSON key set on stdout (additive changes only —
    APPEND new keys to ``FACADE_OUTCOME_KEYS`` deliberately; removing
    or renaming a key is a facade break),
  * the SIGKILL-safe outcome sidecar (written even when stdout fails),
  * exit codes: ``build`` is 0 only on ``success``; ``doctor`` is 2 on
    critical service failure, 1 under ``--strict`` for any failure.

Every test here must stay green through Series 2-4. If a change makes
one fail, the change is wrong — not the test — unless the design
record's §4.3 is amended first.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

# cli imports the agent loop at module top, which imports the SDK.
# Package convention (see tests conftest): SDK-dependent tests gate
# with importorskip. Series 4 removes the SDK dependency — deleting
# this line then is part of that series' definition of done, at which
from cve_env import cli as cli_mod  # noqa: E402
from cve_env.models import Outcome

CVE = "CVE-2018-7600"

# The stdout/sidecar outcome JSON key set as shipped by the original
# tool. Additions must be APPENDED here in the same change that adds
# them (additive-only); removals/renames are facade breaks.
FACADE_OUTCOME_KEYS = frozenset({
    "cve_id",
    "status",
    "verify_passed",
    "give_up_reason",
    "give_up_detail",
    "num_turns",
    "total_cost_usd",
    "stop_reason",
    "reason",
    "tool_names_called",
    "method",
    "final_text",
    "audit_path",
    "refusals",
    "daemon_corruption",
    "stage_costs",
    "stage_calls",
    "over_budget_stages_list",
    # /cve-diff pre-fill provenance (None when off/miss) — additive.
    "prefill",
    # --describe provenance label (False on CVE runs) — additive.
    "operator_described",
})

# build flag → (argparse dest, shipped default). The grammar half of
# the contract: every one of these must keep parsing, with this default.
BUILD_FLAG_DEFAULTS = {
    "--product": ("product", None),
    "--version": ("version", None),
    "--description": ("description", None),
    "--max-turns": ("max_turns", 96),
    "--max-cost-usd": ("max_cost_usd", 1.80),
    "--audit-root": ("audit_root", None),
    "--silent": ("silent", False),
    "--auto-cleanup-containers": ("auto_cleanup_containers", False),
    "--auto-prune-images": ("auto_prune_images", False),
    "--auto-stop-colima": ("auto_stop_colima", False),
}


# ── CLI grammar ────────────────────────────────────────────────────────


class TestCliGrammar:
    def test_build_defaults(self):
        args = cli_mod._build_argparser().parse_args(["build", CVE])
        assert args.cmd == "build"
        assert args.cve_id == CVE
        for _flag, (dest, default) in BUILD_FLAG_DEFAULTS.items():
            assert getattr(args, dest) == default, dest
        # Extension knobs exist with the config-derived defaults.
        assert hasattr(args, "max_turn_extensions")
        assert hasattr(args, "turn_extension_pct")

    def test_build_accepts_every_documented_flag(self):
        args = cli_mod._build_argparser().parse_args([
            "build", CVE,
            "--product", "drupal", "--version", "8.5.0",
            "--description", "drupalgeddon2",
            "--max-turns", "40", "--max-cost-usd", "0.90",
            "--max-turn-extensions", "1", "--turn-extension-pct", "0.10",
            "--audit-root", "/tmp/x", "--silent",
            "--auto-cleanup-containers", "--auto-prune-images",
            "--auto-stop-colima",
        ])
        assert args.product == "drupal"
        assert args.max_turns == 40
        assert args.max_cost_usd == 0.90
        assert args.silent is True
        assert args.auto_stop_colima is True

    def test_doctor_grammar(self):
        p = cli_mod._build_argparser()
        assert p.parse_args(["doctor"]).strict is False
        assert p.parse_args(["doctor", "--strict"]).strict is True

    @pytest.mark.parametrize("bad", ["CVE-18-7600", "cve-2018-7600x",
                                     "GHSA-xxxx", "2018-7600", ""])
    def test_invalid_cve_id_rejected_at_parse(self, bad):
        with pytest.raises(SystemExit):
            cli_mod._build_argparser().parse_args(["build", bad])

    def test_subcommand_required_and_unknown_rejected(self):
        with pytest.raises(SystemExit):
            cli_mod._build_argparser().parse_args([])
        with pytest.raises(SystemExit):
            cli_mod._build_argparser().parse_args(["frobnicate"])


# ── build outcome JSON + sidecar + exit codes ─────────────────────────


def _outcome(status="success", **kw):
    base = dict(
        cve_id=CVE, status=status, reason="",
        num_turns=12, total_cost_usd=0.42,
        stop_reason="end_turn", verify_passed=(status == "success"),
        tool_names_called=["nvd_lookup", "image_resolve", "docker_run",
                           "verify"],
        final_text="done",
    )
    base.update(kw)
    return Outcome(**base)


def _run_build(tmp_path, monkeypatch, capsys, outcome, extra_argv=()):
    """Drive cli.main(['build', ...]) with the agent + network + lock
    layers stubbed. Returns (exit_code, stdout_text)."""
    def _fake_build(cve, host, **kw):
        return outcome

    with (
        patch.object(cli_mod, "build_core", _fake_build),
        patch("cve_env.agent.health_constraints.probe_for_constraints",
              return_value=""),
        patch("cve_env.utils.lifecycle.acquire_lock",
              return_value=tmp_path / "lock"),
        patch("cve_env.utils.lifecycle.release_lock"),
    ):
        rc = cli_mod.main([
            "build", CVE, "--silent",
            "--audit-root", str(tmp_path),
            *extra_argv,
        ])
    return rc, capsys.readouterr().out


class TestOutcomeContract:
    def test_stdout_json_key_set_is_the_facade(self, tmp_path, monkeypatch,
                                               capsys):
        rc, out = _run_build(tmp_path, monkeypatch, capsys, _outcome())
        assert rc == 0
        data = json.loads(out)
        assert set(data.keys()) == FACADE_OUTCOME_KEYS, (
            "outcome JSON keys changed — additions must be appended to "
            "FACADE_OUTCOME_KEYS deliberately; removals are facade breaks"
        )
        assert data["cve_id"] == CVE
        assert data["status"] == "success"
        assert data["verify_passed"] is True
        assert isinstance(data["method"], (str, list))

    def test_sidecar_written_and_matches_stdout(self, tmp_path, monkeypatch,
                                                capsys):
        _rc, out = _run_build(tmp_path, monkeypatch, capsys, _outcome())
        sidecar = tmp_path / f"{CVE}.outcome.json"
        assert sidecar.exists()
        assert json.loads(sidecar.read_text()) == json.loads(out)

    def test_sidecar_survives_stdout_failure(self, tmp_path, monkeypatch,
                                             capsys):
        """The SIGKILL-safety property bench runners rely on: the
        sidecar lands even when the stdout pipe is already dead."""
        def _fake_build(cve, host, **kw):
            return _outcome()

        real_print = print

        def _broken_print(*a, **kw):
            raise BrokenPipeError("stdout gone")

        with (
            patch.object(cli_mod, "build_core", _fake_build),
            patch("cve_env.agent.health_constraints.probe_for_constraints",
                  return_value=""),
            patch("cve_env.utils.lifecycle.acquire_lock",
                  return_value=tmp_path / "lock"),
            patch("cve_env.utils.lifecycle.release_lock"),
            patch("builtins.print", _broken_print),
        ):
            with pytest.raises(BrokenPipeError):
                cli_mod.main(["build", CVE, "--silent",
                              "--audit-root", str(tmp_path)])
        sidecar = tmp_path / f"{CVE}.outcome.json"
        assert sidecar.exists(), "sidecar must be written before stdout"
        assert json.loads(sidecar.read_text())["status"] == "success"
        real_print("sidecar-before-stdout contract holds")

    @pytest.mark.parametrize("status", [
        "verified_partial", "verify_failed", "unresolvable",
        "budget_exhausted", "turn_cap", "interrupted", "rate_limited",
    ])
    def test_exit_1_on_every_non_success_status(self, tmp_path, monkeypatch,
                                                capsys, status):
        rc, out = _run_build(
            tmp_path, monkeypatch, capsys,
            _outcome(status=status, verify_passed=False),
        )
        assert rc == 1
        assert json.loads(out)["status"] == status

    def test_exit_0_only_on_success(self, tmp_path, monkeypatch, capsys):
        rc, _ = _run_build(tmp_path, monkeypatch, capsys, _outcome())
        assert rc == 0


# ── doctor exit codes ─────────────────────────────────────────────────


class _Probe:
    def __init__(self, ok):
        self.ok = ok


class TestDoctorContract:
    def _run(self, results, critical, argv):
        with (
            patch("cve_env.infra.service_health.run_all",
                  return_value=results),
            patch("cve_env.infra.service_health.render_table",
                  return_value="(table)"),
            patch("cve_env.infra.service_health.has_critical_failure",
                  return_value=critical),
        ):
            return cli_mod.main(argv)

    def test_all_healthy_exits_0(self):
        assert self._run([_Probe(True)], False, ["doctor"]) == 0

    def test_critical_failure_exits_2(self):
        assert self._run([_Probe(False)], True, ["doctor"]) == 2

    def test_strict_noncritical_failure_exits_1(self):
        assert self._run([_Probe(False), _Probe(True)], False,
                         ["doctor", "--strict"]) == 1

    def test_noncritical_failure_without_strict_exits_0(self):
        assert self._run([_Probe(False), _Probe(True)], False,
                         ["doctor"]) == 0
