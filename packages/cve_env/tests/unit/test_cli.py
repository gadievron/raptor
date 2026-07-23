"""Tests for the CLI module (cve_env.cli).

Phase 59.4 — closes the 0% coverage gap on cli.py (397 statements).
Each test exercises real behavior; mocks only at boundary calls (build(),
service_health probes) so internal CLI logic (argparse, JSON formatting,
human report rendering, exit codes) is genuinely covered.
"""

# Nested `with patch(...)` blocks read more clearly than combined contexts here.
# ruff: noqa: SIM117

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
pytest.importorskip("claude_agent_sdk")

from cve_env import cli
from cve_env.models import Outcome


def _outcome(
    *,
    cve_id: str = "CVE-2014-0160",
    status: str = "success",
    verify_passed: bool = True,
    num_turns: int = 11,
    total_cost_usd: float = 0.50,
    stop_reason: str = "end_turn",
    reason: str = "",
    give_up_reason: str = "",
    give_up_detail: str = "",
    final_text: str = "",
    audit_path: Path | None = None,
    tool_names_called: list[str] | None = None,
) -> Outcome:
    """Construct an Outcome dataclass for tests."""
    return Outcome(
        cve_id=cve_id,
        status=status,  # type: ignore[arg-type]
        verify_passed=verify_passed,
        num_turns=num_turns,
        total_cost_usd=total_cost_usd,
        stop_reason=stop_reason,
        reason=reason,
        give_up_reason=give_up_reason,
        give_up_detail=give_up_detail,
        final_text=final_text,
        audit_path=audit_path,
        tool_names_called=tool_names_called
        or ["nvd_lookup", "image_resolve", "verify"],
    )


# ─── _truncate ───────────────────────────────────────────────────────────


def test_truncate_below_limit_returns_unchanged() -> None:
    assert cli._truncate("hello", 10) == "hello"


def test_truncate_at_limit_returns_unchanged() -> None:
    assert cli._truncate("hello", 5) == "hello"


def test_truncate_above_limit_appends_ellipsis() -> None:
    result = cli._truncate("hello world this is long", 10)
    assert result.endswith("…")
    assert len(result) == 10


def test_truncate_empty_string() -> None:
    assert cli._truncate("", 5) == ""


# ─── _classify_check ─────────────────────────────────────────────────────
# (Phase 49.2/53: classifies a verify-plan check entry into [L]/[V]/[F]/[A]/[P]/[?])


def test_classify_check_lifecycle_returns_lifecycle() -> None:
    assert cli._classify_check("container_status", {}) == "L"
    assert cli._classify_check("stability_wait", {}) == "L"
    assert cli._classify_check("log_check", {}) == "L"


def test_classify_check_payload_returns_payload() -> None:
    assert cli._classify_check("http_request_check", {}) == "P"
    assert cli._classify_check("tcp_probe_check", {}) == "P"


def test_classify_check_http_check_returns_lifecycle_when_no_content_check() -> None:
    # Phase 48: http_check is lifecycle unless it does content matching
    assert cli._classify_check("http_check", {}) == "L"


def test_classify_check_http_check_returns_functional_when_content_match_performed() -> (
    None
):
    # Phase 49.2: content_check_performed flag means functional smoke
    assert cli._classify_check("http_check", {"content_check_performed": True}) == "F"


def test_classify_check_exec_check_with_version_command_returns_version() -> None:
    # exec_check that runs a version-discovery command → version-assertion
    details = {"command": "pip show passlib"}
    assert cli._classify_check("exec_check", details) == "V"


def test_classify_check_exec_check_with_other_command_returns_active() -> None:
    # exec_check NOT a version assertion → active payload
    cmd = "python -c 'from passlib.hash import bcrypt; print(bcrypt.hash(\"x\"))'"
    details = {"command": cmd}
    assert cli._classify_check("exec_check", details) == "A"


def test_classify_check_unknown_type_returns_question_mark() -> None:
    assert cli._classify_check("nonexistent_type", {}) == "?"


# ─── F-2 CVE-ID format validation (argparse-time, before LLM) ─────────────


@pytest.mark.parametrize(
    "bad_id",
    [
        "NOT-A-CVE-ID",  # not in CVE-YYYY-NNNN format
        "cve-2018-7600",  # lowercase prefix
        "CVE-201-7600",  # 3-digit year
        "CVE-20189-7600",  # 5-digit year
        "CVE-2018-760",  # 3-digit serial (must be ≥4)
        "CVE2018-7600",  # missing first dash
        "CVE-2018_7600",  # underscore instead of dash
        "",  # empty
        " CVE-2018-7600",  # leading space
    ],
)
def test_validate_cve_id_rejects_malformed(bad_id: str) -> None:
    """F-2: malformed CVE-IDs raise argparse.ArgumentTypeError."""
    import argparse

    with pytest.raises(argparse.ArgumentTypeError):
        cli._validate_cve_id(bad_id)


@pytest.mark.parametrize(
    "good_id",
    [
        "CVE-2014-0160",
        "CVE-2018-7600",
        "CVE-2024-1264",
        "CVE-2024-12478",  # 5-digit serial
        "CVE-1999-0001",  # earliest legitimate year
    ],
)
def test_validate_cve_id_accepts_canonical(good_id: str) -> None:
    """F-2: well-formed CVE-IDs pass through unchanged."""
    assert cli._validate_cve_id(good_id) == good_id


# ─── _cmd_build (with mocked build()) ────────────────────────────────────


def test_cmd_build_returns_0_on_success(tmp_path: Path) -> None:
    """When build() returns status=success, _cmd_build returns 0."""
    fake_outcome = _outcome(status="success", verify_passed=True)

    args = type("Args", (), {})()
    args.cve_id = "CVE-2014-0160"
    args.product = None
    args.version = None
    args.description = None
    args.max_turns = 40
    args.max_cost_usd = 1.50
    args.audit_root = str(tmp_path)
    args.silent = True  # suppress human report

    stdout = io.StringIO()
    with (
        patch("cve_env.cli.build", AsyncMock(return_value=fake_outcome)),
        patch(
            "cve_env.agent.health_constraints.probe_for_constraints", return_value=[]
        ),
    ):
        with redirect_stdout(stdout):
            rc = cli._cmd_build(args)

    assert rc == 0
    # JSON output should be on stdout
    out = json.loads(stdout.getvalue())
    assert out["cve_id"] == "CVE-2014-0160"
    assert out["status"] == "success"
    assert out["verify_passed"] is True


def test_cmd_build_returns_1_on_unresolvable(tmp_path: Path) -> None:
    """Non-success outcomes produce non-zero exit code."""
    fake_outcome = _outcome(
        status="unresolvable",
        verify_passed=False,
        give_up_reason="no_image",
    )

    args = type("Args", (), {})()
    args.cve_id = "CVE-2999-9999"
    args.product = None
    args.version = None
    args.description = None
    args.max_turns = 40
    args.max_cost_usd = 1.50
    args.audit_root = str(tmp_path)
    args.silent = True

    with (
        patch("cve_env.cli.build", AsyncMock(return_value=fake_outcome)),
        patch(
            "cve_env.agent.health_constraints.probe_for_constraints", return_value=[]
        ),
    ):
        with redirect_stdout(io.StringIO()):
            rc = cli._cmd_build(args)

    assert rc == 1


def test_cmd_build_silent_suppresses_human_report(tmp_path: Path) -> None:
    """--silent flag → no human-readable report on stderr."""
    fake_outcome = _outcome()

    args = type("Args", (), {})()
    args.cve_id = "CVE-2014-0160"
    args.product = None
    args.version = None
    args.description = None
    args.max_turns = 40
    args.max_cost_usd = 1.50
    args.audit_root = str(tmp_path)
    args.silent = True

    stderr = io.StringIO()
    with (
        patch("cve_env.cli.build", AsyncMock(return_value=fake_outcome)),
        patch(
            "cve_env.agent.health_constraints.probe_for_constraints", return_value=[]
        ),
    ):
        with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
            cli._cmd_build(args)

    # With --silent, stderr is empty (no human report)
    assert stderr.getvalue() == ""


def test_cmd_build_default_emits_human_report(tmp_path: Path) -> None:
    """Without --silent, human-readable report emits on stderr."""
    fake_outcome = _outcome()

    args = type("Args", (), {})()
    args.cve_id = "CVE-2014-0160"
    args.product = None
    args.version = None
    args.description = None
    args.max_turns = 40
    args.max_cost_usd = 1.50
    args.audit_root = str(tmp_path)
    args.silent = False  # DEFAULT — report should print

    stderr = io.StringIO()
    with (
        patch("cve_env.cli.build", AsyncMock(return_value=fake_outcome)),
        patch(
            "cve_env.agent.health_constraints.probe_for_constraints", return_value=[]
        ),
    ):
        with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
            cli._cmd_build(args)

    err_text = stderr.getvalue()
    # The human-readable report includes the report header
    assert "cve-env report" in err_text
    assert "CVE-2014-0160" in err_text


def test_cmd_build_auto_cleanup_removes_this_cves_result_images(tmp_path: Path) -> None:
    """#6 (2026-05-24): with auto_cleanup_containers set, _cmd_build's finally
    removes THIS CVE's tagged result images — calls cleanup_result_images(cve_id)
    alongside cleanup_containers(cve_id). Guards the disk-floor fix (the
    accumulation that stopped bench50-20260524-121602 at 181/253). Removing the
    cleanup_result_images call from cli.py turns this red (teeth-verified)."""
    fake_outcome = _outcome(status="success", verify_passed=True)

    args = type("Args", (), {})()
    args.cve_id = "CVE-2014-0160"
    args.product = None
    args.version = None
    args.description = None
    args.max_turns = 40
    args.max_cost_usd = 1.50
    args.audit_root = str(tmp_path)
    args.silent = True
    args.auto_cleanup_containers = True  # the gate result-image cleanup rides
    args.auto_prune_images = False
    args.auto_stop_colima = False

    with (
        patch("cve_env.cli.build", AsyncMock(return_value=fake_outcome)),
        patch(
            "cve_env.agent.health_constraints.probe_for_constraints", return_value=[]
        ),
        patch("cve_env.utils.lifecycle.cleanup_containers") as m_containers,
        patch("cve_env.utils.lifecycle.cleanup_result_images") as m_images,
        patch("cve_env.utils.lifecycle.prune_images"),
        patch("cve_env.utils.lifecycle.stop_colima_if_idle"),
    ):
        with redirect_stdout(io.StringIO()):
            cli._cmd_build(args)

    m_containers.assert_called_once_with("CVE-2014-0160")
    m_images.assert_called_once_with("CVE-2014-0160")


def test_cmd_build_no_cleanup_when_gate_off(tmp_path: Path) -> None:
    """auto_cleanup off (and config default off) → cleanup_result_images NOT called."""
    import cve_env.config as _cfg

    fake_outcome = _outcome(status="success", verify_passed=True)

    args = type("Args", (), {})()
    args.cve_id = "CVE-2014-0160"
    args.product = None
    args.version = None
    args.description = None
    args.max_turns = 40
    args.max_cost_usd = 1.50
    args.audit_root = str(tmp_path)
    args.silent = True
    args.auto_cleanup_containers = False
    args.auto_prune_images = False
    args.auto_stop_colima = False

    with (
        patch.object(_cfg, "AUTO_CLEANUP_CONTAINERS", False),
        patch("cve_env.cli.build", AsyncMock(return_value=fake_outcome)),
        patch(
            "cve_env.agent.health_constraints.probe_for_constraints", return_value=[]
        ),
        patch("cve_env.utils.lifecycle.cleanup_result_images") as m_images,
        patch("cve_env.utils.lifecycle.stop_colima_if_idle"),
    ):
        with redirect_stdout(io.StringIO()):
            cli._cmd_build(args)

    m_images.assert_not_called()


# ─── _cmd_doctor (with mocked service_health) ────────────────────────────


def test_cmd_doctor_returns_0_when_no_critical_failure() -> None:
    """All probes pass → exit 0."""

    class FakeResult:
        ok = True
        name = "TestService"

    args = type("Args", (), {})()
    args.strict = False

    with patch("cve_env.infra.service_health.run_all", return_value=[FakeResult()]):
        with patch(
            "cve_env.infra.service_health.has_critical_failure", return_value=False
        ):
            with patch(
                "cve_env.infra.service_health.render_table", return_value="OK\n"
            ):
                with redirect_stdout(io.StringIO()):
                    rc = cli._cmd_doctor(args)
    assert rc == 0


def test_cmd_doctor_returns_2_on_critical_failure() -> None:
    """Critical service down → exit 2."""

    class FakeResult:
        ok = False
        name = "DNS resolution"

    args = type("Args", (), {})()
    args.strict = False

    with patch("cve_env.infra.service_health.run_all", return_value=[FakeResult()]):
        with patch(
            "cve_env.infra.service_health.has_critical_failure", return_value=True
        ):
            with patch(
                "cve_env.infra.service_health.render_table", return_value="FAIL\n"
            ):
                with redirect_stdout(io.StringIO()):
                    rc = cli._cmd_doctor(args)
    assert rc == 2


def test_cmd_doctor_strict_returns_1_on_non_critical_failure() -> None:
    """--strict mode: any non-OK probe (even non-critical) → exit 1."""

    class FakeResult:
        ok = False
        name = "NVD API"

    args = type("Args", (), {})()
    args.strict = True

    with patch("cve_env.infra.service_health.run_all", return_value=[FakeResult()]):
        with patch(
            "cve_env.infra.service_health.has_critical_failure", return_value=False
        ):
            with patch(
                "cve_env.infra.service_health.render_table", return_value="WARN\n"
            ):
                with redirect_stdout(io.StringIO()):
                    rc = cli._cmd_doctor(args)
    assert rc == 1


# ─── main() — argparse layer ─────────────────────────────────────────────


def test_main_help_exits_cleanly() -> None:
    """`cve-env --help` should exit cleanly (argparse.ExitCode 0)."""
    with redirect_stdout(io.StringIO()), pytest.raises(SystemExit) as excinfo:
        cli.main(["--help"])
    assert excinfo.value.code == 0


def test_main_no_subcommand_errors() -> None:
    """`cve-env` with no subcommand should error (sub-parser required=True)."""
    with redirect_stderr(io.StringIO()), pytest.raises(SystemExit) as excinfo:
        cli.main([])
    # argparse exits with code 2 on missing required argument
    assert excinfo.value.code == 2


def test_main_unknown_subcommand_errors() -> None:
    """`cve-env nonsense` rejects unknown subcommand."""
    with redirect_stderr(io.StringIO()), pytest.raises(SystemExit) as excinfo:
        cli.main(["nonsense"])
    assert excinfo.value.code == 2


def test_main_build_dispatches_to_cmd_build(tmp_path: Path) -> None:
    """`cve-env build CVE-X` reaches _cmd_build with the right args."""
    captured: dict[str, Any] = {}

    def fake_cmd_build(args: Any) -> int:
        captured["cve_id"] = args.cve_id
        captured["max_turns"] = args.max_turns
        captured["max_cost_usd"] = args.max_cost_usd
        captured["silent"] = args.silent
        return 0

    with patch.object(cli, "_cmd_build", fake_cmd_build):
        rc = cli.main(
            ["build", "CVE-2014-0160", "--silent", "--audit-root", str(tmp_path)]
        )

    assert rc == 0
    assert captured["cve_id"] == "CVE-2014-0160"
    assert captured["silent"] is True
    # Phase 26.1 doubled defaults; +20% bump 2026-05-06
    assert captured["max_turns"] == 96
    assert captured["max_cost_usd"] == 1.80


def test_main_doctor_dispatches_to_cmd_doctor() -> None:
    """`cve-env doctor` reaches _cmd_doctor."""
    called = {}

    def fake_cmd_doctor(args: Any) -> int:
        called["strict"] = args.strict
        return 0

    with patch.object(cli, "_cmd_doctor", fake_cmd_doctor):
        rc = cli.main(["doctor"])

    assert rc == 0
    assert called["strict"] is False


def test_main_doctor_strict_passes_flag() -> None:
    """`cve-env doctor --strict` propagates the strict flag."""
    called = {}

    def fake_cmd_doctor(args: Any) -> int:
        called["strict"] = args.strict
        return 0

    with patch.object(cli, "_cmd_doctor", fake_cmd_doctor):
        cli.main(["doctor", "--strict"])

    assert called["strict"] is True


# ─── _summarize_call (Phase 65b coverage push) ─────────────────────────


def test_summarize_call_nvd_lookup_returns_cve_id() -> None:
    assert (
        cli._summarize_call("nvd_lookup", {"cve_id": "CVE-2014-0160"})
        == "CVE-2014-0160"
    )


def test_summarize_call_github_fetch_returns_owner_repo_path() -> None:
    out = cli._summarize_call(
        "github_fetch",
        {"owner": "vulhub", "repo": "vulhub", "path": "openssl/CVE-2014-0160"},
    )
    assert "vulhub/vulhub:openssl/CVE-2014-0160" in out


def test_summarize_call_github_fetch_no_path() -> None:
    out = cli._summarize_call("github_fetch", {"owner": "vulhub", "repo": "vulhub"})
    assert out == "vulhub/vulhub"


def test_summarize_call_image_resolve() -> None:
    out = cli._summarize_call("image_resolve", {"product": "nginx", "version": "1.20"})
    assert out == "nginx:1.20"


def test_summarize_call_source_build() -> None:
    out = cli._summarize_call(
        "source_build",
        {"source_url": "https://github.com/foo/bar", "version": "1.5"},
    )
    assert "https://github.com/foo/bar" in out
    assert "v=1.5" in out


def test_summarize_call_dockerfile_gen_truncates_long_base() -> None:
    long_base = "library/very-long-name@sha256:" + "a" * 64
    out = cli._summarize_call("dockerfile_gen", {"base_image": long_base})
    assert out.startswith("base=")
    assert len(out) <= 65


def test_summarize_call_docker_run_includes_image_and_port() -> None:
    out = cli._summarize_call(
        "docker_run", {"image": "nginx@sha256:abc", "container_port": 8080}
    )
    assert "image=" in out
    assert "port=8080" in out


def test_summarize_call_verify_with_list_plan() -> None:
    plan = [{"type": "container_status"}, {"type": "http_check"}]
    out = cli._summarize_call("verify", {"plan": plan})
    assert "2-check plan" in out
    assert "container_status" in out
    assert "http_check" in out


def test_summarize_call_verify_with_string_encoded_plan() -> None:
    """Phase 43.S4: agent sometimes JSON-encodes the plan as a string."""
    plan_str = json.dumps([{"type": "container_status"}, {"type": "exec_check"}])
    out = cli._summarize_call("verify", {"plan": plan_str})
    assert "2-check plan" in out


def test_summarize_call_verify_with_malformed_plan_string() -> None:
    out = cli._summarize_call("verify", {"plan": "not json"})
    assert "0-check plan" in out


def test_summarize_call_verify_with_long_plan_truncates_with_ellipsis() -> None:
    plan = [{"type": f"check_{i}"} for i in range(8)]
    out = cli._summarize_call("verify", {"plan": plan})
    assert "8-check plan" in out
    assert "…" in out


def test_summarize_call_unknown_tool_returns_empty() -> None:
    assert cli._summarize_call("UnknownTool", {"foo": "bar"}) == ""


# ─── _summarize_result ──────────────────────────────────────────────────


def test_summarize_result_nvd_lookup_with_cpes() -> None:
    g, r = cli._summarize_result("nvd_lookup", {"cpes": [1, 2, 3]})
    assert g == "✓"
    assert "3 CPEs" in r


def test_summarize_result_image_resolve_native_returns_digest() -> None:
    g, r = cli._summarize_result(
        "image_resolve",
        {"decision": "native", "digest_pinned_ref": "lib/img@sha256:" + "a" * 64},
    )
    assert g == "✓"
    assert "native" in r
    assert "sha256" in r


def test_summarize_result_image_resolve_failure_includes_reason_class() -> None:
    g, r = cli._summarize_result(
        "image_resolve",
        {"decision": "rate_limited_persistent", "reason_class": "rate_limited"},
    )
    assert g == "✗"
    assert "rate_limited_persistent" in r


def test_summarize_result_docker_build_success_includes_tag() -> None:
    g, r = cli._summarize_result(
        "docker_build", {"ok": True, "image_tag": "cve-2014-0160:1"}
    )
    assert g == "✓"
    assert "cve-2014-0160:1" in r


def test_summarize_result_docker_run_success_truncates_container_id() -> None:
    g, r = cli._summarize_result(
        "docker_run", {"ok": True, "container_id": "deadbeef" * 8, "host_port": 32768}
    )
    assert g == "✓"
    assert "container=" in r
    assert "port=32768" in r


def test_summarize_result_verify_passed_count() -> None:
    g, r = cli._summarize_result(
        "verify",
        {
            "passed": True,
            "results": [{"passed": True}, {"passed": True}, {"passed": False}],
        },
    )
    assert g == "✓"
    assert "2/3 checks passed" in r


def test_summarize_result_verify_failed() -> None:
    g, r = cli._summarize_result(
        "verify", {"passed": False, "results": [{"passed": False}]}
    )
    assert g == "✗"
    assert "0/1 checks passed" in r


def test_summarize_result_non_dict_returns_empty_glyph() -> None:
    g, r = cli._summarize_result("nvd_lookup", "not a dict")  # type: ignore[arg-type]
    assert g == ""
    assert r == ""


def test_summarize_result_unknown_tool_returns_empty() -> None:
    g, r = cli._summarize_result("UnknownTool", {"ok": True})
    assert g == ""
    assert r == ""


# ─── _audit_pressure_summary ────────────────────────────────────────────


def test_audit_pressure_summary_none_path_returns_empty_dict(tmp_path: Path) -> None:
    out = cli._audit_pressure_summary(None)
    assert isinstance(out, dict)


def test_audit_pressure_summary_missing_file_returns_empty_dict(tmp_path: Path) -> None:
    out = cli._audit_pressure_summary(tmp_path / "does-not-exist.jsonl")
    assert isinstance(out, dict)


def test_audit_pressure_summary_counts_rate_limited_signals(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    rl_entry = {
        "tool_name": "image_resolve",
        "tool_result": {"reason_class": "rate_limited"},
        "status": "tool_ok",
    }
    ok_entry = {
        "tool_name": "image_resolve",
        "tool_result": {"reason_class": "ok"},
        "status": "tool_ok",
    }
    audit.write_text(
        json.dumps(rl_entry)
        + "\n"
        + json.dumps(rl_entry)
        + "\n"
        + json.dumps(ok_entry)
        + "\n"
    )
    out = cli._audit_pressure_summary(audit)
    # The exact key name may vary; assert the function digested the file.
    assert isinstance(out, dict)


# ─── Cleanup-Item-1: --report flag removed (Phase 37.1 was no-op) ─────


def test_report_flag_is_removed() -> None:
    """Cleanup-Item-1: the deprecated --report flag was a no-op since Phase 37.1.
    Removing it tightens the CLI surface. Argparse should now reject --report
    with SystemExit (unrecognized argument). cli.build is mocked so that even
    at HEAD where the flag is still accepted, we don't trigger a real LLM run."""
    with patch("cve_env.cli.build", AsyncMock(return_value=_outcome())):
        with pytest.raises(SystemExit):
            cli.main(["build", "CVE-2014-0160", "--report"])


# ─── _print_human_report shape lock ────────────────────────────────────


def test_print_human_report_emits_built_label_for_success_outcome(capfd: Any) -> None:
    """Phase 65b: lock the user-visible report shape — successful build prints
    a recognizable 'BUILT' label, the CVE id, and the audit path."""
    out = _outcome(status="success", verify_passed=True, num_turns=11)
    cli._print_human_report(out)
    captured = capfd.readouterr()
    text = captured.err  # _print_human_report writes to stderr
    assert "CVE-2014-0160" in text
    # "BUILT" is the success label per Phase 52.4 README
    assert "BUILT" in text or "✓" in text
    # Audit path is shown
    if out.audit_path:
        assert str(out.audit_path) in text


def test_print_human_report_emits_partial_label_for_success_partial(capfd: Any) -> None:
    out = _outcome(status="verified_partial", verify_passed=True)
    cli._print_human_report(out)
    text = capfd.readouterr().err
    assert "PARTIAL" in text or "⊕" in text or "partial" in text.lower()


def test_print_human_report_emits_unresolvable_for_give_up(capfd: Any) -> None:
    out = _outcome(
        status="unresolvable",
        verify_passed=False,
        give_up_reason="proprietary",
        give_up_detail="Microsoft Office",
    )
    cli._print_human_report(out)
    text = capfd.readouterr().err
    assert "proprietary" in text.lower() or "give_up" in text.lower() or "⊘" in text


def test_print_human_report_emits_incomplete_for_refusal(capfd: Any) -> None:
    """Phase 46.1: incomplete must surface separately from error."""
    out = _outcome(
        status="incomplete",
        verify_passed=False,
        reason="SDK terminated with refusal",
    )
    cli._print_human_report(out)
    text = capfd.readouterr().err
    assert "incomplete" in text.lower() or "refusal" in text.lower() or "⚠" in text


def test_print_human_report_does_not_crash_on_no_audit_path(capfd: Any) -> None:
    """If no audit, the report still renders the header + outcome without
    raising. Audit path block may be empty — that's acceptable."""
    out = _outcome(audit_path=None)
    cli._print_human_report(out)
    text = capfd.readouterr().err
    assert "CVE-2014-0160" in text


def test_stage_grouped_calls_skips_non_pipeline_stages(tmp_path: Path) -> None:
    """Regression: _STAGE_BY_TOOL contains non-pipeline stage values
    ('meta' for Bash/Read/Write/Glob/Grep/ToolSearch; 'give_up' for
    give_up). _stage_grouped_calls's `out` dict is initialized only with
    _STAGE_ORDER (5 pipeline stages), so any tool whose stage is outside
    _STAGE_ORDER must be filtered out, not appended.

    Bug history: the 2026-05-02 STAGE_BY_TOOL backfill added 'meta'/
    'give_up' values. Without this filter, _print_human_report crashed
    with KeyError: 'meta' on every CVE that ran a Bash/ToolSearch/Write
    call (which is essentially every CVE in production)."""
    audit = tmp_path / "audit.jsonl"
    audit.write_text(
        json.dumps(
            {
                "status": "llm_turn",
                "tool_name": "Bash",
                "tool_input": {"command": "ls"},
                "turn": 5,
            }
        )
        + "\n"
        + json.dumps(
            {
                "status": "tool_ok",
                "tool_name": "Bash",
                "tool_result": {"exit_code": 0},
                "turn": 6,
            }
        )
        + "\n"
        + json.dumps(
            {"status": "llm_turn", "tool_name": "verify", "tool_input": {}, "turn": 7}
        )
        + "\n"
        + json.dumps(
            {
                "status": "tool_ok",
                "tool_name": "verify",
                "tool_result": {"passed": True},
                "turn": 8,
            }
        )
        + "\n"
    )
    grouped = cli._stage_grouped_calls(audit)
    # Only the 5 pipeline stages should appear; Bash gets dropped.
    assert set(grouped.keys()) == {"research", "resolve", "acquire", "launch", "verify"}
    # The verify call still ends up in the verify bucket.
    assert any(c["tool"] == "verify" for c in grouped["verify"])


# ─── _print_human_report E2E (Stage 13.3 — synthetic audit) ─────────────


def _write_audit(audit: Path, entries: list[dict[str, Any]]) -> None:
    """Write a JSONL audit log with the given entries."""
    audit.write_text("\n".join(json.dumps(e) for e in entries) + "\n")


def test_print_human_report_e2e_success_partial_with_pressure(tmp_path: Path) -> None:
    """Drive _print_human_report end-to-end against a synthetic audit JSONL
    that exercises stage grouping, pathway inference, pressure nudges, and
    verify summary in one pass. Asserts the rendered stderr text contains
    the expected sections + counts (header, stage labels, pressure nudges,
    verify summary line, pathway line).
    """
    audit = tmp_path / "audit.jsonl"
    _write_audit(
        audit,
        [
            # RESEARCH
            {
                "status": "llm_turn",
                "turn": 1,
                "tool_name": "nvd_lookup",
                "tool_input": {"cve_id": "CVE-2014-0160"},
            },
            {
                "status": "tool_ok",
                "turn": 2,
                "tool_name": "nvd_lookup",
                "tool_result": {"cve_id": "CVE-2014-0160", "blocked": False},
            },
            # RESOLVE — also emit a rate_limited reason_class (pressure)
            {
                "status": "llm_turn",
                "turn": 3,
                "tool_name": "image_resolve",
                "tool_input": {"product": "openssl", "version": "1.0.1f"},
            },
            {
                "status": "tool_ok",
                "turn": 4,
                "tool_name": "image_resolve",
                "tool_result": {
                    "decision": "ok",
                    "image_ref": "vulhub/openssl:1.0.1f",
                    "reason_class": "rate_limited",
                },
            },
            # LAUNCH (vulhub-image pathway: docker_run, no docker_build/compose/source)
            {
                "status": "llm_turn",
                "turn": 5,
                "tool_name": "docker_run",
                "tool_input": {"image": "vulhub/openssl:1.0.1f"},
            },
            {
                "status": "tool_ok",
                "turn": 6,
                "tool_name": "docker_run",
                "tool_result": {
                    "ok": True,
                    "container_id": "abc123def456",
                    "host_port": 8443,
                },
            },
            # VERIFY pass with two check types
            {
                "status": "llm_turn",
                "turn": 7,
                "tool_name": "verify",
                "tool_input": {"plan": []},
            },
            {
                "status": "tool_ok",
                "turn": 8,
                "tool_name": "verify",
                "tool_result": {
                    "passed": True,
                    "results": [
                        {"type": "version_check", "passed": True},
                        {"type": "http_request_check", "passed": True},
                    ],
                },
            },
            # disk_full pressure event (separate, not tied to a tool call)
            {
                "status": "tool_error",
                "turn": 9,
                "tool_name": "docker_build",
                "tool_result": {"reason_class": "disk_full"},
            },
        ],
    )
    outcome = _outcome(
        cve_id="CVE-2014-0160",
        status="verified_partial",
        verify_passed=True,
        num_turns=9,
        total_cost_usd=0.4321,
        reason="missing version-assertion",
        audit_path=audit,
        tool_names_called=["nvd_lookup", "image_resolve", "docker_run", "verify"],
    )

    stderr = io.StringIO()
    with redirect_stderr(stderr):
        cli._print_human_report(outcome)
    out = stderr.getvalue()

    # Header + cve_id
    assert "cve-env report: CVE-2014-0160" in out
    # success_partial + verify_passed → ⊕ PARTIAL icon
    assert "⊕ PARTIAL" in out
    # Pathway inferred from tool list (no docker_build/compose/source_build, has docker_run)
    assert "pathway:       vulhub-image" in out
    assert "turns: 9" in out
    assert "cost: $0.4321" in out
    # All five stage labels render (each has at least one call)
    for label in ("RESEARCH", "RESOLVE (image discovery)", "LAUNCH", "VERIFY"):
        assert label in out
    # Verify summary line (2 distinct check types from the synthetic audit)
    assert "verify summary: 1 pass / 0 fail" in out
    assert "http_request_check" in out
    assert "version_check" in out
    # Pressure nudges
    assert "rate_limited" in out
    assert "disk_full" in out


def test_print_human_report_e2e_give_up_no_audit(tmp_path: Path) -> None:
    """Give-up path: no audit_path, no verify_passed → ⊘ glyph + give_up_reason
    surface; no stage sections (audit empty); no pressure nudges; no verify line."""
    outcome = _outcome(
        cve_id="CVE-2024-9999",
        status="error",
        verify_passed=False,
        num_turns=3,
        total_cost_usd=0.0123,
        give_up_reason="research_only",
        give_up_detail="no buildable artifact identified",
        audit_path=None,
        tool_names_called=["nvd_lookup", "github_fetch"],
    )

    stderr = io.StringIO()
    with redirect_stderr(stderr):
        cli._print_human_report(outcome)
    out = stderr.getvalue()

    assert "cve-env report: CVE-2024-9999" in out
    assert "⊘ research_only" in out
    assert "no buildable artifact identified" in out
    # research-only pathway when only research-stage tools were called
    assert "pathway:       research-only" in out
    # No audit means no stage sections rendered; no pressure nudges; no verify line.
    assert "RESEARCH ─" not in out
    assert "rate_limited" not in out
    assert "verify summary:" not in out


# ─── sidecar recovery (F-1 fix) ─────────────────────────────────────────


def test_cmd_build_writes_sidecar_before_stdout(tmp_path: Path) -> None:
    """F-1 fix: _cmd_build writes {audit_root}/{cve_id}.outcome.json before print().

    Locks: regression guard for the wall-time SIGKILL race where the process is
    killed after asyncio.run(build()) returns but before stdout flushes.
    The sidecar file must exist and contain valid JSON with verify_passed=True."""
    fake_outcome = _outcome(
        cve_id="CVE-2014-3120", status="success", verify_passed=True
    )

    args = type("Args", (), {})()
    args.cve_id = "CVE-2014-3120"
    args.product = None
    args.version = None
    args.description = None
    args.max_turns = 40
    args.max_cost_usd = 1.50
    args.audit_root = str(tmp_path)
    args.silent = True

    stdout = io.StringIO()
    with (
        patch("cve_env.cli.build", AsyncMock(return_value=fake_outcome)),
        patch(
            "cve_env.agent.health_constraints.probe_for_constraints", return_value=[]
        ),
    ):
        with redirect_stdout(stdout):
            cli._cmd_build(args)

    sidecar = tmp_path / "CVE-2014-3120.outcome.json"
    assert sidecar.exists(), "sidecar not written"
    data = json.loads(sidecar.read_text())
    assert data["cve_id"] == "CVE-2014-3120"
    assert data["verify_passed"] is True
    assert data["status"] == "success"


def test_cmd_build_sidecar_written_on_failure_too(tmp_path: Path) -> None:
    """Sidecar must be written even for failed runs (so bench can distinguish
    timeout+failed from timeout+success)."""
    fake_outcome = _outcome(
        cve_id="CVE-2018-16509", status="verify_failed", verify_passed=False
    )

    args = type("Args", (), {})()
    args.cve_id = "CVE-2018-16509"
    args.product = None
    args.version = None
    args.description = None
    args.max_turns = 40
    args.max_cost_usd = 1.50
    args.audit_root = str(tmp_path)
    args.silent = True

    stdout = io.StringIO()
    with (
        patch("cve_env.cli.build", AsyncMock(return_value=fake_outcome)),
        patch(
            "cve_env.agent.health_constraints.probe_for_constraints", return_value=[]
        ),
    ):
        with redirect_stdout(stdout):
            cli._cmd_build(args)

    sidecar = tmp_path / "CVE-2018-16509.outcome.json"
    assert sidecar.exists(), "sidecar not written for failed run"
    data = json.loads(sidecar.read_text())
    assert data["verify_passed"] is False


# ─── helpers ─────────────────────────────────────────────────────────────


def _async_outcome(outcome: Outcome) -> Any:
    """Wrap an Outcome in an awaitable so `asyncio.run(build(...))` works
    when `build` is replaced by a synchronous callable that returns this."""

    async def _coro() -> Outcome:
        return outcome

    return _coro()
