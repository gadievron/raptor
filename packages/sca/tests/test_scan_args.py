"""Parity tests for the shared scan-args registrar.

Pre-fix, ``packages/sca/cli.py`` and ``libexec/raptor-sca-run``
each owned a copy of the scan-mode argparse and a copy of the
``RunOptions``-builder code. They drifted: flags added to one
silently failed on the other. This module pins the parity so a
new flag must reach both surfaces together (via
``_scan_args.add_scan_args`` + ``options_from_args``) or fail
CI."""

from __future__ import annotations

import argparse
from dataclasses import fields

import pytest

from packages.sca._scan_args import (
    add_scan_args,
    apply_no_llm_umbrella,
    options_from_args,
)
from packages.sca.pipeline import RunOptions


@pytest.fixture(autouse=True)
def _no_project_trust_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    """``options_from_args`` resolves the repo-trust umbrella against
    the active project's markers; pin "no active project" so these
    tests don't depend on the developer machine's ``~/.raptor``
    state. Marker-behaviour tests override this with their own
    patch."""
    from core.project import trust
    monkeypatch.setattr(trust, "active_project_trust",
                        lambda: ({}, None))


@pytest.fixture(autouse=True)
def _restore_trust_overrides():
    """``options_from_args`` propagates the resolved repo-trust value
    to the process-wide ``cc_trust`` / ``codeql_trust`` overrides
    (via ``resolve_repo_trust``); restore both module globals so
    trust state never leaks between tests."""
    from core.security import cc_trust, codeql_trust
    saved_cc = cc_trust.is_trust_overridden()
    saved_ql = codeql_trust._trust_override_set
    yield
    cc_trust.set_trust_override(saved_cc)
    codeql_trust.set_trust_override(saved_ql)


def _parser_with_scan_args() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="test")
    p.add_argument("target")
    add_scan_args(p)
    return p


def _registered_flag_names(p: argparse.ArgumentParser) -> set[str]:
    """Return every ``--flag`` option string the parser knows."""
    out: set[str] = set()
    for action in p._actions:
        for opt in action.option_strings:
            if opt.startswith("--"):
                out.add(opt)
    return out


def test_add_scan_args_registers_expected_flags() -> None:
    """Snapshot of the flag surface. Adding a flag is fine —
    update the expected set deliberately so a reviewer notices.
    Silently dropping one is the regression we're guarding."""
    p = _parser_with_scan_args()
    flags = _registered_flag_names(p)
    must_have = {
        "--out", "--offline", "--no-cache",
        "--use-offline-db", "--offline-db-path",
        "--no-resolve-transitive", "--fallback-registry-metadata",
        "--allow-sdist-builds",
        "--no-kev", "--no-epss", "--no-reachability",
        "--no-supply-chain",
        # Flags added in the UX-hardening batch that previously
        # only reached one of the two entry points:
        "--no-progress", "--pr-comment", "--pr-comment-label",
        # Flags that existed only on the libexec side pre-refactor:
        "--spdx", "--no-llm",
        "--html", "--include-commented", "--trust-repo",
        "--no-trust-repo",
        "--baseline",
        "--no-inline-installs", "--no-dockerfile-from",
        "--skip-review", "--skip-triage",
        "--review-maintainers", "--llm-inline-installs",
        "--impact-analysis", "--cache-root",
    }
    missing = must_have - flags
    assert not missing, (
        f"add_scan_args dropped required flags: {sorted(missing)}"
    )


def test_options_from_args_round_trips_default_flags() -> None:
    """Parsing an empty arg list (just a target) must build a
    valid RunOptions with all defaults."""
    p = _parser_with_scan_args()
    args = p.parse_args(["./target"])
    apply_no_llm_umbrella(args)
    opts = options_from_args(args)
    # Sanity: defaults match the dataclass defaults.
    assert opts.offline is False
    assert opts.enable_progress is True
    assert opts.enable_dockerfile_from is True


def test_options_from_args_propagates_new_flags() -> None:
    """The flags that motivated this refactor must reach
    ``RunOptions``."""
    p = _parser_with_scan_args()
    args = p.parse_args([
        "./target",
        "--no-progress",
        "--spdx",
        "--no-llm",
    ])
    apply_no_llm_umbrella(args)
    opts = options_from_args(args)
    assert opts.enable_progress is False
    assert opts.emit_spdx_sbom is True
    assert opts.enable_llm_review is False    # via --no-llm umbrella
    assert opts.enable_triage is False        # via --no-llm umbrella


def test_no_llm_umbrella_zeros_dependent_flags() -> None:
    """``--no-llm`` must override per-stage opt-ins (so
    ``--no-llm --review-maintainers`` doesn't accidentally
    pay an LLM bill)."""
    p = _parser_with_scan_args()
    args = p.parse_args([
        "./target",
        "--no-llm",
        "--review-maintainers",
        "--llm-inline-installs",
        "--impact-analysis",
    ])
    apply_no_llm_umbrella(args)
    opts = options_from_args(args)
    assert opts.enable_llm_review is False
    assert opts.enable_triage is False
    assert opts.review_maintainers is False
    assert opts.enable_llm_inline_installs is False
    assert opts.enable_impact_analysis is False


def test_run_options_fields_covered_by_options_from_args() -> None:
    """``options_from_args`` should populate every field of
    ``RunOptions`` that the scan flags expose. Catches the case
    where a new RunOptions field is added but the scan-arg
    builder forgets to populate it (silently leaves it as the
    dataclass default).

    Per-field exemption: a small set of RunOptions fields aren't
    flag-controlled (yet) — listed here so the test fails when
    they grow without an accompanying flag."""
    expected_unset = {
        # CLI default is ON (transitive expansion enabled unless
        # the operator passes ``--no-resolve-transitive``), but the
        # RunOptions dataclass default is OFF so unit tests don't
        # spin up the resolver by accident. The asymmetry is
        # documented in pipeline.py:RunOptions.
        "enable_transitive_expansion",
    }
    p = _parser_with_scan_args()
    args = p.parse_args(["./target"])
    apply_no_llm_umbrella(args)
    opts = options_from_args(args)
    defaults = RunOptions()
    drifted: list = []
    for f in fields(RunOptions):
        if f.name in expected_unset:
            continue
        # Any divergence from the dataclass default with default
        # args is suspicious — either the flag's default is wrong
        # or the dataclass default changed.
        if getattr(opts, f.name) != getattr(defaults, f.name):
            drifted.append(f.name)
    assert not drifted, (
        f"options_from_args with default args produced non-default "
        f"values for: {drifted} — check the flag defaults match the "
        f"RunOptions dataclass"
    )


@pytest.mark.parametrize("flag,attr,expected", [
    ("--offline", "offline", True),
    ("--no-cache", "no_cache", True),
    ("--no-kev", "enable_kev", False),
    ("--no-epss", "enable_epss", False),
    ("--no-reachability", "enable_reachability", False),
    ("--no-supply-chain", "enable_supply_chain", False),
    ("--no-progress", "enable_progress", False),
    ("--html", "emit_html_report", True),
    ("--spdx", "emit_spdx_sbom", True),
    ("--include-commented", "include_commented", True),
    ("--no-inline-installs", "enable_inline_installs", False),
    ("--no-dockerfile-from", "enable_dockerfile_from", False),
    ("--no-resolve-transitive", "enable_transitive_expansion", False),
    ("--allow-sdist-builds", "allow_sdist_builds", True),
    ("--fallback-registry-metadata", "fallback_registry_metadata", True),
    ("--use-offline-db", "use_offline_db", True),
    ("--skip-review", "enable_llm_review", False),
    ("--skip-triage", "enable_triage", False),
    ("--review-maintainers", "review_maintainers", True),
    ("--llm-inline-installs", "enable_llm_inline_installs", True),
    ("--impact-analysis", "enable_impact_analysis", True),
])
def test_each_flag_flips_the_expected_run_option(
    flag: str, attr: str, expected,
) -> None:
    """Each scan flag should toggle exactly one RunOptions field.
    This catches the cli.py-was-missing-emit_spdx_sbom class of
    bug: a flag is parsed but never plumbed."""
    p = _parser_with_scan_args()
    args = p.parse_args(["./target", flag])
    apply_no_llm_umbrella(args)
    opts = options_from_args(args)
    assert getattr(opts, attr) == expected, (
        f"flag {flag} did not propagate to RunOptions.{attr}"
    )


# ---------------------------------------------------------------------------
# Repo-trust umbrella resolution
# ---------------------------------------------------------------------------

def test_trust_repo_flag_reaches_run_options() -> None:
    p = _parser_with_scan_args()
    args = p.parse_args(["./target", "--trust-repo"])
    apply_no_llm_umbrella(args)
    opts = options_from_args(args)
    assert opts.trust_repo is True


def test_trust_repo_defaults_off() -> None:
    p = _parser_with_scan_args()
    args = p.parse_args(["./target"])
    apply_no_llm_umbrella(args)
    opts = options_from_args(args)
    assert opts.trust_repo is False


def test_no_trust_repo_wins_over_positive_flag() -> None:
    """Explicit negative beats explicit positive (precedence pinned
    by ``core.project.trust.resolve_trust_flag``)."""
    p = _parser_with_scan_args()
    args = p.parse_args(["./target", "--trust-repo", "--no-trust-repo"])
    apply_no_llm_umbrella(args)
    opts = options_from_args(args)
    assert opts.trust_repo is False


def test_config_marker_implies_trust_repo(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture,
) -> None:
    """Active project's ``config`` trust marker turns the umbrella on
    when neither per-run flag is given, with a banner line."""
    from core.project import trust
    monkeypatch.setattr(
        trust, "active_project_trust",
        lambda: ({"config": "2026-01-01T00:00:00Z"}, "proj"),
    )
    # Marker applies only when the run target matches the project
    # target — precedence is under test here, so pin a match.
    monkeypatch.setattr(trust, "run_target_matches_project",
                        lambda target: True)
    p = _parser_with_scan_args()
    args = p.parse_args(["./target"])
    apply_no_llm_umbrella(args)
    opts = options_from_args(args)
    assert opts.trust_repo is True
    assert "project trust: config" in capsys.readouterr().out


def test_config_marker_ignored_for_foreign_target(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture,
) -> None:
    """A marker asserts trust for ONE target: a run against a
    different tree must not inherit it, and the drop must be loud."""
    from core.project import trust
    monkeypatch.setattr(
        trust, "active_project_trust",
        lambda: ({"config": "2026-01-01T00:00:00Z"}, "proj"),
    )
    monkeypatch.setattr(trust, "run_target_matches_project",
                        lambda target: False)
    p = _parser_with_scan_args()
    args = p.parse_args(["./target"])
    apply_no_llm_umbrella(args)
    opts = options_from_args(args)
    assert opts.trust_repo is False
    assert "IGNORED" in capsys.readouterr().out


def test_no_trust_repo_overrides_config_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from core.project import trust
    monkeypatch.setattr(
        trust, "active_project_trust",
        lambda: ({"config": "2026-01-01T00:00:00Z"}, "proj"),
    )
    p = _parser_with_scan_args()
    args = p.parse_args(["./target", "--no-trust-repo"])
    apply_no_llm_umbrella(args)
    opts = options_from_args(args)
    assert opts.trust_repo is False
