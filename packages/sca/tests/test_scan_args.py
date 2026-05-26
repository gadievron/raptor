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
from typing import Set

import pytest

from packages.sca._scan_args import (
    add_scan_args,
    apply_no_llm_umbrella,
    options_from_args,
)
from packages.sca.pipeline import RunOptions


def _parser_with_scan_args() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="test")
    p.add_argument("target")
    add_scan_args(p)
    return p


def _registered_flag_names(p: argparse.ArgumentParser) -> Set[str]:
    """Return every ``--flag`` option string the parser knows."""
    out: Set[str] = set()
    for action in p._actions:                          # noqa: SLF001
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
        "--no-kev", "--no-epss", "--no-reachability",
        "--no-supply-chain",
        # Flags added in the UX-hardening batch that previously
        # only reached one of the two entry points:
        "--no-progress", "--pr-comment", "--pr-comment-label",
        # Flags that existed only on the libexec side pre-refactor:
        "--spdx", "--no-llm",
        "--html", "--include-commented", "--trust-repo",
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
