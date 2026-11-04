"""A rule plus Python analysis pipeline over a prepared source artifact.

The preparation context may build one view or borrow a corpus prepared once for
many packs. Its resources remain live through matching and analysis, including
failure paths. Command adapters own SARIF, deduplication and hypothesis policy.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager, ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .pipeline import Detector, DetectorResult, Stage, StageResult, run_detector


class PreparationUnavailable(Exception):
    """An expected refusal to prepare this detector's input."""


@dataclass(frozen=True)
class PreparedInput:
    """Explicit scan inputs and their optional caller-owned sandbox root."""

    target: Path
    analyze: Callable[[list[Any]], tuple[list[dict[str, Any]], int]]
    extra_targets: tuple[Path, ...] = ()
    target_root: Path | None = None


@dataclass
class SemgrepAnalysis:
    prepare: Callable[[], AbstractContextManager[PreparedInput]]
    rule_config: str
    timeout: int
    name: str | None = None
    env_factory: Callable[[], dict[str, str]] | None = None
    matches: list[dict[str, Any]] = field(default_factory=list)
    dropped: int = 0
    errors: list[str] = field(default_factory=list)
    invocation_error: str | None = None
    coverage_incomplete: bool = False
    _resources: ExitStack = field(default_factory=ExitStack, repr=False)
    _input: PreparedInput | None = field(default=None, repr=False)
    _raw: Any = field(default=None, repr=False)


def _prepare(state: SemgrepAnalysis) -> StageResult:
    try:
        state._input = state._resources.enter_context(state.prepare())
    except PreparationUnavailable as exc:
        return StageResult("skipped", str(exc))
    return StageResult()


def _match(state: SemgrepAnalysis) -> StageResult:
    assert state._input is not None
    kwargs: dict[str, Any] = {"timeout": state.timeout}
    try:
        from packages.semgrep.runner import run_rule

        if state.name is not None:
            kwargs["name"] = state.name
        if state.env_factory is not None:
            kwargs["env"] = state.env_factory()
        if state._input.extra_targets:
            kwargs["extra_targets"] = state._input.extra_targets
        if state._input.target_root is not None:
            kwargs["target_root"] = state._input.target_root
        state._raw = run_rule(state._input.target, state.rule_config, **kwargs)
    except Exception as exc:  # one failed invocation is a recorded engine failure
        state.invocation_error = str(exc)
        return StageResult("error", "semgrep invocation failed")
    state.errors = list(state._raw.errors)
    state.coverage_incomplete = bool(
        getattr(state._raw, "files_failed", ())
        or (getattr(state._raw, "skipped_summary", None) or {}).get("total", 0)
    )
    if state.errors:
        if not state._raw.findings:
            return StageResult("error", "semgrep returned errors without findings")
        return StageResult("partial", "semgrep returned findings with errors")
    return StageResult()


def _analyze(state: SemgrepAnalysis) -> StageResult:
    assert state._input is not None
    state.matches, state.dropped = state._input.analyze(state._raw.findings)
    return StageResult()


def define_semgrep_detector(identifier: str, version: str) -> Detector[SemgrepAnalysis]:
    """Declare a Raptor-owned detector using rule matching and Python analysis.

    Identity and version belong to the detector, rather than to Semgrep or the
    command invoking it. They are not a substitute for input/tool fingerprints
    if a caller adds persistent caching.
    """
    return Detector(
        identifier, version,
        (Stage("prepare", _prepare), Stage("match", _match), Stage("analyze", _analyze)),
    )


def run_semgrep_analysis(
    *,
    detector: Detector[SemgrepAnalysis],
    prepare: Callable[[], AbstractContextManager[PreparedInput]],
    rule_config: str,
    timeout: int,
    name: str | None = None,
    env_factory: Callable[[], dict[str, str]] | None = None,
) -> DetectorResult[SemgrepAnalysis]:
    """Execute a fresh run, closing owned or borrowed preparation contexts."""
    state = SemgrepAnalysis(prepare, rule_config, timeout, name, env_factory)
    with state._resources:
        return run_detector(detector, state)
