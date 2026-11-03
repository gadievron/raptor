"""Ordered Python/tool detector stages, independent of command verdict policy.

Definitions contain trusted callables supplied by Raptor. This module does not
import plugins from a target, spawn tools, cache conclusions or assign security
verdicts. Tool stages retain their existing sandbox and timeout enforcement.
Expected execution failures return a status; unexpected exceptions propagate to
the caller so its existing error and resource-cleanup policy remains effective.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, Literal, TypeVar

Status = Literal["complete", "partial", "skipped", "error"]
T = TypeVar("T")


@dataclass(frozen=True)
class StageResult:
    status: Status = "complete"
    reason: str = ""

    def __post_init__(self) -> None:
        if self.status not in ("complete", "partial", "skipped", "error"):
            raise ValueError(f"invalid detector stage status: {self.status!r}")


@dataclass(frozen=True)
class Stage(Generic[T]):
    name: str
    execute: Callable[[T], StageResult]


@dataclass(frozen=True)
class Detector(Generic[T]):
    identifier: str
    version: str
    stages: tuple[Stage[T], ...]

    def __post_init__(self) -> None:
        names = [stage.name for stage in self.stages]
        if not self.identifier or not self.version or not names or not all(names):
            raise ValueError("detectors require an ID, version and named stages")
        if len(set(names)) != len(names):
            raise ValueError("detector stage names must be unique")


@dataclass(frozen=True)
class StageRecord:
    name: str
    status: Status
    reason: str
    elapsed_seconds: float


@dataclass(frozen=True)
class DetectorResult(Generic[T]):
    identifier: str
    version: str
    status: Status
    value: T
    stages: tuple[StageRecord, ...]

    @property
    def reason(self) -> str:
        return "; ".join(record.reason for record in self.stages if record.reason)


def run_detector(detector: Detector[T], value: T) -> DetectorResult[T]:
    """Run each stage once; partial data survives, skipped/error stops the chain.

    ``complete`` means the pipeline completed, including when it found nothing.
    It never means that the target or a hypothesis was proved safe.
    """
    records: list[StageRecord] = []
    status: Status = "complete"
    for stage in detector.stages:
        started = time.monotonic()
        outcome = stage.execute(value)
        if not isinstance(outcome, StageResult):
            raise TypeError(f"detector stage {stage.name!r} did not return StageResult")
        records.append(StageRecord(
            stage.name, outcome.status, outcome.reason, time.monotonic() - started,
        ))
        if outcome.status in ("skipped", "error"):
            status = outcome.status
            break
        if outcome.status == "partial":
            status = "partial"
    return DetectorResult(detector.identifier, detector.version, status, value, tuple(records))
