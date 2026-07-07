"""Fuzzer evidence ingestion for black-box binary graphs."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.hash import sha256_file
from core.json import load_json
from packages.fuzzing.crash_collector import CrashCollector

from .evidence import EvidenceRecord, EvidenceTier, make_evidence

logger = logging.getLogger(__name__)


@dataclass
class CrashEvidence:
    id: str
    input_path: str
    input_sha256: str
    signal: str | None
    stack_hash: str | None
    evidence_id: str
    replays: list[dict[str, Any]] = field(default_factory=list)
    replay_evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "input_path": self.input_path,
            "input_sha256": self.input_sha256,
            "signal": self.signal,
            "stack_hash": self.stack_hash,
            "evidence_id": self.evidence_id,
            "replays": [dict(item) for item in self.replays],
            "replay_evidence_ids": list(self.replay_evidence_ids),
        }


@dataclass
class FuzzEvidenceBundle:
    summary: dict[str, Any] = field(default_factory=dict)
    crashes: list[CrashEvidence] = field(default_factory=list)
    evidence: list[EvidenceRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": dict(self.summary),
            "crashes": [crash.to_dict() for crash in self.crashes],
            "evidence": [record.to_dict() for record in self.evidence],
        }


def _resolve_crashes_dir(fuzz_dir: Path, summary: dict[str, Any]) -> Path | None:
    for candidate in (
        summary.get("crashes_dir"),
        fuzz_dir / "afl" / "main" / "crashes",
        fuzz_dir / "libfuzzer" / "crashes",
    ):
        if candidate and Path(candidate).is_dir():
            return Path(candidate)
    return None


def _load_replay_summary(fuzz_dir: Path) -> dict[str, list[dict[str, Any]]]:
    for candidate in (
        fuzz_dir / "crash_analysis" / "replay" / "replay-summary.json",
        fuzz_dir / "replay" / "replay-summary.json",
        fuzz_dir / "replay-summary.json",
    ):
        payload = load_json(candidate)
        if isinstance(payload, dict):
            return {
                str(key): [dict(item) for item in value if isinstance(item, dict)]
                for key, value in payload.items()
                if isinstance(value, list)
            }
    return {}


def load_fuzz_evidence(
    fuzz_dir: Path,
    *,
    binary_sha256: str,
    target_path: str,
) -> FuzzEvidenceBundle:
    fuzz_dir = Path(fuzz_dir)
    summary = load_json(fuzz_dir / "fuzz-summary.json") or {}
    bundle = FuzzEvidenceBundle(summary=summary if isinstance(summary, dict) else {})
    target_matches = True
    if isinstance(summary, dict) and summary:
        summary_target = summary.get("target")
        if summary_target:
            resolved = Path(summary_target)
            if not resolved.is_absolute():
                resolved = fuzz_dir / resolved
            target_matches = str(resolved.resolve()) == str(Path(target_path).resolve())
        else:
            target_matches = True
        bundle.evidence.append(make_evidence(
            binary_sha256,
            kind="fuzz_campaign",
            source="fuzz-summary.json",
            summary=f"Loaded fuzz campaign telemetry from {fuzz_dir.name}",
            tier=EvidenceTier.OBSERVED_RUNTIME,
            confidence="confirmed" if target_matches else "candidate",
            reproducible=True,
            tool=str(summary.get("fuzzer") or "fuzzer"),
            location=str(fuzz_dir / "fuzz-summary.json"),
            data={
                "target_matches": target_matches,
                "fuzzer": summary.get("fuzzer"),
                "total_executions": summary.get("total_executions"),
                "coverage_percent": summary.get("coverage_percent"),
                "crashes": summary.get("crashes"),
            },
        ))
        if not target_matches:
            return bundle

    crashes_dir = _resolve_crashes_dir(fuzz_dir, bundle.summary)
    if crashes_dir is None:
        return bundle
    replay_summary = _load_replay_summary(fuzz_dir)
    try:
        crashes = CrashCollector(crashes_dir).collect_crashes()
    except (FileNotFoundError, OSError):
        return bundle
    for crash in crashes:
        try:
            digest = sha256_file(crash.input_file)
        except OSError:
            logger.warning("crash input disappeared: %s", crash.input_file)
            continue
        record = make_evidence(
            binary_sha256,
            kind="fuzz_crash",
            source="fuzzer_crash_file",
            summary=f"Fuzzer observed signal {crash.signal or 'unknown'} for crash input {crash.crash_id}",
            tier=EvidenceTier.OBSERVED_RUNTIME,
            confidence="confirmed",
            reproducible=True,
            tool=str(bundle.summary.get("fuzzer") or "fuzzer"),
            location=str(crash.input_file),
            data={
                "crash_id": crash.crash_id,
                "signal": crash.signal,
                "stack_hash": crash.stack_hash,
                "input_sha256": digest,
                "input_size": crash.size,
            },
        )
        bundle.evidence.append(record)
        replay_entries = replay_summary.get(str(crash.input_file), [])
        replay_evidence_ids: list[str] = []
        enriched_replays: list[dict[str, Any]] = []
        for replay in replay_entries:
            enriched = dict(replay)
            if replay.get("reproduced") is True:
                replay_record = make_evidence(
                    binary_sha256,
                    kind="crash_replay",
                    source="replay-summary.json",
                    summary=(
                        f"Crash input {crash.crash_id} replayed against "
                        f"{Path(str(replay.get('binary') or 'unknown')).name}"
                    ),
                    tier=EvidenceTier.REPLAYED_CRASH,
                    confidence="confirmed",
                    reproducible=True,
                    tool="sandbox_replay",
                    location=str(replay.get("stderr") or replay.get("stdout") or ""),
                    data={
                        "crash_id": crash.crash_id,
                        "input_sha256": digest,
                        "binary": replay.get("binary"),
                        "returncode": replay.get("returncode"),
                        "stdout": replay.get("stdout"),
                        "stderr": replay.get("stderr"),
                    },
                )
                bundle.evidence.append(replay_record)
                replay_evidence_ids.append(replay_record.id)
                enriched["evidence_id"] = replay_record.id
            enriched_replays.append(enriched)
        bundle.crashes.append(CrashEvidence(
            id=f"BIN-CRASH-{crash.crash_id}",
            input_path=str(crash.input_file),
            input_sha256=digest,
            signal=crash.signal,
            stack_hash=crash.stack_hash,
            evidence_id=record.id,
            replays=enriched_replays,
            replay_evidence_ids=replay_evidence_ids,
        ))
    return bundle


__all__ = ["CrashEvidence", "FuzzEvidenceBundle", "load_fuzz_evidence"]
