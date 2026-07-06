"""Input-channel recovery from import tables and runtime observations.

An imported function is not proof that attacker bytes reach a sink. It is only
evidence that the binary has a possible ingestion surface. Runtime events can
upgrade that to observed, but still do not invent taint.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .evidence import EvidenceRecord, EvidenceTier, make_evidence

_IMPORT_CHANNELS: dict[str, tuple[str, ...]] = {
    "network": (
        "accept", "accept4", "recv", "recvfrom", "recvmsg",
        "SSL_read", "BIO_read", "WSARecv",
    ),
    "stream": (
        "read", "fread", "fgets", "getline", "gets", "scanf",
        "fscanf", "sscanf", "ReadFile",
    ),
    "file": ("open", "openat", "fopen", "CreateFileA", "CreateFileW"),
    "environment": ("getenv", "GetEnvironmentVariableA", "GetEnvironmentVariableW"),
    "ipc": ("readlink", "mq_receive", "msgrcv", "shm_open"),
}


@dataclass
class InputChannel:
    id: str
    kind: str
    name: str
    observed: bool
    confidence: str
    evidence_ids: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "name": self.name,
            "observed": self.observed,
            "confidence": self.confidence,
            "evidence_ids": list(self.evidence_ids),
            "details": dict(self.details),
        }


def recover_static_channels(
    binary_sha256: str,
    imports: Iterable[str],
) -> tuple[list[InputChannel], list[EvidenceRecord]]:
    channels: list[InputChannel] = []
    evidence: list[EvidenceRecord] = []
    import_set = {str(item) for item in imports}
    for kind, symbols in _IMPORT_CHANNELS.items():
        matched = sorted(import_set.intersection(symbols))
        if not matched:
            continue
        record = make_evidence(
            binary_sha256,
            kind="input_channel",
            source="import_table",
            summary=f"Import table contains {kind} ingestion symbols: {', '.join(matched)}",
            tier=EvidenceTier.HEADER_BACKED,
            confidence="candidate",
            reproducible=True,
            tool="binary-intake",
            data={"channel": kind, "symbols": matched},
        )
        evidence.append(record)
        channels.append(InputChannel(
            id=f"BIN-SRC-{kind.upper()}",
            kind=kind,
            name=f"{kind} input surface",
            observed=False,
            confidence="candidate",
            evidence_ids=[record.id],
            details={"symbols": matched},
        ))
    return channels, evidence


def merge_observed_channels(
    binary_sha256: str,
    channels: list[InputChannel],
    runtime_events: Iterable[dict[str, Any]],
) -> tuple[list[InputChannel], list[EvidenceRecord]]:
    by_kind = {channel.kind: channel for channel in channels}
    evidence: list[EvidenceRecord] = []
    observed: dict[str, list[dict[str, Any]]] = {}
    for event in runtime_events:
        kind = event_channel_kind(event)
        if kind is None:
            continue
        category = str(event.get("category") or "")
        fn = str(event.get("fn") or "")
        observed.setdefault(kind, []).append({"category": category, "fn": fn, "args": event.get("args") or {}})

    for kind, events in sorted(observed.items()):
        record = make_evidence(
            binary_sha256,
            kind="input_channel_observation",
            source="frida_events",
            summary=f"Frida observed {kind} ingestion activity",
            tier=EvidenceTier.OBSERVED_RUNTIME,
            confidence="confirmed",
            reproducible=False,
            tool="frida",
            data={"channel": kind, "events": events[:20], "event_count": len(events)},
        )
        evidence.append(record)
        channel = by_kind.get(kind)
        if channel is None:
            channel = InputChannel(
                id=f"BIN-SRC-{kind.upper()}",
                kind=kind,
                name=f"{kind} input surface",
                observed=True,
                confidence="confirmed",
                evidence_ids=[record.id],
                details={"observed_events": len(events)},
            )
            channels.append(channel)
            by_kind[kind] = channel
        else:
            channel.observed = True
            channel.confidence = "confirmed"
            channel.evidence_ids.append(record.id)
            channel.details["observed_events"] = len(events)
    return channels, evidence


def event_channel_kind(event: dict[str, Any]) -> str | None:
    category = str(event.get("category") or "")
    fn = str(event.get("fn") or "")
    if category == "network" and fn in {"accept", "recv", "recvfrom", "recvmsg"}:
        return "network"
    if category == "file" and fn in {"read", "fread", "fgets", "getline"}:
        return "stream"
    if category == "file" and fn in {"open", "openat", "fopen"}:
        return "file"
    if category == "process" and fn in {"getenv", "GetEnvironmentVariableA", "GetEnvironmentVariableW"}:
        return "environment"
    return None


__all__ = ["InputChannel", "event_channel_kind", "merge_observed_channels", "recover_static_channels"]
