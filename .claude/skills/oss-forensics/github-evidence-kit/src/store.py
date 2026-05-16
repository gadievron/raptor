"""
Evidence Store - Persistent storage for evidence collections.

Provides save/load/query functionality for evidence objects.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterator, Sequence

from .schema import AnyEvidence, AnyEvent, AnyObservation
from .schema.common import EvidenceSource


class EvidenceStore:
    """
    A simple store for managing collections of evidence.

    Example:
        store = EvidenceStore()
        store.add(commit_observation)
        store.save("evidence.json")

        store = EvidenceStore.load("evidence.json")
        commits = store.filter(observation_type="commit")
    """

    def __init__(self, evidence: Sequence[AnyEvidence] | None = None):
        self._evidence: list[AnyEvidence] = list(evidence) if evidence else []
        self._by_id: dict[str, AnyEvidence] = {e.evidence_id: e for e in self._evidence}

    def add(self, evidence: AnyEvidence) -> None:
        """Add evidence to the store (replaces existing with same ID)."""
        if evidence.evidence_id in self._by_id:
            self._evidence = [e for e in self._evidence if e.evidence_id != evidence.evidence_id]
        self._evidence.append(evidence)
        self._by_id[evidence.evidence_id] = evidence

    def add_all(self, evidence_list: Sequence[AnyEvidence]) -> None:
        """Add multiple evidence objects to the store."""
        for e in evidence_list:
            self.add(e)

    def get(self, evidence_id: str) -> AnyEvidence | None:
        """Get evidence by ID."""
        return self._by_id.get(evidence_id)

    def remove(self, evidence_id: str) -> bool:
        """Remove evidence by ID. Returns True if removed."""
        if evidence_id in self._by_id:
            del self._by_id[evidence_id]
            self._evidence = [e for e in self._evidence if e.evidence_id != evidence_id]
            return True
        return False

    def clear(self) -> None:
        """Remove all evidence from the store."""
        self._evidence.clear()
        self._by_id.clear()

    def __len__(self) -> int:
        return len(self._evidence)

    def __iter__(self) -> Iterator[AnyEvidence]:
        return iter(self._evidence)

    def __contains__(self, evidence_id: str) -> bool:
        return evidence_id in self._by_id

    @property
    def events(self) -> list[AnyEvent]:
        """Get all events."""
        return [e for e in self._evidence if hasattr(e, "event_type")]

    @property
    def observations(self) -> list[AnyObservation]:
        """Get all observations."""
        return [e for e in self._evidence if hasattr(e, "observation_type")]

    def filter(
        self,
        *,
        event_type: str | None = None,
        observation_type: str | None = None,
        source: EvidenceSource | str | None = None,
        repo: str | None = None,
        after: datetime | None = None,
        before: datetime | None = None,
        predicate: Callable[[AnyEvidence], bool] | None = None,
    ) -> list[AnyEvidence]:
        """Filter evidence by various criteria."""

        def matches(e: AnyEvidence) -> bool:
            if event_type and getattr(e, "event_type", None) != event_type:
                return False
            if observation_type and getattr(e, "observation_type", None) != observation_type:
                return False
            if source:
                src = source if isinstance(source, EvidenceSource) else EvidenceSource(source)
                if e.verification.source != src:
                    return False
            if repo:
                repo_obj = getattr(e, "repository", None)
                if not repo_obj or repo_obj.full_name != repo:
                    return False
            ts = self._get_timestamp(e)
            if ts:
                if after and ts < after:
                    return False
                if before and ts > before:
                    return False
            if predicate and not predicate(e):
                return False
            return True

        return [e for e in self._evidence if matches(e)]

    def _get_timestamp(self, evidence: AnyEvidence) -> datetime | None:
        """Get the primary timestamp for an evidence object."""
        if hasattr(evidence, "when"):
            return evidence.when
        if hasattr(evidence, "original_when") and evidence.original_when:
            return evidence.original_when
        if hasattr(evidence, "observed_when"):
            return evidence.observed_when
        return None

    def to_json(self, indent: int = 2) -> str:
        """Serialize store to JSON string."""
        data = [e.model_dump(mode="json") for e in self._evidence]
        return json.dumps(data, indent=indent, default=str)

    def save(self, path: str | Path) -> None:
        """Save store to JSON file (atomic write).

        Pre-fix `path.write_text(...)` used `open(path, 'w')`
        internally — truncate-then-write. A crash, OOM kill, or
        SIGTERM between truncate and write left a partially-written
        evidence file. Forensic investigations that resumed against
        a corrupted store either failed to load (JSONDecodeError) or
        loaded a truncated set, dropping evidence silently. Both
        modes destroy the audit trail the store is supposed to
        preserve.

        Atomic-write pattern: serialise to `<path>.tmp.<pid>` in the
        same directory then `os.replace` (atomic per POSIX). PID
        suffix disambiguates concurrent saves from different
        processes. On any write failure, clean up the staging file
        so we don't leak `.tmp.<pid>` siblings across crashes.
        """
        import os
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        body = self.to_json()
        tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
        try:
            tmp.write_text(body)
            os.replace(tmp, path)
        except Exception:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise

    # Cap on JSON-string input. Pre-fix `from_json` accepted any
    # length string. A hostile or corrupted evidence file (a 10 GB
    # JSON dump misnamed, an attacker-supplied payload routed
    # through a CI artifact ingest, a malformed recovery dump) would
    # OOM the process during `json.loads`'s parse. Real evidence
    # bundles top out at low MB (the largest pinned-evidence forensic
    # report observed in the wild is ~8 MB); 100 MB cap leaves 10x
    # headroom while bounding pathological input.
    _FROM_JSON_MAX_BYTES = 100 * 1024 * 1024

    @classmethod
    def from_json(cls, json_str: str) -> "EvidenceStore":
        """Create store from JSON string."""
        if len(json_str) > cls._FROM_JSON_MAX_BYTES:
            raise ValueError(
                f"EvidenceStore.from_json: input exceeds "
                f"{cls._FROM_JSON_MAX_BYTES} bytes — refusing to load "
                f"(pathological input bounds enforced)"
            )
        from . import load_evidence_from_json
        data = json.loads(json_str)
        return cls([load_evidence_from_json(item) for item in data])

    @classmethod
    def load(cls, path: str | Path) -> "EvidenceStore":
        """Load store from JSON file.

        Explicit `encoding="utf-8-sig"` so:
          * The read uses UTF-8 regardless of the host locale's default
            encoding (`locale.getpreferredencoding()` returns cp1252
            on a Windows host, latin-1 on some C-locale containers).
            Pre-fix the bare `read_text()` would mangle non-ASCII
            bytes in evidence content (commit messages with
            accented chars, unicode usernames, BOM-prefixed JSON
            from some tools) silently or raise UnicodeDecodeError.
          * `utf-8-sig` is a strict superset of `utf-8` — identical
            for BOM-less files, transparent for BOM-prefixed ones.
            Some Windows-edited evidence JSON files carry a leading
            BOM that the JSON parser would reject as
            "Expecting value: line 1 column 1 (char 0)" with no hint
            that the encoding is the actual problem.
        """
        return cls.from_json(Path(path).read_text(encoding="utf-8-sig"))

    def merge(self, other: "EvidenceStore") -> None:
        """Merge another store into this one."""
        self.add_all(list(other))

    def summary(self) -> dict:
        """Get a summary of the store contents."""
        event_counts: dict[str, int] = {}
        obs_counts: dict[str, int] = {}
        source_counts: dict[str, int] = {}

        for e in self._evidence:
            if hasattr(e, "event_type"):
                event_counts[e.event_type] = event_counts.get(e.event_type, 0) + 1
            if hasattr(e, "observation_type"):
                obs_counts[e.observation_type] = obs_counts.get(e.observation_type, 0) + 1
            src = e.verification.source.value
            source_counts[src] = source_counts.get(src, 0) + 1

        return {
            "total": len(self._evidence),
            "events": event_counts,
            "observations": obs_counts,
            "by_source": source_counts,
        }

    def verify_all(self) -> tuple[bool, list[str]]:
        """Verify all evidence against their original sources."""
        from .verifiers.consistency import ConsistencyVerifier
        verifier = ConsistencyVerifier()
        result = verifier.verify_all(self._evidence)
        return result.is_valid, result.errors
