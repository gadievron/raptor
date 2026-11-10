"""Transient source-input stamps for publication, never checker evidence.

Only pipeline-captured inputs belong here. Durable history carries content
identities instead; neither journal JSON nor model output restores this scope.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from .knowledge_requests import KnowledgeOrigin
from .refutation_source import SourceIdentity, capture_source_identity

_LABEL = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_LIVE_INPUTS = 512


@dataclass(frozen=True)
class CapturedReviewInput:
    root_label: str
    root: Path
    file: str
    source_identity: SourceIdentity


def _valid_input(source: CapturedReviewInput) -> bool:
    return (isinstance(source, CapturedReviewInput)
            and isinstance(source.root_label, str) and _LABEL.fullmatch(source.root_label) is not None
            and isinstance(source.root, Path) and source.root.is_absolute()
            and isinstance(source.file, str) and bool(source.file) and len(source.file) <= 512
            and not source.file.startswith("/") and "\\" not in source.file and ":" not in source.file
            and not any(ord(char) < 32 or ord(char) == 127 for char in source.file)
            and not any(part in ("", ".", "..") for part in source.file.split("/"))
            and isinstance(source.source_identity, SourceIdentity)
            and isinstance(source.source_identity.sha256, str)
            and _SHA256.fullmatch(source.source_identity.sha256) is not None)


@dataclass(frozen=True)
class ReviewInputScope:
    """Original live stamps bound to one occurrence and exact history record.

    Historical contributors in the durable record may be nonreusable. They
    must not substitute for, or refresh, the fresh pass's physical bindings.
    """

    origin: KnowledgeOrigin
    record_digest: str
    inputs: tuple[CapturedReviewInput, ...]

    def roots(self) -> dict[str, Path] | None:
        if (not isinstance(self.inputs, tuple) or len(self.inputs) > MAX_LIVE_INPUTS
                or any(not _valid_input(source) for source in self.inputs)):
            return None
        roots: dict[str, Path] = {}
        for source in self.inputs:
            previous = roots.get(source.root_label)
            if previous is not None and previous != source.root:
                return None
            roots[source.root_label] = source.root
        return roots

    def matches(self, *, file: str, function: str, line_start: int, source_inputs: object) -> bool:
        from .review_context_inputs import context_inputs_record_digest

        return (isinstance(self.origin, KnowledgeOrigin)
                and type(line_start) is int and line_start > 0
                and type(self.origin.line_start) is int
                and (self.origin.file, self.origin.function, self.origin.line_start)
                == (file, function, line_start)
                and isinstance(self.record_digest, str)
                and _SHA256.fullmatch(self.record_digest) is not None
                and context_inputs_record_digest(source_inputs) == self.record_digest)

    def current(self, target_root: Path | str | None) -> bool:
        """Check original stamps and a final set barrier without rebinding."""
        if target_root is None or not isinstance(self.origin, KnowledgeOrigin):
            return False
        roots = self.roots()
        if roots is None or self.origin.source_identity is None:
            return False
        try:
            target = Path(target_root).resolve()
            if roots.get("target", target) != target:
                return False
            expected: dict[tuple[Path, str], SourceIdentity] = {
                (target, self.origin.file): self.origin.source_identity}
            for source in self.inputs:
                key = (source.root, source.file)
                previous = expected.get(key)
                if previous is not None and previous != source.source_identity:
                    return False
                expected[key] = source.source_identity
            for _ in range(2):
                for (root, file), identity in expected.items():
                    if capture_source_identity(root, file) != identity:
                        return False
        except (OSError, ValueError, TypeError, RuntimeError):
            return False
        return True
