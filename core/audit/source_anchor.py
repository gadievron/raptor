"""Portable whole-file and span binding in the existing journal hash slot."""

import re

SOURCE_ANCHOR_PREFIX = "src:"
_SOURCE_ANCHOR = re.compile(r"src:([0-9a-f]{64}):([0-9a-f]{12})")
_CONTEXT_SOURCE_ANCHOR = re.compile(
    r"src:ctx([123]):([0-9a-f]{64}):([0-9a-f]{12}):([0-9a-f]{64}|unknown)"
)


def parse_context_source_anchor(value: object) -> tuple[str, str, str | None] | None:
    """Read context input identity; consumers must separately admit its inputs."""
    if not isinstance(value, str):
        return None
    match = _CONTEXT_SOURCE_ANCHOR.fullmatch(value)
    if match is None:
        return None
    return match[2], match[3], None if match[4] == "unknown" else match[4]


def context_source_anchor_version(value: object) -> int | None:
    """Read the exact context contract version, not a primary-only fallback."""
    if not isinstance(value, str):
        return None
    match = _CONTEXT_SOURCE_ANCHOR.fullmatch(value)
    return int(match[1]) if match else None


def parse_source_anchor(value: object) -> tuple[str, str] | None:
    """Read the exact tagged form; unknown and malformed forms do not match."""
    if not isinstance(value, str):
        return None
    match = _SOURCE_ANCHOR.fullmatch(value)
    if match:
        return match[1], match[2]
    context = parse_context_source_anchor(value)
    return (context[0], context[1]) if context else None


def make_source_anchor(sha256: str, span_hash: str) -> str:
    """Bind a producer's known digest, never a freshly inferred dependency."""
    value = f"{SOURCE_ANCHOR_PREFIX}{sha256}:{span_hash}"
    if _SOURCE_ANCHOR.fullmatch(value) is None:
        raise ValueError("invalid source content or span digest")
    return value


def make_context_source_anchor(
    sha256: str, span_hash: str, dependency_sha256: str | None,
    *, context_version: int = 1,
) -> str:
    """Bind known inputs; unknown dependencies explicitly prevent normal reuse."""
    if type(context_version) is not int or context_version not in (1, 2, 3):
        raise ValueError("invalid context anchor version")
    dependency = "unknown" if dependency_sha256 is None else dependency_sha256
    value = f"{SOURCE_ANCHOR_PREFIX}ctx{context_version}:{sha256}:{span_hash}:{dependency}"
    if parse_context_source_anchor(value) is None:
        raise ValueError("invalid source content, span or context digest")
    return value


def hash_source_spans(root, file, spans) -> tuple[list[str], str | None]:
    """Batch span hashes plus a stable full-file digest, when available.

    Span-only callers retain their old read semantics if whole-file identity
    is unavailable. Bound callers must refuse that missing digest. This is a
    mutable before/after check, not an immutable target snapshot.
    """
    from core.paths import confine
    from core.staleness import hash_spans
    from .refutation_source import capture_source_identity

    before = capture_source_identity(root, file)
    resolved = confine(root, file)
    hashes = hash_spans(resolved, spans) if resolved is not None else [""] * len(spans)
    after = capture_source_identity(root, file) if before is not None else None
    digest = before.sha256 if before is not None and after == before else None
    return hashes, digest
