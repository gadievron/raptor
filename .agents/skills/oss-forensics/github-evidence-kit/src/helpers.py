"""
Shared helper functions for evidence creation and parsing.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from .schema.common import GitHubActor, GitHubRepository


def generate_evidence_id(prefix: str, *parts: str) -> str:
    """Generate a deterministic evidence ID.

    Creates a unique ID by hashing the parts and prefixing with the type.
    Same inputs always produce the same ID (idempotent).

    Returns:
        ID in format: "{prefix}-{12-char-hash}"
    """
    content = ":".join(parts)
    hash_val = hashlib.sha256(content.encode()).hexdigest()[:12]
    return f"{prefix}-{hash_val}"


# Common datetime formats to try
_DATETIME_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S %Z",
    "%Y-%m-%d %H:%M:%S",
]


def _try_parse_datetime(dt_str: str) -> datetime | None:
    """Attempt to parse datetime string. Returns None if all formats fail."""
    # Handle Z suffix for ISO format
    if dt_str.endswith("Z"):
        try:
            return datetime.fromisoformat(dt_str[:-1] + "+00:00")
        except ValueError:
            pass

    # Try fromisoformat first (handles most ISO formats)
    try:
        return datetime.fromisoformat(dt_str)
    except ValueError:
        pass

    # Fall back to strptime for edge cases
    for fmt in _DATETIME_FORMATS:
        try:
            return datetime.strptime(dt_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    return None


def parse_datetime_lenient(dt_str: Any) -> datetime:
    """Parse datetime with fallback to now.

    Lenient parsing for GH Archive data where dates might be malformed.
    Returns current UTC time if parsing fails.
    """
    if dt_str is None:
        return datetime.now(timezone.utc)
    if isinstance(dt_str, datetime):
        return dt_str
    if isinstance(dt_str, str):
        result = _try_parse_datetime(dt_str)
        if result:
            return result
    return datetime.now(timezone.utc)


def parse_datetime_strict(dt_str: str | datetime | None) -> datetime | None:
    """Parse datetime, strict mode.

    For verified data sources where dates should be valid.
    Returns None for None input, raises ValueError on invalid format.
    """
    if dt_str is None:
        return None
    if isinstance(dt_str, datetime):
        return dt_str

    result = _try_parse_datetime(dt_str)
    if result:
        return result
    raise ValueError(f"Unable to parse datetime: {dt_str}")


def make_actor(login: str, actor_id: int | None = None) -> GitHubActor:
    """Create GitHubActor from components."""
    return GitHubActor(login=login, id=actor_id)


def make_repo(owner: str, name: str) -> GitHubRepository:
    """Create GitHubRepository from owner and name."""
    return GitHubRepository(owner=owner, name=name, full_name=f"{owner}/{name}")


def make_repo_from_full_name(full_name: str) -> GitHubRepository:
    """Create GitHubRepository from full name (owner/repo format).

    Raises:
        ValueError: If full_name is not in 'owner/repo' format or contains invalid values.
    """
    if not full_name or full_name in ("unknown/unknown", "/", "unknown"):
        raise ValueError(f"Invalid repository full_name: '{full_name}' - must be 'owner/repo' format")

    parts = full_name.split("/", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid repository full_name: '{full_name}' - must be 'owner/repo' format")

    owner, name = parts
    if not owner or not name or owner == "unknown" or name == "unknown":
        raise ValueError(f"Invalid repository full_name: '{full_name}' - owner and name must be valid")

    return GitHubRepository(owner=owner, name=name, full_name=full_name)
