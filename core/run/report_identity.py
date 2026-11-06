"""Lifecycle-owned reporting identities. UUIDs identify claims, not trust.

Call mutators only while holding the run metadata lock. A resume is another
segment of the same attempt; an explicitly requested retry is a new attempt.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import re
from uuid import uuid4


def valid_identity(value):
    return (isinstance(value, dict) and type(value.get("schema_version")) is int and value.get("schema_version") == 1
            and all(isinstance(value.get(k), str) and re.fullmatch(r"[a-f0-9]{32}", value[k])
                    for k in ("run_id", "pass_id", "attempt_id"))
            and type(value.get("segment")) is int and value["segment"] > 0)


def fresh_identity():
    return {"schema_version": 1, "run_id": uuid4().hex, "pass_id": uuid4().hex,
            "attempt_id": uuid4().hex, "segment": 1}


def checkpoint(directory: Path, identity):
    """Pin only a snapshot carrying this exact lifecycle identity."""
    if not valid_identity(identity):
        return None
    from core.reporting.writer import load_committed_report
    try:
        context, _, manifest = load_committed_report(directory)
        if (context.run_id, context.pass_id, context.attempt_id) == tuple(identity[k] for k in ("run_id", "pass_id", "attempt_id")):
            return {"snapshot_id": context.snapshot_id, "generation": manifest["generation"]}
    except (OSError, ValueError, TypeError):
        pass
    return None


def identity_for_start(command, prior, *, retry_metadata=None, retry_directory=None, target=None):
    if (isinstance(prior, dict) and prior.get("command") == command and prior.get("status") == "running"
            and valid_identity(prior.get("reporting_identity"))):
        existing = prior["reporting_identity"]
        if retry_directory is not None:
            relationship = existing.get("retry_of")
            if not isinstance(relationship, dict) or relationship.get("directory") != str(retry_directory):
                raise ValueError("An active attempt cannot change its retry relationship")
        return deepcopy(existing)
    if retry_directory is not None:
        if (not isinstance(retry_metadata, dict) or retry_metadata.get("command") != command
                or not isinstance(retry_metadata.get("status"), str)
                or retry_metadata["status"] not in {"failed", "cancelled", "interrupted"}):
            raise ValueError("An explicit retry requires a failed, cancelled, or interrupted run of the same command")
        previous_target = retry_metadata.get("target_path")
        if previous_target is not None and not isinstance(previous_target, str):
            raise ValueError("Retry source has a malformed target identity")
        if target and previous_target and Path(target).resolve() != Path(previous_target).resolve():
            raise ValueError("Retry target differs from the explicitly selected prior run")
        result = fresh_identity()
        old = retry_metadata.get("reporting_identity")
        relationship = {"directory": str(retry_directory), "identity_available": valid_identity(old)}
        if valid_identity(old):
            result["pass_id"] = old["pass_id"]
            relationship.update({k: old[k] for k in ("run_id", "pass_id", "attempt_id")})
            relationship["checkpoint"] = checkpoint(retry_directory, old)
        result["retry_of"] = relationship
        # A retry relationship alone does not declare supersession or coverage.
        return result
    return fresh_identity()


def identity_for_resume(metadata, directory, segment):
    previous = metadata.get("reporting_identity")
    result = deepcopy(previous) if valid_identity(previous) else fresh_identity()
    if not valid_identity(previous):
        result["adopted_on_resume"] = True
    result["segment"] = segment
    result["continuation"] = checkpoint(directory, previous)
    return result
