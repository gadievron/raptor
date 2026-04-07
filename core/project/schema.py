"""Schema validation for project.json and .raptor-run.json."""

from typing import Any, Dict, List, Tuple

# Valid values
VALID_RUN_STATUSES = {"running", "completed", "failed", "cancelled"}


def validate_project(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate a project.json dict. Returns (valid, errors)."""
    errors = []

    if not isinstance(data, dict):
        return False, ["project data must be a dict"]

    # Required fields
    for field in ("version", "name", "target", "output_dir"):
        if field not in data:
            errors.append(f"missing required field: {field}")

    if "version" in data and not isinstance(data["version"], int):
        errors.append("version must be an integer")

    if "name" in data:
        name = data["name"]
        if not isinstance(name, str) or not name.strip():
            errors.append("name must be a non-empty string")

    if "target" in data:
        if not isinstance(data["target"], str) or not data["target"].strip():
            errors.append("target must be a non-empty string")

    if "output_dir" in data:
        if not isinstance(data["output_dir"], str) or not data["output_dir"].strip():
            errors.append("output_dir must be a non-empty string")

    # Optional fields — validate type if present
    if "description" in data and not isinstance(data["description"], str):
        errors.append("description must be a string")

    if "notes" in data and not isinstance(data["notes"], str):
        errors.append("notes must be a string")

    if "created" in data and not isinstance(data["created"], str):
        errors.append("created must be a string")

    return len(errors) == 0, errors


def validate_run_metadata(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate a .raptor-run.json dict. Returns (valid, errors)."""
    errors = []

    if not isinstance(data, dict):
        return False, ["run metadata must be a dict"]

    # Required fields
    for field in ("version", "command", "timestamp", "status"):
        if field not in data:
            errors.append(f"missing required field: {field}")

    if "version" in data and not isinstance(data["version"], int):
        errors.append("version must be an integer")

    if "command" in data:
        if not isinstance(data["command"], str) or not data["command"].strip():
            errors.append("command must be a non-empty string")

    if "timestamp" in data:
        if not isinstance(data["timestamp"], str) or not data["timestamp"].strip():
            errors.append("timestamp must be a non-empty string")

    if "status" in data:
        status = data["status"]
        if status not in VALID_RUN_STATUSES:
            errors.append(f"status must be one of {VALID_RUN_STATUSES}, got: {status}")

    # Extra is optional but must be a dict if present
    if "extra" in data and not isinstance(data["extra"], dict):
        errors.append("extra must be a dict")

    return len(errors) == 0, errors
