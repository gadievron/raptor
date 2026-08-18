"""Schema validation for project.json and .raptor-run.json."""

from typing import Any

# Valid values
VALID_RUN_STATUSES = {"running", "completed", "failed", "cancelled", "interrupted"}


def _validate_project(data: dict[str, Any]) -> tuple[bool, list[str]]:
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

    if "target" in data and (
            not isinstance(data["target"], str) or not data["target"].strip()):
        errors.append("target must be a non-empty string")

    if "output_dir" in data and (
            not isinstance(data["output_dir"], str) or not data["output_dir"].strip()):
        errors.append("output_dir must be a non-empty string")

    # Optional fields — validate type if present
    if "description" in data and not isinstance(data["description"], str):
        errors.append("description must be a string")

    if "notes" in data and not isinstance(data["notes"], str):
        errors.append("notes must be a string")

    if "created" in data and not isinstance(data["created"], str):
        errors.append("created must be a string")

    if "threat_model_path" in data and not isinstance(data["threat_model_path"], str):
        errors.append("threat_model_path must be a string")

    if "threat_model_updated" in data and not isinstance(data["threat_model_updated"], str):
        errors.append("threat_model_updated must be a string")

    if "binaries" in data:
        binaries = data["binaries"]
        if not isinstance(binaries, list):
            errors.append("binaries must be a list")
        else:
            for i, b in enumerate(binaries):
                if not isinstance(b, str) or not b.strip():
                    errors.append(
                        f"binaries[{i}] must be a non-empty string")

    if "trust" in data:
        trust = data["trust"]
        if not isinstance(trust, dict):
            errors.append("trust must be a dict")
        else:
            from core.project.project import VALID_TRUST_MARKERS
            for marker, ts in trust.items():
                if marker not in VALID_TRUST_MARKERS:
                    errors.append(
                        f"trust marker '{marker}' invalid; valid: "
                        + ", ".join(VALID_TRUST_MARKERS))
                if not isinstance(ts, str) or not ts.strip():
                    errors.append(
                        f"trust['{marker}'] must be a non-empty "
                        f"timestamp string")

    if "settings" in data:
        settings = data["settings"]
        if not isinstance(settings, dict):
            errors.append("settings must be a dict")
        else:
            from core.project.project import VALID_TARGET_KINDS
            for key, value in settings.items():
                if key == "target-kind":
                    if value not in VALID_TARGET_KINDS:
                        errors.append(
                            "settings['target-kind'] must be one of "
                            + ", ".join(VALID_TARGET_KINDS))
                elif key == "build-command":
                    if not isinstance(value, dict):
                        errors.append(
                            "settings['build-command'] must be a dict "
                            "of language → command")
                    else:
                        for lang, cmd in value.items():
                            if (not isinstance(lang, str)
                                    or not isinstance(cmd, str)
                                    or not cmd.strip()):
                                errors.append(
                                    f"settings['build-command']"
                                    f"['{lang}'] must be a non-empty "
                                    f"string")
                else:
                    errors.append(
                        f"settings key '{key}' invalid; valid: "
                        "build-command, target-kind")

    return len(errors) == 0, errors


def _validate_run_metadata(data: dict[str, Any]) -> tuple[bool, list[str]]:
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

    if "command" in data and (
            not isinstance(data["command"], str) or not data["command"].strip()):
        errors.append("command must be a non-empty string")

    if "timestamp" in data and (
            not isinstance(data["timestamp"], str) or not data["timestamp"].strip()):
        errors.append("timestamp must be a non-empty string")

    if "status" in data:
        status = data["status"]
        if status not in VALID_RUN_STATUSES:
            errors.append(f"status must be one of {VALID_RUN_STATUSES}, got: {status}")

    # Extra is optional but must be a dict if present
    if "extra" in data and not isinstance(data["extra"], dict):
        errors.append("extra must be a dict")

    return len(errors) == 0, errors
