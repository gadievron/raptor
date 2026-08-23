"""Checker synthesis rule management for /audit Mode 2.

When a confirmed finding reveals a pattern, the LLM generalizes it into
a Semgrep or Coccinelle rule. This module manages the rules directory:

- Save rules with metadata (origin finding, CWE, description)
- Deduplicate by rule ID
- List rules for a project
- Wire rules into future /scan runs via the rules/ directory convention

Rules saved per-project in ``$OUTPUT_DIR/rules/``. Future ``/scan`` runs
pick them up via ``--config rules/`` (semgrep) or iterating ``.cocci``
files (coccinelle).
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from typing import Any, TYPE_CHECKING
from pathlib import Path

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

RULES_DIR = "rules"
RULES_MANIFEST = "rules-manifest.json"


def save_rule(
    *,
    out_dir: Path,
    rule_id: str,
    tool: str,
    content: str,
    description: str,
    origin_file: str | None = None,
    origin_function: str | None = None,
    origin_finding: str | None = None,
    cwe: str | None = None,
) -> Path:
    """Save a synthesized rule to the rules directory.

    Args:
        out_dir: Run output directory.
        rule_id: Unique rule identifier (e.g. "unchecked-return-as-index").
        tool: "semgrep" or "coccinelle".
        content: Rule file content (YAML for semgrep, .cocci for coccinelle).
        description: What the rule detects.
        origin_file: Source file where the pattern was first found.
        origin_function: Function where the pattern was first found.
        origin_finding: Finding ID that spawned this rule.
        cwe: CWE identifier.

    Returns:
        Path to the saved rule file.
    """
    # Reject rule_ids that could escape the rules directory.
    if "/" in rule_id or "\\" in rule_id or ".." in rule_id:
        msg = f"invalid rule_id {rule_id!r}: must not contain '/', '\\', or '..'"
        raise ValueError(msg)

    rules_dir = out_dir / RULES_DIR
    rules_dir.mkdir(parents=True, exist_ok=True)

    ext = ".yaml" if tool == "semgrep" else ".cocci"
    rule_path = (rules_dir / f"{rule_id}{ext}").resolve()
    if not str(rule_path).startswith(str(rules_dir.resolve())):
        msg = f"invalid rule_id {rule_id!r}: resolved path escapes rules directory"
        raise ValueError(msg)
    # Atomic like the manifest write below: rules are cross-run
    # artifacts consumed by future /scan runs — a torn write would
    # ship a half-rule to every later scan.
    from core.atomic_fs import write_text_atomically
    write_text_atomically(rule_path, content)

    manifest = _load_manifest(out_dir)
    manifest[rule_id] = {
        "tool": tool,
        "file": str(rule_path.relative_to(out_dir)),
        "description": description,
        "cwe": cwe,
        "origin_file": origin_file,
        "origin_function": origin_function,
        "origin_finding": origin_finding,
    }
    _save_manifest(out_dir, manifest)

    return rule_path


def list_rules(out_dir: Path) -> list[dict[str, Any]]:
    """List all synthesized rules for a run."""
    manifest = _load_manifest(out_dir)
    rules = []
    for rule_id, meta in manifest.items():
        entry = {"rule_id": rule_id}
        entry.update(meta)
        rule_path = out_dir / meta.get("file", "")
        entry["exists"] = rule_path.exists() if rule_path.name else False
        rules.append(entry)
    return rules


def get_rule(out_dir: Path, rule_id: str) -> dict[str, Any] | None:
    """Get a single rule's metadata and content."""
    manifest = _load_manifest(out_dir)
    meta = manifest.get(rule_id)
    if not meta:
        return None

    result = {"rule_id": rule_id}
    result.update(meta)

    rule_path = out_dir / meta.get("file", "")
    if rule_path.exists():
        result["content"] = rule_path.read_text()
    return result


def run_rule_sweep(
    *,
    out_dir: Path,
    rule_id: str,
    target_path: Path,
) -> dict[str, Any]:
    """Run a saved rule against the full target codebase.

    Returns a dict with match count and match details. Uses the
    existing semgrep/coccinelle runner packages.
    """
    meta = _load_manifest(out_dir).get(rule_id)
    if not meta:
        return {"error": f"rule {rule_id!r} not found in manifest"}

    rule_path = out_dir / meta.get("file", "")
    if not rule_path.name:
        return {"error": f"rule file path missing in manifest for {rule_id!r}"}
    if not rule_path.exists():
        return {"error": f"rule file {rule_path} missing"}

    tool = meta["tool"]

    if tool == "semgrep":
        return _run_semgrep_rule(rule_path, target_path)
    if tool == "coccinelle":
        return _run_coccinelle_rule(rule_path, target_path)
    return {"error": f"unknown tool {tool!r}"}


def _finding_to_match(finding: Any) -> dict[str, Any]:
    """Flatten one semgrep finding to ``{file, line, message}``.

    ``SemgrepResult.findings`` holds ``SemgrepFinding`` dataclasses
    (attributes, not dict keys); tolerate raw dicts too, defensively
    like the sweep engine's serializer.
    """
    if isinstance(finding, dict):
        return {
            "file": finding.get("file", "") or finding.get("path", ""),
            "line": (
                finding.get("line", 0)
                or finding.get("start", {}).get("line", 0)
            ),
            "message": (
                finding.get("message", "")
                or finding.get("extra", {}).get("message", "")
            ),
        }
    return {
        "file": getattr(finding, "file", ""),
        "line": getattr(finding, "line", 0),
        "message": getattr(finding, "message", ""),
    }


def _run_semgrep_rule(rule_path: Path, target_path: Path) -> dict[str, Any]:
    try:
        from packages.semgrep.runner import run_rule, is_available

        if not is_available():
            return {"error": "semgrep not installed"}

        result = run_rule(target_path, str(rule_path), timeout=300)
        return {
            "tool": "semgrep",
            "match_count": len(result.findings),
            "matches": [_finding_to_match(f) for f in result.findings],
            "errors": list(getattr(result, "errors", []) or []),
        }
    except Exception as exc:
        return {"error": str(exc)}


def _run_coccinelle_rule(rule_path: Path, target_path: Path) -> dict[str, Any]:
    try:
        from packages.coccinelle.runner import run_rule, is_available

        if not is_available():
            return {"error": "coccinelle (spatch) not installed"}

        result = run_rule(target_path, str(rule_path), timeout=300)
        # ``SpatchResult`` carries ``matches`` (SpatchMatch dataclasses),
        # not ``findings`` — the old attribute raised AttributeError on
        # every sweep of a saved coccinelle rule.
        raw_matches = getattr(result, "matches", []) or []
        matches = []
        for m in raw_matches:
            if hasattr(m, "to_dict"):
                matches.append(m.to_dict())
            elif isinstance(m, dict):
                matches.append(m)
            else:
                matches.append({"raw": str(m)})
        return {
            "tool": "coccinelle",
            "match_count": len(matches),
            "matches": matches,
            "errors": list(getattr(result, "errors", []) or []),
        }
    except Exception as exc:
        return {"error": str(exc)}


def _load_manifest(out_dir: Path) -> dict[str, Any]:
    manifest_path = out_dir / RULES_DIR / RULES_MANIFEST
    if not manifest_path.exists():
        return {}
    try:
        with Path(manifest_path).open(encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_manifest(out_dir: Path, manifest: dict[str, Any]) -> None:
    manifest_path = out_dir / RULES_DIR / RULES_MANIFEST
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(manifest_path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        os.replace(tmp, str(manifest_path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
