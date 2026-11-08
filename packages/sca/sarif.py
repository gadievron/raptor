"""SARIF 2.1.0 emitter for ``raptor-sca`` findings.

GitHub code-scanning, GitLab SAST, Sonar, and most enterprise security
platforms consume SARIF. We emit a minimal-but-valid document that:

- Declares one ``run`` driven by ``raptor-sca``.
- Defines a ``rule`` per finding kind seen, populating each rule's
  ``shortDescription`` and ``helpUri`` from the underlying finding.
- Maps each finding to a SARIF ``result`` with a ``physicalLocation``
  pointing at the manifest file, severity-mapped ``level``,
  fingerprint, and rich ``properties`` for the SCA-specific fields
  (purl, CVE aliases, fixed version, KEV/EPSS, reachability verdict).

Suppressed findings are emitted with a SARIF ``suppressions`` block so
consumers know the operator has acknowledged them — GitHub, for
example, dismisses them in the code-scanning UI accordingly.

Schema reference:
https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING

from core.security.prompt_output_sanitise import sanitise_string

from .kinds import (
    HYGIENE_PREFIX,
    SUPPLY_CHAIN_PREFIX,
    VULNERABLE_DEPENDENCY,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)

# Cap on advisory text in SARIF result.message.text. Most advisory
# summaries fit comfortably under this; longer ones get an ellipsis.
# Larger than the default sanitise_string cap (500) because legitimate
# CVE descriptions can be a couple of paragraphs and SARIF consumers
# (GitHub Security tab) render the full text.
_SARIF_MESSAGE_MAX_CHARS = 2000

_SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/"
    "sarif-schema-2.1.0.json"
)
_SARIF_VERSION = "2.1.0"
_TOOL_NAME = "raptor-sca"
_TOOL_VERSION = "0.1"
_TOOL_URL = "https://github.com/gadievron/raptor"

# severity → SARIF level
_LEVEL_BY_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "none": "none",
}

# Static rule names so consumers see human-readable labels in the UI.
_RULE_NAMES: dict[str, str] = {
    VULNERABLE_DEPENDENCY: "VulnerableDependency",
    f"{HYGIENE_PREFIX}lockfile_missing": "LockfileMissing",
    f"{HYGIENE_PREFIX}lockfile_drift": "LockfileDrift",
    f"{HYGIENE_PREFIX}unpinned_dependency": "UnpinnedDependency",
    f"{HYGIENE_PREFIX}loose_pin": "LoosePin",
    f"{HYGIENE_PREFIX}cross_manifest_inconsistency": "CrossManifestInconsistency",
    f"{SUPPLY_CHAIN_PREFIX}typosquat_candidate": "TyposquatCandidate",
    f"{SUPPLY_CHAIN_PREFIX}slopsquat_suspect": "SlopsquatSuspect",
    f"{SUPPLY_CHAIN_PREFIX}install_hook_suspicious": "InstallHookSuspicious",
    f"{SUPPLY_CHAIN_PREFIX}python_pth_file": "PythonPthFile",
    f"{SUPPLY_CHAIN_PREFIX}binary_in_tests": "BinaryInTests",
    f"{SUPPLY_CHAIN_PREFIX}sentinel_match": "SentinelMatch",
}

# Description text for each rule. Falls back to the vuln_type when a rule
# isn't pre-registered (forward-compat with new kinds).
_RULE_DESCRIPTIONS: dict[str, str] = {
    VULNERABLE_DEPENDENCY:
        "A direct or transitive dependency matches a known CVE/GHSA "
        "advisory and should be upgraded.",
    f"{HYGIENE_PREFIX}lockfile_missing":
        "An ecosystem manifest has no sibling lockfile; CI installs are "
        "non-reproducible and may pull in upgrades that introduce new vulns.",
    f"{HYGIENE_PREFIX}lockfile_drift":
        "The manifest's exact pin disagrees with the lockfile's resolved "
        "version. The two views of the dep tree have diverged.",
    f"{HYGIENE_PREFIX}unpinned_dependency":
        "A dependency was declared without a version pin; the resolver may "
        "pick any version on each install.",
    f"{HYGIENE_PREFIX}loose_pin":
        "A dependency uses caret/tilde/range pinning. New patch versions "
        "land silently and may introduce vulns the operator can't audit.",
    f"{HYGIENE_PREFIX}cross_manifest_inconsistency":
        "The same dependency is declared at different versions across "
        "manifests in different workspaces.",
    f"{SUPPLY_CHAIN_PREFIX}typosquat_candidate":
        "The dependency name is one or two edits away from a popular "
        "package and may be a typosquat targeting that package.",
    f"{SUPPLY_CHAIN_PREFIX}slopsquat_suspect":
        "The dependency name matches a shape that LLMs commonly "
        "hallucinate (generic suffix on a popular prefix, lookalike-"
        "character substitution, or untrusted scope). Attackers "
        "pre-register these hallucinated names; combined with "
        "registry-side recency or low-bus-factor signals this is "
        "the canonical LLM-paste bait archetype.",
    f"{SUPPLY_CHAIN_PREFIX}install_hook_suspicious":
        "The package.json declares a lifecycle script that runs at install "
        "time and matches a pattern associated with malicious behaviour.",
    f"{SUPPLY_CHAIN_PREFIX}python_pth_file":
        "A `.pth` file in the project tree executes at Python startup.",
    f"{SUPPLY_CHAIN_PREFIX}binary_in_tests":
        "A large binary file under a test directory; could be a legitimate "
        "fixture or a hidden payload.",
    f"{SUPPLY_CHAIN_PREFIX}sentinel_match":
        "The dependency exactly matches a known-malicious package from a "
        "documented supply-chain incident.",
}


def write_sarif(path: Path, *, target: Path, rows: Sequence[dict[str, Any]],
                generated_at: datetime | None = None) -> int:
    """Atomically write SARIF 2.1.0 to ``path``; returns ``len(rows)``."""
    from core.json import dumps_artifact
    from core.atomic_fs import write_bytes_atomically
    doc = build_sarif(target=target, rows=(), generated_at=generated_at)
    run = doc["runs"][0]
    rule_index = {}
    count = 0
    def encode(value):
        return dumps_artifact(value, indent=None, ensure_ascii=True).encode("ascii")
    def chunks():
        nonlocal count
        yield b'{"$schema":' + encode(doc["$schema"]) + b',"version":' + encode(doc["version"]) + b',"runs":[{"results":['
        first = True
        for row in rows:
            count += 1
            if not isinstance(row, dict):
                continue
            rid = row.get("vuln_type")
            if isinstance(rid, str) and rid and rid not in rule_index:
                rule_index[rid] = len(rule_index)
            result, _ = _row_to_result(row, target, rule_index)
            if result is None:
                continue
            if not first:
                yield b','
            yield encode(result)
            first = False
        run["tool"]["driver"]["rules"] = [_rule_definition(rid) for rid in rule_index]
        yield b']'
        for key, value in run.items():
            if key != "results":
                yield b',' + encode(key) + b':' + encode(value)
        yield b'}]}'
    write_bytes_atomically(path, chunks())
    return count


def build_sarif(
    *,
    target: Path,
    rows: Sequence[dict[str, Any]],
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Return the SARIF document as a dict (in serialisation order)."""
    generated_at = generated_at or datetime.now(timezone.utc)

    # Collect every distinct rule id seen in the row set so we can
    # emit a matching rule definition. SARIF requires that every result
    # references a defined rule.
    seen_rule_ids: list[str] = []
    seen: set = set()
    for r in rows:
        if not isinstance(r, dict):
            # Hand-edited findings.json may contain stray non-dict
            # elements; skip them like the results loop below does.
            continue
        rid = r.get("vuln_type")
        if isinstance(rid, str) and rid and rid not in seen:
            seen.add(rid)
            seen_rule_ids.append(rid)

    rules = [_rule_definition(rid) for rid in seen_rule_ids]
    rule_index = {rid: i for i, rid in enumerate(seen_rule_ids)}

    results: list[dict[str, Any]] = []
    suppressions: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        result, suppression = _row_to_result(row, target, rule_index)
        if result is None:
            continue
        results.append(result)
        if suppression is not None:
            suppressions.append(suppression)

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": _TOOL_NAME,
                "version": _TOOL_VERSION,
                "informationUri": _TOOL_URL,
                "rules": rules,
            },
        },
        "results": results,
        "invocations": [{
            "executionSuccessful": True,
            "endTimeUtc": generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }],
    }
    if suppressions:
        # SARIF 2.1.0 attaches suppressions onto the result via
        # `result.suppressions`; the per-row `_row_to_result` helper
        # already does this, so the top-level run-level field is just a
        # summary marker. We don't emit that — it's implied by the
        # per-result data.
        pass

    return {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [run],
    }


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _rule_definition(rule_id: str) -> dict[str, Any]:
    name = _RULE_NAMES.get(rule_id, rule_id.replace(":", "_"))
    description = _RULE_DESCRIPTIONS.get(
        rule_id,
        f"RAPTOR /sca finding of type `{rule_id}`.",
    )
    return {
        "id": rule_id,
        "name": name,
        "shortDescription": {"text": _short(description)},
        "fullDescription": {"text": description},
        "helpUri": _TOOL_URL,
        "properties": {
            "tags": _tags_for(rule_id),
        },
    }


def _safe_start_line(val: Any) -> int:
    try:
        return max(int(val or 1), 1)
    except (TypeError, ValueError):
        return 1


def _row_to_result(
    row: dict[str, Any], target: Path,
    rule_index: dict[str, int],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    rule_id = row.get("vuln_type")
    if not isinstance(rule_id, str):
        return None, None
    severity = str(row.get("severity") or "info")
    file_path = row.get("file") or ""
    rel = _relative_uri(file_path, target)

    sca = row.get("sca") or {}
    if not isinstance(sca, dict):
        sca = {}
    advisory = sca.get("advisory") or {}
    aliases = advisory.get("aliases") if isinstance(advisory, dict) else []

    # Stable fingerprint: lets the consumer correlate this finding
    # across runs (so e.g. a dismissed alert in GitHub stays dismissed
    # next time we upload SARIF). Includes the dep + advisory id but
    # NOT the version, so the same CVE on a slightly-different version
    # is recognised as the same alert.
    fingerprint_input = "|".join((
        str(rule_id),
        str(sca.get("ecosystem") or ""),
        str(sca.get("name") or ""),
        str(advisory.get("id") if isinstance(advisory, dict) else ""),
    ))
    fingerprint = hashlib.sha256(
        fingerprint_input.encode("utf-8")
    ).hexdigest()[:16]

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": rule_index.get(rule_id, 0),
        # Lowercase normalisation — LLM verdicts and hand-edited
        # findings.json frequently capitalise ("Critical", "HIGH"); a
        # case-sensitive lookup would silently demote them to "note"
        # and defeat any CI gate that fails on SARIF level=error.
        "level": _LEVEL_BY_SEVERITY.get(
            (severity or "").lower(), "note",
        ),
        # SARIF consumers (GitHub Security tab, IDE plugins) render
        # ``message.text`` as markdown — autofetch markup, terminal-
        # injection bytes, and BIDI control chars in OSV-sourced
        # advisory text would survive unfiltered without this. The
        # description is concatenated upstream from advisory.summary
        # (untrusted third-party data); sanitise_string defangs all
        # three families before emission.
        "message": {"text": sanitise_string(
            row.get("description") or rule_id,
            max_chars=_SARIF_MESSAGE_MAX_CHARS,
        )},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": rel},
                "region": {"startLine": _safe_start_line(row.get("line"))},
            },
        }],
        "partialFingerprints": {
            "raptorScaFingerprint": fingerprint,
        },
        "properties": _result_properties(row, sca, advisory, aliases),
    }

    suppression: dict[str, Any] | None = None
    if row.get("suppressed"):
        # Inline `suppressions` on the result is the SARIF 2.1.0 way.
        # `kind=external` indicates the suppression came from an
        # operator decision external to the tool itself.
        suppression = {
            "kind": "external",
            "status": "accepted",
            "justification": row.get("suppression_reason") or "operator-suppressed",
        }
        result["suppressions"] = [suppression]

    return result, suppression


def _result_properties(
    row: dict[str, Any],
    sca: dict[str, Any],
    advisory: dict[str, Any] | Any,
    aliases: list[str] | None,
) -> dict[str, Any]:
    props: dict[str, Any] = {
        "tags": _tags_for(row.get("vuln_type") or ""),
        "ecosystem": sca.get("ecosystem"),
        "name": sca.get("name"),
        "version": sca.get("version"),
        "purl": sca.get("purl"),
    }
    if isinstance(advisory, dict):
        props["advisory_id"] = advisory.get("id")
        if aliases:
            props["aliases"] = list(aliases)
    for key in ("in_kev", "epss", "fixed_version",
                "cvss_score", "cvss_vector", "transitive_depth"):
        if key in sca:
            props[key] = sca[key]
    reach = sca.get("reachability")
    if isinstance(reach, dict):
        props["reachability_verdict"] = reach.get("verdict")
    # Drop None values — SARIF property bags are tidier without them
    # and consumers don't need to special-case nulls.
    return {k: v for k, v in props.items() if v is not None}


def _relative_uri(file_path: str, target: Path) -> str:
    """Make the artifact URI relative to ``target`` so consumers like
    GitHub can resolve it inside the repo."""
    if not file_path:
        return ""
    try:
        return str(Path(file_path).resolve().relative_to(target.resolve()))
    except (ValueError, TypeError):
        return file_path


def _tags_for(rule_id: str) -> list[str]:
    tags = ["security", "raptor"]
    if rule_id == VULNERABLE_DEPENDENCY:
        tags += ["vulnerability", "cve"]
    elif rule_id.startswith(HYGIENE_PREFIX):
        tags += ["hygiene", "supply-chain"]
    elif rule_id.startswith(SUPPLY_CHAIN_PREFIX):
        tags += ["supply-chain"]
    return tags


def _short(text: str) -> str:
    """SARIF ``shortDescription.text`` should fit one line — cap at 120."""
    one_line = " ".join(text.split())
    return one_line if len(one_line) <= 120 else one_line[:117] + "..."


__all__ = ["build_sarif", "write_sarif"]
