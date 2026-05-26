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
import json as _json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Sequence

from core.security.prompt_output_sanitise import sanitise_string

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
_RULE_NAMES: Dict[str, str] = {
    "sca:vulnerable_dependency": "VulnerableDependency",
    "sca:hygiene:lockfile_missing": "LockfileMissing",
    "sca:hygiene:lockfile_drift": "LockfileDrift",
    "sca:hygiene:unpinned_dependency": "UnpinnedDependency",
    "sca:hygiene:loose_pin": "LoosePin",
    "sca:hygiene:cross_manifest_inconsistency": "CrossManifestInconsistency",
    "sca:supply_chain:typosquat_candidate": "TyposquatCandidate",
    "sca:supply_chain:slopsquat_suspect": "SlopsquatSuspect",
    "sca:supply_chain:install_hook_suspicious": "InstallHookSuspicious",
    "sca:supply_chain:python_pth_file": "PythonPthFile",
    "sca:supply_chain:binary_in_tests": "BinaryInTests",
    "sca:supply_chain:sentinel_match": "SentinelMatch",
}

# Description text for each rule. Falls back to the vuln_type when a rule
# isn't pre-registered (forward-compat with new kinds).
_RULE_DESCRIPTIONS: Dict[str, str] = {
    "sca:vulnerable_dependency":
        "A direct or transitive dependency matches a known CVE/GHSA "
        "advisory and should be upgraded.",
    "sca:hygiene:lockfile_missing":
        "An ecosystem manifest has no sibling lockfile; CI installs are "
        "non-reproducible and may pull in upgrades that introduce new vulns.",
    "sca:hygiene:lockfile_drift":
        "The manifest's exact pin disagrees with the lockfile's resolved "
        "version. The two views of the dep tree have diverged.",
    "sca:hygiene:unpinned_dependency":
        "A dependency was declared without a version pin; the resolver may "
        "pick any version on each install.",
    "sca:hygiene:loose_pin":
        "A dependency uses caret/tilde/range pinning. New patch versions "
        "land silently and may introduce vulns the operator can't audit.",
    "sca:hygiene:cross_manifest_inconsistency":
        "The same dependency is declared at different versions across "
        "manifests in different workspaces.",
    "sca:supply_chain:typosquat_candidate":
        "The dependency name is one or two edits away from a popular "
        "package and may be a typosquat targeting that package.",
    "sca:supply_chain:slopsquat_suspect":
        "The dependency name matches a shape that LLMs commonly "
        "hallucinate (generic suffix on a popular prefix, lookalike-"
        "character substitution, or untrusted scope). Attackers "
        "pre-register these hallucinated names; combined with "
        "registry-side recency or low-bus-factor signals this is "
        "the canonical LLM-paste bait archetype.",
    "sca:supply_chain:install_hook_suspicious":
        "The package.json declares a lifecycle script that runs at install "
        "time and matches a pattern associated with malicious behaviour.",
    "sca:supply_chain:python_pth_file":
        "A `.pth` file in the project tree executes at Python startup.",
    "sca:supply_chain:binary_in_tests":
        "A large binary file under a test directory; could be a legitimate "
        "fixture or a hidden payload.",
    "sca:supply_chain:sentinel_match":
        "The dependency exactly matches a known-malicious package from a "
        "documented supply-chain incident.",
}


def write_sarif(path: Path, *, target: Path, rows: Sequence[Dict[str, Any]],
                generated_at: datetime | None = None) -> int:
    """Atomically write SARIF 2.1.0 to ``path``; returns ``len(rows)``."""
    doc = build_sarif(target=target, rows=rows, generated_at=generated_at)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        _json.dump(doc, fh, indent=2)
    tmp.replace(path)
    return len(rows)


def build_sarif(
    *,
    target: Path,
    rows: Sequence[Dict[str, Any]],
    generated_at: datetime | None = None,
) -> Dict[str, Any]:
    """Return the SARIF document as a dict (in serialisation order)."""
    generated_at = generated_at or datetime.now(timezone.utc)

    # Collect every distinct rule id seen in the row set so we can
    # emit a matching rule definition. SARIF requires that every result
    # references a defined rule.
    seen_rule_ids: List[str] = []
    seen: set = set()
    for r in rows:
        rid = r.get("vuln_type")
        if isinstance(rid, str) and rid and rid not in seen:
            seen.add(rid)
            seen_rule_ids.append(rid)

    rules = [_rule_definition(rid) for rid in seen_rule_ids]

    results: List[Dict[str, Any]] = []
    suppressions: List[Dict[str, Any]] = []
    for idx, row in enumerate(rows):
        result, suppression = _row_to_result(row, target, idx)
        if result is None:
            continue
        results.append(result)
        if suppression is not None:
            suppressions.append(suppression)

    run: Dict[str, Any] = {
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

def _rule_definition(rule_id: str) -> Dict[str, Any]:
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


def _row_to_result(
    row: Dict[str, Any], target: Path, idx: int,
) -> "tuple[Dict[str, Any] | None, Dict[str, Any] | None]":
    rule_id = row.get("vuln_type")
    if not isinstance(rule_id, str):
        return None, None
    severity = row.get("severity") or "info"
    file_path = row.get("file") or ""
    rel = _relative_uri(file_path, target)

    sca = row.get("sca") or {}
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

    result: Dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": idx,            # placeholder; consumers tolerate any int
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
                "region": {"startLine": max(int(row.get("line") or 1), 1)},
            },
        }],
        "partialFingerprints": {
            "raptorScaFingerprint": fingerprint,
        },
        "properties": _result_properties(row, sca, advisory, aliases),
    }

    suppression: Dict[str, Any] | None = None
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
    row: Dict[str, Any],
    sca: Dict[str, Any],
    advisory: Dict[str, Any] | Any,
    aliases: List[str] | None,
) -> Dict[str, Any]:
    props: Dict[str, Any] = {
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
    except ValueError:
        return file_path


def _tags_for(rule_id: str) -> List[str]:
    tags = ["security", "raptor"]
    if rule_id == "sca:vulnerable_dependency":
        tags += ["vulnerability", "cve"]
    elif rule_id.startswith("sca:hygiene:"):
        tags += ["hygiene", "supply-chain"]
    elif rule_id.startswith("sca:supply_chain:"):
        tags += ["supply-chain"]
    return tags


def _short(text: str) -> str:
    """SARIF ``shortDescription.text`` should fit one line — cap at 120."""
    one_line = " ".join(text.split())
    return one_line if len(one_line) <= 120 else one_line[:117] + "..."


__all__ = ["build_sarif", "write_sarif"]
