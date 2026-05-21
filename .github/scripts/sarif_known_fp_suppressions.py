"""Apply suppressions for known false-positive flow classes.

CodeQL's heuristic taint-source list pins identifiers containing
``secret``, ``credential``, ``api_key``, etc. regardless of the
variable's *type*. A path variable named ``vendor_secret_key: Path``
is therefore a "source" even though it points at a file on disk —
the cryptographic material itself lives in the file's contents and
never enters Python's argv. When such a path string flows through a
``cmd`` list into a sandbox audit logger or per-run denial marker,
``py/clear-text-logging-sensitive-data`` and
``py/clear-text-storage-of-sensitive-information`` fire on every
operator-visible logger downstream.

The source-side defences (``paths-ignore: core/sandbox/tests/**``
plus variable renames) handle the bulk of these. This script is the
defence-in-depth for the residual flow class where the sink is in
production code that genuinely needs the audit visibility. It runs
between the multi-run SARIF merge step and the upload step in
``.github/workflows/codeql.yml``.

The suppression mechanism is the standard SARIF 2.1.0 ``suppressions``
property on a result object. GitHub Code Scanning honours external
suppressions on upload, marking the alert as dismissed with the
attached justification visible in the UI. Adding a new suppression
to the table requires a code-review-visible PR — there is no
silent UI dismissal here.

Adding a new entry: append to ``KNOWN_FP_RULES`` below. Each entry
matches results by ``(rule_id, sink_file_prefix)`` and stamps an
external suppression with the documented justification.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class KnownFP:
    """One (rule, sink) pair that has been triaged as a false positive."""

    rule_id: str
    sink_file_prefixes: tuple[str, ...]
    justification: str


# Each entry is reviewed and signed off by the security team. The
# justification is what appears in the GitHub Code Scanning UI.
#
# When CodeQL surfaces a new flow that's actually a false positive,
# the procedure is:
#   1. Confirm the source is heuristically-named (variable name only)
#      OR the sink is operator-visible by design;
#   2. Document the reason in justification text below;
#   3. Open a PR adding the entry — review checks the triage is sound.
KNOWN_FP_RULES: tuple[KnownFP, ...] = (
    KnownFP(
        rule_id="py/clear-text-logging-sensitive-data",
        sink_file_prefixes=(
            "core/sandbox/context.py",
            "core/sandbox/observe.py",
        ),
        justification=(
            "Sandbox audit-log renderer (cmd_display). Source is a "
            "heuristically-named path variable upstream "
            "(e.g. vendor_secret_key: Path); the rendered string "
            "interpolates a truncated cmd argv list for operator "
            "visibility. Production callers do not pass real "
            "credential material via argv — credentials live in "
            "files referenced by path. Triaged FP."
        ),
    ),
    KnownFP(
        rule_id="py/clear-text-storage-of-sensitive-information",
        sink_file_prefixes=(
            "core/sandbox/summary.py",
            "core/sandbox/observe.py",
        ),
        justification=(
            "Sandbox per-run denial / audit-degraded marker files "
            "(record_denial, record_audit_degraded). Per-run JSON "
            "state inside the sandbox's own output directory, "
            "operator-visible by design. Source taint is a "
            "heuristically-named path variable, not real secret "
            "material. Triaged FP."
        ),
    ),
)


def _result_sink_uri(result: dict) -> str | None:
    """Return the sink file URI, or None if the result has no location."""
    locations = result.get("locations") or []
    if not locations:
        return None
    phys = locations[0].get("physicalLocation") or {}
    artifact = phys.get("artifactLocation") or {}
    uri = artifact.get("uri")
    return uri if isinstance(uri, str) else None


def _matches_known_fp(result: dict) -> KnownFP | None:
    """Return the matching KnownFP entry, or None."""
    rule_id = result.get("ruleId")
    if not isinstance(rule_id, str):
        return None
    uri = _result_sink_uri(result)
    if uri is None:
        return None
    for entry in KNOWN_FP_RULES:
        if entry.rule_id != rule_id:
            continue
        if any(uri.startswith(p) for p in entry.sink_file_prefixes):
            return entry
    return None


def _already_suppressed(result: dict) -> bool:
    """True if the result already carries any external suppression."""
    for sup in result.get("suppressions") or []:
        if sup.get("kind") == "external":
            return True
    return False


def apply_suppressions(sarif: dict) -> tuple[int, int]:
    """Annotate matching results with external suppressions.

    Returns ``(matched, newly_suppressed)``. ``matched`` counts every
    result that hit a KnownFP entry; ``newly_suppressed`` excludes
    results that already carried an external suppression (idempotent
    re-runs don't double-stamp).
    """
    matched = 0
    newly_suppressed = 0
    for run in sarif.get("runs") or []:
        for result in run.get("results") or []:
            entry = _matches_known_fp(result)
            if entry is None:
                continue
            matched += 1
            if _already_suppressed(result):
                continue
            suppressions = result.setdefault("suppressions", [])
            suppressions.append(
                {
                    "kind": "external",
                    "status": "accepted",
                    "justification": entry.justification,
                }
            )
            newly_suppressed += 1
    return matched, newly_suppressed


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(
            f"usage: {argv[0]} <sarif_path> "
            "(modifies the file in place)",
            file=sys.stderr,
        )
        return 2
    sarif_path = Path(argv[1])
    if not sarif_path.is_file():
        print(f"ERROR: {sarif_path} is not a file", file=sys.stderr)
        return 1
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    matched, newly = apply_suppressions(sarif)
    sarif_path.write_text(
        json.dumps(sarif, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"Known-FP triage: matched={matched} newly_suppressed={newly} "
        f"(rules: {len(KNOWN_FP_RULES)})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
