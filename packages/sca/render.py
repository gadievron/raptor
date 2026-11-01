"""``/sca render`` — re-emit report.md + findings.sarif from an existing
``findings.json`` without re-running the network pipeline.

Use cases:

- Operator hand-edited ``findings.json`` (added suppressions, dropped
  false positives) and wants a fresh report without re-querying OSV.
- A dashboard wants SARIF after an older analyse run that only kept
  ``findings.json``.
- CI wants to render against a pinned baseline file.

Inputs: ``findings.json``. Outputs (default): ``report.md`` and
``findings.sarif`` next to the input. Override paths with
``--out-md`` / ``--out-sarif`` or skip with ``--no-md`` / ``--no-sarif``.

Limitation: SBOM regeneration is **not** supported. The CycloneDX
emitter needs the resolved-dependency set (with parser confidence,
transitive depth, etc.) which isn't fully recoverable from the row
shape — re-run ``raptor-sca`` if a fresh SBOM is needed.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections import Counter
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any, TYPE_CHECKING

from .findings import severity_rank
from .models import REACHABILITY_LABELS, REACHABILITY_ORDER
from .rows import FindingRow
from .sarif import write_sarif

from core.json import load_json
from core.security.prompt_output_sanitise import sanitise_string

# findings.json artifacts are RAPTOR-written run output — the
# findings-class budget.
_MAX_FINDINGS_BYTES = 64 * 1024 * 1024

# Row fields interpolated into the markdown tables carry advisory- and
# manifest-sourced text (dep names, advisory ids/aliases, descriptions)
# — the same untrusted classes the scan-path report sanitises. Cap
# matches that renderer's detail budget.
_DETAIL_MAX_CHARS = 2000

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)


def main(argv: Sequence[str]) -> int:
    from .cli import _configure_logging

    args = _parse_args(argv)
    _configure_logging(args.verbose)

    findings_path = Path(args.findings).resolve()
    if not findings_path.exists():
        print(f"raptor-sca render: findings file not found: {findings_path}",
              file=sys.stderr)
        return 2
    try:
        rows = load_json(
            findings_path, strict=True, max_bytes=_MAX_FINDINGS_BYTES,
        )
        if rows is None:
            # Strict load_json soft-returns None for a missing file.
            raise FileNotFoundError(findings_path)
    except (OSError, ValueError) as e:
        print(f"raptor-sca render: cannot read {findings_path}: {e}", file=sys.stderr)
        return 2
    if not isinstance(rows, list):
        print(f"raptor-sca render: {findings_path} is not a finding list",
              file=sys.stderr)
        return 2

    base_dir = findings_path.parent
    md_path = Path(args.out_md).resolve() if args.out_md else (
        base_dir / "report.md"
    )
    sarif_path = Path(args.out_sarif).resolve() if args.out_sarif else (
        base_dir / "findings.sarif"
    )
    all_rows = rows
    try:
        rows = _apply_reachability_filters(rows, args)
    except ValueError as e:
        print(f"raptor-sca render: {e}", file=sys.stderr)
        return 2

    target = Path(args.target).resolve() if args.target else base_dir
    wrote: list[str] = []
    if not args.no_md:
        md = _render_markdown(rows, target=target)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        from ._atomic import atomic_write_text
        atomic_write_text(md_path, md)
        wrote.append(f"report.md → {md_path}")
    if not args.no_sarif:
        write_sarif(sarif_path, target=target, rows=rows)
        wrote.append(f"findings.sarif → {sarif_path}")

    if not wrote:
        print("raptor-sca render: nothing to do (both --no-md and --no-sarif "
              "supplied)", file=sys.stderr)
        return 2

    sys.stdout.write("raptor-sca render: wrote " + "; ".join(wrote) + "\n")
    sys.stdout.flush()

    # CI-gate threshold evaluation — only fires when --fail-on-* set.
    from .thresholds import (
        cfg_from_args, evaluate as eval_thresholds, print_result,
    )
    cfg = cfg_from_args(args)
    if cfg.is_active:
        passed, fails = eval_thresholds(all_rows, cfg)
        print_result(passed, fails, prog="raptor-sca render")
        return 0 if passed else 1

    return 0


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="raptor-sca render",
        description="Re-emit report.md + findings.sarif from an existing "
                    "findings.json without rerunning the network pipeline.",
    )
    p.add_argument("findings",
                   help="path to findings.json from a prior `raptor-sca` run")
    p.add_argument("--out-md", help="output path for the markdown report "
                                     "(default: alongside findings.json)")
    p.add_argument("--out-sarif", help="output path for findings.sarif")
    p.add_argument("--no-md", action="store_true",
                   help="skip the markdown report")
    p.add_argument("--no-sarif", action="store_true",
                   help="skip the SARIF emission")
    p.add_argument("--target",
                   help="target root used to relativise SARIF artefact URIs "
                        "(default: parent of findings.json)")
    p.add_argument("--only-reachable", action="store_true",
                   help="render only vulnerable dependency findings whose "
                        "reachability is likely_called or imported. "
                        "Non-vulnerability SCA rows are preserved.")
    p.add_argument("--hide-not-reachable", action="store_true",
                   help="hide vulnerable dependency findings whose "
                        "reachability is not_reachable or "
                        "not_function_reachable. Non-vulnerability SCA rows "
                        "are preserved.")
    p.add_argument("--reachability",
                   help="comma-separated reachability verdict allowlist for "
                        "vulnerable dependency findings, e.g. "
                        "likely_called,imported,not_evaluated. "
                        "Non-vulnerability SCA rows are preserved.")
    # CI gate flags — exit 1 if findings exceed thresholds.
    from .thresholds import add_threshold_args
    add_threshold_args(p)
    p.add_argument("-v", "--verbose", action="count", default=0)
    return p.parse_args(argv)


_REACHABLE_VERDICTS = {"likely_called", "imported"}
_NOT_REACHABLE_VERDICTS = {"not_reachable", "not_function_reachable"}


def _apply_reachability_filters(
    rows: list[dict[str, Any]], args: argparse.Namespace,
) -> list[dict[str, Any]]:
    """Filter vuln rows by reachability while preserving other rows."""
    requested = []
    if args.only_reachable:
        requested.append("--only-reachable")
    if args.hide_not_reachable:
        requested.append("--hide-not-reachable")
    if args.reachability:
        requested.append("--reachability")
    if len(requested) > 1:
        raise ValueError(
            "reachability filters are mutually exclusive: "
            + ", ".join(requested)
        )

    allowed = None
    denied = None
    if args.only_reachable:
        allowed = set(_REACHABLE_VERDICTS)
    elif args.hide_not_reachable:
        denied = set(_NOT_REACHABLE_VERDICTS)
    elif args.reachability:
        allowed = {
            item.strip()
            for item in str(args.reachability).split(",")
            if item.strip()
        }
        if not allowed:
            msg = "--reachability needs at least one verdict"
            raise ValueError(msg)

    if allowed is None and denied is None:
        return rows

    out: list[dict[str, Any]] = []
    for row in rows:
        fr = FindingRow.from_row(row)
        if fr is None or not fr.is_vulnerable_dependency:
            # Non-vulnerability rows (and stray non-dict elements in a
            # hand-edited findings.json) pass through untouched; the
            # renderers and the SARIF emitter each skip malformed
            # entries defensively.
            out.append(row)
            continue
        verdict = fr.reachability_verdict
        if allowed is not None and verdict not in allowed:
            continue
        if denied is not None and verdict in denied:
            continue
        out.append(row)
    return out


# ---------------------------------------------------------------------------
# Row-shaped markdown renderer
# ---------------------------------------------------------------------------

_SEV_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "none": "None",
}


def _cell(value: Any, *, max_chars: int = 200) -> str:
    """Sanitise an untrusted row value for a markdown table cell.

    ``sanitise_string`` defangs autofetch markup (``![](url)``),
    ANSI / OSC / BIDI / control bytes and line-leading markdown; the
    pipe escape stops the value from breaking out of its cell.
    """
    return sanitise_string(str(value), max_chars=max_chars).replace("|", "\\|")



def _render_markdown(rows: list[dict[str, Any]], *, target: Path) -> str:
    # Defensive — hand-edited findings.json may contain non-dict
    # elements; ``from_row`` parses them to None, filtered here.
    parsed = [fr for fr in map(FindingRow.from_row, rows) if fr is not None]
    vuln_rows = [fr for fr in parsed if fr.is_vulnerable_dependency]
    hygiene_rows = [fr for fr in parsed if fr.is_hygiene]
    supply_rows = [fr for fr in parsed if fr.is_supply_chain]
    license_rows = [fr for fr in parsed if fr.is_license]

    suppressed_count = sum(1 for r in vuln_rows if r.suppressed)
    severity_counts: Counter[str] = Counter()
    kev_count = 0
    for r in vuln_rows:
        if r.suppressed:
            continue
        # Lowercase — LLM verdicts and hand-edited rows may capitalise
        # ("Critical", "HIGH"); a case-sensitive counter would drop
        # them from the summary while still surfacing them below.
        severity_counts[r.severity.lower()] += 1
        if r.sca.get("in_kev"):
            kev_count += 1

    buf = StringIO()
    buf.write(f"# SCA Report — {target}\n\n")
    buf.write(f"_Generated by `raptor-sca render` at "
              f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}_\n\n")

    buf.write("## Summary\n\n")
    buf.write("| Severity | Count |\n|---|---|\n")
    for sev in ("critical", "high", "medium", "low", "info", "none"):
        n = severity_counts.get(sev, 0)
        if n:
            buf.write(f"| {_SEV_LABEL[sev]} | {n} |\n")
    if not any(severity_counts.values()):
        buf.write("| (none) | 0 |\n")
    buf.write("\n")
    buf.write(f"- Vulnerable findings: **{len(vuln_rows)}** "
              f"(active: **{len(vuln_rows) - suppressed_count}**, "
              f"suppressed: **{suppressed_count}**)\n")
    buf.write(f"- KEV-listed: **{kev_count}**\n")
    buf.write(f"- Supply-chain findings: **{len(supply_rows)}**\n")
    buf.write(f"- Hygiene findings: **{len(hygiene_rows)}**\n")
    if license_rows:
        buf.write(f"- License findings: **{len(license_rows)}**\n")
    buf.write("\n")
    reach_table = _render_reachability_breakdown(vuln_rows)
    if reach_table:
        buf.write(reach_table)

    if vuln_rows:
        buf.write("## Vulnerable dependencies\n\n")
        _render_vuln_table(buf, vuln_rows)
    if supply_rows:
        buf.write("## Supply-chain findings\n\n")
        _render_kind_table(buf, supply_rows)
    if hygiene_rows:
        buf.write("## Hygiene findings\n\n")
        _render_kind_table(buf, hygiene_rows)
    if license_rows:
        buf.write("## License findings\n\n")
        _render_kind_table(buf, license_rows)
    if not (vuln_rows or supply_rows or hygiene_rows or license_rows):
        buf.write("No findings.\n")
    return buf.getvalue()


def _render_reachability_breakdown(rows: list[FindingRow]) -> str:
    counts: Counter[str] = Counter()
    for row in rows:
        if row.suppressed:
            continue
        counts[row.reachability_verdict] += 1
    if not counts:
        return ""
    buf = StringIO()
    buf.write("### Reachability breakdown\n\n")
    buf.write("| Verdict | Count |\n|---|---:|\n")
    for verdict in REACHABILITY_ORDER:
        if counts.get(verdict):
            label = REACHABILITY_LABELS.get(verdict, verdict)
            buf.write(f"| {label} | {counts[verdict]} |\n")
    for verdict in sorted(set(counts) - set(REACHABILITY_ORDER)):
        # Unknown verdicts come straight from (possibly hand-edited)
        # row data — same table-cell treatment as the other columns.
        buf.write(f"| {_cell(verdict)} | {counts[verdict]} |\n")
    buf.write("\n")
    return buf.getvalue()


def _render_vuln_table(buf: StringIO, rows: list[FindingRow]) -> None:
    ordered = sorted(
        rows,
        key=lambda r: (
            -severity_rank(r.severity),
            not r.sca.get("in_kev"),
            -(r.sca.get("epss") or 0.0),
            r.sca.get("name") or "",
        ),
    )
    buf.write("| Severity | Dep | Advisory | Reachability | KEV | EPSS | Fix |\n")
    buf.write("|---|---|---|---|---|---|---|\n")
    for r in ordered:
        sca = r.sca
        adv = r.advisory
        sev = _cell(r.severity.title())
        if r.suppressed:
            sev += " (suppressed)"
        dep = _cell(
            f"{sca.get('ecosystem','')}:{sca.get('name','')}"
            f"@{sca.get('version','')}"
        )
        aliases = adv.get("aliases") or []
        adv_id = adv.get("id") or ""
        adv_label = _cell(adv_id + (
            f" ({aliases[0]})" if aliases else ""
        ))
        kev = "yes" if sca.get("in_kev") else ""
        epss_val = sca.get("epss")
        epss = f"{epss_val:.2f}" if isinstance(epss_val, (int, float)) else ""
        fix_value = sca.get("fixed_version") or ""
        query = sca.get("advisory_package")
        if fix_value and isinstance(query, dict) and (query.get("name"), query.get("version")) != (sca.get("name"), sca.get("version")):
            fix_value = f"source {query.get('name', '')} {fix_value}"
        fix = _cell(fix_value)
        reach = _cell(REACHABILITY_LABELS.get(
            r.reachability_verdict,
            r.reachability_verdict,
        ))
        buf.write(
            f"| {sev} | {dep} | {adv_label} | {reach} "
            f"| {kev} | {epss} | {fix} |\n"
        )
    buf.write("\n")


def _render_kind_table(buf: StringIO, rows: list[FindingRow]) -> None:
    # Collapse identical (severity, kind, ecosystem, name) rows that
    # share the same detail — a dep loose-pinned across both
    # ``requirements.txt`` and ``requirements-dev.txt`` produces two
    # findings with the same description; rendering both is just
    # noise for human readers (the per-manifest detail is in
    # findings.json for tooling). When multiple rows collapse, the
    # detail is suffixed with `(in N manifests)`.
    from collections import defaultdict

    groups: dict[tuple[Any, ...], list[FindingRow]] = defaultdict(list)
    for r in rows:
        key = (
            r.severity.lower(),
            r.vuln_type,
            r.sca.get("ecosystem") or "",
            r.sca.get("name") or "",
            r.description,
            r.suppressed,
        )
        groups[key].append(r)

    ordered_keys = sorted(
        groups.keys(),
        key=lambda k: (-severity_rank(k[0]), k[1], k[3]),
    )

    buf.write("| Severity | Kind | Dep | Detail |\n")
    buf.write("|---|---|---|---|\n")
    for key in ordered_keys:
        members = groups[key]
        first = members[0]
        sev = _cell(first.severity.title())
        if first.suppressed:
            sev += " (suppressed)"
        kind = _cell(first.vuln_type.rsplit(":", 1)[-1])
        sca = first.sca
        dep = _cell(f"{sca.get('ecosystem','')}:{sca.get('name','')}")
        detail = _cell(first.description,
                       max_chars=_DETAIL_MAX_CHARS)
        if len(detail) > 90:
            detail = detail[:87] + "..."
        if len(members) > 1:
            detail = f"{detail} (in {len(members)} manifests)"
        buf.write(f"| {sev} | {kind} | {dep} | {detail} |\n")
    buf.write("\n")


__all__ = ["main"]
