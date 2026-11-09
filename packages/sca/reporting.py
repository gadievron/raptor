"""One structured SCA document for every shared-engine output format."""
from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
import json
from pathlib import Path

from core.reporting.adapters import native_findings
from core.reporting.builders import build_document
from core.reporting.document import Block, Inline, MAX_FINDINGS, ReportContext, StageEnvelope


def build_sca_document(*, rows: Iterable[dict], target: Path, output_dir: Path, deps_analysed: int | None,
                       parse_failures=(), project_license: str | None = None,
                       cache_hits: int | None = 0, cache_misses: int | None = 0, cache_evictions: int | None = None, rerender: bool = False,
                       artifacts: list[dict] | None = None, selection: dict | None = None, limitations=()):
    diagnostics = [*limitations, *(f"Manifest parser failed: {f.path}: {f.reason}" for f in parse_failures)]
    captured: list[dict] = []
    counts: Counter[str] = Counter()
    health: list[dict] = []
    recorded = invalid = kev = 0
    for row in rows:
        if not isinstance(row, dict):
            invalid += 1
            continue
        recorded += 1
        kind = str(row.get("vuln_type", "unknown"))
        counts[kind] += 1
        if len(captured) < MAX_FINDINGS:
            captured.append(row)
        if kind.startswith("sca:scan_health:") and len(health) < 100:
            health.append(row)
        kev += bool(kind == "sca:vulnerable_dependency" and isinstance(row.get("sca"), dict)
                    and row["sca"].get("in_kev") is True and row.get("suppressed") is not True)
    if invalid:
        diagnostics.append(f"{invalid} non-object row(s) omitted from reporting; original input retained")
    if rerender:
        diagnostics.append("Regenerated from recorded findings; no dependency analysis or network queries ran. Original inventory completeness and cache statistics are unknown.")
        if selection:
            diagnostics.append(f"Selection: {selection['selected_rows']} of {selection['source_rows']} input rows; CI thresholds still evaluate the full input.")
    diagnostics.extend(str(r.get("description") or r.get("title") or "Scan health limitation") for r in health)
    if recorded > MAX_FINDINGS:
        diagnostics.append(f"Report details and overview truncated: showing {MAX_FINDINGS} of {recorded} recorded SCA rows; finding-class and KEV counts include all rows. Full evidence remains in findings.json")
    findings = native_findings(captured, run_id=output_dir.name, producer="sca", triage=True)
    for row, f in zip(captured, findings):
        f["status"] = "Advisory match" if row.get("vuln_type") == "sca:vulnerable_dependency" else "Recorded signal"
        if str(row.get("vuln_type", "")).startswith("sca:scan_health:"):
            f["status"] = "Scan limitation"
        f["verdict_origin"] = "sca/mechanical"
    state = "unknown" if rerender else "partial" if diagnostics else "completed"
    context = ReportContext("sca", output_dir.name, target=str(target), state=state,
                            findings=findings, diagnostics=diagnostics,
                            stages=[StageEnvelope("dependency analysis", state,
                                                  coverage=[{"unit": "dependency", "completed": deps_analysed,
                                                             "population": str(target), "scope": "parsed dependency inventory"}] if deps_analysed is not None else [])],
                            artifacts=artifacts if artifacts is not None else [{"path": str(output_dir / "findings.json")}],
                            extensions={"raptor.accounting": {"recorded_rows": recorded, "captured_rows": len(captured)},
                                        "raptor.scope": {"target": str(target), "population": "recorded finding rows" if rerender else "parsed dependency inventory",
                                                         **({"filters": {k: (selection or {}).get(k) for k in ("reachability", "only_reachable", "hide_not_reachable")}} if rerender else {})},
                                        **({"raptor.rerender": selection or {}} if rerender else {})})
    context.extensions["raptor.metrics"] = {"Dependencies analysed": deps_analysed,
                                            "Cache hits": cache_hits, "Cache misses": cache_misses,
                                            "Cache evictions": cache_evictions,
                                            "Project license": project_license or "not recorded"}
    blocks = [Block("paragraph", inline=[Inline("strong", "KEV"), Inline("text", f": {kev} unsuppressed known-exploited advisory matches.")]),
              Block("paragraph", text="Advisory matches and supply-chain signals do not by themselves establish exploitability. Reachability, suppression, and evidence retain their recorded meanings."),
              Block("table", title="Finding classes", columns=["Class", "Recorded rows"], rows=[[k, v] for k, v in sorted(counts.items())])]
    blocks.extend(_overview_blocks(captured))
    details = []
    for index, row in enumerate(captured, 1):
        raw_sca = row.get("sca")
        data = raw_sca if isinstance(raw_sca, dict) else {}
        reachability = data.get("reachability") or {}
        reachability = reachability.get("verdict") or reachability.get("status", "not recorded") if isinstance(reachability, dict) else str(reachability)
        fields = [["Package", data.get("name")], ["Ecosystem", data.get("ecosystem")], ["Version", data.get("version")],
                  ["Fixed version", data.get("fixed_version")], ["KEV", data.get("in_kev")], ["EPSS", data.get("epss")],
                  ["Reachability", reachability], ["CVSS", data.get("cvss_score")], ["Suppressed", row.get("suppressed")],
                  ["Suppression reason", row.get("suppression_reason")]]
        query = data.get("advisory_package")
        if isinstance(query, dict):
            fields.extend([["Advisory package", _package_label(query)],
                           ["Advisory match scope", data.get("advisory_match_scope")]])
            if _source_fix(data):
                fields[3][0] = "Source package fixed version"
        details.append(Block("section", title=f"F{index:05d}: {data.get('name') or row.get('title') or row.get('vuln_type')}",
                             children=[Block("table", columns=["Field", "Value"], rows=fields),
                                       Block("code", title="Recorded dependency evidence", text=json.dumps(data, ensure_ascii=True, sort_keys=True, indent=2), language="json")]))
    blocks.append(Block("section", title="Dependency and policy evidence", children=details))
    document = build_document(context, title=f"SCA Report — {target}", blocks=blocks)
    document.summary.update({"Dependencies analysed": deps_analysed, "KEV matches": kev, "Cache hits": cache_hits,
                             "Cache misses": cache_misses, "Cache evictions": cache_evictions,
                             "Project license": project_license or "not recorded"})
    return context, document


def _package_label(data):
    return f"{data.get('ecosystem') or ''}:{data.get('name') or ''}@{data.get('version') or '*'}"


def _source_fix(data):
    query = data.get("advisory_package")
    return isinstance(query, dict) and (query.get("name"), query.get("version")) != (data.get("name"), data.get("version"))


def _overview_blocks(rows):
    """Portable overview shared by live scan and row-only regeneration."""
    from collections import defaultdict
    from .findings import severity_rank
    from .models import REACHABILITY_LABELS
    from .rows import FindingRow
    parsed = [r for r in map(FindingRow.from_row, rows) if r is not None]
    vulns = [r for r in parsed if r.is_vulnerable_dependency]
    active = [r for r in vulns if not r.suppressed]
    severity = Counter(r.severity.lower() for r in active)
    suppressed = len(vulns) - len(active)
    def metric(label, value):
        return Block("paragraph", inline=[Inline("text", label + ": "), Inline("strong", str(value))])
    reach = Counter(r.reachability_verdict for r in active)
    blocks = [Block("section", title="Dependency summary", children=[
        Block("table", columns=["Severity", "Count"], rows=[[k.title(), v] for k, v in sorted(severity.items(), key=lambda kv: -severity_rank(kv[0]))]),
        metric("Vulnerable findings", len(vulns)), metric("active", len(active)), metric("suppressed", suppressed),
        metric("KEV-listed", sum(r.sca.get("in_kev") is True for r in active)),
        Block("table", title="Reachability breakdown", columns=["Verdict", "Count"], rows=[[REACHABILITY_LABELS.get(k, k), v] for k, v in sorted(reach.items())]),
    ])]
    if vulns:
        records = []
        def priority(row):
            epss = row.sca.get("epss")
            return (-severity_rank(row.severity), row.sca.get("in_kev") is not True,
                    -epss if isinstance(epss, (int, float)) else 0, str(row.sca.get("name") or ""))
        for r in sorted(vulns, key=priority):
            data, adv = r.sca, r.advisory
            aliases = adv.get("aliases")
            alias = str(aliases[0]) if isinstance(aliases, list) and aliases else ""
            records.append([r.severity.title() + (" (suppressed)" if r.suppressed else ""),
                            f"{data.get('ecosystem', '')}:{data.get('name', '')}@{data.get('version', '')}",
                            str(adv.get("id") or "") + (f" ({alias})" if alias else ""),
                            REACHABILITY_LABELS.get(r.reachability_verdict, r.reachability_verdict),
                            data.get("in_kev"), data.get("epss"),
                            (f"Source package {_package_label(data['advisory_package'])}: {data.get('fixed_version') or 'not recorded'}"
                             if _source_fix(data) else data.get("fixed_version"))])
        blocks.append(Block("table", title="Vulnerable dependencies", columns=["Severity", "Dep", "Advisory", "Reachability", "KEV", "EPSS", "Fix"], rows=records))
    for title, predicate in (("Supply-chain findings", lambda r: r.is_supply_chain), ("Hygiene findings", lambda r: r.is_hygiene), ("License findings", lambda r: r.is_license)):
        selected = [r for r in parsed if predicate(r)]
        if not selected:
            continue
        groups = defaultdict(list)
        for r in selected:
            groups[(r.severity.lower(), r.vuln_type, str(r.sca.get("ecosystem") or ""), str(r.sca.get("name") or ""), r.description, r.suppressed)].append(r)
        table = []
        for key, members in sorted(groups.items(), key=lambda pair: (-severity_rank(pair[0][0]), pair[0][1], pair[0][3])):
            sev, kind, ecosystem, name, detail, hidden = key
            table.append([sev.title() + (" (suppressed)" if hidden else ""), kind.rsplit(":", 1)[-1], f"{ecosystem}:{name}",
                          detail + (f" (in {len(members)} manifests)" if len(members) > 1 else "")])
        blocks.extend([metric(title, len(selected)), Block("table", title=title, columns=["Severity", "Kind", "Dep", "Detail"], rows=table)])
    if not parsed:
        blocks.append(Block("paragraph", text="No findings."))
    return blocks
