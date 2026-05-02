"""Coverage summary — Phase 2 reporting.

Computes and formats coverage summaries from checklist.json and
coverage-*.json records. Supports single-run and project-wide aggregation.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from core.json import load_json
from .record import load_records, write_record


def compute_summary(run_dir: Path) -> Optional[Dict[str, Any]]:
    """Compute coverage summary from a run directory.

    Returns a dict with inventory stats and per-tool coverage, or None
    if no checklist exists.
    """
    run_dir = Path(run_dir)
    checklist = load_json(run_dir / "checklist.json")
    if not checklist:
        return None

    # Inventory stats
    files = checklist.get("files", [])
    total_files = len(files)
    total_sloc = sum(f.get("sloc", 0) for f in files)
    total_items = sum(
        len(f.get("items", f.get("functions", [])))
        for f in files
    )
    inventory_paths = set()
    for f in files:
        path = f.get("path", "")
        if path:
            inventory_paths.add(path)

    # Build function lookup: {normalised_path: [func_names]}
    func_lookup = {}
    for f in files:
        path = f.get("path", "")
        items = f.get("items", f.get("functions", []))
        func_lookup[path] = [item.get("name", "") for item in items]

    # Load coverage records
    records = load_records(run_dir)

    tools = {}
    for record in records:
        tool = record.get("tool", "unknown")
        examined = set(record.get("files_examined", []))

        # Normalise: strip leading ./ or target prefix for matching
        examined_normalised = set()
        for p in examined:
            # Try matching against inventory paths
            matched = _match_to_inventory(p, inventory_paths)
            if matched:
                examined_normalised.add(matched)
            else:
                examined_normalised.add(p)

        tool_info = {
            "files_examined": len(examined_normalised & inventory_paths),
            "files_total": total_files,
        }

        # Tool-specific fields
        if record.get("rules_applied"):
            tool_info["rules_applied"] = record["rules_applied"]
        if record.get("packs"):
            tool_info["packs"] = record["packs"]
        if record.get("files_failed"):
            tool_info["files_failed"] = record["files_failed"]
        if record.get("version"):
            tool_info["version"] = record["version"]

        # Functions analysed (LLM)
        functions_analysed = record.get("functions_analysed", [])
        if functions_analysed:
            tool_info["functions_analysed"] = len(functions_analysed)
            tool_info["functions_total"] = total_items
            # Compute SLOC covered by analysed functions
            analysed_sloc = 0
            for fa in functions_analysed:
                file_path = fa.get("file", "")
                func_name = fa.get("function", "")
                matched_path = _match_to_inventory(file_path, inventory_paths) or file_path
                for f in files:
                    if f.get("path") == matched_path:
                        for item in f.get("items", f.get("functions", [])):
                            if item.get("name") == func_name:
                                start = item.get("line_start", item.get("line", 0))
                                end = item.get("line_end", start)
                                if end > start:
                                    analysed_sloc += end - start
                                break
                        break
            if analysed_sloc:
                tool_info["sloc_analysed"] = analysed_sloc

        tools[tool] = tool_info

    # Compute unreviewed
    llm_info = tools.get("llm", {})
    reviewed_funcs = llm_info.get("functions_analysed", 0)
    unreviewed_funcs = total_items - reviewed_funcs

    # Tool config validation — check Semgrep policy groups
    missing_groups = []
    semgrep_info = tools.get("semgrep", {})
    if semgrep_info:
        try:
            from core.config import RaptorConfig
            all_groups = set(RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK.keys())
            used_groups = set(semgrep_info.get("rules_applied", []))
            missing_groups = sorted(all_groups - used_groups)
        except Exception:
            pass

    # Per-file breakdown
    # Build sets of files examined by each tool
    tool_files = {}
    for record in records:
        tool = record.get("tool", "unknown")
        examined = set()
        for p in record.get("files_examined", []):
            matched = _match_to_inventory(p, inventory_paths) or p
            examined.add(matched)
        tool_files[tool] = examined

    # Build set of analysed functions
    analysed_funcs_by_file = set()
    for record in records:
        for fa in record.get("functions_analysed", []):
            path = _match_to_inventory(fa.get("file", ""), inventory_paths) or fa.get("file", "")
            analysed_funcs_by_file.add((path, fa.get("function", "")))

    # Count findings and vulns per file from findings.json
    findings_by_file = {}
    vulns_by_file = {}
    findings_data = load_json(run_dir / "findings.json")
    if findings_data:
        if isinstance(findings_data, list):
            findings_list = findings_data
        elif isinstance(findings_data, dict):
            findings_list = findings_data.get("findings", findings_data.get("results", []))
        else:
            findings_list = []
        # Group findings per file for vuln counting
        from collections import defaultdict
        per_file_findings = defaultdict(list)
        for finding in findings_list:
            fpath = finding.get("file", "")
            matched = _match_to_inventory(fpath, inventory_paths) or fpath
            findings_by_file[matched] = findings_by_file.get(matched, 0) + 1
            per_file_findings[matched].append(finding)
        from core.project.findings_utils import count_vulns
        for fpath, flist in per_file_findings.items():
            vulns_by_file[fpath] = count_vulns(flist)

    per_file = []
    for f in files:
        path = f.get("path", "")
        items = f.get("items", f.get("functions", []))
        total = len(items)
        if total == 0:
            continue
        reviewed_names = [
            item.get("name", "") for item in items
            if (path, item.get("name", "")) in analysed_funcs_by_file
        ]
        unreviewed_names = [
            item.get("name", "") for item in items
            if (path, item.get("name", "")) not in analysed_funcs_by_file
        ]
        reviewed = len(reviewed_names)
        pf_entry = {
            "path": path,
            "reviewed": reviewed,
            "total": total,
            "pct": reviewed / total * 100,
            "sloc": f.get("sloc", 0),
            "findings": findings_by_file.get(path, 0),
            "vulns": vulns_by_file.get(path, 0),
            "unreviewed_functions": unreviewed_names if unreviewed_names else [],
        }
        # Per-tool scan flags for detailed view
        for tool_name in tool_files:
            pf_entry[f"scanned_{tool_name}"] = path in tool_files[tool_name]
        per_file.append(pf_entry)
    per_file.sort(key=lambda x: (x["pct"], x["path"]))

    return {
        "inventory": {
            "files": total_files,
            "sloc": total_sloc,
            "items": total_items,
        },
        "tools": tools,
        "unreviewed_functions": unreviewed_funcs,
        "unreviewed_sloc": total_sloc - llm_info.get("sloc_analysed", 0),
        "missing_groups": missing_groups,
        "per_file": per_file,
    }


def _pl(n: int, word: str) -> str:
    """Pluralise: 1 item, 2 items."""
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def llm_item_coverage_percent(summary: Dict[str, Any]) -> float:
    """Return percentage of inventory items reviewed by LLM coverage records."""
    if not summary:
        return 0.0
    total = summary.get("inventory", {}).get("items", 0)
    if not total:
        return 100.0
    reviewed = total - summary.get("unreviewed_functions", 0)
    return max(0.0, min(100.0, reviewed / total * 100))


def coverage_threshold_met(summary: Dict[str, Any], fail_under: float) -> bool:
    """Return whether LLM item coverage satisfies ``fail_under`` percent."""
    return llm_item_coverage_percent(summary) >= fail_under


def format_threshold_result(summary: Dict[str, Any], fail_under: float) -> str:
    """Format a copy-paste friendly coverage threshold result."""
    pct = llm_item_coverage_percent(summary)
    status = "PASS" if coverage_threshold_met(summary, fail_under) else "FAIL"
    return (
        f"Coverage threshold: {pct:.1f}% LLM item coverage; "
        f"required {fail_under:.1f}% — {status}"
    )


def format_summary(summary: Dict[str, Any]) -> str:
    """Format coverage summary — Option D (actionable overview)."""
    if not summary:
        return "No coverage data available."

    inv = summary["inventory"]
    lines = [
        "Coverage:",
        f"  Inventory: {_pl(inv['files'], 'file')}, {inv['sloc']:,} SLOC, {_pl(inv['items'], 'item')}",
    ]

    for tool, info in summary["tools"].items():
        files_pct = (info["files_examined"] / info["files_total"] * 100
                     if info["files_total"] else 0)

        if tool == "semgrep":
            rules = info.get("rules_applied", [])
            rules_str = f", {_pl(len(rules), 'group')}" if rules else ""
            lines.append(
                f"  Semgrep: {info['files_examined']}/{info['files_total']} files{rules_str}"
            )
        elif tool == "codeql":
            packs = info.get("packs", [])
            packs_str = f" ({', '.join(packs)})" if packs else ""
            rules_count = len(info.get("rules_applied", []))
            lines.append(
                f"  CodeQL: {info['files_examined']}/{info['files_total']} files, "
                f"{_pl(rules_count, 'rule')}{packs_str}"
            )
        elif tool == "llm":
            funcs = info.get("functions_analysed", 0)
            funcs_total = info.get("functions_total", 0)
            lines.append(
                f"  LLM: {info['files_examined']}/{info['files_total']} files, "
                f"{funcs}/{funcs_total} {'function' if funcs_total == 1 else 'functions'}"
            )
        else:
            lines.append(
                f"  {tool}: {info['files_examined']}/{info['files_total']} files ({files_pct:.0f}%)"
            )

    # Action needed
    actions = []
    missing = summary.get("missing_groups", [])
    if missing:
        actions.append(f"{_pl(len(missing), 'Semgrep policy group')} not used")
    unrev = summary["unreviewed_functions"]
    if unrev > 0:
        actions.append(f"{_pl(unrev, 'item')} not reviewed by LLM")
    # Count files with findings but no LLM review
    per_file = summary.get("per_file", [])
    unreviewed_with_findings = [
        pf for pf in per_file
        if pf.get("findings", 0) > 0 and pf["reviewed"] == 0
    ]
    if unreviewed_with_findings:
        total_vulns = sum(pf.get("vulns", pf["findings"]) for pf in unreviewed_with_findings)
        actions.append(
            f"{_pl(total_vulns, 'finding')} in {_pl(len(unreviewed_with_findings), 'file')} not yet reviewed"
        )

    if actions:
        lines.append("")
        lines.append("  Action needed:")
        for a in actions:
            lines.append(f"    {a}")

    return "\n".join(lines)


def format_detailed(summary: Dict[str, Any]) -> str:
    """Format detailed per-file coverage table."""
    if not summary:
        return "No coverage data available."

    inv = summary["inventory"]
    lines = [
        "Coverage (detailed):",
        f"  Inventory: {_pl(inv['files'], 'file')}, {inv['sloc']:,} SLOC, {_pl(inv['items'], 'item')}",
    ]

    # Tool summary (same as format_summary but compact)
    tools = summary.get("tools", {})
    tool_abbrevs = []
    if "semgrep" in tools:
        tool_abbrevs.append(("S", "Semgrep"))
    if "codeql" in tools:
        tool_abbrevs.append(("C", "CodeQL"))
    if "llm" in tools:
        tool_abbrevs.append(("L", "LLM"))

    per_file = summary.get("per_file", [])
    if not per_file:
        lines.append("\n  No per-file data available.")
        return "\n".join(lines)

    # Table header
    lines.append("")
    name_col = max(max(len(pf["path"]) for pf in per_file) + 2, 20)
    fmt = f"  {{:<{name_col}s}} {{:>5s}}  {{:7s}}  {{:>10s}}  {{:>8s}}"
    lines.append(fmt.format("File", "SLOC", "Scanned", "Items", "Findings"))
    lines.append(fmt.format("-" * name_col, "-" * 5, "-" * 7, "-" * 10, "-" * 8))

    # Sort: unreviewed with findings first, then unreviewed without, then reviewed
    def _sort_key(pf):
        has_findings = pf.get("findings", 0) > 0
        is_reviewed = pf["reviewed"] > 0
        # Priority: unreviewed+findings=0, unreviewed+no findings=1, reviewed=2
        if not is_reviewed and has_findings:
            return (0, -pf.get("findings", 0), pf["path"])
        elif not is_reviewed:
            return (1, 0, pf["path"])
        else:
            return (2, 0, pf["path"])

    for pf in sorted(per_file, key=_sort_key):
        # Scanned column: which tools scanned this file
        scanned_flags = []
        for abbrev, tool_name in tool_abbrevs:
            tool_key = tool_name.lower()
            tool_info = tools.get(tool_key, {})
            # Check if this file was in the tool's examined list
            if pf.get(f"scanned_{tool_key}", False):
                scanned_flags.append(abbrev)
            else:
                scanned_flags.append(" ")
        scanned_str = " ".join(scanned_flags) if scanned_flags else "-"

        # Findings (grouped — one logical finding may span multiple lines)
        vulns = pf.get("vulns", pf.get("findings", 0))
        findings_str = str(vulns) if vulns else "-"

        # Reviewed
        if pf["total"] == 0:
            reviewed_str = f"{'—':>10s}"
        elif pf["reviewed"] == pf["total"]:
            reviewed_str = f"{pf['reviewed']}/{pf['total']} \u2713".rjust(10)
        elif pf["reviewed"] > 0:
            reviewed_str = f"{pf['reviewed']}/{pf['total']}  ".rjust(10)
        else:
            reviewed_str = f"{'—':>10s}"

        lines.append(
            f"  {pf['path']:<{name_col}s} {pf['sloc']:>5d}  {scanned_str:7s}  "
            f"{reviewed_str}  {findings_str:>8s}"
        )

    # Legend
    if tool_abbrevs:
        legend = "  " + "  ".join(f"{a} = {n}" for a, n in tool_abbrevs)
        lines.append("")
        lines.append(legend)

    return "\n".join(lines)


def compute_project_summary(project) -> Optional[Dict[str, Any]]:
    """Compute accumulated coverage across all runs in a project.

    Merges coverage records from every run directory, using the project's
    checklist as the inventory denominator.

    Args:
        project: A Project dataclass instance.

    Returns a summary dict (same shape as compute_summary), or None.
    """
    output_path = Path(project.output_dir)

    # Find the best checklist (project-level symlink or newest run's)
    checklist = load_json(output_path / "checklist.json")
    if not checklist:
        for d in project.get_run_dirs(sweep=False):
            cl = load_json(d / "checklist.json")
            if cl:
                checklist = cl
                break
    if not checklist:
        return None

    # Collect all records across runs
    all_records = []
    for d in project.get_run_dirs(sweep=False):
        all_records.extend(load_records(d))

    if not all_records:
        # Still return inventory-only summary
        pass

    # Merge records by tool — union files_examined, union functions_analysed
    merged_by_tool = {}
    for record in all_records:
        tool = record.get("tool", "unknown")
        if tool not in merged_by_tool:
            merged_by_tool[tool] = {
                "tool": tool,
                "files_examined": set(),
                "functions_analysed": [],
                "rules_applied": set(),
                "packs": set(),
                "files_failed": [],
            }
        m = merged_by_tool[tool]
        for f in record.get("files_examined", []):
            m["files_examined"].add(f)
        for fa in record.get("functions_analysed", []):
            key = (fa.get("file", ""), fa.get("function", ""))
            if key not in {(x.get("file"), x.get("function")) for x in m["functions_analysed"]}:
                m["functions_analysed"].append(fa)
        for r in record.get("rules_applied", []):
            m["rules_applied"].add(r)
        for p in record.get("packs", []):
            m["packs"].add(p)
        for f in record.get("files_failed", []):
            m["files_failed"].append(f)

    # Convert sets back to lists for compute_summary compatibility
    merged_records = []
    for m in merged_by_tool.values():
        rec = {"tool": m["tool"], "files_examined": sorted(m["files_examined"])}
        if m["functions_analysed"]:
            rec["functions_analysed"] = m["functions_analysed"]
        if m["rules_applied"]:
            rec["rules_applied"] = sorted(m["rules_applied"])
        if m["packs"]:
            rec["packs"] = sorted(m["packs"])
        if m["files_failed"]:
            rec["files_failed"] = m["files_failed"]
        merged_records.append(rec)

    # Aggregate findings across all runs, dedup by (file, function, line)
    all_findings = []
    seen = set()
    for d in project.get_run_dirs(sweep=False):
        fdata = load_json(d / "findings.json")
        if fdata:
            if isinstance(fdata, list):
                flist = fdata
            elif isinstance(fdata, dict):
                flist = fdata.get("findings", fdata.get("results", []))
            else:
                flist = []
            for f in flist:
                key = (f.get("file", ""), f.get("function", ""), f.get("line", 0))
                if key not in seen:
                    all_findings.append(f)
                    seen.add(key)

    # Build synthetic run dir with merged data to reuse compute_summary
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        from core.json import save_json
        save_json(tmp_path / "checklist.json", checklist)
        if all_findings:
            save_json(tmp_path / "findings.json", {"findings": all_findings})
        for rec in merged_records:
            write_record(tmp_path, rec, tool_name=rec["tool"])
        return compute_summary(tmp_path)


def _match_to_inventory(path: str, inventory_paths: set) -> Optional[str]:
    """Try to match a tool-reported path to an inventory path."""
    if path in inventory_paths:
        return path

    # Strip leading ./
    stripped = path.lstrip("./")
    if stripped in inventory_paths:
        return stripped

    # Try matching by filename
    name = Path(path).name
    matches = [p for p in inventory_paths if Path(p).name == name]
    if len(matches) == 1:
        return matches[0]

    # Try suffix matching (tool may report relative to different root)
    for inv_path in inventory_paths:
        if inv_path.endswith(path) or path.endswith(inv_path):
            return inv_path

    return None
