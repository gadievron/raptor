"""Portable CVE remediation receipts from completed domain operations."""
from __future__ import annotations

from dataclasses import asdict
from itertools import islice
import sys

from core.reporting.document import StageEnvelope
from core.reporting.results import NativeResult, complete_native_result
from core.security.log_sanitisation import sanitise_for_terminal
from .update import _change_key, _change_to_dict

DETAIL_LIMIT = 100


def cve_result(args, *, out_dir, targets, excluded_files, changes, compatibility, mode, exit_code,
               patch_path, apply_exit, cascade_result, external_result, hash_pin_result,
               cascade_attempted, external_attempted, hash_pin_attempted):
    notes = ["Recorded CVE remediation. Materialised proposals and a command exit code do not by themselves establish that all advisories or resolver conflicts were cleared.",
             "Mode labels the CVE patch phase; hash-pin writes are an independent operation recorded separately."]
    if mode == "no actionable changes":
        notes.append("No actionable upgrade survived the selected filters; this is not a clean-scan or complete-coverage verdict.")
        notes.append("changes.json and changes.md were not emitted in this mode; those paths remain reserved for native workflow output.")
    plans = []
    for plan in islice(targets.values(), DETAIL_LIMIT):
        row = asdict(plan)
        row["manifest"] = str(plan.manifest)
        plans.append(row)
    if len(targets) > len(plans) or len(changes) > DETAIL_LIMIT:
        notes.append(f"Report captures up to {DETAIL_LIMIT} plans/change records; native findings and changes.json retain their respective source evidence.")
    stages = [StageEnvelope("CVE remediation", "failed" if exit_code else "completed", producer="sca")]
    if args.apply:
        stages.append(StageEnvelope("apply", "skipped" if apply_exit is None else ("failed" if apply_exit else "completed"),
                                    producer="sca", reason="not reached" if apply_exit is None else f"Domain exit code {apply_exit}"))
    auxiliary = {}
    missing = False
    conflicts = 0
    for name, requested, attempted, receipt in [
        ("cascade", args.allow_cascade, cascade_attempted, cascade_result),
        ("external validation", bool(args.validate_against), external_attempted, external_result),
        ("hash pin", args.hash_pin, hash_pin_attempted, hash_pin_result),
    ]:
        counts = {}
        verdicts = receipt if isinstance(receipt, list) else ([receipt] if isinstance(receipt, dict) else [])
        conflicts += sum(isinstance(row, dict) and row.get("verdict") == "conflict" for row in verdicts)
        captured = receipt
        if isinstance(receipt, list):
            counts["records"] = len(receipt)
            captured = receipt[:DETAIL_LIMIT]
        elif isinstance(receipt, dict):
            captured = {}
            for key, value in receipt.items():
                if isinstance(value, list):
                    counts[key] = len(value)
                    captured[key] = value[:DETAIL_LIMIT]
                else:
                    captured[key] = value
        if any(count > DETAIL_LIMIT for count in counts.values()):
            notes.append(f"{name}: report captures up to {DETAIL_LIMIT} entries per list; native receipt retains the full result.")
        auxiliary[name] = {"requested": requested, "attempted": attempted, "result": captured, "recorded counts": counts}
        if requested:
            state = "skipped" if not attempted else ("unknown" if receipt is None else "completed")
            stages.append(StageEnvelope(name, state, producer="sca", reason="No current result recorded" if receipt is None else "Native verdicts retained in result data"))
            if receipt is None:
                missing = True
                notes.append(f"{name}: no current outcome was recorded; success is not inferred from command completion.")
    if conflicts:
        notes.append(f"{conflicts} resolver conflict outcome(s) recorded; command completion does not imply those constraints resolved.")
    source = getattr(args, "_findings_source", args.findings)
    payload = {"mode": mode, "exit_code": exit_code, "input mode": "recorded findings" if args.findings else "scan prepass",
               "findings source": str(source) if source is not None else None,
               "native change files emitted": mode != "no actionable changes",
               "auxiliary operations": auxiliary, "recorded targets": len(targets), "targets": plans,
               "recorded changes": len(changes), "skipped changes": sum(change.skipped_reason is not None for change in changes),
               "changes": [_change_to_dict(change, compatibility.get(_change_key(change))) for change in changes[:DETAIL_LIMIT]],
               "selection": {"advisory filter": args.fix, "allow major": args.allow_major, "pin only": args.pin_only,
                             "exclude patterns": list(args.exclude or []), "excluded surfaces": list(excluded_files[:DETAIL_LIMIT]),
                             "recorded excluded surfaces": len(excluded_files), "offline": args.offline,
                             "hash-pin writes requested": args.hash_pin_write}}
    artifacts = [out_dir / "changes.md", out_dir / "changes.json"]
    if source is not None:
        artifacts.append(source)
    if patch_path is not None:
        artifacts.append(patch_path)
    for receipt, filename in [(cascade_result, "cascade.json"), (external_result, "validate-against.json"), (hash_pin_result, "hash-pin.json")]:
        if receipt is not None:
            artifacts.append(out_dir / filename)
    artifacts.extend(plan.manifest for plan in targets.values())
    state = "failed" if exit_code else ("partial" if missing else "completed")
    return NativeResult("sca-fix-cve", str(args.target or source or "recorded findings"), out_dir.name, payload,
                        state=state, diagnostics=notes, stages=stages,
                        metrics={"Mode": mode, "Recorded targets": len(targets), "Recorded changes": len(changes),
                                 "Recorded resolver conflicts": conflicts,
                                 "CVE fix exit code": exit_code}, artifacts=[{"path": str(path)} for path in artifacts])


def complete_cve_report(args, **observations):
    try:
        result = cve_result(args, **observations)
        output = args._report_options.output
        root = output if output.is_dir() or not output.suffix else output.parent / ("." + output.stem + "-report")
        return complete_native_result(result, root, stem="sca-fix-cve", options=args._report_options, stream=sys.stderr)
    except (OSError, ValueError, TypeError) as error:
        print(sanitise_for_terminal("Optional CVE fix report unavailable (" + type(error).__name__ + "); native workflow and exit status retained"), file=sys.stderr)
        return None
