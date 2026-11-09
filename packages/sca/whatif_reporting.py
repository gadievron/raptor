"""Bounded capture of upgrade observations; comparison logic stays domain-owned."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import sys

from core.reporting.document import StageEnvelope
from core.reporting.results import NativeResult, complete_native_result
from core.security.log_sanitisation import sanitise_for_terminal

DETAIL_LIMIT = 100


@dataclass
class UpgradeCapture:
    observations: list[dict] = field(default_factory=list)
    outcomes: list[dict] = field(default_factory=list)
    recorded: int = 0
    diagnostics: list[str] = field(default_factory=list)

    @property
    def has_capacity(self):
        return len(self.observations) < DETAIL_LIMIT

    def record(self, kind, payload):
        if kind in {"comparison", "candidate comparison", "refusal", "impact explanation"}:
            self.outcomes.append({"kind": kind, "result": payload})
            return
        self.recorded += 1
        if len(self.observations) < DETAIL_LIMIT:
            self.observations.append({"kind": kind, "result": payload})

    def findings(self, role, version, findings):
        from .findings import _vuln_finding_to_row
        if not self.has_capacity:
            self.record(role, {"version": version, "advisory count": len(findings)})
            return
        try:
            rows = [_vuln_finding_to_row(f) for f in findings[:DETAIL_LIMIT]]
        except (ValueError, TypeError, AttributeError, KeyError):
            rows = []
            self.diagnostics.append("Optional advisory detail capture unavailable; native comparison retained")
        self.record(role, {"version": version, "advisory count": len(findings), "advisories": rows})


def upgrade_result(args, capture, *, exit_code, osv):
    modal = bool(args.add or args.remove or args.from_file)
    mode = "add/remove change set" if modal else ("candidates" if args.candidate else "pairwise")
    notes = ["Forward-looking advisory comparison, not an applied upgrade or proof of exploitability.",
             "Advisory details are bounded to 100 per observation; native output retains the domain comparison.", *capture.diagnostics]
    if modal:
        notes.append("Removal effects use the supplied findings only; an absent or unreadable baseline cannot establish that a removal clears no advisories.")
    if capture.recorded > len(capture.observations):
        notes.append(f"Report captures {len(capture.observations)} of {capture.recorded} version/change observations; native output retains the full comparison.")
    if osv.degraded:
        notes.append(f"{osv.failed_lookups} advisory lookups unavailable; verdict unavailable. Re-run with available advisory data.")
    state = "partial" if osv.degraded else ("failed" if exit_code == 2 else "completed")
    payload = {"mode": mode, "exit_code": exit_code, "outcomes": capture.outcomes,
               "coverage": {"offline": args.offline, "OSV degraded": osv.degraded,
                            "failed lookups": osv.failed_lookups, "failed package sample": list(osv.failed_dep_keys[:5]),
                            "KEV enabled": not args.no_kev, "EPSS enabled": not args.no_epss},
               "observations": capture.observations}
    artifacts = [{"path": str(Path(path).resolve())} for path in (args.out, args.findings, args.from_file) if path]
    return NativeResult("sca-upgrade", "proposed change set" if modal else f"{args.ecosystem}:{args.name}",
                        "sca-upgrade", payload, state=state, diagnostics=notes, artifacts=artifacts,
                        stages=[StageEnvelope("upgrade comparison", state, producer="sca")],
                        metrics={"Recorded observations": capture.recorded, "Captured observations": len(capture.observations),
                                 "Comparison exit code": exit_code})


def complete_upgrade_report(args, capture, *, exit_code, osv):
    try:
        result = upgrade_result(args, capture, exit_code=exit_code, osv=osv)
        output = args._report_options.output
        root = output if output.is_dir() or not output.suffix else output.parent / ("." + output.stem + "-report")
        return complete_native_result(result, root, stem="sca-upgrade", options=args._report_options, stream=sys.stderr)
    except (OSError, ValueError, TypeError) as error:
        print(sanitise_for_terminal("Optional upgrade report unavailable (" + type(error).__name__ + "); native comparison and exit status retained"), file=sys.stderr)
        return None
