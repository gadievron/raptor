"""Rules-based triage over a completed run's sandbox telemetry.

Reads <run_dir>/sandbox-summary.json, <run_dir>/proxy-events.jsonl, and
<run_dir>/sandbox-audit-degraded.json (if present) and classifies the run
into a 3-tier verdict — clean / notable / suspicious — based on whether any
signature pattern resembling an escape/recon/credential-theft attempt fired,
as distinct from ordinary "tool needed something the profile didn't allow"
denial noise.

Pure, rules-based, offline: no LLM call, no network, no cost — cheap
enough that core/run/metadata.py runs it unconditionally on every
terminal-state transition (complete/fail/cancel/interrupt), right after
the sandbox-summary finalise it reads from. libexec/raptor-sandbox-triage
re-runs it by hand (stranded runs, post-hoc re-classification after
editing telemetry). This is the cheap deterministic pre-filter a future
LLM-based deeper-reasoning pass would consume, not a replacement for one.

Known limitation: socket()/ioctl() denials collapse to a generic
syscall="socket"/"ioctl" under audit tracing (see
core/sandbox/tracer.py:_NAME_TO_TYPE) — the AF_UNIX/AF_NETLINK/AF_PACKET
family and TIOCSTI/TIOCCONS/TIOCSCTTY ioctl-cmd detail isn't captured by the
current tracer record shape, so escape_primitive_denied can't distinguish a
docker.sock-escape attempt from an ordinary blocked AF_UNIX call. Fixing
this means enriching tracer.py's record with decoded syscall arguments — a
separate, larger change.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.atomic_fs import write_text_atomically
from core.sandbox.escalation_signatures import (
    DEFAULT_HOST_RECON_THRESHOLD,
    ESCAPE_PRIMITIVE_SYSCALLS,
    is_credential_path,
)
from core.sandbox.profiles import host_recon_threshold_for_profile
from core.security.log_sanitisation import sanitise_for_terminal
from core.sandbox.proxy import PROXY_EVENTS_FILENAME
from core.sandbox.summary import (
    AUDIT_DEGRADED_FILE,
    MAX_DENIALS_PER_RUN,
    SUMMARY_FILE,
)

TRIAGE_FILE = "sandbox-triage.json"

# Control-plane record types written into the same denials stream by
# core/sandbox/audit_budget.py — not enforcement denials, must be excluded
# from the enforcement-oriented signal checks below.
_BUDGET_MARKER_TYPES = frozenset({
    "pid_budget_exceeded", "category_budget_exceeded",
    "category_budget_exceeded_sampling", "audit_summary",
})

VERDICT_CLEAN = "clean"
VERDICT_NOTABLE = "notable"
VERDICT_SUSPICIOUS = "suspicious"

SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

# Fraction of MAX_DENIALS_PER_RUN that counts as "near the cap" for
# volume_anomaly's cap-proximity check.
_VOLUME_ANOMALY_CAP_FRACTION = 0.9

# Evidence bounds. Evidence values (hostnames, paths) are attacker-
# controlled: a hostile target can mint thousands of distinct denied
# hosts, each an arbitrarily long string, to bloat sandbox-triage.json
# or to stuff content into a report a human or LLM pass later reads.
# Signals keep the true `count`; only the illustrative evidence list
# is capped, with an explicit elision marker so a capped list never
# masquerades as complete.
_MAX_EVIDENCE_ITEMS = 32
_MAX_EVIDENCE_ITEM_LEN = 512


def _cap_evidence(items: List[str]) -> List[str]:
    capped = [
        item if len(item) <= _MAX_EVIDENCE_ITEM_LEN
        else item[:_MAX_EVIDENCE_ITEM_LEN]
        + f"...[+{len(item) - _MAX_EVIDENCE_ITEM_LEN} chars]"
        for item in items
    ]
    if len(capped) > _MAX_EVIDENCE_ITEMS:
        dropped = len(capped) - _MAX_EVIDENCE_ITEMS
        capped = capped[:_MAX_EVIDENCE_ITEMS] + [f"...[+{dropped} more]"]
    return capped


def triage_run(run_dir: Path, *,
                host_recon_threshold: Optional[int] = None,
                ) -> Optional[Dict[str, Any]]:
    """Classify a completed run's sandbox telemetry.

    Returns the triage dict (also written to <run_dir>/sandbox-triage.json),
    or None if neither sandbox-summary.json nor proxy-events.jsonl exists
    for this run_dir — mirrors summarize_and_write's "no denials → None, no
    file written" convention so file-presence keeps meaning "something
    happened" across every sibling run-dir artifact.

    ``host_recon_threshold``: explicit override (e.g. from a CLI flag or a
    test wanting deterministic behaviour) takes precedence exactly as
    passed. When omitted (the ``None`` default — this is how
    ``core.run.metadata._finalize_sandbox_triage`` calls this), the
    threshold is resolved from whichever sandbox profile(s) this run's
    denial records were attributed to, via
    ``core.sandbox.profiles.host_recon_threshold_for_profile``.

    A single run_dir can aggregate telemetry from MULTIPLE sandbox()
    invocations, potentially under different profiles (e.g. mostly
    ``full``, with one nested ``debug`` call for a crash-analysis step) —
    there is no single well-defined "the profile" for the run as a whole.
    Best-effort resolution: take the MIN (most sensitive/tightest)
    threshold across every profile named in a seccomp-type denial record's
    ``profile`` field, erring toward flagging real recon over suppressing
    it. Falls back to DEFAULT_HOST_RECON_THRESHOLD when no denial carries a
    ``profile`` (clean runs, network-only denials, or a non-seccomp-type
    run) — this is the same behaviour as before this parameter existed.
    """
    run_dir = Path(run_dir)
    summary = _load_json(run_dir / SUMMARY_FILE)
    proxy_events = _load_jsonl(run_dir / PROXY_EVENTS_FILENAME)
    audit_degraded = _load_json(run_dir / AUDIT_DEGRADED_FILE)

    if summary is None and not proxy_events:
        return None

    denials = (summary or {}).get("denials", [])
    enforcement_denials = [d for d in denials
                            if d.get("type") not in _BUDGET_MARKER_TYPES]
    budget_markers = [d for d in denials
                       if d.get("type") in _BUDGET_MARKER_TYPES]

    if host_recon_threshold is None:
        observed_profiles = {d["profile"] for d in enforcement_denials
                              if d.get("profile")}
        host_recon_threshold = min(
            (host_recon_threshold_for_profile(p, DEFAULT_HOST_RECON_THRESHOLD)
             for p in observed_profiles),
            default=DEFAULT_HOST_RECON_THRESHOLD,
        )

    signals: List[Dict[str, Any]] = []
    signals += _check_escape_primitive(enforcement_denials)
    signals += _check_seccomp_unattributed(enforcement_denials)
    signals += _check_resolved_ip_screened(proxy_events)
    signals += _check_host_recon(proxy_events, host_recon_threshold)
    signals += _check_credential_path_touch(enforcement_denials)
    signals += _check_volume_anomaly(summary, budget_markers)

    verdict = _derive_verdict(signals)

    report: Dict[str, Any] = {
        "run_dir": str(run_dir),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "signals": signals,
        "inputs": {
            "sandbox_summary_present": summary is not None,
            "proxy_events_present": bool(proxy_events),
            "total_denials": (summary or {}).get("total_denials", 0),
            "total_proxy_events": len(proxy_events),
        },
        "audit_degraded": audit_degraded is not None,
        "caveats": [],
    }
    if audit_degraded is not None:
        report["caveats"].append(
            "Audit tracer did not engage this run "
            f"(reason: {audit_degraded.get('reason', 'unknown')}); "
            "syscall-level attribution (escape_primitive_denied) was "
            "unavailable, so this verdict has lower confidence than a "
            "run with --audit fully engaged."
        )

    _write(run_dir / TRIAGE_FILE, report)
    return report


# ---- signal checks (each returns a list of 0 or 1 signal dicts) --------

def _check_escape_primitive(denials: List[dict]) -> List[dict]:
    hits = [d for d in denials
            if d.get("syscall") in ESCAPE_PRIMITIVE_SYSCALLS]
    if not hits:
        return []
    return [{
        "type": "escape_primitive_denied",
        "severity": SEVERITY_HIGH,
        "count": len(hits),
        "evidence": _cap_evidence(sorted({h["syscall"] for h in hits})),
    }]


def _check_seccomp_unattributed(denials: List[dict]) -> List[dict]:
    hits = [d for d in denials
            if d.get("type") == "seccomp" and "syscall" not in d]
    if not hits:
        return []
    return [{
        "type": "seccomp_denied_unattributed",
        "severity": SEVERITY_LOW,
        "count": len(hits),
        "evidence": [
            "non-audit run: syscall identity unavailable, only "
            f"profile={hits[0].get('profile')!r} known",
        ],
    }]


def _check_resolved_ip_screened(proxy_events: List[dict]) -> List[dict]:
    # ANY occurrence — doc-confirmed purely-attack pattern (see
    # docs/sandbox.md's audit-mode section), not threshold-based. Read
    # from proxy-events.jsonl rather than sandbox-summary.json's mirrored
    # network-type denial: the audit-mode mirror
    # (_record_proxy_denial -> record_denial(..., "network", ...)) writes
    # a plain type="network" denial indistinguishable from an ordinary
    # network-allowlist denial in the summary — resolved_ip is only
    # reliably present in proxy-events.jsonl's resolved_ip field.
    hits = [e for e in proxy_events if e.get("result") == "denied_resolved_ip"]
    if not hits:
        return []
    return [{
        "type": "resolved_ip_screened",
        "severity": SEVERITY_HIGH,
        "count": len(hits),
        "evidence": _cap_evidence(sorted({e["resolved_ip"] for e in hits
                                          if e.get("resolved_ip")})),
    }]


def _check_host_recon(proxy_events: List[dict], threshold: int) -> List[dict]:
    hosts = {e.get("host") for e in proxy_events
             if e.get("result") in ("denied_host", "would_deny_host")
             and e.get("host")}
    if len(hosts) < threshold:
        return []
    return [{
        "type": "host_recon_pattern",
        "severity": SEVERITY_MEDIUM,
        "count": len(hosts),
        "evidence": _cap_evidence(sorted(hosts)),
    }]


def _check_credential_path_touch(denials: List[dict]) -> List[dict]:
    hits = []
    for d in denials:
        path = d.get("path")
        if not path:
            continue
        if is_credential_path(path):
            hits.append(path)
    if not hits:
        return []
    return [{
        "type": "credential_path_touch",
        "severity": SEVERITY_HIGH,
        "count": len(hits),
        "evidence": _cap_evidence(sorted(set(hits))),
    }]


def _check_volume_anomaly(summary: Optional[dict],
                           budget_markers: List[dict]) -> List[dict]:
    evidence = []
    total = (summary or {}).get("total_denials", 0)
    cap_threshold = int(MAX_DENIALS_PER_RUN * _VOLUME_ANOMALY_CAP_FRACTION)
    if total >= cap_threshold:
        evidence.append(
            f"total_denials={total} near/at cap ({MAX_DENIALS_PER_RUN})"
        )
    marker_types = sorted({m.get("type") for m in budget_markers
                            if m.get("type") != "audit_summary"})
    if marker_types:
        evidence.append(f"audit budget markers present: {marker_types}")
    if not evidence:
        return []
    return [{
        "type": "volume_anomaly",
        "severity": SEVERITY_MEDIUM,
        "count": total,
        "evidence": evidence,
    }]


def _derive_verdict(signals: List[dict]) -> str:
    if any(s["severity"] == SEVERITY_HIGH for s in signals):
        return VERDICT_SUSPICIOUS
    if signals:
        return VERDICT_NOTABLE
    return VERDICT_CLEAN


# ---- I/O helpers ---------------------------------------------------------

def _load_json(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _load_jsonl(path: Path) -> List[dict]:
    if not path.exists():
        return []
    out: List[dict] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        return []
    return out


def _write(path: Path, report: dict) -> None:
    write_text_atomically(
        path,
        json.dumps(report, indent=2, ensure_ascii=True) + "\n",
        tmp_prefix=".~triage-",
    )


def _cli_main(argv: Optional[list] = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Rules-based triage of a completed run's sandbox "
                    "telemetry for escape/recon/credential-theft signatures.",
    )
    parser.add_argument("run_dir", help="run directory to triage")
    parser.add_argument(
        "--json", action="store_true",
        help="print the full triage report as JSON on stdout "
             "(the report is also written to sandbox-triage.json)",
    )
    try:
        args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2

    target = Path(args.run_dir)
    if not target.is_dir():
        print(f"error: {target} is not a directory", file=sys.stderr)
        return 1

    result = triage_run(target)
    if result is None:
        print(f"(no sandbox telemetry found for {target})")
        return 0

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=True))
    else:
        print(f"Verdict: {result['verdict'].title()}  "
              f"({len(result['signals'])} signal(s)) -> "
              f"{target / TRIAGE_FILE}")
        for signal in result["signals"]:
            print(f"  - {signal['type']} [{signal['severity']}] "
                  f"count={signal['count']}")
        for caveat in result.get("caveats", []):
            # Caveat text embeds the audit-degraded reason, read from
            # a file inside the run dir — which the sandboxed target
            # may have write access to. Sanitise before a terminal.
            print(f"  ⚠️  {sanitise_for_terminal(caveat)}")
    # Verdict-reflecting exit codes for scripting/CI gates:
    #   0 clean (or no telemetry), 1 error, 2 usage,
    #   3 notable, 4 suspicious.
    return {VERDICT_CLEAN: 0, VERDICT_NOTABLE: 3,
            VERDICT_SUSPICIOUS: 4}[result["verdict"]]


if __name__ == "__main__":
    raise SystemExit(_cli_main())
