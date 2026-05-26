"""Threshold-based exit-code evaluation for findings.

Replaces the standalone ``raptor-sca-gate`` binary. The same logic is now
exposed as flags on:

  - the main scan path (``bin/raptor-sca <target> --fail-on-severity high``)
  - the render path (``bin/raptor-sca render findings.json --fail-on-severity high``)

Returns ``(passed, failure_messages)`` so callers can decide exit code
and how to report.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import List, Optional, Sequence, TextIO

from .findings import severity_rank

_SEVERITY_CHOICES = ("info", "low", "medium", "high", "critical")


@dataclass
class ThresholdConfig:
    """Threshold knobs for "fail this build if ..." logic.

    All fields default to a non-failing value; callers populate from
    CLI args. ``is_active`` returns False when nothing is set, in which
    case ``evaluate`` is a no-op (always passes).
    """
    fail_on_severity: Optional[str] = None
    fail_on_kev: bool = False
    fail_on_supply_chain: Optional[str] = None
    fail_on_hygiene: Optional[str] = None
    include_suppressed: bool = False
    fail_on_capability_drift: bool = False
    max_added_capability_buckets: Optional[int] = None

    @property
    def is_active(self) -> bool:
        return (self.fail_on_severity is not None
                or self.fail_on_kev
                or self.fail_on_supply_chain is not None
                or self.fail_on_hygiene is not None
                or self.fail_on_capability_drift
                or self.max_added_capability_buckets is not None)


def evaluate(
    rows: Sequence[dict], cfg: ThresholdConfig,
) -> "tuple[bool, List[str]]":
    """Evaluate findings against thresholds.

    Returns ``(passed, failure_messages)``. ``passed=True`` → caller
    exits 0. ``passed=False`` → caller exits 1 and surfaces the
    messages.
    """
    if not cfg.is_active:
        return True, []

    sev_floor = (severity_rank(cfg.fail_on_severity)
                 if cfg.fail_on_severity else None)
    sc_floor = (severity_rank(cfg.fail_on_supply_chain)
                if cfg.fail_on_supply_chain else None)
    hyg_floor = (severity_rank(cfg.fail_on_hygiene)
                 if cfg.fail_on_hygiene else None)

    fails: List[str] = []
    for row in rows:
        if not isinstance(row, dict):
            # Hand-edited or third-party-tool findings.json may contain
            # non-dict elements; skip rather than crash.
            continue
        if row.get("suppressed") and not cfg.include_suppressed:
            continue
        vuln_type = row.get("vuln_type", "")
        sev = row.get("severity", "info")
        rank = severity_rank(sev)
        desc = row.get("description") or row.get("id") or "(no description)"
        if vuln_type == "sca:vulnerable_dependency":
            if sev_floor is not None and rank >= sev_floor:
                fails.append(f"[{sev}] {desc}")
                continue
            if cfg.fail_on_kev and row.get("sca", {}).get("in_kev"):
                fails.append(f"[KEV] {desc}")
        elif vuln_type.startswith("sca:supply_chain:"):
            if sc_floor is not None and rank >= sc_floor:
                fails.append(f"[supply-chain {sev}] {desc}")
            # Drift-specific gates layer on top of (and may fire
            # independently of) the supply-chain severity floor —
            # operators may want to gate on drift without gating on
            # other supply-chain signals.
            if vuln_type == "sca:supply_chain:image_capability_drift":
                if cfg.fail_on_capability_drift:
                    fails.append(f"[capability-drift] {desc}")
                if cfg.max_added_capability_buckets is not None:
                    # Defensive: a hand-edited findings.json or a
                    # third-party emitter may produce a non-dict
                    # evidence field or a non-list ``added_buckets``.
                    # Treat anything we can't count as zero added
                    # buckets rather than crash the build gate.
                    ev = row.get("evidence", {})
                    if not isinstance(ev, dict):
                        ev = {}
                    raw_added = ev.get("added_buckets")
                    added = raw_added if isinstance(raw_added, list) else []
                    if len(added) > cfg.max_added_capability_buckets:
                        fails.append(
                            f"[capability-drift +{len(added)} buckets > "
                            f"max {cfg.max_added_capability_buckets}] "
                            f"{desc}"
                        )
        elif vuln_type.startswith("sca:hygiene:"):
            if hyg_floor is not None and rank >= hyg_floor:
                fails.append(f"[hygiene {sev}] {desc}")

    return len(fails) == 0, fails


def add_threshold_args(parser) -> None:
    """Register the shared --fail-on-* flags on an argparse parser."""
    parser.add_argument(
        "--fail-on-severity",
        choices=_SEVERITY_CHOICES, default=None,
        help="exit 1 if any vulnerable_dependency finding meets-or-exceeds "
             "this severity (CI gate)",
    )
    parser.add_argument(
        "--fail-on-kev", action="store_true",
        help="exit 1 if any vulnerable_dependency is on CISA's KEV list, "
             "even below --fail-on-severity",
    )
    parser.add_argument(
        "--fail-on-supply-chain",
        choices=_SEVERITY_CHOICES, default=None,
        help="exit 1 if any supply_chain finding meets-or-exceeds this severity",
    )
    parser.add_argument(
        "--fail-on-hygiene",
        choices=_SEVERITY_CHOICES, default=None,
        help="exit 1 if any hygiene finding meets-or-exceeds this severity",
    )
    parser.add_argument(
        "--include-suppressed", action="store_true",
        help="evaluate findings the operator marked suppressed in "
             ".raptor-sca-suppress.yml (default: skip them)",
    )
    parser.add_argument(
        "--fail-on-capability-drift", action="store_true",
        help=(
            "exit 1 if any image_capability_drift finding is present, "
            "regardless of severity. Use when you want to gate on "
            "binary-shape change without coupling to the supply-chain "
            "severity ladder."
        ),
    )
    parser.add_argument(
        "--max-added-capability-buckets",
        type=int, default=None, metavar="N",
        help=(
            "exit 1 if any image_capability_drift finding has MORE "
            "than N added capability buckets. Use 0 to fail on any "
            "new bucket; higher values tolerate small-scope drift."
        ),
    )


def cfg_from_args(args) -> ThresholdConfig:
    """Build a ``ThresholdConfig`` from an argparse Namespace."""
    return ThresholdConfig(
        fail_on_severity=getattr(args, "fail_on_severity", None),
        fail_on_kev=getattr(args, "fail_on_kev", False),
        fail_on_supply_chain=getattr(args, "fail_on_supply_chain", None),
        fail_on_hygiene=getattr(args, "fail_on_hygiene", None),
        include_suppressed=getattr(args, "include_suppressed", False),
        fail_on_capability_drift=getattr(
            args, "fail_on_capability_drift", False,
        ),
        max_added_capability_buckets=getattr(
            args, "max_added_capability_buckets", None,
        ),
    )


def print_result(
    passed: bool, fails: List[str], *,
    prog: str = "raptor-sca",
    out: Optional[TextIO] = None,
    err: Optional[TextIO] = None,
) -> None:
    """Print the pass/fail summary in the legacy gate's format."""
    if out is None:
        out = sys.stdout
    if err is None:
        err = sys.stderr
    if passed:
        print(f"{prog}: pass — no findings above thresholds", file=out)
        return
    print(f"{prog}: fail — {len(fails)} finding(s) above thresholds:",
          file=err)
    for line in fails[:50]:
        print(f"  {line}", file=err)
    if len(fails) > 50:
        print(f"  … and {len(fails) - 50} more", file=err)


__all__ = [
    "ThresholdConfig",
    "add_threshold_args",
    "cfg_from_args",
    "evaluate",
    "print_result",
]
