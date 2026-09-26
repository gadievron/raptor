"""Three-part flip gate: candidate run vs a frozen baseline.

The decision instrument for detection-default flips (e.g. turning a
new engine's opt-in flag default-on): a frozen baseline dir (the
``out/eval-baselines/<id>/`` artifacts recorded per the
baseline-freeze protocol) is compared against a candidate run's
reports, and the flip is justified only when ALL THREE hold:

1. ``recall_uplift`` — aggregate recall over the paired manifests is
   strictly higher (beyond ``--min-uplift``) on the candidate side;
2. ``clean_region_fp_ceiling`` — findings on labelled-clean regions
   do not grow beyond the pinned ceiling (default: no growth);
3. ``no_displacement`` — every expected finding the baseline matched
   is still matched by the candidate, per manifest. Displacement is
   invisible to a standalone recall percentage: a candidate can gain
   two findings, lose one, and still show "uplift" — the lost one is
   a regression the flip must not ride over.

Comparability is fail-closed: each baseline manifest must have
exactly one candidate counterpart measured against the same pinned
sha and the same label set — pinned sha, expected_total,
clean_region_total, and the ``label_digest`` content pin all must
match (a pruned clean_regions list between freeze and candidate run
would otherwise blind the FP ceiling while every other pin still
matched); unpaired or drifted manifests refuse the gate rather than
silently shrinking the comparison. The PROFILE PAIR is declared, not
inferred: every baseline report must carry the declared baseline
profile and every candidate report the declared candidate profile
(defaults: ``agentic`` -> ``agentic-taint``), so a mis-frozen
baseline cannot manufacture unattributable uplift. Same-profile
pairs (two detector builds measured via ``--pipeline-dir``) are
legitimate but must be declared explicitly. Reports themselves are
consistency-checked: ``clean_region_fp_count`` is REQUIRED (a
truncated report must never read as zero FPs), and ``found_total``
must sit within ``expected_total`` and agree with the missed list.

Frozen baselines that predate the label-set pins (no
``clean_region_total`` / ``label_digest`` in their reports) refuse
by default; the operator may grandfather them explicitly with
``allow_legacy_baseline`` / ``--allow-legacy-baseline``, which
accepts ABSENT pins on the baseline side only (present-but-mismatched
still refuses, and the candidate side always requires them) and is
called out on stdout. The clean remedy is a re-freeze with the
current scorer.

OUTPUT DISCIPLINE (hide-gaps): stdout carries pass/fail and the
mechanism names only. Every number — recall figures, FP counts,
displaced ids — goes to the local report file, which is
recall-ground-truth class like the reports it derives from: never
feed it to FP-suppression or scorecard learning stores.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.json import load_json
from core.recall.manifest import PROFILES
from core.recall.score import LABEL_CLASS, SEGREGATION_NOTE

#: Byte budget per report file (mirrors the CLI's report loads).
_MAX_REPORT_BYTES = 64 * 1024 * 1024

CHECK_NAMES = ("recall_uplift", "clean_region_fp_ceiling",
               "no_displacement")

#: The default declared profile pair: the flip this gate exists for.
DEFAULT_PROFILE_PAIR = ("agentic", "agentic-taint")


class FlipGateError(RuntimeError):
    """The gate could not be evaluated (never a pass OR a fail)."""


def _is_recall_report(doc: Any) -> bool:
    return (isinstance(doc, dict)
            and doc.get("label_class") == LABEL_CLASS
            and isinstance(doc.get("manifest"), str)
            and isinstance(doc.get("expected_total"), int)
            and isinstance(doc.get("found_total"), int))


def load_reports(path: Path) -> dict[str, dict[str, Any]]:
    """Recall reports keyed by manifest name from a file or dir.

    A dir is scanned recursively for ``*.json``; non-report JSON
    artifacts riding along in a frozen baseline (census, warm,
    markdown twins) are skipped — but a side that yields ZERO reports
    refuses, and two reports claiming the same manifest name refuse
    (which one is the measurement?).
    """
    if path.is_file():
        candidates = [path]
    elif path.is_dir():
        candidates = sorted(path.rglob("*.json"))
    else:
        msg = f"{path}: not a file or directory"
        raise FlipGateError(msg)

    reports: dict[str, dict[str, Any]] = {}
    for p in candidates:
        try:
            doc = load_json(p, strict=True,
                            max_bytes=_MAX_REPORT_BYTES)
        except (OSError, ValueError) as exc:
            if path.is_file():
                msg = f"cannot read report {p}: {exc}"
                raise FlipGateError(msg) from exc
            continue  # sibling artifact, not this gate's input
        if not _is_recall_report(doc):
            if path.is_file():
                msg = (f"{p} is not a recall report "
                       f"(label_class {LABEL_CLASS!r} + manifest/"
                       "expected_total/found_total required)")
                raise FlipGateError(msg)
            continue
        name = doc["manifest"]
        if name in reports:
            msg = (f"{path}: two reports claim manifest {name!r} — "
                   "one side, one measurement per manifest")
            raise FlipGateError(msg)
        reports[name] = doc
    if not reports:
        msg = f"{path}: no recall reports found"
        raise FlipGateError(msg)
    return reports


def _missed_ids(report: dict[str, Any]) -> set[str]:
    return {str(m.get("id")) for m in report.get("missed", [])}


def _is_count(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _report_guard(name: str, side: str, report: dict[str, Any], *,
                  expected_profile: str, legacy_ok: bool) -> bool:
    """Refuse malformed or internally inconsistent reports.

    Returns True when the legacy-baseline grandfather was used (both
    label-set pins absent AND ``legacy_ok``); every other problem
    raises. ``side`` and ``expected_profile`` are operator-declared
    values, never report content — error text stays free of
    report-derived strings beyond the manifest name.
    """
    problems = []
    if report.get("profile") != expected_profile:
        problems.append(
            f"profile does not match the declared {side} profile "
            f"{expected_profile!r} — a mis-frozen baseline (or a "
            "candidate run on the wrong profile) yields "
            "unattributable uplift")
    fp = report.get("clean_region_fp_count")
    if not _is_count(fp):
        problems.append(
            "clean_region_fp_count missing or malformed — a "
            "truncated report must never sail through the FP "
            "ceiling as zero")
    found = report["found_total"]
    expected = report["expected_total"]
    missed = report.get("missed")
    if found < 0 or found > expected:
        problems.append(
            "found_total out of range for expected_total "
            "(impossible from a real run)")
    elif not isinstance(missed, list) or found != expected - len(missed):
        problems.append(
            "found_total does not equal expected_total minus the "
            "missed count (inconsistent report)")

    total = report.get("clean_region_total")
    digest = report.get("label_digest")
    legacy = False
    if total is None and digest is None and legacy_ok:
        # Pre-pin frozen baseline, explicitly grandfathered. Only the
        # fully-absent shape qualifies: a report carrying one pin but
        # not the other is not a legacy report.
        legacy = True
    else:
        if not _is_count(total):
            problems.append(
                "clean_region_total missing or malformed — the gate "
                "pins the clean-region label population (re-freeze "
                "the baseline with the current scorer, or "
                "grandfather a pre-pin baseline explicitly with "
                "--allow-legacy-baseline)")
        elif _is_count(fp) and fp > total:
            problems.append(
                "clean_region_fp_count exceeds clean_region_total "
                "(inconsistent report)")
        if not (isinstance(digest, str) and digest):
            problems.append(
                "label_digest missing or malformed — the gate pins "
                "the label-set content (same re-freeze / "
                "--allow-legacy-baseline remedies)")
    if problems:
        msg = (f"{side} report for manifest {name!r} refused: "
               + "; ".join(problems))
        raise FlipGateError(msg)
    return legacy


def _pair_guard(name: str, base: dict[str, Any], cand: dict[str, Any],
                *, baseline_legacy: bool) -> None:
    """Refuse pairs whose measurements are not label-set comparable."""
    problems = []
    if base.get("pinned_sha") != cand.get("pinned_sha"):
        problems.append("pinned_sha differs (different trees)")
    if base.get("expected_total") != cand.get("expected_total"):
        problems.append("expected_total differs (label set drifted)")
    if base.get("language") != cand.get("language"):
        problems.append("language differs")
    if not baseline_legacy:
        # Label-set pins: a clean_regions prune between freeze and
        # candidate run passes every guard above while blinding the
        # FP ceiling — these two are the pins that see it.
        if base.get("clean_region_total") != cand.get(
                "clean_region_total"):
            problems.append("clean_region_total differs "
                            "(clean-region label set drifted)")
        if base.get("label_digest") != cand.get("label_digest"):
            problems.append("label_digest differs "
                            "(label content drifted)")
    if problems:
        msg = (f"manifest {name!r} is not comparable: "
               + "; ".join(problems)
               + " — re-freeze the baseline against the current "
                 "manifest set")
        raise FlipGateError(msg)


def evaluate_flip_gate(
    baseline: dict[str, dict[str, Any]],
    candidate: dict[str, dict[str, Any]],
    *, fp_ceiling: int = 0, min_uplift: float = 0.0,
    profiles: tuple[str, str] = DEFAULT_PROFILE_PAIR,
    allow_legacy_baseline: bool = False,
) -> dict[str, Any]:
    """Evaluate the three checks; return the full (numeric) result.

    ``profiles`` is the DECLARED (baseline, candidate) profile pair —
    both must name known detection profiles, and every report on each
    side must carry its side's declared profile (see module
    docstring). ``allow_legacy_baseline`` grandfathers pre-pin frozen
    baselines whose reports lack the label-set pins entirely.

    The returned dict is the LOCAL report — it carries every number.
    Callers that print must go through :func:`render_public`.
    """
    if fp_ceiling < 0:
        msg = "fp_ceiling must be >= 0"
        raise FlipGateError(msg)
    if min_uplift < 0:
        msg = "min_uplift must be >= 0"
        raise FlipGateError(msg)
    for side, prof in zip(("baseline", "candidate"), profiles):
        if prof not in PROFILES:
            msg = (f"declared {side} profile {prof!r} is not a known "
                   f"detection profile (choose from {sorted(PROFILES)})")
            raise FlipGateError(msg)
    only_base = sorted(set(baseline) - set(candidate))
    only_cand = sorted(set(candidate) - set(baseline))
    if only_base or only_cand:
        msg = (
            "manifest sets differ — the gate refuses a shrunken "
            f"comparison (baseline-only: {only_base or 'none'}; "
            f"candidate-only: {only_cand or 'none'})")
        raise FlipGateError(msg)

    manifests: list[dict[str, Any]] = []
    displaced: dict[str, list[str]] = {}
    legacy_baseline = False
    b_found = b_expected = b_fp = 0
    c_found = c_fp = 0
    for name in sorted(baseline):
        base, cand = baseline[name], candidate[name]
        base_legacy = _report_guard(
            name, "baseline", base, expected_profile=profiles[0],
            legacy_ok=allow_legacy_baseline)
        legacy_baseline = legacy_baseline or base_legacy
        # The candidate ran under the current scorer by definition —
        # its pins are never grandfathered.
        _report_guard(name, "candidate", cand,
                      expected_profile=profiles[1], legacy_ok=False)
        _pair_guard(name, base, cand, baseline_legacy=base_legacy)
        b_found += base["found_total"]
        b_expected += base["expected_total"]
        c_found += cand["found_total"]
        # Key presence + shape guaranteed by _report_guard above — a
        # defaulted .get() here would let a truncated report read as
        # zero FPs.
        b_fp += base["clean_region_fp_count"]
        c_fp += cand["clean_region_fp_count"]
        base_missed = _missed_ids(base)
        cand_missed = _missed_ids(cand)
        newly_missed = sorted(cand_missed - base_missed)
        if newly_missed:
            displaced[name] = newly_missed
        manifests.append({
            "manifest": name,
            "profiles": {"baseline": base.get("profile"),
                         "candidate": cand.get("profile")},
            "found": {"baseline": base["found_total"],
                      "candidate": cand["found_total"]},
            "expected_total": base["expected_total"],
            "clean_region_fps": {
                "baseline": base["clean_region_fp_count"],
                "candidate": cand["clean_region_fp_count"],
            },
            "newly_found": sorted(base_missed - cand_missed),
            "newly_missed": newly_missed,
        })

    if b_expected == 0:
        msg = ("zero expected findings across the paired manifests — "
               "recall uplift is undefined; the gate needs a recall "
               "corpus, not fp-only twins alone")
        raise FlipGateError(msg)

    base_recall = b_found / b_expected
    cand_recall = c_found / b_expected
    uplift = cand_recall - base_recall
    # Cross-multiplied comparison: (Δfound / expected) > margin
    # evaluated as Δfound > margin * expected — one division fewer,
    # so a margin equal to the true uplift stays strict instead of
    # flipping on float noise (0.8 - 0.6 > 0.2 is True in binary64).
    uplift_ok = (c_found - b_found) > min_uplift * b_expected
    checks = {
        "recall_uplift": {
            "passed": uplift_ok,
            "min_uplift": min_uplift,
            "baseline_recall": base_recall,
            "candidate_recall": cand_recall,
            "uplift": uplift,
            "baseline_found": b_found,
            "candidate_found": c_found,
            "expected_total": b_expected,
        },
        "clean_region_fp_ceiling": {
            "passed": c_fp <= b_fp + fp_ceiling,
            "ceiling": fp_ceiling,
            "baseline_fps": b_fp,
            "candidate_fps": c_fp,
        },
        "no_displacement": {
            "passed": not displaced,
            "displaced": displaced,
        },
    }
    return {
        "label_class": LABEL_CLASS,
        "segregation": SEGREGATION_NOTE,
        "passed": all(c["passed"] for c in checks.values()),
        "profiles": {"baseline": profiles[0],
                     "candidate": profiles[1]},
        "legacy_baseline": legacy_baseline,
        "checks": checks,
        "manifests": manifests,
    }


def render_public(result: dict[str, Any],
                  report_path: Path | None = None) -> str:
    """The stdout-safe view: verdicts + mechanism names, NO numbers.

    Hide-gaps: recall figures, FP counts, and displaced-label ids are
    gaps-in-progress — they live in the local report file only.
    """
    lines = ["flip-gate: " + ("PASS" if result["passed"] else "FAIL")]
    # The DECLARED profile pair (validated against the closed PROFILES
    # vocabulary, never raw report content): the verdict is only
    # attributable to a detector change when the reader can see which
    # pair was compared.
    profiles = result.get("profiles", {})
    lines.append(f"  profiles: {profiles.get('baseline')} -> "
                 f"{profiles.get('candidate')}")
    if result.get("legacy_baseline"):
        lines.append("  legacy-baseline: label-set pins absent on the "
                     "frozen baseline (grandfathered by operator flag)")
    lines += [
        f"  {name}: "
        + ("pass" if result["checks"][name]["passed"] else "fail")
        for name in CHECK_NAMES
    ]
    if report_path is not None:
        lines.append(f"report: {report_path}")
    return "\n".join(lines)
