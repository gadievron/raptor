"""Tier 0-aware analysis of ``synth_results`` from the trust-witness bridge.

Reads :mod:`cvefix_bridge`'s ``synth_results`` table (schema includes
``backend``, populated post-Tier 0) and produces the numbers we want to
look at the moment a corpus run finishes:

  * Headline: processed / sound / not_sound / no_barrier / pipeline errors.
  * Suppression rate: sound / (sound + not_sound) — the trust-tier KPI.
  * Backend split among SOUND verdicts: smt (Tier 0, free) vs codeql
    (Tier 2, LLM + CodeQL adjudication).  Quantifies how much of the
    suppression we're getting for zero LLM tokens.
  * Per-CWE and per-language breakdowns — grounds the per-CWE backend
    prior we eventually want (instead of asserting it).
  * ``not_sound`` failure-mode distribution: ``suppress_fp_failed`` vs
    ``preserve_tp_failed`` counts — tells us whether the Tier 2 wall is
    "guard insufficient" (suppress) or "guard kills the TP too"
    (preserve).
  * Token-savings estimate from Tier 0 short-circuits.  Conservative
    rough cost: each Tier 0 SOUND skips up to ``max_attempts`` LLM
    proposer calls + up to ``max_attempts`` CodeQL adjudications + one
    pre-fix DB build.  Reported in attempts saved, not dollars (the
    dollar conversion depends on the per-run model).

Safe to run WHILE the bridge is still writing — opens the DB with
``mode=ro`` so concurrent writes from the bridge process aren't blocked.

CLI: ``python3 -m core.dataflow.trust_corpus_report --synth-db PATH``
(shim: ``core/dataflow/scripts/trust-report``).
"""

from __future__ import annotations

import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# Status / backend constants — mirror cvefix_bridge.
_PIPELINE_ERRORS = frozenset(
    {"no_query", "fetch_fail", "build_fail", "analyze_fail", "no_finding", "error"}
)
_OUTCOME_STATUSES = frozenset({"sound", "not_sound", "no_barrier"})

# Conservative Tier 0 savings model.  Each SOUND Tier 0 short-circuit avoids:
#   * one pre-fix CodeQL DB build,
#   * up to ``max_attempts`` LLM proposer calls,
#   * up to ``max_attempts`` CodeQL adjudication runs.
# Reported as attempts saved (units are LLM calls).  Dollar conversion is
# operator-dependent so we don't bake a price in.
_DEFAULT_TIER2_MAX_ATTEMPTS = 3


@dataclass
class CorpusReport:
    """Structured aggregation of one ``synth_results`` table.

    All counts are over rows whose ``status`` is one of
    ``sound`` / ``not_sound`` / ``no_barrier`` (pipeline-error rows are
    tracked separately so they don't pollute the rate).
    """

    # Headline counts (excludes pipeline_errors).
    processed: int = 0
    sound: int = 0
    not_sound: int = 0
    no_barrier: int = 0

    # status -> count for rows that never reached adjudication.
    pipeline_errors: Counter = field(default_factory=Counter)

    # Backend split for SOUND verdicts only.
    sound_by_backend: Counter = field(default_factory=Counter)   # "smt" / "codeql"

    # Per-CWE and per-language breakdowns: status -> backend -> count.
    by_cwe: Dict[str, Dict[str, Counter]] = field(default_factory=dict)
    by_language: Dict[str, Dict[str, Counter]] = field(default_factory=dict)

    # not_sound detail-shape distribution: e.g. "suppress_fp_failed",
    # "preserve_tp_failed", "both", "other".  Tells us whether the Tier 2
    # wall is over-restrictive guards or under-restrictive ones.
    not_sound_modes: Counter = field(default_factory=Counter)

    # Sample of not_sound finding_ids for spot-checking (capped).
    not_sound_samples: List[Tuple[str, str, str, str]] = field(
        default_factory=list,
    )                                                # (cve_id, cwe, lang, detail)

    @property
    def suppression_rate(self) -> Optional[float]:
        """``sound / (sound + not_sound)``.  None when nothing reached a
        verdict yet (in-flight run, very early)."""
        denom = self.sound + self.not_sound
        return self.sound / denom if denom else None

    @property
    def tier0_share_of_sound(self) -> Optional[float]:
        """Fraction of sound verdicts that came from Tier 0 (free SMT).
        Headline: how much of the suppression cost us zero LLM tokens."""
        if not self.sound:
            return None
        return self.sound_by_backend.get("smt", 0) / self.sound

    def tier0_attempts_saved(self, max_attempts: int = _DEFAULT_TIER2_MAX_ATTEMPTS) -> int:
        """Conservative count of LLM proposer attempts not spent because
        Tier 0 short-circuited.  Each Tier 0 SOUND row saves up to
        ``max_attempts`` LLM calls + the matching CodeQL adjudications."""
        return self.sound_by_backend.get("smt", 0) * max_attempts


def _classify_not_sound_mode(detail: str) -> str:
    """Map the ``detail`` string written by the bridge for a ``not_sound``
    row onto a coarse failure-mode bucket.

    The bridge writes:
      ``suppress_fp_failed(after=N)``    -- guard didn't kill the FP
      ``preserve_tp_failed(before=N)``  -- guard killed the FP AND the TP
      both, joined by ``"; "``           -- guard moved nothing
    """
    has_suppress = "suppress_fp_failed" in detail
    has_preserve = "preserve_tp_failed" in detail
    if has_suppress and has_preserve:
        return "both"
    if has_suppress:
        return "suppress_fp_failed"
    if has_preserve:
        return "preserve_tp_failed"
    return "other"


_NOT_SOUND_SAMPLES_CAP = 20


def analyze(synth_db: Path) -> CorpusReport:
    """Read ``synth_db`` and produce a :class:`CorpusReport`.

    Opens read-only via the SQLite URI scheme so a concurrent writer
    (the bridge mid-run) isn't blocked or affected.  Empty / missing
    table -> zero-counts report (no error)."""
    rep = CorpusReport()
    try:
        con = sqlite3.connect(f"file:{synth_db}?mode=ro", uri=True)
    except sqlite3.OperationalError:
        return rep
    try:
        rows = list(con.execute(
            "SELECT cve_id, cwe, repo_language, status, backend, detail "
            "FROM synth_results"
        ))
    except sqlite3.OperationalError:
        # Table doesn't exist yet (bridge hasn't written its first row).
        con.close()
        return rep
    con.close()

    for cve_id, cwe, lang, status, backend, detail in rows:
        if status in _PIPELINE_ERRORS:
            rep.pipeline_errors[status] += 1
            continue
        if status not in _OUTCOME_STATUSES:
            # Unknown status — surface under pipeline_errors so it doesn't
            # silently distort the rate.
            rep.pipeline_errors[status] += 1
            continue

        rep.processed += 1
        if status == "sound":
            rep.sound += 1
            rep.sound_by_backend[backend or ""] += 1
        elif status == "not_sound":
            rep.not_sound += 1
            mode = _classify_not_sound_mode(detail or "")
            rep.not_sound_modes[mode] += 1
            if len(rep.not_sound_samples) < _NOT_SOUND_SAMPLES_CAP:
                rep.not_sound_samples.append(
                    (cve_id, cwe, lang, (detail or "")[:80])
                )
        else:    # no_barrier
            rep.no_barrier += 1

        # Per-CWE / per-language breakdowns.  Backend bucket only meaningful
        # for the "sound" status; for the others we still track the count
        # under the empty-string backend so the table totals balance.
        rep.by_cwe.setdefault(cwe, {}).setdefault(status, Counter())[backend or ""] += 1
        rep.by_language.setdefault(lang, {}).setdefault(status, Counter())[backend or ""] += 1

    return rep


def _fmt_rate(n: int, d: int) -> str:
    """Render ``n/d (XX.X%)`` or ``n/d (-)`` when d==0."""
    if not d:
        return f"{n}/{d} (-)"
    return f"{n}/{d} ({100.0 * n / d:.1f}%)"


def render_text(rep: CorpusReport) -> str:
    """Plain-text report suitable for terminal display while the bridge
    is still running."""
    out: List[str] = []

    out.append("== Trust-witness corpus report ==")
    out.append("")
    out.append("Headline:")
    out.append(f"  processed (sound + not_sound + no_barrier): {rep.processed}")
    out.append(f"  sound                : {rep.sound}")
    out.append(f"  not_sound            : {rep.not_sound}")
    out.append(f"  no_barrier           : {rep.no_barrier}")
    if rep.suppression_rate is not None:
        out.append(
            f"  suppression rate     : {_fmt_rate(rep.sound, rep.sound + rep.not_sound)}"
        )
    else:
        out.append("  suppression rate     : (no verdicts yet)")
    if rep.pipeline_errors:
        out.append(f"  pipeline errors      : {dict(rep.pipeline_errors)}")
    out.append("")

    out.append("Tier 0 vs Tier 2 (backend split among SOUND verdicts):")
    if rep.sound:
        for backend in ("smt", "codeql", ""):
            n = rep.sound_by_backend.get(backend, 0)
            label = backend if backend else "<unknown>"
            out.append(f"  {label:8s} : {_fmt_rate(n, rep.sound)}")
        attempts = rep.tier0_attempts_saved()
        out.append(
            f"  Tier 0 attempts saved (rough): ~{attempts} LLM proposer "
            f"calls + matched adjudications"
        )
    else:
        out.append("  (no sound verdicts yet)")
    out.append("")

    out.append("not_sound failure modes:")
    if rep.not_sound:
        for mode in ("suppress_fp_failed", "preserve_tp_failed", "both", "other"):
            n = rep.not_sound_modes.get(mode, 0)
            out.append(f"  {mode:22s} : {_fmt_rate(n, rep.not_sound)}")
    else:
        out.append("  (no not_sound verdicts yet)")
    out.append("")

    out.append("By CWE:")
    if rep.by_cwe:
        out.append(f"  {'CWE':10s} {'sound':>16s} {'not_sound':>10s} {'no_barrier':>11s}")
        for cwe in sorted(rep.by_cwe):
            statuses = rep.by_cwe[cwe]
            smt = statuses.get("sound", Counter()).get("smt", 0)
            ql = statuses.get("sound", Counter()).get("codeql", 0)
            ns = sum(statuses.get("not_sound", Counter()).values())
            nb = sum(statuses.get("no_barrier", Counter()).values())
            out.append(
                f"  {cwe:10s} {smt:>5d} smt {ql:>5d} ql {ns:>10d} {nb:>11d}"
            )
    else:
        out.append("  (no rows yet)")
    out.append("")

    out.append("By language:")
    if rep.by_language:
        out.append(f"  {'lang':12s} {'sound':>16s} {'not_sound':>10s} {'no_barrier':>11s}")
        for lang in sorted(rep.by_language):
            statuses = rep.by_language[lang]
            smt = statuses.get("sound", Counter()).get("smt", 0)
            ql = statuses.get("sound", Counter()).get("codeql", 0)
            ns = sum(statuses.get("not_sound", Counter()).values())
            nb = sum(statuses.get("no_barrier", Counter()).values())
            out.append(
                f"  {lang:12s} {smt:>5d} smt {ql:>5d} ql {ns:>10d} {nb:>11d}"
            )
    else:
        out.append("  (no rows yet)")
    out.append("")

    if rep.not_sound_samples:
        out.append(
            f"not_sound samples (first {len(rep.not_sound_samples)} of "
            f"{rep.not_sound}, capped):"
        )
        for cve_id, cwe, lang, detail in rep.not_sound_samples:
            out.append(f"  {cve_id:24s} {cwe:8s} {lang:12s} {detail}")
    return "\n".join(out)


def main(argv=None) -> None:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--synth-db", type=Path, default=Path("/data/corpus/synth-results-tier0.db"),
        help="trust-witness bridge's synth_results SQLite (default: "
             "/data/corpus/synth-results-tier0.db)",
    )
    args = ap.parse_args(argv)
    rep = analyze(args.synth_db)
    print(render_text(rep), flush=True)


if __name__ == "__main__":
    main()
