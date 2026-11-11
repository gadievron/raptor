"""Portable presentation of one completed offline panel replay."""
from __future__ import annotations

import statistics
from typing import TYPE_CHECKING

from core.reporting.document import Block, Inline, ReportDocument, digest
from core.security.redaction import redact_secrets

if TYPE_CHECKING:
    from .replay import ReplayReport


def build_document(report: ReplayReport) -> ReportDocument:
    """Read computed results only; no estimation, source reads or scorecard IO."""
    limited: set[str] = set()

    def capture(value: str, label: str) -> str:
        text = redact_secrets(value).replace("\n", " ").replace("\r", " ")
        if len(text) > 64:
            limited.add(label)
        return text[:64]

    def rate(value: float) -> str:
        if report.total_findings_with_panel <= report.n_no_recorded_verdict:
            return "unavailable (no comparable recorded verdicts)"
        return f"{value:.1%}"

    metrics = {"Sources": len(report.sources), "Panel records": report.total_panels,
               "Findings with usable panel": report.total_findings_with_panel,
               "Distinct models": len(report.distinct_models), "Distinct decision classes": len(report.distinct_decision_classes)}
    blocks = [Block("table", title="Headline metrics", columns=["Metric", "Value"], rows=[
        ["Flip rate", rate(report.flip_rate)], ["Flips to exploitable", rate(report.flip_to_exploitable_rate)],
        ["Flips to NOT exploitable", rate(report.flip_to_not_exploitable_rate)],
        ["Findings with no recorded verdict (excluded from flip rates)", report.n_no_recorded_verdict]])]
    if report.distinct_models:
        blocks.append(Block("table", title="Recorded models", columns=["Model"],
                            rows=[[capture(model, "Model")] for model in report.distinct_models]))
    if report.total_findings_with_panel:
        maximum = max(report.posterior_distribution.values(), default=1.0) or 1.0
        blocks.append(Block("table", title="Posterior distribution", columns=["bin", "count", "bar"],
                            rows=[[capture(label, "Posterior bin"), int(count), "█" * int(round(40 * count / maximum))]
                                  for label, count in report.posterior_distribution.items()]))
    if report.class_summaries:
        blocks.append(Block("table", title="Per-decision-class summary",
                            columns=["decision_class", "n", "→exploitable", "→not-exploitable", "converged", "iters"],
                            rows=[[capture(summary.decision_class, "Decision class"), summary.n_findings,
                                   summary.n_flips_to_exploitable, summary.n_flips_to_not_exploitable,
                                   "✓" if summary.converged else "×", summary.iterations]
                                  for summary in sorted(report.class_summaries, key=lambda value: value.decision_class)]))
        alphas: dict[str, list[float]] = {}
        betas: dict[str, list[float]] = {}
        for summary in report.class_summaries:
            for record in summary.model_reliabilities:
                alphas.setdefault(record["model"], []).append(record["alpha"])
                betas.setdefault(record["model"], []).append(record["beta"])
        blocks.append(Block("table", title="Inferred per-model reliability (averaged across classes)",
                            columns=["model", "mean α", "mean β", "n classes"],
                            rows=[[capture(model, "Model"), f"{statistics.mean(alphas[model]):.3f}",
                                   f"{statistics.mean(betas[model]):.3f}", len(alphas[model])] for model in sorted(alphas)]))
    else:
        blocks.append(Block("paragraph", title="Per-decision-class summary", inline=[Inline("emphasis", "No classes")]))
    document = ReportDocument("Panel-log replay", "panel-replay", "", summary=metrics, blocks=blocks,
                              diagnostics=["Offline estimator comparison only: a posterior above 0.5 disagrees with the recorded is_exploitable value when a flip is reported. Rendering neither validates findings nor changes recorded verdicts.",
                                           "Flip rates exclude findings with no recorded verdict. Corpus-wide reliability estimates are not new execution evidence."])
    if limited:
        document.diagnostics.append("Presentation truncated fields to 64 characters: " + ", ".join(sorted(limited))
                                    + ". Native replay JSON retains the original recorded strings.")
    document.extensions["raptor.truncated_fields"] = sorted(limited)
    document.snapshot_id = digest(document.to_dict())
    return document
