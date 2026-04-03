"""Concrete dispatch tasks for the orchestrator.

Each task defines: what to prompt, what schema, which model, and
any post-processing. The generic dispatcher in dispatch.py handles
the mechanics (threading, progress, cost, errors).
"""

import logging
from typing import Dict, List, Optional

from .dispatch import DispatchTask
from .prompts import (
    build_analysis_prompt_from_finding, build_analysis_schema,
    build_exploit_prompt_from_finding, build_patch_prompt_from_finding,
    ANALYSIS_SYSTEM_PROMPT, EXPLOIT_SYSTEM_PROMPT, PATCH_SYSTEM_PROMPT,
)

logger = logging.getLogger(__name__)


class AnalysisTask(DispatchTask):
    """Per-finding exploitability analysis."""

    name = "analysis"
    model_role = "analysis"

    def build_prompt(self, finding):
        return build_analysis_prompt_from_finding(finding)

    def get_schema(self, finding):
        return build_analysis_schema(has_dataflow=finding.get("has_dataflow", False))

    def get_system_prompt(self):
        return ANALYSIS_SYSTEM_PROMPT

    def process_result(self, item, result):
        out = super().process_result(item, result)
        # Compute CVSS score from vector if LLM provided one
        from packages.cvss import compute_score_safe
        cvss_vector = out.get("cvss_vector")
        if cvss_vector:
            score, _ = compute_score_safe(cvss_vector)
            if score is not None:
                out["cvss_score_estimate"] = score
        return out


class ExploitTask(DispatchTask):
    """Exploit PoC generation for exploitable findings."""

    name = "exploit"
    model_role = "code"
    temperature = 0.8
    budget_cutoff = 0.85

    def select_items(self, findings, prior_results):
        return [f for f in findings
                if prior_results.get(f.get("finding_id"), {}).get("is_exploitable")
                and not prior_results.get(f.get("finding_id"), {}).get("exploit_code")]

    def build_prompt(self, finding):
        return build_exploit_prompt_from_finding(finding)

    def get_system_prompt(self):
        return EXPLOIT_SYSTEM_PROMPT

    def get_schema(self, finding):
        return None  # Free-form code generation

    def finalize(self, results, prior_results):
        for r in results:
            fid = r.get("finding_id")
            if fid and fid in prior_results and "error" not in r:
                content = r.get("content", "")
                if content:
                    prior_results[fid]["exploit_code"] = content
                    prior_results[fid]["has_exploit"] = True
        return results


class PatchTask(DispatchTask):
    """Secure patch generation for exploitable findings."""

    name = "patch"
    model_role = "code"
    temperature = 0.3
    budget_cutoff = 0.85

    def select_items(self, findings, prior_results):
        return [f for f in findings
                if prior_results.get(f.get("finding_id"), {}).get("is_exploitable")
                and not prior_results.get(f.get("finding_id"), {}).get("patch_code")]

    def build_prompt(self, finding):
        return build_patch_prompt_from_finding(finding)

    def get_system_prompt(self):
        return PATCH_SYSTEM_PROMPT

    def get_schema(self, finding):
        return None  # Free-form code generation

    def finalize(self, results, prior_results):
        for r in results:
            fid = r.get("finding_id")
            if fid and fid in prior_results and "error" not in r:
                content = r.get("content", "")
                if content:
                    prior_results[fid]["patch_code"] = content
                    prior_results[fid]["has_patch"] = True
        return results


class ConsensusTask(DispatchTask):
    """Independent second opinion from consensus models."""

    name = "consensus"
    model_role = "consensus"
    budget_cutoff = 0.70

    def get_models(self, role_resolution):
        return role_resolution.get("consensus_models", [])

    def select_items(self, findings, prior_results):
        # Only findings that were successfully analysed and are true positives
        return [f for f in findings
                if "error" not in prior_results.get(f.get("finding_id"), {"error": True})
                and prior_results.get(f.get("finding_id"), {}).get("is_true_positive", True)]

    def build_prompt(self, finding):
        return build_analysis_prompt_from_finding(finding)

    def get_schema(self, finding):
        return build_analysis_schema(has_dataflow=finding.get("has_dataflow", False))

    def get_system_prompt(self):
        return ANALYSIS_SYSTEM_PROMPT

    def finalize(self, results, prior_results):
        """Apply verdict rules across analysis + consensus results.

        Verdict rules:
        - 1 consensus model: either says exploitable -> exploitable (conservative)
        - 2+ consensus models: majority across analysis + all consensus
        """
        # Group consensus results by finding_id
        consensus_by_finding: Dict[str, List[Dict]] = {}
        for r in results:
            fid = r.get("finding_id")
            if fid and "error" not in r:
                consensus_by_finding.setdefault(fid, []).append(r)

        # Apply verdicts to prior results (mutate in place)
        for fid, primary in prior_results.items():
            if isinstance(primary, dict) and "error" not in primary:
                consensus_analyses = consensus_by_finding.get(fid, [])
                if not consensus_analyses:
                    continue

                primary_exploitable = primary.get("is_exploitable", False)
                verdicts = [primary_exploitable]
                for ca in consensus_analyses:
                    verdicts.append(ca.get("is_exploitable", False))

                n_consensus = len(consensus_analyses)
                if n_consensus == 1:
                    final = any(verdicts)
                else:
                    final = sum(1 for v in verdicts if v) > len(verdicts) / 2

                disputed = not all(v == verdicts[0] for v in verdicts)
                primary["consensus"] = "disputed" if disputed else "agreed"
                primary["is_exploitable"] = final
                primary["consensus_analyses"] = [
                    {"model": ca.get("analysed_by", "?"),
                     "is_exploitable": ca.get("is_exploitable"),
                     "reasoning": ca.get("reasoning", "")}
                    for ca in consensus_analyses
                ]

        return results


class GroupAnalysisTask(DispatchTask):
    """Cross-finding group analysis for related findings."""

    name = "group_analysis"
    model_role = "analysis"
    temperature = 0.3

    def __init__(self, results_by_id: Optional[Dict[str, Dict]] = None):
        self.results_by_id = results_by_id or {}

    def select_items(self, groups, prior_results):
        return [g for g in groups if len(g.get("finding_ids", [])) >= 2]

    def build_prompt(self, group):
        finding_ids = group.get("finding_ids", [])
        criterion = group.get("criterion", "unknown")
        criterion_value = group.get("criterion_value", "?")

        summaries = []
        for fid in finding_ids:
            r = self.results_by_id.get(fid, {})
            exploitable = r.get("is_exploitable", "unknown")
            score = r.get("exploitability_score", "?")
            reasoning = (r.get("reasoning") or "")[:300]
            summaries.append(f"- {fid}: exploitable={exploitable}, score={score}\n  {reasoning}")

        findings_text = "\n".join(summaries)

        return f"""You are analysing {len(finding_ids)} related security findings that share: {criterion} = {criterion_value}

## Findings

{findings_text}

## Your task

Analyse the relationship between these findings:
1. **Shared root cause?** Do they stem from the same underlying issue?
2. **Attack chaining?** Can exploiting one finding enable or amplify another?
3. **Inconsistencies?** Do any findings have contradictory verdicts that should be reviewed?

Return a concise analysis. If there's no meaningful relationship beyond the shared {criterion}, say so.
"""

    def get_system_prompt(self):
        return "You are a security research analyst reviewing cross-finding patterns."

    def get_item_id(self, group):
        return group.get("group_id", "unknown")

    def get_item_display(self, group):
        return f"{group.get('criterion', '?')}={group.get('criterion_value', '?')[:30]}"

    def get_schema(self, group):
        return None  # Free-form analysis


class RetryTask(AnalysisTask):
    """Stage F: self-consistency check + retry contradictions and low confidence.

    Runs _check_self_consistency to flag contradictions, then selects findings
    that are self-contradictory OR have ambiguous scores (0.3-0.7).

    For contradictions: provides feedback context ("you said X but marked Y").
    For low confidence: fresh re-analysis without prior context.
    """

    name = "retry"
    LOW = 0.3
    HIGH = 0.7

    def __init__(self, results_by_id: Optional[Dict[str, Dict]] = None):
        self.results_by_id = results_by_id or {}

    def select_items(self, findings, prior_results):
        # Run self-consistency check to flag contradictions
        from packages.llm_analysis.orchestrator import _check_self_consistency
        _check_self_consistency(prior_results)

        selected = []
        for f in findings:
            fid = f.get("finding_id")
            r = prior_results.get(fid, {})
            if "error" in r:
                continue
            # Contradiction
            if r.get("self_contradictory"):
                selected.append(f)
                continue
            # Low confidence
            try:
                score = float(r.get("exploitability_score"))
            except (ValueError, TypeError):
                continue
            if self.LOW <= score <= self.HIGH:
                selected.append(f)
        return selected

    def build_prompt(self, finding):
        fid = finding.get("finding_id")
        r = self.results_by_id.get(fid, {})

        if r.get("self_contradictory"):
            # Stage F: feedback with contradiction context
            contradictions = r.get("contradictions", [])
            original_reasoning = (r.get("reasoning") or "")[:500]
            base_prompt = super().build_prompt(finding)
            return f"""{base_prompt}

**IMPORTANT: Your previous analysis of this finding contradicted itself:**
{chr(10).join(f'- {c}' for c in contradictions)}

Previous reasoning excerpt:
> {original_reasoning}

Resolve the contradiction. Ensure your ruling, is_true_positive, and is_exploitable
are consistent with your reasoning."""
        else:
            # Low confidence: fresh re-analysis
            return super().build_prompt(finding)

    def finalize(self, results, prior_results):
        for r in results:
            fid = r.get("finding_id")
            if not fid or "error" in r:
                continue
            try:
                score = float(r.get("exploitability_score"))
            except (ValueError, TypeError):
                score = None

            was_contradictory = prior_results.get(fid, {}).get("self_contradictory")
            decisive = score is not None and not (self.LOW <= score <= self.HIGH)

            if was_contradictory or decisive:
                prior_results[fid] = r
            prior_results[fid]["retried"] = True
            if not was_contradictory and not decisive:
                prior_results[fid]["low_confidence"] = True
        return results
