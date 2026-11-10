"""Side-effect-free report capabilities, scoped to actual command boundaries.

This registry describes completion adapters, not a promise that every subcommand
of a domain accepts report flags. Specialized views keep their own serializers.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class CommandCapability:
    command: str
    document_kind: str
    artifact_policy: str
    summary: str
    compatibility: str = ""
    formats: tuple[str, ...] = ()


CAPABILITIES = (
    CommandCapability("panel-replay", "panel-replay", "explicit companion export; native --out retained", "native stdout and mechanical stderr quick view", "offline estimator comparison; no verdict mutation or model calls"),
    CommandCapability("scan", "triage", "automatic", "terminal and summary.md"),
    CommandCapability("codeql", "triage", "automatic", "terminal and summary.md"),
    CommandCapability("validate", "validation", "automatic", "terminal, summary.md and legacy summary.txt"),
    CommandCapability("agentic", "agentic", "automatic", "summary.md and existing terminal summary"),
    CommandCapability("project report", "project", "automatic", "terminal and summary.md", "native finding/annotation exports retained"),
    CommandCapability("project threat-model report", "threat-model", "explicit companion export; native atomic report retained", "native counts or JSON stdout; portable summary on stderr", "recorded statuses/provenance stay model claims; no oracle or lifecycle adoption"),
    CommandCapability("sca scan", "sca", "automatic", "terminal and summary.md", "--html adds HTML"),
    CommandCapability("sca render", "sca", "existing output policy", "terminal and summary.md", "offline; legacy Markdown/SARIF switches retained"),
    CommandCapability("sca diff", "sca-diff", "explicit destination required", "existing stdout; report summary on stderr", "native --json/--out and gate status retained"),
    CommandCapability("sca check", "sca-check", "explicit destination required", "existing stdout; report summary on stderr", "native verdict and unavailable-advisory status retained"),
    CommandCapability("sca verify", "sca-verify", "explicit destination required", "existing stdout; report summary on stderr", "native overlay, delta artifacts and gate status retained"),
    CommandCapability("sca upgrade", "sca-upgrade", "explicit destination required", "existing stdout; report summary on stderr", "pairwise, candidates and add/remove comparisons; domain status retained"),
    CommandCapability("sca fix", "sca-fix", "explicit destination required", "existing stdout; report summary on stderr", "standard plan/proposed/apply modes; native change artifacts retained"),
    CommandCapability("sca fix --harden", "sca-harden", "explicit destination required", "existing stdout; report summary on stderr", "planner decisions, check gates, self-test and apply phases retained"),
    CommandCapability("sca fix --cve-only", "sca-fix-cve", "explicit destination required", "existing stdout; report summary on stderr", "native patch, compatibility and auxiliary resolver/hash-pin results retained"),
    CommandCapability("sca triage", "sca-triage", "explicit destination required", "existing stdout; report summary on stderr", "candidate listing, LLM gate outcomes and re-audit flags; no extra inference or curation writes"),
    CommandCapability("sca suppress list/check", "sca-suppress", "explicit destination required", "existing stdout; report summary on stderr", "native entries, orphan/expired check groups and gate status retained"),
    CommandCapability("sca fix-diff", "sca-fix-diff", "explicit destination required", "existing stdout; report summary on stderr", "native CVE discovery summary, caps and exit status retained; no extra agent calls"),
    CommandCapability("sca fingerprint", "sca-fingerprint", "explicit destination required", "existing stdout; report summary on stderr", "compute/save/check modes; native drift and missing-baseline statuses retained"),
    CommandCapability("sca health", "sca-health", "explicit destination required", "existing stdout; report summary on stderr", "live reachability only; native gate and offline refusal retained"),
    CommandCapability("sca bump", "sca-bump", "explicit destination required", "existing stdout; report summary on stderr", "native JSON/PR output retained; verdicts separate from actual rewrites"),
    CommandCapability("sca sbom inspect", "sbom-inspect", "explicit output or native directory", "stderr and captured summary", "native evidence formats retained", ("markdown", "json", "xml")),
    CommandCapability("sca sbom stats", "sbom-stats", "explicit output or native directory", "stderr and captured summary", "native evidence formats retained", ("markdown", "json", "xml")),
    CommandCapability("sca sbom diff", "sbom-diff", "explicit output or native directory", "stderr and captured summary", "native evidence formats retained", ("markdown", "json", "xml")),
    CommandCapability("sca sbom why", "sbom-why", "explicit output or native directory", "stderr and captured summary", "native evidence formats retained", ("markdown", "json", "xml")),
    CommandCapability("sca sbom plan", "sbom-plan", "explicit output or native directory", "stderr and captured summary", "native evidence formats retained", ("markdown", "json", "xml")),
    CommandCapability("sca sbom verify-plan", "sbom-verify-plan", "explicit output or native directory", "stderr and captured summary", "native evidence formats retained", ("markdown", "json", "xml")),
    CommandCapability("sca sbom collect", "sbom-collect", "explicit output or native directory", "stderr and captured summary", "native evidence formats retained", ("markdown", "json", "xml")),
    CommandCapability("sca sbom notices", "sbom-notices", "explicit output or native directory", "stderr and captured summary", "native evidence formats retained", ("markdown", "json", "xml")),
    CommandCapability("web", "web", "automatic", "terminal and summary.md", "existing redaction applies before capture"),
    CommandCapability("fuzz", "fuzz", "automatic", "terminal and summary.md", "corpus preparation excluded"),
    CommandCapability("openant", "openant", "automatic", "terminal and summary.md", "recovered hints separate from findings"),
    CommandCapability("audit run", "audit", "automatic detailed reports", "existing terminal summary and summary.md", "canonical domain JSON retained; rendered JSON uses companion filename"),
    CommandCapability("audit resume", "audit", "automatic detailed reports", "existing terminal summary and summary.md", "canonical domain JSON retained; rendered JSON uses companion filename"),
    CommandCapability("audit report", "audit", "automatic detailed reports", "existing terminal summary and summary.md", "canonical domain JSON retained; rendered JSON uses companion filename"),
    CommandCapability("engagement report", "engagement", "automatic detailed reports", "existing terminal summary and summary.md", "canonical domain JSON retained; rendered JSON uses companion filename"),
    CommandCapability("describe", "describe", "explicit destination required", "existing stdout and captured summary", "no default file writes"),
    CommandCapability("understand native map/hunt/trace/resume", "understand", "explicit export; portable-reports directory default", "existing stdout; report summary on stderr", "captured counts and bounded metadata; resume costs already include carried checkpoints; source-tree in-session modes unchanged"),
    CommandCapability("recall-measure run", "recall-evaluation", "explicit portable export; existing native report policy retained", "native measurement summary; portable summary on stderr", "recall ground truth remains segregated from FP suppression and model learning; no additional detector execution"),
    CommandCapability("cve-checker", "cve-checker", "explicit export; native checker directory default", "native JSON stdout; report summary on stderr", "public provenance gates and actual promotion outcomes retained; no extra synthesis or rule execution"),
    CommandCapability("cve-diff run (libexec and Typer)", "cve-diff", "explicit portable export; per-CVE directory default", "native stdout and sentinel; mechanical summary on stderr even without export", "native OSV/Markdown/flow artifacts and each interface's exit policy retained; no discovery or model replay"),
    CommandCapability("frida", "frida", "explicit export; lifecycle directory default", "existing stdout; report summary on stderr", "capture metadata only; no raw events, hook source, seed data or instrumentation replay"),
    CommandCapability("binary runtime/trace-parser", "frida", "delegated; Frida run directory default", "native stdout; report summary from Frida", "validated report controls forwarded; existing trace gates, child count and sandbox permissions retained"),
    CommandCapability("diagram / binary diagram", "diagrams", "explicit companion export; native diagrams.md and force policy retained", "native diagram output; portable summary on stderr", "typed Mermaid source/fallback captured from one native render; input snapshots retained"),
    CommandCapability("binary graph", "binary-graph-query", "explicit export; native run directory or database parent default", "native text/JSON stdout; report summary on stderr", "single query metadata; raw evidence properties omitted; existing child status retained"),
    CommandCapability("binary harness", "binary-harness-plan", "explicit export; native run directory default", "native text/JSON stdout; report summary on stderr", "plan status retained; verification requirements are not executed checks; no extra generation or ranking"),
    CommandCapability("binary hunt", "binary-hunt", "explicit export; native run directory default", "native text/JSON stdout; report summary on stderr", "separate query populations and native degradation retained; no extra hunt or finding inference"),
    CommandCapability("binary siblings", "binary-siblings", "explicit export; native run directory default", "native text/JSON stdout; report summary on stderr", "structural review leads remain distinct from findings; bounded detail and native caveats retained"),
    CommandCapability("binary corpus", "binary-corpus", "explicit export; native run directory default", "existing stdout; report summary on stderr", "single captured profile; skip counts and native caps retained; sample contents and names omitted"),
    CommandCapability("binary map/investigate", "binary-map", "explicit export; native run directory default", "existing stdout; report summary on stderr", "final map and current phase statuses; no intermediate-population aggregation or active replay"),
    CommandCapability("binary report", "binary", "explicit export", "existing report display or export summary", "no analysis is run"),
)


def _capability_row(capability: CommandCapability) -> dict:
    from .renderers import available_formats
    return {**asdict(capability), "formats": [name for name in available_formats() if not capability.formats or name in capability.formats], "summary_independent": True}


def command_capabilities() -> list[dict]:
    return [_capability_row(capability) for capability in CAPABILITIES]
