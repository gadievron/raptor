"""Structured native result reporting for domains that do not speak SARIF."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .adapters import native_findings
from .builders import build_document
from .document import Block, MAX_FINDINGS, ReportContext, StageEnvelope, json_value
from .service import capture_failure_summary, complete_reporting


def result_blocks(value: Any, *, title: str = "Recorded result", limit: int = 5000) -> list[Block]:
    """Keep nested results structured, with explicit presentation bounds.

    The complete JSON payload remains in the context. No Markdown parsing,
    business-rule inference, or new domain status taxonomy is involved.
    """
    remaining = [limit]

    def convert(item, label, depth=0):
        remaining[0] -= 1
        if remaining[0] < 0 or depth > 12:
            return Block("paragraph", title=label, text="Presentation truncated; complete structured data is retained in report-context.json.")
        if isinstance(item, dict):
            scalar_rows = []
            children = []
            for k, v in item.items():
                if remaining[0] <= 0:
                    children.append(Block("paragraph", text="Additional fields omitted from presentation; complete data retained in report-context.json."))
                    break
                if isinstance(v, (dict, list)):
                    children.append(convert(v, k, depth + 1))
                elif isinstance(v, str) and ("\n" in v or len(v) > 300):
                    remaining[0] -= 1
                    kind = "code" if k in {"code", "snippet", "exploit_code", "patch_code"} else "paragraph"
                    children.append(Block(kind, title=k, text=v))
                else:
                    remaining[0] -= 1
                    scalar_rows.append([k, v])
            if scalar_rows:
                children.insert(0, Block("table", columns=["Field", "Value"], rows=scalar_rows))
            return Block("section", title=label, children=children)
        if isinstance(item, list):
            children = []
            for i, v in enumerate(item):
                children.append(convert(v, f"Record {i + 1}", depth + 1))
                if remaining[0] < 0:
                    break
            return Block("section", title=label, children=children)
        return Block("paragraph", title=label, text="not recorded" if item is None else str(item))

    return [convert(json_value(value), title)]


@dataclass
class NativeResult:
    kind: str
    target: str
    run_id: str
    payload: dict | list
    findings: list[dict] | None = None
    state: str = "unknown"
    diagnostics: list[str] | None = None
    stages: list[StageEnvelope] | None = None
    triage: bool = False
    metrics: dict | None = None
    metadata: dict | None = None
    blocks: list[Block] | None = None
    artifacts: list[dict] | None = None
    pass_id: str = ""
    attempt_id: str = ""
    parents: list[str] | None = None
    lifecycle_dir: Path | None = None
    lifecycle_producer: str | None = None
    lifecycle_metadata: dict | None = None

    def build(self):
        payload = json_value(self.payload)
        findings = self.findings
        diagnostics = list(self.diagnostics or [])
        if findings is not None and len(findings) > MAX_FINDINGS:
            diagnostics.append(f"Report finding table truncated: {MAX_FINDINGS} of {len(findings)} observations; complete domain payload retained")
        normalized = native_findings((findings or [])[:MAX_FINDINGS], run_id=self.run_id, producer=self.kind, triage=self.triage,
                                     pass_id=self.pass_id, attempt_id=self.attempt_id)
        context = ReportContext(self.kind, self.run_id, target=self.target, state=self.state,
                                findings=normalized, diagnostics=diagnostics, stages=list(self.stages or []),
                                artifacts=list(self.artifacts or []),
                                pass_id=self.pass_id, attempt_id=self.attempt_id, parents=list(self.parents or []),
                                extensions={"raptor.result": payload, "raptor.findings_available": findings is not None,
                                            "raptor.metrics": self.metrics or {},
                                            "raptor.metadata": self.metadata or {},
                                            "raptor.result_sections": [asdict(b) for b in self.blocks or []],
                                            "raptor.accounting": {"recorded_findings": len(findings)} if findings is not None else {}})
        if self.lifecycle_dir is not None:
            from copy import deepcopy
            from .lifecycle import apply_lifecycle
            context.stages = deepcopy(context.stages)
            apply_lifecycle(context, self.lifecycle_dir, producer_command=self.lifecycle_producer, metadata=self.lifecycle_metadata)
        document = build_document(context, blocks=[*(self.blocks or []), *result_blocks(payload)])
        document.metadata.update(self.metadata or {})
        return context, document


def complete_native_result(result: NativeResult, output_dir: Path, *, stem: str, options=None, stream=None):
    from .options import ReportOptions
    options = (options or ReportOptions()).validate()
    try:
        context, document = result.build()
    except (ValueError, TypeError, OSError) as exc:
        return capture_failure_summary(result.kind, result.run_id, result.target, output_dir, cause=exc,
                                       artifacts=result.artifacts, stem=stem, stream=stream)
    return complete_reporting(context, output_dir, document=document, stem=stem, options=options, stream=stream)
