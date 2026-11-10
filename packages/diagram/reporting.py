"""Snapshot-driven diagrams for the reporting engine; no live artifact reads."""
from __future__ import annotations

from typing import Any
from pathlib import Path
import re

from core.reporting.document import Block, json_value
from . import attack_paths, context_map, findings_summary, flow_trace


def build_report_blocks(inputs: dict[str, Any], *, snapshot_id: str) -> list[Block]:
    """Capture generated source and its textual equivalent with provenance.

    Uses the existing bounded generators. Unsupported graphs remain explicit
    rather than being regenerated from a changing output directory at render time.
    """
    inputs = json_value(inputs)
    blocks = []
    findings = inputs.get("findings")
    if isinstance(findings, list) and findings:
        blocks.append(Block("diagram", title="Finding verdicts",
                            text=f"Verdict distribution over {len(findings)} captured finding occurrences; the findings table provides the exact values.",
                            source_refs=[snapshot_id],
                            extensions={"mermaid": findings_summary.generate_verdict_pie(findings), "generator": "raptor.findings_summary/v1"}))
        blocks.append(Block("diagram", title="Finding types",
                            text=f"Type distribution over {len(findings)} captured finding occurrences; counts describe scanner/analysis classifications.",
                            source_refs=[snapshot_id],
                            extensions={"mermaid": findings_summary.generate_type_pie(findings), "generator": "raptor.findings_summary/v1"}))
    for key, generator, description in (
        ("context_map", context_map.generate, "Recorded code context; graph edges do not establish validation or exploitability."),
        ("flow_trace", flow_trace.generate, "Recorded flow trace; see captured evidence for each step."),
        ("attack_paths", attack_paths.generate, "Recorded candidate paths; hypotheses remain distinct from validated evidence."),
    ):
        if key in inputs:
            try:
                source = generator(inputs[key])
                blocks.append(Block("diagram", title=key.replace("_", " ").title(), text=description,
                                    source_refs=[snapshot_id], extensions={"mermaid": source, "generator": f"raptor.{key}/v1"}))
            except (TypeError, ValueError, KeyError, AttributeError):
                blocks.append(Block("paragraph", title=key, text="Diagram unavailable: captured input did not match the generator schema."))
    return blocks


def capture_directory_blocks(output_dir: Path) -> list[Block]:
    """Compatibility adapter: capture existing rich diagrams once, before freeze.

    Extract typed diagram sources from the existing generator's fixed section
    and fence structure. This adapter never parses arbitrary report Markdown.
    Renderers validate captured Mermaid again and keep a textual fallback.
    """
    from .renderer import render_directory
    import os
    from core.json.bounded import loads_bounded
    from core.source.beneath import open_regular_beneath
    output_dir = Path(output_dir)
    remaining = 32 * 1024 * 1024
    refusals = []
    def load_artifact(path):
        nonlocal remaining
        try:
            Path(path).lstat()
        except FileNotFoundError:
            return None  # absent optional artifacts are normal
        limit = min(8 * 1024 * 1024, remaining)
        stream = open_regular_beneath(output_dir, Path(path).relative_to(output_dir), mode="rb")
        if stream is None:
            refusals.append("An additional diagram artifact was unavailable or unsafe; it was not captured.")
            return None
        try:
            with stream:
                if os.fstat(stream.fileno()).st_size > limit:
                    raise ValueError("Diagram capture budget exceeded")
                raw = stream.read(limit + 1)
            remaining -= len(raw)
            return loads_bounded(raw, max_bytes=limit)
        except (OSError, ValueError, RecursionError):
            refusals.append("An additional diagram artifact exceeded capture limits or contained invalid JSON; it was not captured.")
            return None
    try:
        content = render_directory(output_dir, artifact_loader=load_artifact, allow_graph_fallback=False)
    except Exception:  # optional diagram capture must not hide completed results
        return [Block("paragraph", title="Additional diagrams",
                      text="Diagram capture unavailable; the finding results and other report sections are retained.",
                      extensions={"raptor.diagram_export": True})]
    blocks = directory_blocks_from_rendered(content)
    for note in dict.fromkeys(refusals):
        blocks.append(Block("paragraph", title="Additional diagram limitations", text=note,
                            extensions={"raptor.diagram_export": True}))
    return blocks


def directory_blocks_from_rendered(content: str, *, include_findings_summary: bool = False) -> list[Block]:
    """Adapt the fixed directory renderer's output, never arbitrary Markdown.

    Standalone diagram exports retain pies; finding reports already supply
    typed summary pies and omit those duplicates through the default mode.
    """
    blocks = []
    fence = re.compile(r"(?ms)^```mermaid\n(.*?)^```[ \t]*$")  # line-model: render_directory emits literal-LF structural fences in memory; this is not raw Markdown input.
    for match in re.finditer(r"(?ms)^## ([^\n]+)\n(.*?)(?=^## |\Z)", content):
        title, body = match.groups()
        # Summary pies already have a typed equivalent for this population.
        # Filter during the existing section walk instead of rescanning text.
        if title == "Findings Summary" and not include_findings_summary:
            continue
        sources = [m.group(1).strip() for m in fence.finditer(body)]
        prose = fence.sub("", body).strip()
        if not sources:
            blocks.append(Block("paragraph", title=title, text=title + ": " + prose,
                                extensions={"raptor.diagram_export": True}))
        for i, source in enumerate(sources, 1):
            blocks.append(Block("diagram", title=title if len(sources) == 1 else f"{title} ({i})",
                                text=title + ": " + (prose or "Recorded domain graph; the captured source retains node and edge evidence."),
                                extensions={"raptor.diagram_export": True, "mermaid": source,
                                            "generator": "raptor.diagram.directory/v1"}))
    return blocks
