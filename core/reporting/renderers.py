"""Explicit format registry. Renderers consume captured data and perform no IO."""
from __future__ import annotations

from dataclasses import dataclass
from html import escape
import json
import re
from typing import Callable
from urllib.parse import quote, urlsplit
from xml.etree.ElementTree import Element, SubElement, tostring

from core.security.log_sanitisation import escape_nonprintable
from core.security.markdown_render import md_fence, md_inline, md_prose
from .document import Block, MAX_JSON_BYTES, ReportDocument, encode


@dataclass(frozen=True)
class RenderedReport:
    content: bytes
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True)
class Renderer:
    name: str
    extension: str
    media_type: str
    render: Callable[[ReportDocument], RenderedReport]
    version: str = "1"


def safe_mermaid(source: str) -> bool:
    """Conservative report subset; unsafe/unsupported source falls back to text."""
    return (len(source) <= 100_000 and len(source.splitlines()) <= 500
            and re.match(r"\s*(?:(?:flowchart|graph)\s+(?:TD|TB|BT|LR|RL)\b|pie\b)", source) is not None
            and not re.search(r"(?i)(%%\{|@\{|&|\bclick\b|\bstyle\b|\bclassDef\b|\blinkStyle\b|\bimage\b|\bicon\b|url\s*\(|//|https?:|javascript:|data:|file:|<|>|`)", source.replace("-->", "").replace("==>", "").replace("-.->", "")))


def _markdown(document: ReportDocument) -> RenderedReport:
    notes: list[str] = []

    def literal(value):
        # Escape link/image delimiters so partial constructs in separate
        # sanitized fields cannot become fetching markup when composed later.
        value = value.replace("\\", "\\\\")
        return re.sub(r"[\[\]!]", lambda match: f"&#{ord(match[0])};", value)

    def bounded(value, sanitizer, max_chars):
        if len(str(value)) > max_chars:
            notes.append("Markdown presentation truncated long values; complete content is retained in report-document.json")
        return sanitizer(value, max_chars=max_chars)

    def cell(value):
        return literal(bounded(value, md_inline, 4000))

    def inline(part) -> str:
        value = cell(part.text)
        if part.kind == "strong":
            return "**" + value + "**"
        if part.kind == "emphasis":
            return "*" + value + "*"
        if part.kind == "code":
            return "`" + bounded(part.text, md_inline, 4000) + "`"
        if part.kind == "link" and _link_allowed(part.url):
            return "[" + value + "](" + quote(part.url, safe="/:#?&=%+@") + ")"
        return value

    def block(b: Block, level: int = 2) -> str:
        lines = [("#" * min(level, 6) + " " + cell(b.title) + "\n") if b.title else ""]
        if b.kind == "paragraph":
            lines.append(literal(bounded(b.text, md_prose, 20_000)) + "".join(inline(p) for p in b.inline))
        elif b.kind == "table":
            lines.extend(["| " + " | ".join(cell(c) for c in b.columns) + " |", "|" + "|".join("---" for _ in b.columns) + "|"])
            lines.extend("| " + " | ".join(cell("—" if v is None else v) for v in row) + " |" for row in b.rows)
        elif b.kind == "list":
            lines.extend("- " + literal(bounded(item, md_inline, 2000)) for item in b.items)
        elif b.kind == "code":
            language = b.language if re.fullmatch(r"[a-zA-Z0-9_-]{0,30}", b.language) else ""
            content = bounded(b.text, md_fence, 200_000)
            lines.append(f"```{language}\n{content}\n```")
        elif b.kind == "diagram":
            lines.append(literal(bounded(b.text, md_prose, 20_000)))
            source = b.extensions.get("mermaid", "")
            if isinstance(source, str) and source and safe_mermaid(source):
                lines.append(f"```mermaid\n{md_fence(source, max_chars=100_000)}\n```")
            else:
                notes.append("Diagram visual unavailable; textual equivalent retained")
                if isinstance(source, str) and source:
                    # Retain labels/edges without admitting unsupported source
                    # to an executable Mermaid fence. The normal code-block
                    # path owns bounds and fence-break sanitisation.
                    lines.append(block(Block("code", title="Captured diagram source", text=source, language="text"), level + 1))
        elif b.kind == "legacy_markdown":
            # A snapshot digest establishes byte identity, not the provenance
            # of producer-built Markdown. Preserve it as inert literal content.
            notes.append("Legacy Markdown displayed as literal text; portable blocks are required for formatted presentation")
            content = bounded(b.text, md_fence, 200_000)
            lines.append(f"```text\n{content}\n```")
        elif b.kind != "section":
            raise ValueError(f"Unsupported report block: {b.kind}")
        lines.extend(block(child, level + 1) for child in b.children)
        return "\n\n".join(x for x in lines if x)

    lines = ["# " + cell(document.title), ""]
    lines.extend(f"**{cell(k)}:** {cell(v)}" for k, v in document.metadata.items() if v != "")
    if document.summary:
        lines.append(block(Block("table", title="Summary", columns=["Metric", "Value"], rows=[[k, v] for k, v in document.summary.items()])))
    if document.diagnostics:
        lines.append(block(Block("list", title="Limitations", items=document.diagnostics)))
    lines.extend(block(b) for b in document.blocks)
    if notes:
        lines.append(block(Block("list", title="Format notes", items=list(dict.fromkeys(notes)))))
    return RenderedReport(("\n\n".join(lines) + "\n").encode(), tuple(dict.fromkeys(notes)))


def _html(document: ReportDocument) -> RenderedReport:
    notes: list[str] = []
    def text(value: object) -> str:
        return escape(escape_nonprintable(str(value), preserve_newlines=True))

    def inline(part) -> str:
        value = text(part.text)
        tag = {"strong": "strong", "emphasis": "em", "code": "code"}.get(part.kind)
        if tag:
            return f"<{tag}>{value}</{tag}>"
        if part.kind == "link" and _link_allowed(part.url):
            return '<a href="' + text(part.url) + '">' + value + '</a>'
        return value

    def block(b: Block, level: int = 2) -> str:
        heading = f"<h{min(level, 6)}>{text(b.title)}</h{min(level, 6)}>" if b.title else ""
        if b.kind == "table":
            content = "<table><thead><tr>" + "".join(f"<th>{text(c)}</th>" for c in b.columns) + "</tr></thead><tbody>"
            content += "".join("<tr>" + "".join(f"<td>{text('—' if v is None else v)}</td>" for v in row) + "</tr>" for row in b.rows) + "</tbody></table>"
        elif b.kind == "list":
            content = "<ul>" + "".join(f"<li>{text(item)}</li>" for item in b.items) + "</ul>"
        elif b.kind in {"legacy_markdown", "code"}:
            if b.kind == "legacy_markdown":
                notes.append("Legacy Markdown displayed as literal text")
            content = "<pre>" + text(b.text) + "</pre>"
        elif b.kind in {"paragraph", "diagram"}:
            content = "<p>" + text(b.text) + "".join(inline(p) for p in b.inline) + "</p>"
            if b.kind == "diagram":
                notes.append("Diagram visual unavailable in static HTML; textual equivalent retained")
        elif b.kind == "section":
            content = ""
        else:
            raise ValueError(f"Unsupported report block: {b.kind}")
        return heading + content + "".join(block(c, level + 1) for c in b.children)

    body = "<h1>" + text(document.title) + "</h1>"
    body += block(Block("table", title="Metadata", columns=["Field", "Value"], rows=[[k, v] for k, v in document.metadata.items()]))
    body += block(Block("table", title="Summary", columns=["Metric", "Value"], rows=[[k, v] for k, v in document.summary.items()]))
    body += block(Block("list", title="Limitations", items=document.diagnostics)) if document.diagnostics else ""
    body += "".join(block(b) for b in document.blocks)
    if notes:
        body += block(Block("list", title="Format notes", items=list(dict.fromkeys(notes))))
    html = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + text(document.title) + '</title></head><body>' + body + '</body></html>\n'
    return RenderedReport(html.encode(), tuple(dict.fromkeys(notes)))


def _xml(document: ReportDocument) -> RenderedReport:
    """Serialize the report schema, explicitly not SARIF or another XML standard."""
    root = Element("raptor-report", {"schema-version": str(document.schema_version)})
    def text(value):
        value = escape_nonprintable(str(value), preserve_newlines=True)
        return "".join(c if (c in "\t\n\r" or 0x20 <= ord(c) <= 0xD7FF or 0xE000 <= ord(c) <= 0xFFFD or 0x10000 <= ord(c) <= 0x10FFFF)
                       else f"\\u{ord(c):04x}" for c in value)
    def append(parent: Element, key: str, value: object) -> None:
        node = SubElement(parent, "field", {"name": text(key)})
        if isinstance(value, dict):
            node.set("type", "object")
            for k, v in value.items():
                append(node, k, v)
        elif isinstance(value, list):
            node.set("type", "array")
            for v in value:
                append(node, "item", v)
        else:
            node.set("type", "null" if value is None else type(value).__name__)
            # XML 1.0 forbids surrogate/noncharacter code points even when
            # they arrived as valid JSON string escapes.
            node.text = text(value) if value is not None else ""
    for key, value in document.to_dict().items():
        append(root, key, value)
    return RenderedReport(tostring(root, encoding="utf-8", xml_declaration=True))


_RENDERERS: dict[str, Renderer] = {}


def _link_allowed(value: str) -> bool:
    try:
        return len(value) <= 4000 and urlsplit(value).scheme.lower() in {"http", "https"} and not any(ord(c) < 32 for c in value)
    except ValueError:
        return False


def register_renderer(renderer: Renderer) -> None:
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", renderer.name) or not re.fullmatch(r"\.[a-z0-9]{1,10}", renderer.extension):
        raise ValueError("Unsafe renderer name or extension")
    if renderer.name in _RENDERERS:
        raise ValueError(f"Renderer already registered: {renderer.name}")
    _RENDERERS[renderer.name] = renderer


def available_formats() -> tuple[str, ...]:
    return tuple(_RENDERERS)


def get_renderer(name: str) -> Renderer:
    name = "markdown" if name == "md" else name
    if name not in _RENDERERS:
        raise ValueError(f"Unsupported report format {name!r}; available: {', '.join(available_formats())}")
    return _RENDERERS[name]


def render_document(document: ReportDocument, format: str = "markdown") -> RenderedReport:
    # Validate in-memory data as strictly as offline imported documents.
    document = ReportDocument.from_dict(json.loads(encode(document.to_dict())))
    renderer = get_renderer(format)
    try:
        rendered = renderer.render(document)
        if (not isinstance(rendered, RenderedReport)
                or not isinstance(rendered.content, bytes)
                or not isinstance(rendered.diagnostics, tuple)
                or not all(isinstance(note, str) for note in rendered.diagnostics)):
            raise ValueError(f"{renderer.name} renderer returned invalid report content or diagnostics")
    except (OSError, ValueError, TypeError):
        raise
    except Exception as exc:  # noqa: BLE001 — isolate optional plugins; cancellation still propagates
        raise ValueError(f"{renderer.name} renderer failed ({type(exc).__name__})") from exc
    if len(rendered.content) > MAX_JSON_BYTES:
        raise ValueError("Rendered report exceeds 32 MiB")
    return rendered


for _renderer in (
    Renderer("markdown", ".md", "text/markdown", _markdown),
    Renderer("json", ".json", "application/json", lambda d: RenderedReport(encode(d.to_dict()) + b"\n")),
    Renderer("html", ".html", "text/html", _html),
    Renderer("xml", ".xml", "application/xml", _xml),
):
    register_renderer(_renderer)
