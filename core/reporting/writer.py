"""Immutable report generations and offline regeneration.

Compatibility files are mirrors. Consistent readers follow reporting-manifest.json.
No report write changes scanner evidence or workflow findings.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Iterator
from urllib.parse import unquote, urlsplit

from core.atomic_fs import write_bytes_atomically
from core.json import load_json
from core.json.bounded import loads_bounded
from core.security.capped_read import read_capped
from core.source.beneath import open_dir_beneath, open_regular_beneath
from .document import MAX_JSON_BYTES, ReportContext, ReportDocument, digest, encode
from .options import ReportOptions
from .renderers import get_renderer, render_document
from .summary import OperatorSummary, render_operator_summary


PERSISTENCE_FILENAMES = frozenset({
    "report-context.json", "report-document.json", "reporting-manifest.json",
    "summary.json", "summary.md", "diagrams.md", "manifest.json",
    ".raptor-run.json", ".raptor-imported.json", "reporting-input.json", "findings-import.json",
})


def _check_report_destination(path: Path) -> None:
    # Check both spellings: an innocuous filename must not alias internal state.
    for candidate in (path, path.resolve()):
        if candidate.name in PERSISTENCE_FILENAMES:
            raise ValueError("Report output uses a reserved persistence filename")
        if any(parent.name == ".reporting" for parent in candidate.parents):
            raise ValueError("Report output cannot modify an immutable reporting generation")


@dataclass
class Publication:
    snapshot_id: str
    generation: str = ""
    outputs: dict[str, str] = field(default_factory=dict)
    diagnostics: list[str] = field(default_factory=list)
    failed_formats: list[str] = field(default_factory=list)
    accepted: bool = False
    committed: bool = False


def _owned_dir(path: Path, root: Path) -> Path:
    fd = open_dir_beneath(root, path.relative_to(root), create=True)
    os.close(fd)
    return path


@contextmanager
def _lock(directory: Path) -> Iterator[None]:
    parent_fd = open_dir_beneath(directory.parent, Path(directory.name))
    try:
        fd = os.open(".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("Report lock is not a regular file")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _current_manifest(output_dir: Path, *, root: Path | None = None) -> dict:
    path = output_dir / "reporting-manifest.json"
    try:
        data = _read_json(path, 1024 * 1024, root=root)
    except FileNotFoundError:
        return {}
    if (not isinstance(data, dict) or type(data.get("schema_version")) is not int or data.get("schema_version") != 1
            or not isinstance(data.get("generation"), str)):
        raise ValueError("Invalid current reporting manifest")
    return data


def _guard(output_dir: Path, expected_generation: str | None) -> dict:
    current = _current_manifest(output_dir)
    if expected_generation is not None and (current.get("generation") or "") != expected_generation:
        raise ValueError("A newer report generation was published")
    return current


def _read_bytes(path: Path, limit: int = MAX_JSON_BYTES, *, root: Path | None = None) -> bytes:
    if root is None:
        return read_capped(path, limit, raise_on_refusal=True)
    stream = open_regular_beneath(root, path.relative_to(root), mode="rb")
    if stream is None:
        raise ValueError("Committed reporting path refused")
    with stream:
        if os.fstat(stream.fileno()).st_size > limit:
            raise ValueError("Committed reporting file exceeds read limit")
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Committed reporting file exceeds read limit")
    return raw


def _read_json(path: Path, limit: int = MAX_JSON_BYTES, *, root: Path | None = None):
    try:
        return loads_bounded(_read_bytes(path, limit, root=root), max_bytes=limit)
    except (RecursionError, UnicodeDecodeError) as exc:
        raise ValueError("Invalid committed reporting JSON") from exc


def _protected(context: ReportContext, output_dir: Path) -> set[Path]:
    protected = set()
    for artifact in context.artifacts:
        if not isinstance(artifact, dict):
            raise ValueError("Invalid reporting artifact reference")
        for reference in (artifact.get("path"), artifact.get("uri")):
            if not isinstance(reference, str):
                continue
            if "://" in reference:
                parts = urlsplit(reference)
                if parts.scheme != "file" or parts.netloc.lower() not in ("", "localhost"):
                    continue
                reference = unquote(parts.path)
            path = Path(reference)
            protected.add(path.resolve())
            if not path.is_absolute():
                protected.add((output_dir / path).resolve())
    return protected


def _summary_payload(summary: OperatorSummary) -> dict[str, bytes]:
    return {"summary.json": encode(summary.to_dict()),
            "summary.md": render_operator_summary(summary, markdown=True).encode()}


def publish_report(context: ReportContext, document: ReportDocument, output_dir: Path, *,
                   stem: str = "report", options: ReportOptions | None = None,
                   expected_generation: str | None = None, summary: OperatorSummary | None = None,
                   summary_writer=None) -> Publication:
    """Publish an immutable content generation and a separate publication record.

    Renderer results, filenames and file hashes determine generation identity.
    External mirror destinations and mirror failures never mutate its manifest.
    The comparison guard is checked before any root-level summary/mirror writes.
    """
    import re
    options = (options or ReportOptions()).validate()
    reserved = {"report-context", "report-document", "reporting-manifest", "summary", "diagrams"}
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}", stem) or stem in reserved:
        raise ValueError("Unsafe report filename stem")
    if document.snapshot_id != context.snapshot_id:
        raise ValueError("Document and context snapshot identities disagree")
    output_dir = Path(os.path.abspath(output_dir))
    blocked = _protected(context, output_dir)
    destinations = {}
    filenames = dict(options.filenames)
    destination_paths = set()
    for name in options.formats if options.enabled else ():
        renderer = get_renderer(name)
        filename = filenames.get(name, stem + renderer.extension)
        if filename in PERSISTENCE_FILENAMES:
            raise ValueError("Report filename uses a reserved persistence filename")
        dest = output_dir / filename
        if options.output:
            chosen = Path(options.output)
            dest = chosen if options.output_is_file or chosen.suffix and not chosen.is_dir() else chosen / filename
        dest = Path(os.path.abspath(dest))
        _check_report_destination(dest)
        if dest.resolve() in blocked:
            raise ValueError("Report output would overwrite an input artifact")
        if dest.resolve() in destination_paths:
            raise ValueError("Report formats resolve to the same destination")
        destination_paths.add(dest.resolve())
        destinations[name] = dest
    publication = Publication(context.snapshot_id)
    rendered = {}
    format_notes: list[str] = []
    render_failures = []
    for name in destinations:
        try:
            result = render_document(document, name)
            rendered[name] = result.content
            format_notes.extend(result.diagnostics)
        except (ValueError, TypeError, OSError) as exc:
            render_failures.append(name)
            publication.diagnostics.append(f"{name} report failed ({type(exc).__name__})")
    publication.failed_formats.extend(render_failures)
    publication.diagnostics.extend(dict.fromkeys(format_notes))
    captured_context = {**context.to_dict(), "snapshot_id": context.snapshot_id}
    payloads = {"report-context.json": encode(captured_context), "report-document.json": encode(document.to_dict())}
    payloads.update({filenames.get(name, stem + get_renderer(name).extension): content for name, content in rendered.items()})
    diagrams = [b for b in document.blocks if b.kind == "diagram" or b.extensions.get("raptor.diagram_export") is True]
    if diagrams and options.enabled:
        try:
            diagram_doc = ReportDocument("RAPTOR Diagrams", document.kind, document.snapshot_id, blocks=diagrams)
            payloads["diagrams.md"] = render_document(diagram_doc).content
        except (ValueError, TypeError, OSError):
            publication.diagnostics.append("Diagram export unavailable; other report outputs are retained")
    if summary is not None:
        payloads.update(_summary_payload(summary))
    files = {name: {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)} for name, data in payloads.items()}
    definition = {"schema_version": 1, "snapshot_id": context.snapshot_id, "stem": stem,
                  "formats": list(destinations), "renderer_versions": {f: get_renderer(f).version for f in destinations},
                  "files": files, "render_failures": render_failures,
                  "diagnostics": publication.diagnostics.copy()}
    generation_id = digest(definition)
    publication.generation = generation_id
    output_dir.mkdir(parents=True, exist_ok=True)
    owned = _owned_dir(output_dir / ".reporting", output_dir)
    with _lock(owned):
        _guard(output_dir, expected_generation)
        publication.accepted = True
        generation = _owned_dir(owned / generation_id, owned)
        immutable_manifest = {**definition, "generation": generation_id,
                              "directory": str(generation.relative_to(output_dir)),
                              "status": "partial" if render_failures else "completed"}
        for name, content in {**payloads, "manifest.json": encode(immutable_manifest)}.items():
            dest = generation / name
            if dest.exists() or dest.is_symlink():
                if _read_bytes(dest, root=output_dir) != content:
                    raise ValueError("Immutable report generation content changed")
            else:
                write_bytes_atomically(dest, content, root=output_dir)
        for name, dest in destinations.items():
            if name not in rendered:
                continue
            try:
                if dest.is_relative_to(output_dir):
                    write_bytes_atomically(dest, rendered[name], root=output_dir)
                else:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    write_bytes_atomically(dest, rendered[name], root=dest.parent)
                publication.outputs[name] = str(dest)
            except OSError as exc:
                publication.diagnostics.append(f"{name} report mirror failed ({type(exc).__name__})")
                publication.failed_formats.append(name)
        if summary is not None:
            if any((output_dir / name).resolve() in blocked for name in ("summary.json", "summary.md")):
                publication.diagnostics.append("Summary persistence failed: input artifact preserved")
                publication.failed_formats.append("summary")
            else:
                try:
                    (summary_writer or write_summary)(summary, output_dir)
                except (OSError, ValueError, TypeError) as exc:
                    publication.diagnostics.append(f"Summary persistence failed ({type(exc).__name__}); other outputs are retained")
                    publication.failed_formats.append("summary")
        # A failed render attempt is inspectable, but cannot displace the last
        # committed full report. Its fresh operator summary is still useful.
        if options.enabled and not rendered:
            return publication
        for name in ("report-context.json", "report-document.json", "diagrams.md"):
            if name not in payloads:
                continue
            dest = output_dir / name
            if dest.resolve() in blocked:
                publication.diagnostics.append(f"Compatibility mirror {name} skipped: input artifact preserved")
                continue
            try:
                write_bytes_atomically(dest, payloads[name], root=output_dir)
            except OSError:
                publication.diagnostics.append(f"Compatibility mirror {name} unavailable; committed snapshot remains readable")
        if (output_dir / "reporting-manifest.json").resolve() in blocked:
            publication.failed_formats.append("manifest")
            publication.diagnostics.append("Reporting manifest input artifact preserved")
            return publication
        current = {**immutable_manifest, "outputs": publication.outputs,
                   "diagnostics": publication.diagnostics, "failed_formats": publication.failed_formats,
                   "status": "partial" if publication.failed_formats else "completed"}
        write_bytes_atomically(output_dir / "reporting-manifest.json", encode(current), root=output_dir)
        publication.committed = True
    return publication


def publish_summary(summary: OperatorSummary, output_dir: Path, *, context: ReportContext,
                    expected_generation: str | None = None, summary_writer=None) -> None:
    output_dir = Path(os.path.abspath(output_dir))
    output_dir.mkdir(parents=True, exist_ok=True)
    owned = _owned_dir(output_dir / ".reporting", output_dir)
    with _lock(owned):
        _guard(output_dir, expected_generation)
        if any((output_dir / name).resolve() in _protected(context, output_dir) for name in ("summary.json", "summary.md")):
            raise ValueError("Summary persistence failed: input artifact preserved")
        (summary_writer or write_summary)(summary, output_dir)


def write_summary(summary: OperatorSummary, output_dir: Path) -> None:
    output_dir = Path(os.path.abspath(output_dir))
    output_dir.mkdir(parents=True, exist_ok=True)
    write_bytes_atomically(output_dir / "summary.json", encode(summary.to_dict()), root=output_dir)
    write_bytes_atomically(output_dir / "summary.md", render_operator_summary(summary, markdown=True).encode(), root=output_dir)


def load_document(path: Path) -> ReportDocument:
    if Path(path).is_dir():
        return load_committed_report(Path(path))[1]
    data = load_json(Path(path), max_bytes=MAX_JSON_BYTES)
    if not isinstance(data, dict):
        raise ValueError("Report document could not be loaded")
    return ReportDocument.from_dict(data)


def load_context(path: Path) -> ReportContext:
    if Path(path).is_dir():
        return load_committed_report(Path(path))[0]
    data = load_json(Path(path), max_bytes=MAX_JSON_BYTES)
    return ReportContext.from_dict(data)


def load_committed_report(output_dir: Path, *, root: Path | None = None) -> tuple[ReportContext, ReportDocument, dict]:
    """Read the exact committed generation, with bounded regular-file reads.

    Digests enforce consistency, not authentication. Imported snapshots retain
    their caller/domain-owned provenance policy regardless of hash validity.
    Root compatibility mirrors are deliberately not consulted. An explicit
    root anchors every component of a nested output path beneath its owner.
    """
    output_dir = Path(output_dir)
    return _load_generation_report(output_dir, _current_manifest(output_dir, root=root), root=root)


def load_report_generation(output_dir: Path, generation: str, snapshot_id: str):
    """Read an explicitly pinned historical generation; never move current."""
    return _load_generation_report(Path(output_dir), {"generation": generation, "snapshot_id": snapshot_id})


def _load_generation_report(output_dir, current, *, root=None):
    root = Path(root) if root is not None else output_dir
    import re
    identity = current.get("generation")
    if not isinstance(identity, str) or not re.fullmatch(r"[a-f0-9]{64}", identity):
        raise ValueError("No valid committed reporting generation")
    owned = output_dir / ".reporting"
    generation = owned / identity
    if owned.is_symlink() or generation.is_symlink() or not generation.resolve().is_relative_to(owned.resolve()):
        raise ValueError("Committed reporting directory is not contained")
    try:
        manifest = _read_json(generation / "manifest.json", 1024 * 1024, root=root)
    except (OSError, ValueError) as exc:
        raise ValueError("Committed reporting manifest unavailable") from exc
    if not isinstance(manifest, dict) or manifest.get("generation") != identity:
        raise ValueError("Committed generation identity mismatch")
    definition = {k: v for k, v in manifest.items() if k not in {"generation", "directory", "status"}}
    if digest(definition) != identity or current.get("snapshot_id") != manifest.get("snapshot_id"):
        raise ValueError("Committed generation digest mismatch")
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise ValueError("Invalid committed file manifest")
    loaded = {}
    for name in ("report-context.json", "report-document.json"):
        metadata = files.get(name)
        if not isinstance(metadata, dict):
            raise ValueError("Missing committed reporting input")
        raw = _read_bytes(generation / name, root=root)
        if len(raw) != metadata.get("size") or hashlib.sha256(raw).hexdigest() != metadata.get("sha256"):
            raise ValueError(f"Committed {name} digest mismatch")
        try:
            loaded[name] = json.loads(raw)
        except (ValueError, RecursionError) as exc:
            raise ValueError("Invalid committed JSON") from exc
    context = ReportContext.from_dict(loaded["report-context.json"])
    document = ReportDocument.from_dict(loaded["report-document.json"])
    if context.snapshot_id != document.snapshot_id or context.snapshot_id != manifest["snapshot_id"]:
        raise ValueError("Committed context/document mismatch")
    return context, document, current


def regenerate(document_path: Path, destination: Path, *, format: str = "markdown") -> list[str]:
    document = load_document(document_path)
    result = render_document(document, format)
    if Path(document_path).resolve() == Path(destination).resolve():
        raise ValueError("Regeneration cannot overwrite its input document")
    _check_report_destination(Path(destination))
    artifacts = document.extensions.get("raptor.artifacts", [])
    context = ReportContext(document.kind, "regeneration", artifacts=artifacts)
    source_root = Path(document_path) if Path(document_path).is_dir() else Path(document_path).parent
    if Path(destination).resolve() in _protected(context, source_root):
        raise ValueError("Regeneration cannot overwrite a captured source artifact")
    for parent in Path(destination).resolve().parents:
        if parent.parent.name == ".reporting":
            raise ValueError("Regeneration cannot modify an immutable reporting generation")
    destination = Path(os.path.abspath(destination))
    source_root = Path(os.path.abspath(source_root))
    if destination.is_relative_to(source_root):
        write_bytes_atomically(destination, result.content, root=source_root)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        write_bytes_atomically(destination, result.content, root=destination.parent)
    return list(result.diagnostics)
