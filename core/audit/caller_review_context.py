"""Bounded related-code packets for a subsequent caller-context review.

Requests and packets carry source provenance. They do not establish a call
relationship, exhaustive caller coverage, or confirmation/refutation authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from uuid import uuid4

from core.source import read_contained

from .knowledge_requests import KnowledgeOrigin
from .refutation_source import MAX_SOURCE_BYTES, SourceIdentity, capture_source_identity

_MAX_REQUESTS = 4
_MAX_BODY_CHARS = 16_000


@dataclass(frozen=True)
class CallerContextRequest:
    request_id: str
    origin: KnowledgeOrigin
    caller_file: str
    caller_function: str
    caller_line: int
    reason: str


@dataclass(frozen=True)
class CallerContextRejection:
    index: int | None
    reason: str
    count: int = 1


@dataclass(frozen=True)
class CallerContextBatch:
    accepted: tuple[CallerContextRequest, ...]
    rejected: tuple[CallerContextRejection, ...]


@dataclass(frozen=True)
class CallerContextMaterial:
    file: str
    function: str
    line_start: int
    line_end: int
    source_identity: SourceIdentity
    source: str
    truncated: bool


@dataclass(frozen=True)
class CallerContextAnswer:
    request_id: str
    origin: KnowledgeOrigin
    material: CallerContextMaterial | None
    status: Literal['ready', 'partial', 'unavailable', 'ambiguous', 'deferred']
    reason: str


def _bounded_request_text(row: dict, field: str, limit: int) -> str | None:
    value = row.get(field)
    if not isinstance(value, str) or len(value) > limit or not value.strip():
        return None
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return None
    return value.strip()


def register_caller_context_requests(review: object, origin: KnowledgeOrigin) -> CallerContextBatch:
    """Register separate review requests; model identities are never adopted."""
    if not isinstance(review, dict):
        return CallerContextBatch((), ())
    rows = review.get('caller_context_requests', [])
    if not isinstance(rows, list):
        return CallerContextBatch((), (CallerContextRejection(None, 'expected_array'),))
    accepted = []
    rejected = []
    seen = set()
    if len(rows) > _MAX_REQUESTS:
        rejected.append(CallerContextRejection(None, 'request_limit', len(rows) - _MAX_REQUESTS))
    for index, row in enumerate(rows[:_MAX_REQUESTS]):
        if not isinstance(row, dict):
            rejected.append(CallerContextRejection(index, 'expected_object'))
            continue
        file = _bounded_request_text(row, 'file', 512)
        function = _bounded_request_text(row, 'function', 256)
        reason = _bounded_request_text(row, 'reason', 1000)
        line = row.get('line_start')
        if (file is None or function is None or reason is None
                or any(c in file or c in function for c in ('\0', '\n', '\r'))
                or type(line) is not int or line < 1):
            rejected.append(CallerContextRejection(index, 'invalid_request_fields'))
            continue
        signature = file, function, line, reason
        if signature in seen:
            rejected.append(CallerContextRejection(index, 'duplicate_request'))
            continue
        seen.add(signature)
        accepted.append(CallerContextRequest(uuid4().hex, origin, file, function, line, reason))
    return CallerContextBatch(tuple(accepted), tuple(rejected))


def _answer(request: CallerContextRequest, reason: str, *, ambiguous: bool = False,
            deferred: bool = False) -> CallerContextAnswer:
    return CallerContextAnswer(request.request_id, request.origin, None,
                               'ambiguous' if ambiguous else 'deferred' if deferred else 'unavailable', reason)


def _matching_spans(request: CallerContextRequest, inventory: object) -> list[tuple[int, int] | None]:
    matches: list[tuple[int, int] | None] = []
    if not isinstance(inventory, dict) or not isinstance(inventory.get('files'), list):
        return matches
    for file in inventory['files']:
        if not isinstance(file, dict) or file.get('path') != request.caller_file:
            continue
        rows = file.get('items', file.get('functions', []))
        if not isinstance(rows, list):
            continue
        for row in rows:
            if (not isinstance(row, dict) or row.get('name') != request.caller_function
                    or row.get('kind') not in (None, 'function', 'method')):
                continue
            lo, hi = row.get('line_start'), row.get('line_end')
            if type(lo) is not int or lo != request.caller_line:
                continue
            matches.append((lo, hi) if type(hi) is int and hi >= lo else None)
    return matches


def _definition_reason(file: str, function: str, lo: int, hi: int, text: str) -> str:
    """Match current parser output, without treating stale inventory as scope."""
    import ast
    import warnings

    from collections.abc import Sequence
    from core.inventory.extractors import CodeItem, PythonExtractor, TreeSitterExtractor
    from core.inventory.languages import detect_language

    definitions: Sequence[CodeItem]
    language = detect_language(file)
    if language is None:
        return 'caller_definition_parser_unavailable'
    try:
        # The general extract_functions adapter silently falls back to regex.
        # That fallback cannot establish this exact current-definition gate.
        if language == 'python':
            # PythonExtractor itself has a regex fallback after SyntaxError.
            # Establish that the immutable input parses before using its walk.
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', SyntaxWarning)
                ast.parse(text)
            definitions = PythonExtractor().extract(file, text)
        else:
            tree_cache: dict = {}
            definitions = TreeSitterExtractor(language).extract(file, text, _tree_cache=tree_cache)
            tree = tree_cache.get('tree')
            if tree is None or tree.root_node.has_error:
                return 'caller_definition_parse_incomplete'
    except Exception:
        return 'caller_definition_parser_unavailable'
    matching = [item for item in definitions
                if item.kind == 'function' and item.name == function and item.line_start == lo]
    if len(matching) > 1:
        return 'ambiguous_current_caller_definition'
    if len(matching) != 1 or matching[0].line_end != hi:
        return 'caller_definition_changed'
    return ''


def _origin_reason(origin: KnowledgeOrigin, root: Path) -> str:
    if not isinstance(origin, KnowledgeOrigin) or not isinstance(origin.file, str):
        return 'origin_source_unavailable'
    if origin.file.startswith('binary:'):
        return 'binary_context_binding_unavailable'
    if origin.source_identity is None:
        return 'origin_source_unavailable'
    if (type(origin.line_start) is not int or type(origin.line_end) is not int
            or origin.line_start < 1 or origin.line_end < origin.line_start):
        return 'origin_span_unavailable'
    if capture_source_identity(root, origin.file) != origin.source_identity:
        return 'origin_source_changed'
    return ''


def resolve_caller_context(request: CallerContextRequest, root: Path,
                           inventory: object) -> CallerContextAnswer:
    """Resolve one current occurrence and bind both endpoint sources.

    Parser and inventory correspondence admits source for inspection. It does
    not certify a call relationship or establish that all callers were found.
    """
    root = Path(root)
    if (not isinstance(request.caller_file, str) or not isinstance(request.caller_function, str)
            or type(request.caller_line) is not int or request.caller_line < 1):
        return _answer(request, 'invalid_request_fields')
    if request.caller_file.startswith('binary:') or request.origin.file.startswith('binary:'):
        return _answer(request, 'binary_context_binding_unavailable', deferred=True)
    reason = _origin_reason(request.origin, root)
    if reason:
        return _answer(request, reason, deferred=True)
    spans = _matching_spans(request, inventory)
    if len(spans) > 1:
        return _answer(request, 'ambiguous_caller_occurrence', ambiguous=True)
    if not spans or spans[0] is None:
        return _answer(request, 'caller_span_unavailable')
    lo, hi = spans[0]
    before = capture_source_identity(root, request.caller_file)
    if before is None:
        return _answer(request, 'caller_source_unavailable')
    text = read_contained(root, request.caller_file, max_chars=MAX_SOURCE_BYTES, newline='')
    if text is None:
        return _answer(request, 'caller_source_unavailable')
    # A universal-newline hash alone cannot resolve bare-CR inventory
    # coordinates. Refuse rather than quote a shifted function occurrence.
    text = text.replace('\r\n', '\n')
    if '\r' in text:
        return _answer(request, 'source_line_model_unavailable')
    reason = _definition_reason(request.caller_file, request.caller_function, lo, hi, text)
    if reason:
        return _answer(request, reason, ambiguous=reason.startswith('ambiguous_'))
    lines = text.split('\n')  # line-model: inventory coordinates use LF
    if lines and lines[-1] == '':
        lines.pop()
    if hi > len(lines):
        return _answer(request, 'caller_span_unavailable')
    body = '\n'.join(lines[lo - 1:hi])
    if not body.strip():
        return _answer(request, 'caller_source_unavailable')
    truncated = len(body) > _MAX_BODY_CHARS
    if truncated:
        boundary = body.rfind('\n', 0, _MAX_BODY_CHARS + 1)
        if boundary <= 0:
            return _answer(request, 'caller_line_exceeds_context_cap')
        body = body[:boundary]
    identity = capture_source_identity(root, request.caller_file, excerpt=body, line_start=lo)
    if identity is None or identity != before:
        return _answer(request, 'caller_source_changed', deferred=True)
    material = CallerContextMaterial(request.caller_file, request.caller_function, lo,
                                     lo + body.count('\n'), identity, body, truncated)
    answer = CallerContextAnswer(request.request_id, request.origin, material,
                                 'partial' if truncated else 'ready',
                                 'caller_body_truncated' if truncated else 'related_code_available')
    admitted, reason = validate_caller_context(answer, root)
    return answer if admitted else _answer(request, reason, deferred=True)


def validate_caller_context(answer: CallerContextAnswer, root: Path) -> tuple[bool, str]:
    """Recheck observed sources, without granting relationship or proof scope."""
    if not isinstance(answer, CallerContextAnswer) or answer.status not in ('ready', 'partial'):
        return False, 'context_unavailable'
    material = answer.material
    if (not isinstance(material, CallerContextMaterial)
            or not isinstance(material.file, str) or not isinstance(material.function, str)
            or not isinstance(material.source, str) or not material.source
            or len(material.source) > _MAX_BODY_CHARS
            or type(material.line_start) is not int or material.line_start < 1
            or type(material.line_end) is not int
            or material.line_end != material.line_start + material.source.count('\n')
            or type(material.truncated) is not bool
            or material.truncated != (answer.status == 'partial')):
        return False, 'invalid_context_material'
    root = Path(root)
    if material.file.startswith('binary:'):
        return False, 'binary_context_binding_unavailable'
    reason = _origin_reason(answer.origin, root)
    if reason:
        return False, reason
    text = read_contained(root, material.file, max_chars=MAX_SOURCE_BYTES, newline='')
    if text is None:
        return False, 'caller_source_changed'
    text = text.replace('\r\n', '\n')
    if '\r' in text:
        return False, 'source_line_model_unavailable'
    lines = text.split('\n')  # line-model: exact displayed LF coordinates
    if lines and lines[-1] == '':
        lines.pop()
    if (material.line_end > len(lines)
            or '\n'.join(lines[material.line_start - 1:material.line_end]) != material.source):
        return False, 'caller_excerpt_changed'
    observed = capture_source_identity(root, material.file, excerpt=material.source,
                                       line_start=material.line_start)
    if observed is None or observed != material.source_identity:
        return False, 'caller_source_changed'
    reason = _origin_reason(answer.origin, root)
    if reason:
        return False, reason
    if capture_source_identity(root, material.file) != observed:
        return False, 'caller_source_changed'
    return True, ''
