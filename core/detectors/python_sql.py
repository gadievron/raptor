"""Recover Python SQL leads hidden by shadowed numeric-conversion names.

Prepared sources retain their AST and restore original byte coordinates.
The caller supplies already-admitted source paths; this detector never grants
verification or refutation authority and discloses partial preparation.
"""
from __future__ import annotations

import ast
from collections.abc import Iterable, Mapping
from typing import Any
from core.analysis.python_module_callgraph import (
    function_scope_bindings,
    module_dynamic_namespace,
    module_shadowed_identity_roots,
)
from bisect import bisect_right
from dataclasses import dataclass
import hashlib
from pathlib import Path
from core.source import read_contained_bytes
from contextlib import contextmanager
from dataclasses import replace
import copy
import json
import re
import yaml
from core.detectors import semgrep
from core.detectors.pipeline import Stage, StageResult
from core.security.log_sanitisation import escape_nonprintable
from core.run.scratch import scratch_dir
from core.source import read_text_capped

RULE_ID = 'raptor.injection.sql.taint.python'
RULE_SOURCE = Path(__file__).resolve().parents[2] / 'engine/semgrep/rules/injection/sql-concat.yaml'


def _trusted_int_sites(source: str, *, tree: ast.Module | None = None) -> set[tuple[int, int, int | None, int | None]]:
    tree = ast.parse(source) if tree is None else tree
    whole, dynamic = module_dynamic_namespace(tree)
    if whole:
        return set()
    module = module_shadowed_identity_roots(tree) | dynamic
    scopes = function_scope_bindings(tree)
    admitted: set[tuple[int, int, int | None, int | None]] = set()
    pending: list[tuple[ast.AST, frozenset[str], bool]] = [(tree, frozenset(), False)]
    while pending:
        node, bound, uncertain = pending.pop()
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == 'int' and 'int' not in bound | module and not uncertain:
                admitted.add((node.lineno, node.col_offset, node.end_lineno, node.end_col_offset))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            body = node.body if not isinstance(node, ast.Lambda) else [node.body]
            pending.extend((statement, scopes[node], False) for statement in body)
            headers = [*node.args.defaults, *(d for d in node.args.kw_defaults if d is not None)]
            if not isinstance(node, ast.Lambda):
                headers.extend(node.decorator_list)
            pending.extend((header, bound, uncertain) for header in headers)
        else:
            unknown = uncertain or isinstance(node, (ast.ClassDef, ast.ListComp, ast.SetComp,
                                                     ast.DictComp, ast.GeneratorExp))
            pending.extend((child, bound, unknown) for child in ast.iter_child_nodes(node))
    return admitted


class _PreparationRefused(ValueError):
    pass


@dataclass(frozen=True)
class _SourceView:
    root: Path
    relative: str
    original: bytes
    prepared: bytes
    marker: str
    spans: tuple[tuple[int, int, int, bool], ...]
    original_starts: tuple[int, ...]
    has_uncertain_int: bool
    cap: int
    span_starts: tuple[int, ...] = ()

    def verify_source(self) -> None:
        current = read_contained_bytes(self.root, self.relative, self.cap)
        if current is None or current[1] or current[0] != self.original:
            raise _PreparationRefused('source changed or became unreadable after preparation')

    def original_point(self, offset: int) -> tuple[int, int]:
        if type(offset) is not int or not 0 <= offset <= len(self.prepared):
            raise _PreparationRefused('prepared offset outside snapshot')
        starts = self.span_starts or tuple(span[0] for span in self.spans)
        begin, end, origin, inserted = self.spans[bisect_right(starts, offset) - 1]
        if not begin <= offset <= end or (inserted and begin < offset < end):
            raise _PreparationRefused('prepared offset lies inside generated text')
        absolute = origin if inserted else origin + offset - begin
        line = bisect_right(self.original_starts, absolute) - 1
        return line + 1, absolute - self.original_starts[line] + 1


def _prepare_source(root, relative, *, expected=None, cap=1024 * 1024, node_cap=100_000, depth_cap=200, _snapshot_bytes=None):
    got = read_contained_bytes(root, relative, cap) if _snapshot_bytes is None else (_snapshot_bytes, len(_snapshot_bytes) > cap)
    if got is None or got[1]:
        raise _PreparationRefused('source unavailable, outside root, or truncated')
    raw = got[0]
    if expected is not None and raw != expected:
        raise _PreparationRefused('source differs from admitted snapshot')
    if b'\r' in raw.replace(b'\r\n', b''):
        raise _PreparationRefused('standalone carriage returns have incompatible line origins')
    try:
        text = raw.decode('utf-8')
        tree = ast.parse(text)
    except (UnicodeDecodeError, SyntaxError, RecursionError) as exc:
        raise _PreparationRefused('unsupported Python source') from exc
    pending: list[tuple[ast.AST, int]] = [(tree, 0)]
    nodes: list[ast.AST] = []
    while pending:
        node, depth = pending.pop()
        nodes.append(node)
        if len(nodes) > node_cap or depth > depth_cap:
            raise _PreparationRefused('Python syntax budget exceeded')
        pending.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    starts = [0] + [index + 1 for index, byte in enumerate(raw) if byte == 10]
    approved = _trusted_int_sites(text, tree=tree)
    embedded: set[ast.AST] = set()
    for node in nodes:
        if isinstance(node, (ast.JoinedStr, getattr(ast, 'TemplateStr', ast.JoinedStr))):
            embedded.update(ast.walk(node))
    marker = 'RAPTOR_BUILTIN_INT_' + hashlib.sha256(raw).hexdigest()
    for _ in range(4):
        if marker.encode() not in raw:
            break
        marker += '_'
    else:
        raise _PreparationRefused('could not select a private source marker')
    edits, uncertain, unsupported_trusted = [], False, False
    for node in nodes:
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'int'):
            continue
        site = (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)
        if site not in approved:
            uncertain = True
            continue
        if node in embedded:
            unsupported_trusted = True
            continue
        if node.func.end_lineno is None or node.func.end_col_offset is None:
            raise _PreparationRefused('Python call has no complete source range')
        position = starts[node.func.end_lineno - 1] + node.func.end_col_offset
        while position < len(raw) and raw[position] in b' \t\f':
            position += 1
        if raw[position:position + 1] != b'(':
            # Grouped names, explicit continuations and other uncommon
            # spellings remain unsanitized instead of changing their syntax.
            unsupported_trusted = True
            continue
        edits.append((position + 1, f' # {marker}\n'.encode()))
    if uncertain and unsupported_trusted:
        raise _PreparationRefused(
            'trusted numeric conversion uses unsupported syntax in a mixed recovery source'
        )
    pieces, spans, cursor, size = [], [], 0, 0
    for position, inserted in sorted(edits):
        chunk = raw[cursor:position]
        spans.append((size, size + len(chunk), cursor, False))
        pieces.append(chunk)
        size += len(chunk)
        spans.append((size, size + len(inserted), position, True))
        pieces.append(inserted)
        size += len(inserted)
        cursor = position
    spans.append((size, size + len(raw[cursor:]), cursor, False))
    pieces.append(raw[cursor:])
    return _SourceView(Path(root), relative, raw, b''.join(pieces), marker, tuple(spans), tuple(starts), uncertain, cap)


@dataclass(frozen=True)
class SqlRecoveryResult:
    status: str
    matches: tuple[dict[str, Any], ...] = ()
    limitations: tuple[tuple[str, str], ...] = ()
    selected: int = 0
    prepared: int = 0
    reason: str = ''
    verification_authority: bool = False


def _render_marker(view: _SourceView, marker: str) -> _SourceView:
    pieces, spans, cursor, size = [], [], 0, 0
    inserted = f' # {marker}\n'.encode()
    for position in (span[2] for span in view.spans if span[3]):
        chunk = view.original[cursor:position]
        spans.append((size, size + len(chunk), cursor, False))
        pieces.append(chunk)
        size += len(chunk)
        spans.append((size, size + len(inserted), position, True))
        pieces.append(inserted)
        size += len(inserted)
        cursor = position
    spans.append((size, size + len(view.original[cursor:]), cursor, False))
    pieces.append(view.original[cursor:])
    return replace(view, prepared=b''.join(pieces), marker=marker, spans=tuple(spans),
                   span_starts=tuple(span[0] for span in spans))


def recover_python_sql(
    root: Path, relatives: Iterable[str], *, out_dir: Path | None,
    expected: Mapping[str, bytes] | None = None, max_files: int = 64,
    max_candidates: int = 16, max_snapshot_bytes: int = 8 * 1024 * 1024,
    per_file_bytes: int = 1024 * 1024, timeout: int = 120,
) -> SqlRecoveryResult:
    limitations: list[tuple[str, str]] = []
    views: list[_SourceView] = []
    seen: set[str] = set()
    used = 0
    for index, relative in enumerate(relatives):
        if index >= max_files:
            limitations.append(('', 'input selection budget exhausted; remaining inputs not prepared'))
            break
        if not isinstance(relative, str):
            limitations.append(('', 'non-string source path refused'))
            continue
        if relative in seen:
            continue
        seen.add(relative)
        if len(views) >= max_candidates or used >= max_snapshot_bytes:
            limitations.append(('', 'candidate or snapshot byte budget exhausted; remaining inputs not prepared'))
            break
        cap = min(per_file_bytes, max_snapshot_bytes - used)
        got = read_contained_bytes(root, relative, cap)
        if got is None:
            limitations.append((relative, 'source unavailable or outside root'))
            continue
        used += len(got[0])
        if got[1]:
            limitations.append((relative, 'source exceeds snapshot byte budget'))
            continue
        try:
            view = _prepare_source(root, relative, expected=(expected or {}).get(relative),
                           cap=cap, _snapshot_bytes=got[0])
        except _PreparationRefused as exc:
            limitations.append((relative, str(exc)))
            continue
        if view.has_uncertain_int:
            views.append(view)
    if not views:
        return SqlRecoveryResult('partial' if limitations else 'skipped', limitations=tuple(limitations),
                             selected=len(seen), reason='no prepared candidate files')
    marker = 'RAPTOR_BUILTIN_INT_' + hashlib.sha256(
        b''.join(hashlib.sha256(view.original).digest() for view in views)).hexdigest()
    for _ in range(4):
        if all(marker.encode() not in view.original for view in views):
            break
        marker += '_'
    else:
        return SqlRecoveryResult('error', limitations=tuple(limitations), selected=len(seen),
                             reason='could not select a marker absent from every source')
    rule_text = read_text_capped(RULE_SOURCE, 256 * 1024, errors='strict')
    if rule_text is None or rule_text[1]:
        return SqlRecoveryResult('error', reason='shipped SQL rule unavailable')
    selected_rule = [rule for rule in yaml.safe_load(rule_text[0])['rules'] if rule['id'] == RULE_ID]
    if len(selected_rule) != 1:
        return SqlRecoveryResult('error', reason='shipped SQL rule identity is ambiguous')
    views = [_render_marker(view, marker) for view in views]
    with scratch_dir('python_sql_batch_', dir=out_dir, keepalive=True) as work:
        config = work / 'rules.json'
        target = work / 'sources'
        path_views: dict[Path, _SourceView] = {}
        prepared_line_starts: dict[str, tuple[int, ...]] = {}
        witnessed: set[Path] = set()

        @contextmanager
        def preparation():
            target.mkdir()
            for index, view in enumerate(views):
                path = target / f'source_{index}.py'
                path.write_bytes(view.prepared)
                path_views[path.absolute()] = view
                prepared_line_starts[view.relative] = tuple([0] + [i + 1 for i, byte in enumerate(view.prepared) if byte == 10])
            rule = copy.deepcopy(selected_rule[0])
            rule['pattern-sanitizers'] = [{'patterns': [
                {'pattern': '$CALL'},
                {'metavariable-pattern': {'metavariable': '$CALL', 'pattern': 'int(...)'}},
                {'metavariable-regex': {'metavariable': '$CALL',
                    'regex': r'(?s)^int\s*\(\s*#\s*' + re.escape(marker) + r'\b'}},
            ], 'exact': True}]
            config.write_text(json.dumps({'rules': [rule]}))

            def point(view, line, column):
                starts = prepared_line_starts[view.relative]
                if type(line) is not int or type(column) is not int or not 1 <= line <= len(starts) or column <= 0:
                    raise _PreparationRefused('tool location has no prepared origin')
                end = starts[line] - 1 if line < len(starts) else len(view.prepared)
                offset = starts[line - 1] + column - 1
                if offset > end:
                    raise _PreparationRefused('tool column exceeds prepared line')
                return view.original_point(offset)

            def analyze(findings):
                for view in views:
                    view.verify_source()
                rows = []
                for finding in findings:
                    path = Path(finding.file).absolute()
                    if path not in path_views or path not in witnessed:
                        raise _PreparationRefused('finding has no witnessed prepared source')
                    view = path_views[path]
                    row = finding.to_dict()
                    row['line'], row['column'] = point(view, finding.line, finding.column)
                    if finding.line_end and finding.column_end:
                        row['line_end'], row['column_end'] = point(view, finding.line_end, finding.column_end)
                    else:
                        row['line_end'] = row['column_end'] = 0
                    row.update(file=view.relative, rule_id=RULE_ID,
                               source_sha256=hashlib.sha256(view.original).hexdigest(),
                               prepared_view='python-builtin-int')
                    rows.append(row)
                return rows, 0
            yield semgrep.PreparedInput(target, analyze, target_root=work)

        def check_witness(state):
            examined = state._raw.files_examined or []
            witnessed.update(Path(path).absolute() for path in examined if isinstance(path, str))
            missing = set(path_views) - witnessed
            if missing:
                return StageResult('partial', f'{len(missing)} prepared file(s) lack a scanned witness')
            return StageResult()

        base = semgrep.define_semgrep_detector('python-sql-identity', '1')
        detector = replace(base, stages=base.stages[:2] + (Stage('witness', check_witness),) + base.stages[2:])
        try:
            execution = semgrep.run_semgrep_analysis(detector=detector, prepare=preparation,
                                                     rule_config=str(config), timeout=timeout)
        except _PreparationRefused as exc:
            return SqlRecoveryResult('error', limitations=tuple(limitations), selected=len(seen),
                                 prepared=len(views), reason=str(exc))
        state = execution.value
        status = 'partial' if limitations and execution.status == 'complete' else execution.status
        preview = '; '.join(error[:200] for error in state.errors[:3])
        if state.errors:
            preview += f' ({len(state.errors)} tool error(s))'
        reason = escape_nonprintable(state.invocation_error or preview or execution.reason)[:1000]
        return SqlRecoveryResult(status, tuple(state.matches), tuple(limitations), len(seen), len(views), reason)


def is_curated_sql_config(config: str) -> bool:
    """Whether a selected shipped config includes Raptor's Python SQL rule."""
    try:
        path = Path(config).resolve(strict=True)
        source = RULE_SOURCE.resolve(strict=True)
        path.relative_to(source.parents[1])
    except (OSError, ValueError, RuntimeError):
        return False
    return path == source or (path.is_dir() and source.is_relative_to(path))
