"""Typed source-study jobs on the audit's existing study phase and client."""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass, replace
from hashlib import sha256
import logging
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from core.concepts.lang_resolve import LangResolution, include_scope_files, resolve_concept_docs, resolve_identifiers
from core.concepts.model import StudyItem
from core.concepts.subject_study import StudySubject, StudySubjects, SubjectMaterial, SubjectPacket
from core.paths import confine
from core.source import read_contained
from core.source.lines import join_lf_slice

from .knowledge_requests import KnowledgeRequest
from .refutation_source import MAX_SOURCE_BYTES, SourceIdentity, capture_source_identity

if TYPE_CHECKING:
    from .knowledge_runtime import AuditKnowledgeRuntime
    from .orchestrator import OrchestratorConfig, OrchestratorResult

logger = logging.getLogger(__name__)


@dataclass
class _SourcePlan:
    items: list[StudyItem]
    request_items: dict[str, frozenset[str]]
    material_roots: dict[str, str]
    request_context: dict[str, tuple[SubjectMaterial, ...]]
    unavailable: dict[str, str]
    expected: dict[str, SourceIdentity]


def _matches_identifier(subject: str, item: StudyItem) -> bool:
    """Keep namespace association which the flattened resolver can establish."""
    wanted = subject.replace("::", ".")
    actual = item.name.replace("::", ".")
    if wanted == actual:
        return True
    parts = wanted.split(".")
    # A class qualifier comes from extraction metadata, not a guessed tail.
    # Outer modules/aliases need a richer binding than this resolver provides.
    return len(parts) == 2 and actual == parts[-1] and parts[0] in item.related_items


def _safe_resolve(root: Path, names: list[str], **kwargs) -> LangResolution:
    # The legacy regex fallback stops at its first type/constant match.
    # Resolve each bounded file once so a global-name collision is visible
    # rather than silently choosing whichever file sorted first.
    from core.concepts.lang_resolve import (
        _C_SUFFIXES, STUDY_SUFFIXES, _iter_source_files, _type_pattern, _const_pattern, language_for_path,
    )
    explicit = kwargs.get("files")
    if explicit is None:
        suffixes = frozenset(STUDY_SUFFIXES | _C_SUFFIXES) if kwargs.get("include_c") else None
        files = _iter_source_files(Path(kwargs.get("scope") or root), max_files=4000, suffixes=suffixes)
    else:
        files = list(explicit)[:4000]
    found = LangResolution()
    for path in files:
        result = resolve_identifiers(root, names, files=[path], include_c=kwargs.get("include_c", False))
        # Also refuse repeated regex-only type/constant declarations within
        # one file: the legacy fallback emits just the first such match.
        try:
            relative = Path(path).relative_to(root).as_posix()
        except ValueError:
            continue
        text = read_contained(root, relative, max_chars=MAX_SOURCE_BYTES, newline="")
        language = language_for_path(path)
        ambiguous = set()
        if text is not None and language:
            for item in result.items:
                pattern = (_type_pattern(language, item.name) if item.kind == "struct" else
                           _const_pattern(language, item.name) if item.kind == "macro" else None)
                if pattern is not None and sum(1 for _ in pattern.finditer(text)) > 1:
                    ambiguous.add(item.name)
        found.items.extend(item for item in result.items if item.name not in ambiguous)
        found.unresolved.extend(result.unresolved)
        found.related_docs.extend(result.related_docs)
    associations = {name: [item for item in found.items if _matches_identifier(name, item)] for name in names}
    admitted = {id(item) for matches in associations.values() for item in matches}
    reasons = {row.get("name"): row for row in found.unresolved}
    return LangResolution(
        items=[item for item in found.items if id(item) in admitted],
        unresolved=[reasons.get(name, {"name": name, "language": "", "reason": "qualified source binding unavailable"})
                    for name in names if not associations[name]], related_docs=found.related_docs)


def _material_key(item: StudyItem, label: str) -> tuple:
    return label, item.file, item.line, item.name, item.definition


def _prepare(requests: tuple[KnowledgeRequest, ...], runtime: AuditKnowledgeRuntime,
             config: OrchestratorConfig) -> _SourcePlan:
    from .orchestrator import StudyRequest, _resolve_scoped

    target_root = Path(config.target_path).resolve()
    study_root = Path(config.study_root or config.target_path).resolve()
    label = "target" if target_root == study_root else "study"
    runtime.bindings.register_root(label, study_root)
    plan = _SourcePlan([], {}, {}, {}, {}, {})
    groups: dict[str, list[KnowledgeRequest]] = {}
    origin_cache: dict[tuple, SubjectMaterial | None] = {}
    for request in requests:
        origin = request.origin
        key = (origin.file, origin.function, origin.line_start, origin.line_end, origin.source_identity)
        if key not in origin_cache:
            before = capture_source_identity(target_root, origin.file)
            text = read_contained(target_root, origin.file, max_chars=MAX_SOURCE_BYTES, newline="")
            after = capture_source_identity(target_root, origin.file)
            material = None
            if (origin.source_identity is not None and before == after == origin.source_identity
                    and text is not None and 0 < origin.line_start <= origin.line_end):
                raw = join_lf_slice(text.replace("\r\n", "\n"), origin.line_start - 1, origin.line_end)
                if raw:
                    identity = sha256(repr(key).encode()).hexdigest()[:24]
                    material = SubjectMaterial("origin-" + identity, origin.file, origin.line_start,
                                               origin.function, raw[:800], len(raw) > 800)
            origin_cache[key] = material
        material = origin_cache[key]
        if material is None:
            plan.unavailable[request.request_id] = "source_changed_before_study"
            plan.request_items[request.request_id] = frozenset()
            continue
        plan.request_context[request.request_id] = (material,)
        assert origin.source_identity is not None
        plan.expected[material.material_id] = origin.source_identity
        physical = confine(target_root, origin.file)
        translated = ""
        if physical is not None:
            try:
                translated = physical.resolve().relative_to(study_root).as_posix()
            except ValueError:
                pass
        groups.setdefault(translated, []).append(request)

    items: dict[tuple, StudyItem] = {}
    all_names = list(dict.fromkeys(r.subject for r in requests if r.resolution == "identifier"))
    resolution_cache: dict[tuple, LangResolution] = {}
    current_files: dict[tuple[str, str], tuple[SourceIdentity, LangResolution]] = {}
    concept_docs: dict[str, list[dict]] = {}

    def resolve(root: Path, names: list[str], **kwargs) -> LangResolution:
        scope = kwargs.get("files")
        key = (str(root), str(kwargs.get("scope") or root),
               None if scope is None else tuple(sorted(str(p) for p in scope)))
        if key not in resolution_cache:
            resolution_cache[key] = _safe_resolve(root, all_names, **kwargs)
        found = resolution_cache[key]
        selected = [item for item in found.items if any(_matches_identifier(name, item) for name in names)]
        return LangResolution(items=selected, unresolved=[row for row in found.unresolved if row["name"] in names],
                              related_docs=found.related_docs)


    def add(item: StudyItem, root_label: str, subject: str | None = None) -> str | None:
        root = target_root if root_label == "target" else study_root
        if not isinstance(item.file, str) or confine(root, item.file) is None or not item.definition:
            return None
        before = capture_source_identity(root, item.file)
        if subject is not None:
            # Re-extract in the current file: a body can stay identical while
            # its enclosing class (and therefore qualified identity) changes.
            file_key = (root_label, item.file)
            if before is None:
                return None
            if file_key not in current_files:
                current_files[file_key] = (before, _safe_resolve(root, all_names, files=[root / item.file], include_c=True))
            cached_identity, current = current_files[file_key]
            if cached_identity != before or not any(
                    _matches_identifier(subject, found)
                    and _material_key(found, root_label) == _material_key(item, root_label)
                    for found in current.items):
                return None
        after = capture_source_identity(root, item.file)
        if before is None or before != after:
            return None
        key = (*_material_key(item, root_label), before)
        if key not in items:
            item_id = "source-" + sha256(repr(key).encode()).hexdigest()[:32]
            items[key] = replace(item, id=item_id)
            plan.material_roots[item_id] = root_label
            plan.expected[item_id] = before
        return items[key].id

    for source_file, group in groups.items():
        identifiers = [r for r in group if r.resolution == "identifier"]
        names = list(dict.fromkeys(r.subject for r in identifiers))
        resolved = LangResolution()
        remaining = names
        if source_file and names:
            origin_path = confine(study_root, source_file)
            focused = [origin_path] if origin_path is not None and origin_path.is_file() else []
            focused.extend(include_scope_files(study_root, source_file))
            if focused:
                resolved = resolve(study_root, names, files=list(dict.fromkeys(focused)), include_c=True)
                remaining = [r["name"] for r in resolved.unresolved]
        if remaining:
            views = [StudyRequest(r.subject, source_file, r.origin.function,
                                  priority=r.priority, resolution=r.resolution, context=r.context) for r in identifiers]
            fallback = _resolve_scoped(study_root, remaining, views, resolve, include_c=True)
            resolved.items.extend(fallback.items)
        for request in identifiers:
            candidates = {_material_key(item, label): item for item in resolved.items
                          if _matches_identifier(request.subject, item)}
            if len(candidates) != 1:
                plan.unavailable[request.request_id] = (
                    "ambiguous_identifier_material" if candidates else "source_subject_unresolved_in_bounded_scope")
                plan.request_items[request.request_id] = frozenset()
                continue
            item_id = add(next(iter(candidates.values())), label, request.subject)
            plan.request_items[request.request_id] = frozenset((item_id,)) if item_id else frozenset()
            if item_id is None:
                plan.unavailable[request.request_id] = "source_material_outside_study_root"
        for request in (r for r in group if r.resolution == "concept"):
            if request.subject not in concept_docs:
                concept_docs[request.subject] = resolve_concept_docs(study_root, [request.subject])
            ids = []
            for doc in concept_docs[request.subject]:
                path = Path(doc.get("file", ""))
                try:
                    rel = path.resolve().relative_to(study_root).as_posix()
                except (ValueError, OSError):
                    continue
                text = read_contained(study_root, rel, max_chars=8192, newline="")
                if text:
                    item_id = add(StudyItem("", "documentation", request.subject, rel, line=1,
                                            definition=text.replace("\r\n", "\n")), label)
                    if item_id:
                        ids.append(item_id)
            plan.request_items[request.request_id] = frozenset(ids)
            if not ids:
                plan.unavailable[request.request_id] = "source_concept_documentation_unavailable"
    plan.items = list(items.values())
    return plan


def study_batch(batch, runtime: AuditKnowledgeRuntime, config: OrchestratorConfig,
                result: OrchestratorResult, *, checklist: dict,
                should_stop: Callable[[], bool], throttle=None) -> None:
    """Resolve and explain typed subjects using the run's existing Phase 2."""
    from .orchestrator import _client_class_cost, _run_llm_client
    from core.concepts.study import run_phase2
    from core.concepts.subject_study import SubjectDispatchRefused

    requests = tuple(r for r in batch if isinstance(r, KnowledgeRequest) and r.kind == "target_study")
    if not requests:
        return
    requested = tuple(StudySubject(r.request_id, r.subject, r.context, r.resolution, r.origin.file) for r in requests)
    notify = getattr(runtime, "notify", None)
    subjects = StudySubjects(requested, on_update=notify)
    tracked = False
    client: Any = None
    before = 0.0

    def unavailable(reason: str) -> None:
        pending = set(subjects.pending_ids())
        subjects.unavailable(SubjectPacket(tuple(s for s in requested if s.request_id in pending), ()), reason)

    try:
        if should_stop():
            unavailable("source_study_stopped")
            return
        plan = _prepare(requests, runtime, config)
        subjects = StudySubjects(requested, bind_packet=lambda packet: runtime.bindings.bind(packet, expected=plan.expected),
                                 request_items=plan.request_items, material_roots=plan.material_roots,
                                 request_context=plan.request_context, on_update=notify)
        runtime.track_source_job(subjects)
        tracked = True
        for request_id, reason in plan.unavailable.items():
            subjects.unavailable(SubjectPacket(tuple(s for s in requested if s.request_id == request_id), ()), reason)
        if not any(plan.request_items.values()) or should_stop():
            unavailable("source_study_stopped" if should_stop() else "source_subject_unresolved")
            return
        if getattr(config, "llm_budget_client", None) is None:
            unavailable("source_study_budget_client_unavailable")
            return
        client = _run_llm_client(config)
        before = _client_class_cost(client, "study")
        by_id = {r.request_id: r for r in requests}

        class StudyClient:
            def __getattr__(self, name):
                return getattr(client, name)

            def generate_structured(self, *args, **kwargs):
                packet = subjects.current_packet()
                submitted = tuple(by_id[s.request_id] for s in packet.subjects if s.request_id in by_id) if packet else ()
                gate = throttle.acquire_sync(low_priority=True) if throttle is not None else nullcontext()
                with gate:
                    if should_stop():
                        raise SubjectDispatchRefused("source_study_stopped")
                    if not submitted or packet is None or len(submitted) != len(packet.subjects):
                        raise SubjectDispatchRefused("source_dispatch_packet_unavailable")
                    from .knowledge_calls import KnowledgeCallRefused, observed_client, owned_call_scope
                    reason = "source_study_admission_refused"

                    def admit(purpose, method):
                        nonlocal reason
                        if should_stop():
                            reason = "source_study_stopped"
                            return False
                        admitted, reason = runtime.bindings.admit_inputs(packet.materials)
                        if not admitted:
                            return False
                        reason = "source_study_admission_refused"
                        return runtime.admit_source_attempt(submitted)

                    packet_key = json.dumps(sorted({r.request_id for r in submitted}), separators=(",", ":"))
                    with owned_call_scope(
                        admit, work_id="study:" + sha256(packet_key.encode()).hexdigest(),
                        beneficiaries=tuple(dict.fromkeys(r.origin.pass_id for r in submitted)),
                    ):
                        try:
                            return observed_client(client, purpose="study").generate_structured(*args, **kwargs)
                        except KnowledgeCallRefused as error:
                            raise SubjectDispatchRefused(reason) from error

        run_phase2(plan.items, str(config.study_root or config.target_path), StudyClient(),
                   source_root=str(config.study_root or config.target_path), subjects=subjects,
                   should_stop=should_stop)
        unavailable("source_study_stopped" if should_stop() else "source_subject_unresolved")
    except Exception:
        unavailable("source_study_failed")
        logger.debug("typed source-study batch failed", exc_info=True)
    except BaseException:
        unavailable("source_study_interrupted")
        raise
    finally:
        try:
            spent = max(0.0, _client_class_cost(client, "study") - before) if client is not None else 0.0
            if spent:
                with result._lock:
                    result.total_cost_usd += spent
                result.cost_tracker.record_call("study", cost_usd=spent)
        finally:
            if tracked:
                runtime.finish_source_job(subjects)
            else:
                runtime.record_source_answers(subjects.drain_updates())
