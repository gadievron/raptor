"""Pure resolved-material identity controls; no resolver, parser or dispatch."""

from dataclasses import replace
from pathlib import Path

import pytest

from core.audit import knowledge_study as module
from core.audit.knowledge_requests import KnowledgeOrigin, KnowledgeRequest
from core.audit.refutation_source import SourceIdentity
from core.concepts.model import StudyItem
from core.concepts.subject_study import StudySubject, SubjectMaterial, SubjectPacket


ROOTS = {"target": Path("/owned-target"), "study": Path("/owned-study")}


@pytest.fixture(autouse=True)
def _no_source_resolution(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("resolved-material identity must not resolve, reread or dispatch")

    for name in ("_safe_resolve", "capture_source_identity", "read_contained"):
        monkeypatch.setattr(module, name, forbidden)


def _request(request_id="request-A", *, subject="Box.Read", context="question", resolution="identifier"):
    origin = KnowledgeOrigin("pass-A", "caller.cpp", "Caller", 1, 2,
                             SourceIdentity("a" * 64, (1, 2, 30, 4, 5)))
    return KnowledgeRequest(request_id, origin, "target_study", subject, context, "normal", resolution)


def _plan(request, *, item=None, label="target", identity=None):
    item = item or StudyItem("source-A", "function", "Read", "unit.cpp", line=3,
                             definition="int Read() { return 1; }", related_items=["Box"])
    identity = identity or SourceIdentity("b" * 64, (1, 2, 40, 5, 6))
    return module._SourcePlan(
        [item], {request.request_id: frozenset((item.id,))}, {item.id: label}, {}, {},
        {item.id: identity},
    )


def _jobs(plan, request, roots=ROOTS):
    return module._job_descriptors(plan, (request,), roots=roots)[request.request_id]


def test_source_plan_preserves_existing_six_argument_constructor():
    plan = module._SourcePlan([], {}, {}, {}, {}, {})
    assert plan.jobs == {} and plan.material_jobs == {}
    assert module._SourcePlan([], {}, {}, {}, {}, {}, {}).material_jobs == {}


@pytest.mark.parametrize("subject", ["Read", "Box.Read", "Box::Read"])
def test_uuid_wording_pass_and_normalized_separator_do_not_renew_lineage(subject):
    first = _request()
    plan = _plan(first)
    expected = _jobs(plan, first)
    later = replace(first, request_id="request-B", subject=subject, context="reworded question",
                    origin=replace(first.origin, pass_id="pass-B"))
    plan.request_items[later.request_id] = plan.request_items[first.request_id]
    assert _jobs(plan, later) == expected


@pytest.mark.parametrize("change", ["line", "definition", "source-bytes", "source-version"])
def test_material_changes_update_generation_without_replacing_lineage(change):
    request = _request()
    plan = _plan(request)
    before = _jobs(plan, request)[0]
    if change == "line":
        plan.items[0] = replace(plan.items[0], line=4)
    elif change == "definition":
        plan.items[0] = replace(plan.items[0], definition="int Read() { return 2; }")
    elif change == "source-bytes":
        plan.expected[plan.items[0].id] = replace(plan.expected[plan.items[0].id], sha256="c" * 64)
    else:
        plan.expected[plan.items[0].id] = replace(plan.expected[plan.items[0].id], version=(1, 2, 40, 6, 7))
    after = _jobs(plan, request)[0]
    assert after.lineage == before.lineage
    assert after.generation != before.generation


@pytest.mark.parametrize("root_change", ["label", "registered-root"])
def test_equal_source_in_different_registered_roots_stays_distinct(root_change):
    request = _request()
    plan = _plan(request)
    before = _jobs(plan, request)[0]
    roots = dict(ROOTS)
    if root_change == "label":
        plan.material_roots[plan.items[0].id] = "study"
    else:
        roots["target"] = Path("/another-owned-target")
    after = _jobs(plan, request, roots)[0]
    assert after.lineage != before.lineage
    assert after.generation != before.generation


def test_document_wording_and_split_subset_preserve_each_document_lineage():
    first = _request(subject="allocation rules", resolution="concept")
    docs = [StudyItem("doc-A", "documentation", first.subject, "docs/a.md", line=1, definition="A"),
            StudyItem("doc-B", "documentation", first.subject, "docs/b.md", line=1, definition="B")]
    identity = SourceIdentity("d" * 64, (1, 2, 3, 4, 5))
    plan = module._SourcePlan(
        docs, {first.request_id: frozenset(item.id for item in docs)},
        {item.id: "target" for item in docs}, {}, {}, {item.id: identity for item in docs},
    )
    before = _jobs(plan, first)
    later = replace(first, request_id="other-request", subject="different wording", context="another question")
    plan.request_items[later.request_id] = frozenset(("doc-A",))
    plan.items[0] = replace(plan.items[0], name=later.subject)
    after = _jobs(plan, later)
    assert len(before) == 2 and len(after) == 1
    assert after[0] in before


@pytest.mark.parametrize("missing", ["identity", "root", "item", "association"])
def test_incomplete_material_association_does_not_mint_a_job(missing):
    request = _request()
    plan = _plan(request)
    if missing == "identity":
        plan.expected.clear()
    elif missing == "root":
        plan.material_roots.clear()
    elif missing == "item":
        plan.items.clear()
    else:
        request = replace(request, subject="Other.Read")
    assert request.request_id not in module._job_descriptors(plan, (request,), roots=ROOTS)


def test_same_leaf_name_in_different_source_validated_classes_stays_distinct():
    first = _request()
    other = _request("request-B", subject="Other.Read")
    left = _plan(first)
    right = _plan(other, item=replace(left.items[0], related_items=["Other"]))
    assert _jobs(left, first)[0].lineage != _jobs(right, other)[0].lineage


def test_ambiguous_function_parent_metadata_does_not_mint_a_job():
    request = _request()
    plan = _plan(request)
    plan.items[0] = replace(plan.items[0], related_items=["Box", "Other"])
    assert request.request_id not in module._job_descriptors(plan, (request,), roots=ROOTS)


@pytest.mark.parametrize("kind", ["struct", "macro"])
def test_nonfunction_related_types_do_not_change_identifier_lineage(kind):
    request = _request(subject="Count")
    item = StudyItem("source-A", kind, "Count", "unit.cpp", line=3,
                     definition="source declaration", related_items=["Box"])
    plan = _plan(request, item=item)
    before = _jobs(plan, request)
    plan.items[0] = replace(item, related_items=["Other", "Third"])
    assert _jobs(plan, request) == before


def test_already_qualified_occurrence_name_is_not_prefixed_twice():
    request = _request()
    plan = _plan(request)
    before = _jobs(plan, request)
    plan.items[0] = replace(plan.items[0], name="Box::Read")
    assert _jobs(plan, request) == before


def _document_packet_inputs():
    request = _request(subject="allocation rules", resolution="concept")
    docs = [StudyItem("doc-A", "documentation", request.subject, "docs/a.md", line=1, definition="A"),
            StudyItem("doc-B", "documentation", request.subject, "docs/b.md", line=1, definition="B")]
    identity = SourceIdentity("d" * 64, (1, 2, 3, 4, 5))
    plan = module._SourcePlan(
        docs, {request.request_id: frozenset(item.id for item in docs)},
        {item.id: "target" for item in docs}, {}, {}, {item.id: identity for item in docs},
    )
    plan.jobs = module._job_descriptors(plan, (request,), roots=ROOTS)
    materials = {
        item.id: SubjectMaterial("material-" + item.id, item.file, item.line, item.name,
                                 item.definition, False, binding_id="bound-" + item.id,
                                 source_item_id=item.id)
        for item in docs
    }
    origin = SubjectMaterial("origin", "caller.cpp", 1, "Caller", "caller context", False,
                             binding_id="bound-origin")
    subject = StudySubject(request.request_id, request.subject, request.context,
                           request.resolution, request.origin.file)
    return request, subject, plan, materials, origin


@pytest.mark.parametrize("present", [("doc-A",), ("doc-B",), ("doc-A", "doc-B")])
def test_split_packet_charges_only_present_requested_document_lineages(present):
    request, subject, plan, materials, origin = _document_packet_inputs()
    packet = SubjectPacket(
        (subject,), tuple(materials[item_id] for item_id in present) + (origin,),
        excluded_materials=tuple(material for item_id, material in materials.items() if item_id not in present),
    )
    jobs = module._packet_job_descriptors(plan, (request,), packet)
    assert jobs == tuple(sorted({plan.material_jobs[item_id] for item_id in present},
                                key=lambda job: (job.lineage, job.generation)))
    assert len(jobs) == len(present)


def test_origin_only_packet_does_not_substitute_for_omitted_requested_materials():
    request, subject, plan, materials, origin = _document_packet_inputs()
    packet = SubjectPacket((subject,), (origin,), excluded_materials=tuple(materials.values()))
    assert module._packet_job_descriptors(plan, (request,), packet) is None


def test_shared_present_material_is_charged_once_for_multiple_requests_and_instances():
    request, subject, plan, materials, origin = _document_packet_inputs()
    other = replace(request, request_id="request-B", context="another question")
    plan.request_items[other.request_id] = frozenset(("doc-A",))
    plan.jobs = module._job_descriptors(plan, (request, other), roots=ROOTS)
    other_subject = replace(subject, request_id=other.request_id, context=other.context)
    first = materials["doc-A"]
    second = replace(first, material_id="another-packet-instance", binding_id="another-binding")
    packet = SubjectPacket((subject, other_subject), (first, second, origin))
    assert module._packet_job_descriptors(plan, (request, other), packet) == (plan.material_jobs["doc-A"],)


@pytest.mark.parametrize("change", ["missing", "unassociated-generation"])
def test_present_material_requires_its_original_job_descriptor(change):
    request, subject, plan, materials, _origin = _document_packet_inputs()
    packet = SubjectPacket((subject,), (materials["doc-A"],))
    if change == "missing":
        del plan.material_jobs["doc-A"]
    else:
        plan.material_jobs["doc-A"] = replace(plan.material_jobs["doc-A"], generation="0" * 64)
    assert module._packet_job_descriptors(plan, (request,), packet) is None
