"""Work quanta must preserve evidence and paid progress across continuations."""
from dataclasses import replace

import pytest

from core.audit.cross_entry import Limits, build_access_index, build_slices
from core.audit.cross_entry.cache import load_or_build_index
from core.audit.cross_entry.catalogue import Catalogue
from core.audit.cross_entry.integration import prepare_cross_entry
from core.audit.cross_entry.progress import WorkQueue, acknowledge_delivery, exclusive_session
from core.audit.cross_entry.study import run_studies
from core.audit.tests.test_cross_entry import Client, semantic, sources


def test_single_call_segments_resume_refutation_without_rebuying_study(tmp_path):
    index = build_access_index(sources())
    unit = build_slices(index,["reader.c:get"])[0][0]
    client = Client([semantic(unit),{"verdict":"survives","reason":"conditional","evidence_ids":[unit.consumer]}])
    first = run_studies(index,[unit],client,out_dir=tmp_path,limits=replace(Limits(),max_calls=1))[unit.id]
    assert first["status"] != "complete"
    second = run_studies(index,[unit],client,out_dir=tmp_path,limits=replace(Limits(),max_calls=2))[unit.id]
    assert second["status"] == "complete"
    assert len(client.calls) == 2
    assert second["refutations"][0]["verdict"] == "survives"
    run_studies(index,[unit],client,out_dir=tmp_path)
    assert len(client.calls) == 2


def test_catalogue_quanta_discover_late_files_and_track_changes(tmp_path):
    root = tmp_path/"src"
    root.mkdir()
    out = tmp_path/"out"
    out.mkdir()
    for n in range(7):
        (root/f"{n}.c").write_text("void f(struct state *p) { p->len = 1; }")
    limits = replace(Limits(),index_batch_files=1)
    cat = Catalogue(root,out)
    try:
        cat.begin()
        assert not cat.advance(limits)["index_complete"]
        for _ in range(20):
            if cat.advance(limits)["index_complete"]:
                break
        assert cat.summary()["files"] == {"indexed":7}
        assert len(cat.matching_files({"field:len"})) == 7
        (root/"0.c").unlink()
        (root/"late.c").write_text("void f(struct state *p) { p->novel = 1; }")
        cat.begin()
        for _ in range(20):
            if cat.advance(limits)["index_complete"]:
                break
        assert cat.matching_files({"field:novel"}) == ["late.c"]
        assert "0.c" not in cat.matching_files({"field:len"})
        assert "0.c" in cat.changed_files()
    finally:
        cat.close()


def test_blocked_job_does_not_hide_completed_undelivered_evidence(tmp_path):
    q = WorkQueue(tmp_path,"n")
    try:
        q.add_views(iter([""]))
        view = q.next_view()["id"]
        q.bind_view(view,"v1",{"a.c":"hash"})
        q.add_jobs(view,[("consumer",""),("consumer","large")])
        jobs = q.pending(view)
        q.finish(view,jobs[0]["id"],"complete",{"key":"evidence"})
        q.finish(view,jobs[1]["id"],"blocked")
        q.complete_view_if_finished(view)
        assert q.next_view()["id"] == view
        acknowledge_delivery(tmp_path,{"namespace":"n","view":view,"job":jobs[0]["id"],"evidence":"old"})
        assert q.undelivered()
        q.acknowledge(view,jobs[0]["id"],"evidence")
        assert not q.undelivered()
        assert q.summary()["views"] == {"blocked":1}
        q.invalidate_files(["a.c"])
        q.bind_view(view,"v2",{"a.c":"changed"})
        q.add_jobs(view,[("consumer","")])
        assert len(q.pending(view)) == 1
    finally:
        q.close()


def test_busy_worker_prevents_duplicate_dispatch(tmp_path):
    with exclusive_session(tmp_path/"lease.sqlite"):
        with pytest.raises(RuntimeError,match="another worker"):
            with exclusive_session(tmp_path/"lease.sqlite"):
                pytest.fail("second worker acquired lease")


def test_typed_cache_reused_and_source_change_invalidates(tmp_path,monkeypatch):
    src = sources()
    _,hit = load_or_build_index(src,out_dir=tmp_path,limits=Limits())
    assert not hit
    import core.audit.cross_entry.cache as cache
    original = cache.build_access_index
    def forbidden(*a,**kw):
        pytest.fail("unchanged typed view was parsed again")
    monkeypatch.setattr(cache,"build_access_index",forbidden)
    _,hit = load_or_build_index(src,out_dir=tmp_path,limits=replace(Limits(),max_calls=1))
    assert hit
    monkeypatch.setattr(cache,"build_access_index",original)
    _,hit = load_or_build_index({**src,"new.c":"void new(void) {}"},out_dir=tmp_path,limits=Limits())
    assert not hit


def test_context_queue_advances_after_delivery_instead_of_repeating_root(tmp_path):
    root = tmp_path/"src"
    root.mkdir()
    out = tmp_path/"out"
    for fp,body in sources().items():
        (root/fp).write_text(body)
    limits = replace(Limits(),max_slices=1)
    receipts = {}
    first = prepare_cross_entry(root,[{"file":"reader.c","name":"get"}],mode="context",out_dir=out,
                                limits=limits,drain_index=True,delivery_receipts=receipts)
    assert first and receipts
    receipt = receipts["reader.c:get"]
    acknowledge_delivery(out,receipt)
    receipts2 = {}
    prepare_cross_entry(root,[{"file":"reader.c","name":"get"}],mode="context",out_dir=out,
                        limits=limits,delivery_receipts=receipts2)
    assert receipts2
    assert receipts2["reader.c:get"]["job"] != receipt["job"]


def test_received_response_survives_interruption_before_validation(tmp_path,monkeypatch):
    import core.audit.cross_entry.study_engine as engine
    index = build_access_index(sources())
    unit = build_slices(index,["reader.c:get"])[0][0]
    client = Client([semantic(unit),{"verdict":"survives","reason":"conditional","evidence_ids":[unit.consumer]}])
    original = engine._validate
    def interrupt(*a,**kw):
        raise KeyboardInterrupt()
    monkeypatch.setattr(engine,"_validate",interrupt)
    with pytest.raises(KeyboardInterrupt):
        run_studies(index,[unit],client,out_dir=tmp_path)
    assert len(client.calls) == 1
    monkeypatch.setattr(engine,"_validate",original)
    result = run_studies(index,[unit],client,out_dir=tmp_path)[unit.id]
    assert result["status"] == "complete"
    assert len(client.calls) == 2


def test_source_change_reactivates_acknowledged_context(tmp_path):
    root = tmp_path/"src"
    root.mkdir()
    out = tmp_path/"out"
    for fp,body in sources().items():
        (root/fp).write_text(body)
    gaps = [{"file":"reader.c","name":"get"}]
    receipts = {}
    prepare_cross_entry(root,gaps,mode="context",out_dir=out,delivery_receipts=receipts,drain_index=True)
    old = receipts["reader.c:get"]
    acknowledge_delivery(out,old)
    (root/"writer.c").write_text(sources()["writer.c"].replace("= 2","= 9"))
    newer = {}
    context = prepare_cross_entry(root,gaps,mode="context",out_dir=out,delivery_receipts=newer,drain_index=True)
    assert "= 9" in context["reader.c:get"]
    assert newer["reader.c:get"]["evidence"] != old["evidence"]


def test_catalogue_indexes_hidden_source_dirs_and_records_exclusions(tmp_path):
    root = tmp_path/"src"
    (root/".generated").mkdir(parents=True)
    (root/".generated"/"state.c").write_text("void f(struct state *p) { p->rare = 1; }")
    (root/"external.c").symlink_to(tmp_path/"outside.c")
    out = tmp_path/"out"
    out.mkdir()
    cat = Catalogue(root,out)
    try:
        cat.begin()
        summary = cat.advance(Limits())
        assert summary["index_complete"]
        assert cat.matching_files({"field:rare"}) == [".generated/state.c"]
        assert {"path":"external.c","reason":"symlink"} in summary["excluded"]
    finally:
        cat.close()


def test_late_writer_outside_initial_context_gets_its_own_view(tmp_path):
    root = tmp_path/"src"
    root.mkdir()
    out = tmp_path/"out"
    (root/"state.h").write_text(sources()["state.h"])
    (root/"reader.c").write_text(sources()["reader.c"])
    for n in range(5):
        (root/f"filler{n}.c").write_text("void unrelated(void) {}")
    (root/"zz_writer.c").write_text(sources()["writer.c"])
    gaps = [{"file":"reader.c","name":"get"}]
    limits = replace(Limits(),max_files=3,max_slices=1,index_batch_files=1)
    contexts = []
    for _ in range(30):
        receipts = {}
        got = prepare_cross_entry(root,gaps,mode="context",out_dir=out,limits=limits,delivery_receipts=receipts)
        contexts.extend(got.values())
        for receipt in receipts.values():
            acknowledge_delivery(out,receipt)
        if any("void put" in c for c in contexts):
            break
    assert any("void put" in c for c in contexts)


def test_extraction_ceiling_stays_blocked_after_context_delivery(tmp_path):
    from core.json import load_json
    root = tmp_path/"src"
    root.mkdir()
    out = tmp_path/"out"
    for fp,body in sources().items():
        (root/fp).write_text(body)
    receipts = {}
    prepare_cross_entry(root,[{"file":"reader.c","name":"get"}],mode="context",out_dir=out,
                        limits=replace(Limits(),max_sites=1),delivery_receipts=receipts,drain_index=True)
    for receipt in receipts.values():
        acknowledge_delivery(out,receipt)
    progress = load_json(out/"cross-entry-progress.json")
    assert any(b["detail"]["reason"] == "typed_index_coverage" for b in progress["blocked_work"])
    assert progress["work_remaining"]
