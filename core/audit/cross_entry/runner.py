"""Resumable catalogue, typed views, and focused model-work batches."""
from __future__ import annotations

import hashlib
import re
import time
from contextlib import closing
from dataclasses import asdict, replace
from pathlib import Path

from core.json import save_json, load_json

from .cache import load_or_build_index
from .catalogue import Catalogue
from .integration import collect_sources, json_text
from .model import Limits, VERSION, digest
from .progress import WorkQueue, exclusive_session
from .slices import build_slices
from .study import run_studies


def _terms(index, consumers, depth):
    reachable = set(consumers)
    for _ in range(depth):
        reachable |= {r.target for r in index.relations if r.kind == "call" and r.source in reachable}
    terms = set()
    for a in index.accesses:
        if a.function not in reachable:
            continue
        match = re.search(r"(?:struct|class|union) ([A-Za-z_]\w*)$",a.type_id)
        if match:
            terms.add("type:"+match[1])
        for member in re.findall(r"[A-Za-z_]\w*",a.member_path):
            terms.add("field:"+member)
    terms |= {"symbol:"+c.name for c in index.calls if c.caller in reachable and re.fullmatch(r"[A-Za-z_]\w*",c.name)}
    return terms


def _header_signature(path, include_dirs):
    try:
        path = Path(path).resolve()
        if not any(path.is_relative_to(root) for root in include_dirs):
            return None
        info = path.stat()
        return [info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
    except (OSError,RuntimeError):
        return None


def prepare(target,gaps,*,mode,out_dir,limits=None,client=None,entry_points=(),model_key="configured",
            should_stop=None,context_root=None,drain_index=False,delivery_receipts=None,include_dirs=()):
    if mode not in {"off","index","shadow","context","study"}:
        raise ValueError(f"unknown cross-entry mode: {mode}")
    if mode == "off":
        return {}
    limits = limits or Limits()
    include_dirs = tuple(dict.fromkeys(Path(p).resolve() for p in include_dirs))
    target = Path(target).resolve()
    base = target.parent if target.is_file() else target
    root = Path(context_root).resolve() if context_root is not None else base
    if not base.is_relative_to(root):
        raise ValueError("context root must contain the report target")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True,exist_ok=True)
    receipts = delivery_receipts if delivery_receipts is not None else {}
    reports = {}
    for gap in gaps:
        fp = gap.get("file","")
        if not fp:
            continue
        path = (base/fp).resolve()
        if path.is_relative_to(base):
            reports[f"{path.relative_to(root).as_posix()}:{gap.get('name','')}"] = f"{fp}:{gap.get('name','')}"
    report_files = sorted({key.partition(":")[0] for key in reports})
    config = getattr(client,"config",None)
    resolve_model = getattr(config,"get_model_for_task",None)
    model = resolve_model("study") if callable(resolve_model) else None
    identity = {k:getattr(model,k,None) for k in ("provider","model_name","temperature")}
    implementation = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob("*.py")}  # raw-open: __file__-relative module source for namespace key
    namespace = digest({"root":str(root),"target":str(target),"mode":mode,
                        "include_dirs":[str(p) for p in include_dirs],
                        "model":[model_key,identity],"settings":limits.content_settings(),"code":implementation})
    with exclusive_session(out_dir/"cross-entry-lease.sqlite"), closing(Catalogue(root,out_dir)) as catalogue, closing(WorkQueue(out_dir,namespace)) as queue:
        queue.add_requests(gaps)
        gaps = queue.requests()
        for gap in gaps:
            path = (base/gap["file"]).resolve()
            if path.is_relative_to(base):
                reports[f"{path.relative_to(root).as_posix()}:{gap['name']}"] = f"{gap['file']}:{gap['name']}"
        report_files = sorted({key.partition(":")[0] for key in reports})
        queue.add_reports(reports.values())
        catalogue.begin(report_files)
        indexing = catalogue.advance(limits,should_stop)
        while drain_index and not indexing["index_complete"] and (indexing["batch_files"] or indexing["batch_directories"]):
            if should_stop and should_stop():
                break
            indexing = catalogue.advance(limits,should_stop)

        def progress(extra=None):
            state = queue.summary()
            value = {"version":VERSION,"namespace":namespace,"mode":mode,"report_requests":gaps,
                     "selection_key":model_key,"target":str(target),
                     **state,"indexing":catalogue.summary(),
                     "work_remaining":bool(state["remaining_jobs"] or state["remaining_views"] or
                                           state["undelivered_results"] or not catalogue.summary()["index_complete"]),
                     "queue_exhausted_is_not_a_safety_proof":True}
            if extra:
                value.update(extra)
            save_json(out_dir/"cross-entry-progress.json",value)
            return value

        if mode == "index" or not reports:
            progress()
            return {}

        sources,scope = collect_sources(root,report_files,limits,include_dirs=include_dirs)
        auxiliary = {p:scope["raw_source_hashes"][p] for p in scope["auxiliary_headers"]}
        auxiliary_path = out_dir/f"cross-entry-auxiliary-{namespace[:24]}.json"
        previous_auxiliary = load_json(auxiliary_path) or {}
        tracked_headers = {}
        changed_header = bool(set(auxiliary)-set(previous_auxiliary))
        for key,record in previous_auxiliary.items():
            signature = _header_signature(record["path"],include_dirs)
            changed_header |= signature != record["signature"]
            tracked_headers[key] = {**record,"signature":signature}
        if changed_header:
            queue.db.execute("UPDATE views SET status='pending',fingerprint='' WHERE namespace=? AND status!='obsolete'",(namespace,))
            queue.db.commit()
        def remember_headers(scope):
            for key,path in scope["auxiliary_headers"].items():
                tracked_headers[key] = {"path":path,"signature":_header_signature(path,include_dirs)}
            save_json(auxiliary_path,tracked_headers)
        remember_headers(scope)
        catalogue.ingest({p:s for p,s in sources.items() if p not in auxiliary},scope["raw_source_hashes"])
        translated = []
        for key in entry_points:
            fp,sep,name = key.partition(":")
            path = (base/fp).resolve()
            if sep and path.is_relative_to(root):
                translated.append(f"{path.relative_to(root).as_posix()}:{name}")
        warm,warm_cached = load_or_build_index(sources,out_dir=out_dir,limits=limits,entry_points=translated,include_edges=scope["include_edges"])
        requested = {f.id:reports[f"{f.file}:{f.name}"] for f in warm.functions.values() if f"{f.file}:{f.name}" in reports}
        # Ambiguous bare definitions cannot silently overwrite one another.
        for report in reports:
            matches = [f.id for f in warm.functions.values() if f"{f.file}:{f.name}" == report]
            if len(matches) != 1:
                warm.coverage["unresolved"].append({"report":report,"reason":"ambiguous_or_missing_report_definition"})
                for fid in matches:
                    requested.pop(fid,None)
        queue.add_terms(_terms(warm,requested,limits.graph_depth))
        matches = catalogue.matching_files(queue.terms())
        views = [""]+[p for p in matches if p not in sources]
        queue.reconcile_views(views)
        queue.invalidate_files(catalogue.changed_files())
        queue.bind_view(digest("")[:24],digest({"typed":warm.fingerprint,"scope":scope}),scope["raw_source_hashes"])
        view = queue.next_view()
        if view is None:
            progress({"typed_index_cache_hit":warm_cached})
            return {}
        if view["extra_file"]:
            sources,scope = collect_sources(root,report_files+[view["extra_file"]],limits,include_dirs=include_dirs)
            remember_headers(scope)
            index,cached = load_or_build_index(sources,out_dir=out_dir,limits=limits,entry_points=translated,include_edges=scope["include_edges"])
            requested = {f.id:reports[f"{f.file}:{f.name}"] for f in index.functions.values() if f"{f.file}:{f.name}" in reports}
        else:
            index,cached = warm,warm_cached
        for report in reports:
            matches = [f.id for f in index.functions.values() if f"{f.file}:{f.name}" == report]
            if len(matches) != 1:
                for fid in matches:
                    requested.pop(fid,None)
        if not requested:
            save_json(out_dir/"cross-entry-index.json",index.to_dict())
            queue.db.execute("UPDATE views SET status='blocked' WHERE namespace=? AND id=?",(namespace,view["id"]))
            queue.db.commit()
            progress({"blocked_reason":"ambiguous_or_missing_report_definition"})
            return {}
        index.coverage["scope"] = scope
        index.coverage["complete"] = index.coverage["complete"] and scope["complete"] and catalogue.summary()["index_complete"]
        # Repository expansion adds views, rather than invalidating finished
        # studies merely because an unrelated new file was indexed.
        index.fingerprint = digest({"typed":index.fingerprint,"scope":scope})
        queue.add_terms(_terms(index,requested,limits.graph_depth))
        dependencies = dict(scope["raw_source_hashes"])
        if view["extra_file"]:
            dependencies.setdefault(view["extra_file"],"not_collected")
        queue.bind_view(view["id"],index.fingerprint,dependencies)
        queue.add_jobs(view["id"],[(fid,"") for fid in requested])
        # A source-view extraction ceiling cannot be discharged by completing
        # the smaller set of functions it happened to expose. Keep the loss
        # visible as blocked work requiring a larger extraction allowance.
        omissions = index.coverage["truncated"] + index.coverage["skipped"]
        if omissions:
            marker = digest(["typed_index_coverage",omissions])[:24]
            queue.add_jobs(view["id"],[("__typed_index_coverage__",marker)])
            queue.finish(view["id"],digest(["__typed_index_coverage__",marker])[:24],"blocked",
                         {"reason":"typed_index_coverage","omissions":omissions})
        save_json(out_dir/"cross-entry-index.json",index.to_dict())

        units = []
        jobs_by_unit = {}
        deferred = []
        assembly_started = time.monotonic()
        deliveries = queue.undelivered(view["id"])
        jobs = deliveries if deliveries else queue.pending(view["id"])
        represented = set()
        for job in jobs:
            if len(units) >= limits.max_slices or time.monotonic()-assembly_started >= limits.graph_seconds:
                break
            if mode in {"context","shadow"} and job["consumer"] in represented:
                continue
            focused = [job["focus"]] if job["focus"] else []
            built,not_built = build_slices(index,[job["consumer"]],limits=replace(limits,max_slices=1),focus_functions=focused)
            deferred.extend(not_built)
            if not built:
                queue.finish(view["id"],job["id"],"blocked" if not_built else "not_applicable",{"reason":"no_assembled_context"})
                continue
            unit = built[0]
            dispatch_gaps = [t for t in unit.truncated if t.startswith(("dispatch_path_depth:","dispatch_path_budget:"))]
            if dispatch_gaps:
                marker = digest(["dispatch_path_coverage",unit.consumer,dispatch_gaps])[:24]
                queue.add_jobs(view["id"],[("__dispatch_path_coverage__",marker)])
                queue.finish(view["id"],digest(["__dispatch_path_coverage__",marker])[:24],"blocked",
                             {"reason":"dispatch_path_coverage","omissions":dispatch_gaps})
            if not job["focus"]:
                queue.add_jobs(view["id"],[(unit.consumer,f) for f in unit.evidence_candidates if f != unit.consumer])
            units.append(unit)
            jobs_by_unit[unit.id] = job
            represented.add(unit.consumer)

        save_json(out_dir/"cross-entry-slices.json",{"version":VERSION,"mode":mode,"limits":asdict(limits),
                  "index_fingerprint":index.fingerprint,"view":view["id"],
                  "selected":[u.to_dict() for u in units],"deferred":deferred,
                  "durable_queue":str(out_dir/"cross-entry-work.sqlite")})
        semantic = {}
        if mode == "study" and not deliveries:
            if client is None:
                raise ValueError("study mode requires the run's budget-governed client")
            semantic = run_studies(index,units,client,out_dir=out_dir,limits=limits,model_key=model_key,should_stop=should_stop)
            for unit in units:
                result = semantic[unit.id]
                status = result["status"]
                queue.finish(view["id"],jobs_by_unit[unit.id]["id"],
                             "blocked" if status == "context_incomplete" else "partial" if status == "deferred" else status,result)
        elif mode in {"context","shadow"} and not deliveries:
            for unit in units:
                queue.finish(view["id"],jobs_by_unit[unit.id]["id"],"prepared",{"key":unit.fingerprint})

        contexts = {}
        available = queue.undelivered(view["id"])
        for unit in units:
            key = requested.get(unit.consumer)
            if key is None or key in contexts:
                continue
            job = jobs_by_unit[unit.id]
            result = semantic.get(unit.id) or job.get("outcome")
            if mode in {"context","study"}:
                text = ("Shared-state investigation context; no verified finding.\nCoverage: "
                        +json_text({"complete":index.coverage["complete"],"unresolved":unit.unresolved,
                                    "truncated":unit.truncated,"repository":catalogue.summary()})
                        +"\nEntry/helper paths: "+json_text(unit.entry_paths)+"\n"+unit.source)
                if result:
                    text += "\nConditional semantic study (including refutation):\n"+json_text(result)
                contexts[key] = text
                ready = next((r for r in available if r["id"] == job["id"]),None)
                if ready:
                    receipts[key] = {"namespace":namespace,"view":view["id"],"job":job["id"],"evidence":ready["evidence"]}
            elif mode == "shadow":
                # Artifact-only mode has no review delivery obligation.
                for ready in available:
                    queue.acknowledge(view["id"],ready["id"],ready["evidence"])
        queue.complete_view_if_finished(view["id"])
        progress({"typed_index_cache_hit":cached})
        save_json(out_dir/"cross-entry-delivery.json",{"version":VERSION,"mode":mode,
                  "available_to_review":sorted(contexts),"semantic_results":len(semantic),
                  "receipts":receipts,"deferred":queue.summary()["remaining_jobs"]})
        return contexts
