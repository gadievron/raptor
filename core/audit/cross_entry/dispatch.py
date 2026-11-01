"""Typed callback candidates and source excerpts, never proven runtime targets.

Join assignment and invocation slots by their enclosing declaration type.
Pointer identity, initialization order and runtime algorithm selection remain
obligations for the reviewer; a unique candidate does not discharge them.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque

from .index import _binding, declared_name, text, walk
from .model import Relation


def index_dispatch(index, trees, types, contexts, resolve, limits):
    started = time.monotonic()
    members = defaultdict(dict)
    layouts = {}
    returns = defaultdict(list)
    functions_by_file = defaultdict(list)
    for function in index.functions.values():
        functions_by_file[function.file].append(function)

    def fields(body):
        for n in body.named_children:
            if n.type != "field_declaration":
                continue
            typ = n.child_by_field_name("type")
            declarators = n.children_by_field_name("declarator")
            if not declarators and typ is not None and typ.child_by_field_name("body") is not None:
                # Members of an anonymous struct/union are visible on its owner.
                yield from fields(typ.child_by_field_name("body"))
            for dec in declarators:
                yield typ,dec

    for fp,(tree,src) in trees.items():
        for n in walk(tree.root_node):
            if n.type in {"struct_specifier","union_specifier","class_specifier"} and n.child_by_field_name("body") is not None:
                tag = n.type.split("_")[0]+" "+text(n.child_by_field_name("name"),src)
                key = f"{fp}:{n.start_byte}:{tag}"
                # Positional C initialization follows declaration order. Do
                # not guess through anonymous aggregates or preprocessor arms.
                layout = []
                simple = True
                for typ,dec in fields(n.child_by_field_name("body")):
                    name = text(declared_name(dec),src)
                    if name:
                        members[key][name] = types.resolve(typ,fp,src)
                        layout.append(name)
                for child in n.child_by_field_name("body").named_children:
                    if child.type != "field_declaration" or not child.children_by_field_name("declarator"):
                        simple = False
                if simple:
                    layouts[key] = layout[:1] if n.type == "union_specifier" else layout
            if n.type in {"function_definition","declaration"}:
                for dec in n.children_by_field_name("declarator"):
                    if any(c.type == "function_declarator" for c in walk(dec)):
                        name = text(declared_name(dec),src)
                        returns[name].append((fp,types.resolve(n.child_by_field_name("type"),fp,src)))

    def expr_type(node,fp,src,bindings,depth=0):
        if node is None or depth > limits.graph_depth+4:
            return "","unresolved"
        if node.type == "identifier":
            binding = _binding(bindings,text(node,src),node.start_byte)
            return (binding.type_id,binding.resolution) if binding else ("","unresolved")
        if node.type == "field_expression":
            owner,_ = expr_type(node.child_by_field_name("argument"),fp,src,bindings,depth+1)
            return members.get(owner,{}).get(text(node.child_by_field_name("field"),src),("","unresolved"))
        if node.type == "call_expression":
            name = text(node.child_by_field_name("function"),src)
            visible = [ret for file,ret in returns[name] if file in types.visible[fp]]
            choices = set(visible)
            return choices.pop() if len(choices) == 1 else ("","unresolved")
        if node.type in {"parenthesized_expression","pointer_expression","cast_expression","subscript_expression"}:
            if node.type == "cast_expression":
                descriptor = node.child_by_field_name("type")
                if descriptor is not None:
                    cast_type = types.resolve(descriptor.child_by_field_name("type"),fp,src)
                    if cast_type[1] != "unresolved":
                        return cast_type
            inner = node.child_by_field_name("argument") or node.child_by_field_name("value")
            if inner is None and node.named_children:
                inner = node.named_children[0]
            return expr_type(inner,fp,src,bindings,depth+1)
        return "","unresolved"

    def slot(node,fp,src,bindings):
        if node is None or node.type != "field_expression":
            return "","","unresolved"
        owner,resolution = expr_type(node.child_by_field_name("argument"),fp,src,bindings)
        return owner,text(node.child_by_field_name("field"),src),resolution

    buckets = defaultdict(list)
    alias_events = defaultdict(list)

    def register(owner,member,value,fp,src,installer,node,resolution,aliases=(),seen=frozenset()):
        if not owner or not member or resolution == "unresolved":
            return
        # Resolve actual definitions; an arbitrary identifier is not a callback.
        while value is not None and value.type in {"pointer_expression","parenthesized_expression","cast_expression"}:
            value = value.child_by_field_name("argument") or value.child_by_field_name("value") or (value.named_children[0] if value.named_children else None)
        if value is not None and value.type == "conditional_expression":
            for field in ("consequence","alternative"):
                register(owner,member,value.child_by_field_name(field),fp,src,installer,node,resolution,aliases,seen)
            return
        if value is None or value.type not in {"identifier","qualified_identifier"}:
            return
        if installer in contexts:
            binding = _binding(contexts[installer][1],text(value,src),value.start_byte)
            if binding is not None:
                events = [event for event in alias_events[binding.id] if event[0] <= value.start_byte]
                if binding.id in seen or not events:
                    index.coverage["unresolved"].append({"file":fp,"line":node.start_point[0]+1,"reason":"callback_value_indirect"})
                    return
                for _,origin,evidence_node in events:
                    evidence = f"callback-alias:{fp}:{evidence_node.start_byte}"
                    index.declarations[evidence] = {"file":fp,"line":evidence_node.start_point[0]+1,"source":text(evidence_node,src)}
                    register(owner,member,origin,fp,src,installer,node,resolution,aliases+(evidence,),seen|{binding.id})
                return
        targets = resolve(text(value,src),fp)
        if len(targets) != 1:
            if targets:
                index.coverage["unresolved"].append({"file":fp,"line":node.start_point[0]+1,"reason":"ambiguous_callback_assignment"})
            return
        evidence = f"callback:{fp}:{node.start_byte}"
        index.declarations[evidence] = {"file":fp,"line":node.start_point[0]+1,"source":text(node,src)}
        row = {"owner_type":owner,"slot":member,"target":targets[0],"installer":installer,
               "evidence_id":evidence,"file":fp,"line":node.start_point[0]+1,
               "start_byte":node.start_byte,
               "alias_evidence":list(aliases),
               "type_resolution":resolution,"status":"conditional_runtime_selection"}
        index.callbacks.append(row)
        buckets[owner,member].append(row)

    call_nodes = {}
    for fid,(fn,bindings) in contexts.items():
        fp = index.functions[fid].file
        src = trees[fp][1]
        for n in walk(fn.child_by_field_name("body")):
            if n.type == "declaration":
                for dec in n.children_by_field_name("declarator"):
                    name = declared_name(dec)
                    binding = _binding(bindings,text(name,src),dec.end_byte)
                    value = dec.child_by_field_name("value")
                    if binding is not None and value is not None:
                        alias_events[binding.id].append((dec.end_byte,value,n))
            if n.type == "assignment_expression" and text(n.child_by_field_name("operator"),src) == "=":
                lhs = n.child_by_field_name("left")
                if lhs is not None and lhs.type == "identifier":
                    binding = _binding(bindings,text(lhs,src),lhs.start_byte)
                    if binding is not None:
                        alias_events[binding.id].append((n.end_byte,n.child_by_field_name("right"),n))
                owner,member,resolution = slot(lhs,fp,src,bindings)
                register(owner,member,n.child_by_field_name("right"),fp,src,fid,n,resolution)
            if n.type == "call_expression":
                call_nodes[fid,n.start_byte,n.end_byte] = n
        if time.monotonic()-started > limits.graph_seconds:
            index.coverage["truncated"].append("callback_index_time_budget")
            break

    def initializers(node,owner,fp,src,installer):
        if node is None or node.type != "initializer_list":
            return
        position = 0
        layout = layouts.get(owner)
        for pair in node.named_children:
            if pair.type != "initializer_pair":
                if layout is None or position >= len(layout):
                    index.coverage["unresolved"].append({"file":fp,"line":pair.start_point[0]+1,"reason":"positional_callback_layout_unresolved"})
                    continue
                member = layout[position]
                position += 1
                if pair.type == "initializer_list":
                    nested,_ = members.get(owner,{}).get(member,("","unresolved"))
                    initializers(pair,nested,fp,src,installer)
                else:
                    register(owner,member,pair,fp,src,installer,pair,"resolved")
                continue
            designators = pair.children_by_field_name("designator")
            names = [text(n,src).lstrip(".") for n in designators if n.type == "field_designator"]
            value = pair.child_by_field_name("value")
            if not names:
                # An array designator does not identify a struct member.
                initializers(value,owner,fp,src,installer)
                continue
            if layout is not None and names[0] in layout:
                position = layout.index(names[0])+1
            typ = owner
            for member in names[:-1]:
                typ,_ = members.get(typ,{}).get(member,("","unresolved"))
            member = names[-1]
            if value is not None and value.type == "initializer_list":
                nested,_ = members.get(typ,{}).get(member,("","unresolved"))
                initializers(value,nested,fp,src,installer)
            else:
                register(typ,member,value,fp,src,installer,pair,"resolved" if typ in members else "partial")

    for fp,(tree,src) in trees.items():
        for n in walk(tree.root_node):
            if n.type == "compound_literal_expression":
                descriptor = n.child_by_field_name("type")
                owner,resolution = types.resolve(descriptor.child_by_field_name("type") if descriptor else None,fp,src)
                installer = next((f.id for f in functions_by_file[fp] if f.start_byte <= n.start_byte < f.end_byte),"")
                if resolution != "unresolved":
                    initializers(n.child_by_field_name("value"),owner,fp,src,installer)
            if n.type == "declaration":
                owner,resolution = types.resolve(n.child_by_field_name("type"),fp,src)
                if resolution != "unresolved":
                    installer = next((f.id for f in functions_by_file[fp] if f.start_byte <= n.start_byte < f.end_byte),"")
                    for dec in n.children_by_field_name("declarator"):
                        value = dec.child_by_field_name("value")
                        # Outer lists of array elements each initialize one
                        # object, rather than successive fields of one object.
                        if value is not None and value.type == "initializer_list" and any(c.type == "array_declarator" for c in walk(dec)):
                            for element in value.named_children:
                                initializers(element.child_by_field_name("value") if element.type == "initializer_pair" else element,owner,fp,src,installer)
                        else:
                            initializers(value,owner,fp,src,installer)
        if time.monotonic()-started > limits.graph_seconds:
            index.coverage["truncated"].append("callback_index_time_budget")
            break

    def callback_slots(node,fp,src,bindings,pos,seen=frozenset()):
        if node is None or len(seen) > limits.graph_depth+4:
            return []
        if node.type in {"parenthesized_expression","pointer_expression","cast_expression"}:
            return callback_slots(node.child_by_field_name("argument") or node.child_by_field_name("value") or next(iter(node.named_children),None),fp,src,bindings,pos,seen)
        if node.type == "conditional_expression":
            return [slot for field in ("consequence","alternative")
                    for slot in callback_slots(node.child_by_field_name(field),fp,src,bindings,pos,seen)]
        if node.type == "field_expression":
            owner,member,resolution = slot(node,fp,src,bindings)
            return [(owner,member,resolution,[])]
        if node.type == "identifier":
            binding = _binding(bindings,text(node,src),node.start_byte)
            if binding is None or binding.id in seen:
                return []
            result = []
            for offset,value,evidence_node in alias_events[binding.id]:
                if offset > pos:
                    continue
                evidence = f"callback-alias:{fp}:{evidence_node.start_byte}"
                index.declarations[evidence] = {"file":fp,"line":evidence_node.start_point[0]+1,"source":text(evidence_node,src)}
                for owner,member,resolution,trail in callback_slots(value,fp,src,bindings,value.start_byte,seen|{binding.id}):
                    result.append((owner,member,resolution,trail+[evidence]))
            return result
        return []

    edges = 0
    for call in index.calls:
        n = call_nodes.get((call.caller,call.start_byte,call.end_byte))
        if n is None:
            continue
        fn,bindings = contexts[call.caller]
        fp = index.functions[call.caller].file
        slots = callback_slots(n.child_by_field_name("function"),fp,trees[fp][1],bindings,n.start_byte)
        rows = []
        invocation = f"callback-call:{fp}:{n.start_byte}"
        for owner,member,resolution,aliases in slots:
            call.dispatch_type,call.dispatch_slot = owner,member
            if not owner or resolution == "unresolved":
                index.coverage["unresolved"].append({"caller":call.caller,"line":call.line,"reason":"callback_owner_unresolved"})
                continue
            rows.extend({**row,"alias_evidence":row["alias_evidence"]+aliases} for row in buckets[owner,member])
        for row in sorted(rows,key=lambda r:(r["target"],r["evidence_id"])):
            if edges >= limits.max_sites or time.monotonic()-started > limits.graph_seconds:
                index.coverage["truncated"].append("dispatch_edge_budget")
                break
            target = index.functions[row["target"]]
            count_matches = len(target.params) == len(call.arguments)
            if not count_matches:
                # Casts and ABI mistakes can themselves be the bug. Retain
                # the typed slot candidate; do not silently prune it by arity.
                index.coverage["unresolved"].append({"caller":call.caller,"line":call.line,
                    "target":target.id,"reason":"callback_argument_count_unverified"})
            index.declarations[invocation] = {"file":fp,"line":call.line,"source":text(n,trees[fp][1])}
            binding = {**row,"caller":call.caller,"call_line":call.line,"arguments":call.arguments,
                       "invocation_evidence":invocation,
                       "argument_count_matches":count_matches,
                       "parameter_bindings":dict(zip(target.params,call.arguments))}
            if binding not in call.dispatch_bindings:
                call.dispatch_bindings.append(binding)
            if target.id not in call.dispatch_candidates:
                call.dispatch_candidates.append(target.id)
                index.relations.append(Relation(call.caller,target.id,"dispatch_candidate",row["evidence_id"],"conditional"))
                for argument,parameter in zip(call.arguments,target.params):
                    index.relations.append(Relation(f"{call.caller}:{argument}",f"{target.id}:parameter:{parameter}",
                                                    "dispatch_argument_binding",row["evidence_id"],"conditional"))
                edges += 1


def expand_dispatch_paths(index, roots, limits):
    """Follow calls after a conditional dispatch without making them direct
    consumer edges. Keep one concrete source path per root and destination.
    """
    calls = defaultdict(list)
    for call in index.calls:
        calls[call.caller].append(call)
    rows = []
    deferred = []
    started = time.monotonic()

    def direct_step(call,target):
        fn = index.functions[call.caller]
        evidence = f"callback-helper-call:{fn.file}:{call.start_byte}"
        source = fn.source.encode()[call.start_byte-fn.start_byte:call.end_byte-fn.start_byte].decode(errors="replace")
        index.declarations[evidence] = {"file":fn.file,"line":call.line,"source":source}
        return {"caller":call.caller,"target":target,"kind":"direct_call",
                "evidence_id":evidence,"parameter_bindings":dict(zip(index.functions[target].params,call.arguments))}

    todo = deque()
    seen = set()
    for root_id,root in enumerate(roots):
        first = {"caller":root["caller"],"target":root["target"],"kind":"dispatch_candidate",
                 "evidence_id":root["evidence_id"],"invocation_evidence":root.get("invocation_evidence"),
                 "alias_evidence":root.get("alias_evidence",[]),"parameter_bindings":root.get("parameter_bindings",{})}
        initial = {**root,"callback_target":root["target"],"dispatch_root":root["target"],"dispatch_path":[first]}
        # Retain every initial target even if no traversal allowance remains.
        rows.append(initial)
        todo.append((root_id,initial))
        seen.add((root_id,root["target"]))

    def enqueue(root_id,row):
        identity = root_id,row["target"]
        if identity in seen:
            return
        seen.add(identity)
        if len(rows) >= limits.max_sites:
            deferred.append({"reason":"dispatch_path_budget","target":row["target"],"root":row["dispatch_root"]})
            return
        rows.append(row)
        todo.append((root_id,row))

    # Multi-source BFS gives all immediate implementations a turn before
    # exploring deep helpers of any one implementation.
    while todo:
        root_id,row = todo.popleft()
        if time.monotonic()-started > limits.graph_seconds:
            deferred.extend({"reason":"dispatch_path_budget","target":r["target"],"root":r["dispatch_root"]}
                            for _,r in [(root_id,row)]+list(todo))
            break
        outgoing = calls[row["target"]]
        if len(row["dispatch_path"]) > limits.graph_depth:
            if any(c.targets or c.dispatch_bindings for c in outgoing):
                deferred.append({"reason":"dispatch_path_depth","target":row["target"],"root":row["dispatch_root"]})
            continue
        for call in outgoing:
            for target in call.targets:
                if (root_id,target) in seen:
                    continue
                step = direct_step(call,target)
                enqueue(root_id,{**row,"target":target,"dispatch_path":row["dispatch_path"]+[step]})
            for binding in call.dispatch_bindings:
                step = {"caller":call.caller,"target":binding["target"],"kind":"dispatch_candidate",
                        "evidence_id":binding["evidence_id"],"invocation_evidence":binding["invocation_evidence"],
                        "alias_evidence":binding.get("alias_evidence",[]),"parameter_bindings":binding["parameter_bindings"]}
                enqueue(root_id,{**binding,"callback_target":binding["target"],"dispatch_root":row["dispatch_root"],
                                 "dispatch_path":row["dispatch_path"]+[step]})
    return rows,deferred


def dispatch_catalogue(index, rows, budget):
    """Return exact source fragments plus citeable IDs; preserve omitted counts.

    Prefer helper uses of pointers derived from fields over generic setup.
    Give each visited implementation a binding/effect packet. All target
    rows and omitted-site counts remain available outside the prompt.
    """
    by_target = defaultdict(list)
    for row in rows:
        by_target[row["target"]].append(row)
    fragments = []
    per_function = defaultdict(list)
    per_calls = defaultdict(list)
    for a in index.accesses:
        per_function[a.function].append(a)
    for call in index.calls:
        per_calls[call.caller].append(call)
    for fid,bindings in sorted(by_target.items()):
        fn = index.functions[fid]
        accesses = [a for a in per_function[fid] if a.operation != "read"]
        def priority(a):
            derived = any(p+"->" in a.object_origin or p+"." in a.object_origin for p in fn.params)
            derived |= a.object_origin.startswith("parameter:") and a.member_path != "*"
            calls = [c for c in per_calls[fid] if c.start_byte <= a.start_byte < c.end_byte]
            computed = max((sum(k in {"binary_expression","subscript_expression"} for k in c.argument_kinds)
                            for c in calls),default=0)
            return (not derived,a.operation not in {"indirect_write","read_modify_write"},-computed,a.line,a.id)
        seen = set()
        candidates = []
        for a in sorted(accesses,key=priority):
            calls = [c for c in per_calls[fid] if c.start_byte <= a.start_byte < c.end_byte]
            if calls:
                call = min(calls,key=lambda c:c.end_byte-c.start_byte)
                source = fn.source.encode()[call.start_byte-fn.start_byte:call.end_byte-fn.start_byte].decode(errors="replace")
                location = call.line
            else:
                offset = a.line-fn.start
                source = fn.source.splitlines()[offset] if 0 <= offset < len(fn.source.splitlines()) else ""
                location = a.line
            if not source or (location,source) in seen:
                continue
            seen.add((location,source))
            candidates.append({"function":fid,"evidence_id":a.id,"file":fn.file,"line":location,
                               "origin":a.object_origin,"source":source,"kind":"effect_fragment"})
        for row in bindings[:1]:
            decl = index.declarations[row["evidence_id"]]
            candidates.insert(0,{"function":fid,"evidence_id":row["evidence_id"],**decl,
                                 "installer":row["installer"],"callback_target":row.get("callback_target",fid),
                                 "kind":"callback_assignment"})
        resource_effects = sum(not priority(a)[0] for a in accesses)
        path_depth = min((len(r.get("dispatch_path",[None])) for r in bindings),default=1)
        fragments.append((path_depth,resource_effects,fid,candidates))
    emitted = []
    used = 0
    seen_evidence = set()
    # Invocation and alias statements carry the resource handoff. Keep the
    # source-backed path, not just the destination implementation's effects.
    path_fragments = []
    for row in rows:
        steps = row.get("dispatch_path") or [{"caller":row.get("caller",row["target"]),
                  "evidence_id":row["evidence_id"],"invocation_evidence":row.get("invocation_evidence"),
                  "alias_evidence":row.get("alias_evidence",[])}]
        for step in steps:
            for evidence in [step["evidence_id"],step.get("invocation_evidence")]+step.get("alias_evidence",[]):
                if not evidence or evidence in seen_evidence or evidence not in index.declarations:
                    continue
                seen_evidence.add(evidence)
                decl = index.declarations[evidence]
                fragment = {"function":step["caller"],"evidence_id":evidence,**decl,"kind":"dispatch_path"}
                rendered = f"\nCONDITIONAL DISPATCH PATH EVIDENCE {evidence} ({decl['file']}:{decl['line']})\n{decl['source']}\n"
                path_fragments.append((fragment,rendered))
    # Leave most of the excerpt budget available for callback side effects.
    path_used = 0
    for fragment,rendered in path_fragments:
        if path_used+len(rendered) <= budget//8:
            emitted.append((fragment,rendered))
            used += len(rendered)
            path_used += len(rendered)
    # First give each visited implementation its binding and up to three
    # effect sites together. A list of assignments alone gives the study no
    # evidence of what any callback does. Remaining sites stay deferred.
    for _,_,fid,group in sorted(fragments,key=lambda item:(item[0],-item[1],item[2])):
        packet = []
        for fragment in group[:4]:
            heading = (f"CALLBACK BINDING in {fragment['installer'] or '<static initializer>'} for {fragment['callback_target']}"
                       if fragment["kind"] == "callback_assignment" else f"CALLBACK EFFECT FRAGMENT {fragment['function']}")
            rendered = (f"\n{heading}\n"
                        f"EVIDENCE {fragment['evidence_id']} ({fragment['file']}:{fragment['line']})\n"
                        + fragment["source"]+"\n")
            packet.append((fragment,rendered))
        size = sum(len(rendered) for _,rendered in packet)
        if used+size <= budget:
            emitted.extend(packet)
            used += size
    return emitted,sum(len(group) for _,_,_,group in fragments)+len(path_fragments)-len(emitted)
