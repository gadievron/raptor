"""Checkpointed study state machine. A call allowance is a work quantum."""
from __future__ import annotations

import json
import time
from pathlib import Path

from core.json import load_json, save_json
from core.security.prompt_envelope import wrap_untrusted

from .model import Limits, VERSION, digest
from .progress import exclusive_session
from .study import SYSTEM, REFUTE_SYSTEM, STUDY_SCHEMA, REFUTE_SCHEMA, _payload, _validate, _refutation


class _BudgetStop(Exception):
    pass


def run_studies(index, units, client, *, out_dir, limits=None, model_key="configured", should_stop=None):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True,exist_ok=True)
    with exclusive_session(out_dir/"cross-entry-study-lease.sqlite"):
        return _run(index,units,client,out_dir,limits or Limits(),model_key,should_stop)


def _run(index,units,client,out_dir,limits,model_key,should_stop):
    from core.llm.structured_call import unwrap_structured_response
    from core.llm.prompt_budget import estimate_tokens

    cache_dir = out_dir/"cross-entry-cache"
    cache_dir.mkdir(parents=True,exist_ok=True)
    started = time.monotonic()
    calls = 0
    call_records = []
    results = {}
    config = getattr(client,"config",None)
    resolve_model = getattr(config,"get_model_for_task",None)
    model = resolve_model("study") if callable(resolve_model) else None
    identity = {k:getattr(model,k,None) for k in ("provider","model_name","temperature","max_context")}

    def stopped():
        exhausted = getattr(client,"is_budget_exhausted",None)
        return (calls >= limits.max_calls or time.monotonic()-started >= limits.study_seconds
                or bool(should_stop and should_stop()) or bool(exhausted and exhausted()))

    def summary():
        save_json(out_dir/"cross-entry-study.json",{"version":VERSION,"index_fingerprint":index.fingerprint,
                  "calls_attempted":calls,"call_records":call_records,"model_identity":identity,"results":results})

    for unit in units:
        targets = {r["target"] for r in unit.dispatch_candidates}
        key = digest({"engine":2,"unit":unit.fingerprint,"model":[model_key,identity],
                      "prompts":[SYSTEM,REFUTE_SYSTEM],"schemas":[STUDY_SCHEMA,REFUTE_SCHEMA],
                      "settings":limits.content_settings()})
        path = cache_dir/f"{key}.json"
        state = load_json(path)
        resumed = isinstance(state,dict) and state.get("key") == key
        if not resumed:
            state = {"key":key,"phase":"study","functions":list(unit.functions),"retrieved_functions":[],
                     "refutations":[],"retrieval_rounds_done":0,"total_attempts":0,"receipts":[]}
        state["cache_hit"] = False
        state["resumed"] = resumed
        state.pop("pending_refutations",None)
        if state.get("in_flight") and not state.get("pending_response"):
            state["ambiguous_previous_attempt"] = True
        state["in_flight"] = False

        # Repair malformed checkpoints before entering the paid state machine,
        # rather than requiring an extra invocation merely to clear them.
        if "study" in state:
            try:
                _,check_allowed,check_present = _payload(index,unit,state["functions"],limits)
                _validate(state["study"],check_allowed,check_present,consumer=unit.consumer,conditional_targets=targets)
            except (ValueError,KeyError,TypeError):
                state.update(phase="study",functions=list(unit.functions),refutations=[],retrieval_rounds_done=0)
                state.pop("study",None)
                state.pop("pending_response",None)

        def checkpoint():
            save_json(path,state)

        def payload(functions):
            if not isinstance(functions,list) or any(f not in index.functions for f in functions):
                raise ValueError("invalid checkpoint functions")
            return _payload(index,unit,functions,limits)

        def validate(raw,allowed,present):
            return _validate(raw,allowed,present,consumer=unit.consumer,conditional_targets=targets)

        def response(stage,prompt,schema,system,functions):
            nonlocal calls
            pending = state.get("pending_response")
            if isinstance(pending,dict) and pending.get("stage") == stage and pending.get("functions") == functions:
                return pending["result"]
            if stopped():
                raise _BudgetStop()
            if estimate_tokens(prompt+system+json.dumps(schema)) > limits.input_tokens:
                raise ValueError("cross-entry input token budget exceeded")
            state["in_flight"] = True
            state["total_attempts"] += 1
            checkpoint()
            calls += 1
            raw = client.generate_structured(prompt,schema,system_prompt=system,task_type="study",
                call_class="study",max_tokens=limits.output_tokens,timeout_s=60,timeout_retry_cap=0)
            call = unwrap_structured_response(raw,empty_result={})
            receipt = {"model":call.model,"cost_usd":call.cost,"usage":call.usage}
            call_records.append(receipt)
            state["receipts"].append(receipt)
            state["pending_response"] = {"stage":stage,"result":call.result,"functions":functions}
            state["in_flight"] = False
            checkpoint()  # Resume a received response without buying it again.
            return call.result

        def consumed():
            state.pop("pending_response",None)

        try:
            functions = state["functions"]
            prompt,allowed,present = payload(functions)
            if state.get("phase") not in {"study","retrieve","refute","complete","blocked"}:
                raise ValueError("invalid checkpoint phase")
            if "study" in state:
                state["study"] = validate(state["study"],allowed,present)
                refs = state.get("refutations")
                if not isinstance(refs,list) or len(refs) > len(state["study"]["witnesses"]):
                    raise ValueError("invalid checkpoint refutations")
                state["refutations"] = [_refutation(r,allowed) for r in refs]
            if state["phase"] == "complete":
                if "study" not in state or len(state["refutations"]) != len(state["study"]["witnesses"]):
                    raise ValueError("incomplete cached result")
                state.update(status="complete",cache_hit=True)
            elif unit.consumer not in present:
                state.update(status="context_incomplete",phase="blocked",reason="consumer_body_budget")
            elif not set(unit.focus_functions).issubset(allowed):
                state.update(status="context_incomplete",phase="blocked",reason="focus_body_budget")
            elif state["phase"] == "blocked":
                state.update(status="context_incomplete")
            else:
                while state["phase"] != "complete":
                    phase = state["phase"]
                    if phase == "study":
                        raw = response("study",prompt,STUDY_SCHEMA,SYSTEM,functions)
                        state["study"] = validate(raw,allowed,present)
                        consumed()
                        state["phase"] = "retrieve"
                    elif phase == "retrieve":
                        study = state["study"]
                        extra = []
                        if state["retrieval_rounds_done"] < limits.retrieval_rounds:
                            for name in study["needed_symbols"]:
                                matches = [f.id for f in index.functions.values() if f.name == name]
                                if len(matches) == 1 and matches[0] not in functions:
                                    extra.append(matches[0])
                        extra = sorted(set(extra))[:max(0,min(4,limits.functions_per_slice-1))]
                        if extra:
                            next_functions = ([unit.consumer]+extra+[f for f in functions if f != unit.consumer])[:limits.functions_per_slice]
                            next_prompt,next_allowed,next_present = payload(next_functions)
                            raw = response(f"retrieve:{state['retrieval_rounds_done']}",next_prompt,STUDY_SCHEMA,SYSTEM,next_functions)
                            state["study"] = validate(raw,next_allowed,next_present)
                            state["retrieved_functions"] += extra
                            state["retrieval_rounds_done"] += 1
                            functions = state["functions"] = next_functions
                            prompt,allowed,present = next_prompt,next_allowed,next_present
                            consumed()
                        else:
                            state["phase"] = "refute"
                            state["unresolved_symbols"] = study["needed_symbols"]
                    elif phase == "refute":
                        number = len(state["refutations"])
                        witnesses = state["study"]["witnesses"]
                        if number == len(witnesses):
                            state["phase"] = "complete"
                        else:
                            hypothesis = wrap_untrusted(json.dumps(witnesses[number]),kind="cross-entry-hypothesis",origin="semantic-study")
                            raw = response(f"refute:{number}",prompt+"\n"+hypothesis,REFUTE_SCHEMA,REFUTE_SYSTEM,functions)
                            state["refutations"].append(_refutation(raw,allowed))
                            consumed()
                    checkpoint()
                state.update(status="complete")
        except _BudgetStop:
            state.update(status="partial" if "study" in state else "deferred",reason="study_budget")
            if state.get("phase") == "refute":
                # A placeholder is presentation only; do not checkpoint it as
                # a completed refutation or the next segment cannot resume.
                state["pending_refutations"] = len(state["study"]["witnesses"])-len(state["refutations"])
        except Exception as exc:
            state.update(status="error",error=type(exc).__name__)
            if isinstance(exc,(ValueError,KeyError,TypeError)):
                # Corrupt cached data must not become a permanent stuck head.
                state["phase"] = "study"
                state["functions"] = list(unit.functions)
                state.pop("study",None)
                state["refutations"] = []
                state.pop("pending_response",None)
        checkpoint()
        state["checkpoint"] = str(path)
        result = dict(state)
        if state.get("pending_refutations"):
            result["refutations"] = list(state["refutations"])+[
                {"verdict":"unsupported","reason":"refutation_budget","evidence_ids":[]}
                for _ in range(state["pending_refutations"])]
        results[unit.id] = result
        summary()
    summary()
    return results
