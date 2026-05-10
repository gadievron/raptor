// function_inventory.cocci — emit two record kinds for the validation
// Stage C structural pre-check:
//   * "def:<name>" at every function definition
//   * "call:<name>" at every call site that is NOT a definition
//
// The Python ``prereqs`` module derives:
//   * function_exists(name): finding's claimed function is a real C
//     function in the tree (not a macro the LLM hallucinated as one)
//   * function_has_callers(name): function is called from somewhere
//     other than itself (orphan-static-helper detection)
//
// The rule is intentionally narrow — defs and calls only. Anything
// richer (taint, escape, scope shadowing) overlaps with CodeQL or
// belongs in the LLM stages.

@fdef@
identifier f;
position p;
@@

f@p(...)
{
  ...
}

@script:python@
p << fdef.p;
f << fdef.f;
@@
import json, sys
for _p in p:
    _m = {"file": _p.file, "line": int(_p.line),
          "rule": "function_inventory",
          "message": "def:" + str(f)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")

// Match call sites whose position is NOT one of the definition
// positions — otherwise ``f(...)`` in the def header would match
// here too and inflate the caller count.
@fcall@
identifier g;
position q != fdef.p;
@@

g@q(...)

@script:python@
q << fcall.q;
g << fcall.g;
@@
import json, sys
for _q in q:
    _m = {"file": _q.file, "line": int(_q.line),
          "rule": "function_inventory",
          "message": "call:" + str(g)}
    sys.stderr.write("COCCIRESULT:" + json.dumps(_m) + "\n")
