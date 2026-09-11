// unguarded_sinks.sc — find sink calls NOT dominated by conditionals.
//
// Returns the specific unguarded sink calls with their line numbers and
// code, so the LLM knows exactly where the missing guard is.
//
// Template slots (substituted by core/analysis/reachability_gates.py
// after validation):
//   __FUNCTION__   — target function name
//   __SINK_NAMES__ — sink-name list body, rendered from the single
//                    authority _UNGUARDED_QUERY_SINKS (this file used
//                    to hardcode a drifting copy of it)
//
// Output: JOERN_UNGUARDED: JSON per unguarded sink call — println'd
// for the subprocess transport AND carried in the final expression's
// string echo for the server transport (/query-sync drops println).

import io.shiftleft.semanticcpg.language._

// jsonEsc — the one escape helper for every value interpolated into a
// JSON-string context: backslash before quote; \r stripped; \n, the
// remaining C0 controls (tab included — strict json.loads rejects all
// raw control chars) and U+0085/U+2028/U+2029 (Python str.splitlines
// splits on these) flatten to single spaces so a record stays one
// MARKER:{json} line.
def jsonEsc(v: String): String = v.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", "").replace("\n", " ").flatMap(c => if (c.toInt < 0x20 || c.toInt == 0x85 || c.toInt == 0x2028 || c.toInt == 0x2029) " " else c.toString)

val fnName = "__FUNCTION__"
val sinkNames = List(__SINK_NAMES__)

val fn = cpg.method.name(fnName)
val sinkCalls = fn.call.name(sinkNames.mkString("|")).l

val results = sinkCalls.flatMap { call =>
  val dominated = call.dominatedBy.isControlStructure.l.nonEmpty
  val controlled = call.controlledBy.isControlStructure.l.nonEmpty
  if (!dominated && !controlled) {
    val line = call.lineNumber.getOrElse(0)
    // .take(200) on the RAW string BEFORE jsonEsc — escape-then-
    // truncate can bisect an injected \" and leave a dangling
    // backslash.
    val code = jsonEsc(call.code.take(200))
    val name = jsonEsc(call.name)
    Some(s"""JOERN_UNGUARDED:{"sink":"$name","line":$line,"code":"$code","guarded":false}""")
  } else None
}

val total = sinkCalls.size
val unguarded = results.size

results.foreach(println)
println(s"JOERN_GUARD_SUMMARY:$unguarded/$total")
s"JOERN_GUARD_SUMMARY:$unguarded/$total\n" + results.mkString("\n")
