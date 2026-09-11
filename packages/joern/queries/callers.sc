// callers.sc — find all call sites that invoke a function.
//
// The tree-sitter call graph misses indirect calls (function pointers,
// callbacks, struct dispatch). Joern's CPG resolves these via
// data-dependence edges.
//
// Template slot: __FUNCTION__ (substituted by runner after validation)
//
// Output: one JOERN_CALLER: JSON line per caller — println'd for the
// subprocess transport AND carried in the final expression's string
// echo for the server transport (/query-sync drops println output).

import io.shiftleft.semanticcpg.language._

// jsonEsc — the one escape helper for every value interpolated into a
// JSON-string context: backslash before quote; \r stripped; \n, the
// remaining C0 controls (tab included — strict json.loads rejects all
// raw control chars) and U+0085/U+2028/U+2029 (Python str.splitlines
// splits on these) flatten to single spaces so a record stays one
// MARKER:{json} line. Caller/file names come from the SCANNED repo:
// unescaped they can forge or destroy records.
def jsonEsc(v: String): String = v.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", "").replace("\n", " ").flatMap(c => if (c.toInt < 0x20 || c.toInt == 0x85 || c.toInt == 0x2028 || c.toInt == 0x2029) " " else c.toString)

val target = "__FUNCTION__"
val callSites = cpg.call.name(target)

val callerLines = callSites.map { c =>
  val callerFn = jsonEsc(c.method.name)
  val callerFile = jsonEsc(c.method.filename)
  val line = c.lineNumber.getOrElse(0)
  // .take(200) on the RAW string BEFORE jsonEsc — escape-then-truncate
  // can bisect an injected \" and leave a dangling backslash.
  val code = jsonEsc(c.code.take(200))
  s"""JOERN_CALLER:{"caller":"$callerFn","file":"$callerFile","line":$line,"code":"$code"}"""
}.l

callerLines.foreach(println)
callerLines.mkString("\n")
