// callers.sc — find all call sites that invoke a function.
//
// The tree-sitter call graph misses indirect calls (function pointers,
// callbacks, struct dispatch). Joern's CPG resolves these via
// data-dependence edges.
//
// Template slot: __FUNCTION__ (substituted by runner after validation)
//
// Output: one JOERN_CALLER: JSON line per caller.

import io.shiftleft.semanticcpg.language._

val target = "__FUNCTION__"
val callSites = cpg.call.name(target)

val callerLines = callSites.map { c =>
  val callerFn = c.method.name
  val callerFile = c.method.filename
  val line = c.lineNumber.getOrElse(0)
  val code = c.code.take(200).replace("\\", "\\\\").replace("\"", "\\\"")
  s"""JOERN_CALLER:{"caller":"$callerFn","file":"$callerFile","line":$line,"code":"$code"}"""
}.l

callerLines.foreach(println)
callerLines.mkString("\n")
