// unguarded_sinks.sc — find sink calls NOT dominated by conditionals.
//
// Returns the specific unguarded sink calls with their line numbers and
// code, so the LLM knows exactly where the missing guard is.
//
// Template slot: __FUNCTION__ (substituted by runner after validation)
//
// Output: JOERN_UNGUARDED: JSON per unguarded sink call.

import io.shiftleft.semanticcpg.language._

val fnName = "__FUNCTION__"
val sinkNames = List(
  "memcpy", "memmove", "strcpy", "strcat", "sprintf", "gets",
  "strncpy", "strncat", "snprintf", "system", "popen", "execve",
  "execvp", "fopen", "open"
)

val fn = cpg.method.name(fnName)
val sinkCalls = fn.call.name(sinkNames.mkString("|")).l

val results = sinkCalls.flatMap { call =>
  val dominated = call.dominatedBy.isControlStructure.l.nonEmpty
  val controlled = call.controlledBy.isControlStructure.l.nonEmpty
  if (!dominated && !controlled) {
    val line = call.lineNumber.getOrElse(0)
    val code = call.code.take(200).replace("\\", "\\\\").replace("\"", "\\\"")
    val name = call.name
    Some(s"""JOERN_UNGUARDED:{"sink":"$name","line":$line,"code":"$code","guarded":false}""")
  } else None
}

val total = sinkCalls.size
val unguarded = results.size

results.foreach(println)
println(s"JOERN_GUARD_SUMMARY:$unguarded/$total")
s"JOERN_GUARD_SUMMARY:$unguarded/$total\n" + results.mkString("\n")
