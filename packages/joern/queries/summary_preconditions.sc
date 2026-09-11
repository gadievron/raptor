// summary_preconditions.sc — extract parameter guards for summaries.
//
// For a given function: what conditional checks guard parameter use?
// Emits SUMMARY_GUARD: JSON lines for each guarded parameter —
// println'd for the subprocess transport AND carried in the final
// expression's string echo for the server transport (/query-sync
// drops println output).

import io.shiftleft.semanticcpg.language._
import scala.util.Try

// jsonEsc — the one escape helper for every value interpolated into a
// JSON-string context: backslash before quote; \r stripped; \n, the
// remaining C0 controls (tab included — strict json.loads rejects all
// raw control chars) and U+0085/U+2028/U+2029 (Python str.splitlines
// splits on these) flatten to single spaces so a record stays one
// MARKER:{json} line. Parameter names come from the SCANNED repo.
def jsonEsc(v: String): String = v.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", "").replace("\n", " ").flatMap(c => if (c.toInt < 0x20 || c.toInt == 0x85 || c.toInt == 0x2028 || c.toInt == 0x2029) " " else c.toString)

val targetMethod = cpg.method.name("__TARGET_METHOD__").head

val summaryLines = targetMethod.parameter.l.flatMap { param =>
  Try {
    val guards = param.reachableBy(cpg.controlStructure.isIf).l
    val conditions = guards.flatMap(g => Try(g.condition.code.headOption).toOption.flatten).distinct
    if (conditions.nonEmpty) {
      // .take(200) on the RAW condition BEFORE jsonEsc — escape-then-
      // truncate can bisect an injected \" and leave a dangling
      // backslash.
      val condJson = conditions.map(c => "\"" + jsonEsc(c.take(200)) + "\"").mkString("[", ",", "]")
      Some(s"""SUMMARY_GUARD: {"param": "${jsonEsc(param.name)}", "param_index": ${param.index}, "conditions": $condJson}""")
    } else None
  }.toOption.flatten
}

summaryLines.foreach(println)
summaryLines.mkString("\n")
