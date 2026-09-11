// summary_returns.sc — extract return conditions for summaries.
//
// For a given function: what values are returned under what conditions?
// Emits SUMMARY_RETURN: JSON lines for each return statement —
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
// MARKER:{json} line.
def jsonEsc(v: String): String = v.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", "").replace("\n", " ").flatMap(c => if (c.toInt < 0x20 || c.toInt == 0x85 || c.toInt == 0x2028 || c.toInt == 0x2029) " " else c.toString)

val targetMethod = cpg.method.name("__TARGET_METHOD__").head

val returns = targetMethod.ast.isReturn.l

val summaryLines = returns.flatMap { ret =>
  Try {
    // .take(200) on the RAW string BEFORE jsonEsc — escape-then-
    // truncate can bisect an injected \" and leave a dangling
    // backslash.
    val retCode = jsonEsc(ret.code.take(200))
    val dominatingConditions = ret.dominatedBy.isControlStructure.l
      .flatMap(cs => Try(cs.condition.code.headOption).toOption.flatten)
      .distinct
    val condJson = dominatingConditions.map(c => "\"" + jsonEsc(c.take(200)) + "\"").mkString("[", ",", "]")
    s"""SUMMARY_RETURN: {"code": "$retCode", "line": ${ret.lineNumber.getOrElse(-1)}, "conditions": $condJson}"""
  }.toOption
}

summaryLines.foreach(println)
summaryLines.mkString("\n")
