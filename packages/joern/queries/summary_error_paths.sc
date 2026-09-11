// summary_error_paths.sc — extract error return patterns for summaries.
//
// For a given function: which return statements indicate errors?
// Emits SUMMARY_ERROR: JSON lines for each error-pattern return —
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

val errorPatterns = ".*(-1|NULL|null|nullptr|false|None|err|ERR|FAIL|EINVAL|ENOMEM|ENOENT).*"

val errorReturns = targetMethod.ast.isReturn.where(_.code(errorPatterns)).l

val summaryLines = errorReturns.flatMap { ret =>
  Try {
    // .take(200) on the RAW string BEFORE jsonEsc — escape-then-
    // truncate can bisect an injected \" and leave a dangling
    // backslash.
    val retCode = jsonEsc(ret.code.take(200))
    s"""SUMMARY_ERROR: {"code": "$retCode", "line": ${ret.lineNumber.getOrElse(-1)}}"""
  }.toOption
}

summaryLines.foreach(println)
summaryLines.mkString("\n")
