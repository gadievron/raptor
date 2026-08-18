// summary_error_paths.sc — extract error return patterns for summaries.
//
// For a given function: which return statements indicate errors?
// Emits SUMMARY_ERROR: JSON lines for each error-pattern return.

import io.shiftleft.semanticcpg.language._
import scala.util.Try

val targetMethod = cpg.method.name("__TARGET_METHOD__").head

val errorPatterns = ".*(-1|NULL|null|nullptr|false|None|err|ERR|FAIL|EINVAL|ENOMEM|ENOENT).*"

val errorReturns = targetMethod.ast.isReturn.where(_.code(errorPatterns)).l

errorReturns.foreach { ret =>
  Try {
    val retCode = ret.code.take(200)
    val line = s"""SUMMARY_ERROR: {"code": "${retCode.replace("\"", "\\\"")}", "line": ${ret.lineNumber.getOrElse(-1)}}"""
    println(line)
  }
}
