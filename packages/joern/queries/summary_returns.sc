// summary_returns.sc — extract return conditions for summaries.
//
// For a given function: what values are returned under what conditions?
// Emits SUMMARY_RETURN: JSON lines for each return statement.

import io.shiftleft.semanticcpg.language._
import scala.util.Try

val targetMethod = cpg.method.name("__TARGET_METHOD__").head

val returns = targetMethod.ast.isReturn.l

returns.foreach { ret =>
  Try {
    val retCode = ret.code.take(200)
    val dominatingConditions = ret.dominatedBy.isControlStructure.l
      .flatMap(cs => Try(cs.condition.code.headOption).toOption.flatten)
      .distinct
    val condJson = dominatingConditions.map(c => "\"" + c.replace("\"", "\\\"").take(200) + "\"").mkString("[", ",", "]")
    val line = s"""SUMMARY_RETURN: {"code": "${retCode.replace("\"", "\\\"")}", "line": ${ret.lineNumber.getOrElse(-1)}, "conditions": ${condJson}}"""
    println(line)
  }
}
