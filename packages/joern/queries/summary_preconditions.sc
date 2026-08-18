// summary_preconditions.sc — extract parameter guards for summaries.
//
// For a given function: what conditional checks guard parameter use?
// Emits SUMMARY_GUARD: JSON lines for each guarded parameter.

import io.shiftleft.semanticcpg.language._
import scala.util.Try

val targetMethod = cpg.method.name("__TARGET_METHOD__").head

targetMethod.parameter.l.foreach { param =>
  Try {
    val guards = param.reachableBy(cpg.controlStructure.isIf).l
    if (guards.nonEmpty) {
      val conditions = guards.flatMap(g => Try(g.condition.code.headOption).toOption.flatten).distinct
      if (conditions.nonEmpty) {
        val condJson = conditions.map(c => "\"" + c.replace("\"", "\\\"").take(200) + "\"").mkString("[", ",", "]")
        val line = s"""SUMMARY_GUARD: {"param": "${param.name}", "param_index": ${param.index}, "conditions": ${condJson}}"""
        println(line)
      }
    }
  }
}
