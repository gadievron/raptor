// summary_taint_rules.sc — extract param→callee taint propagation for summaries.
//
// For a given function: which parameters flow to which callee arguments?
// Emits SUMMARY_TAINT: JSON lines for each discovered flow.

import io.joern.dataflowengineoss.queryengine._
import io.joern.dataflowengineoss.language._
import io.shiftleft.semanticcpg.language._
import scala.util.Try

val targetMethod = cpg.method.name("__TARGET_METHOD__").head

val params = targetMethod.parameter.l
val callsInMethod = targetMethod.call.l

params.foreach { param =>
  callsInMethod.foreach { call =>
    Try {
      val flows = call.argument.reachableByFlows(param).l
      if (flows.nonEmpty) {
        flows.foreach { flow =>
          val argIdx = Try(flow.elements.last.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call].argumentIndex).getOrElse(-1)
          val line = s"""SUMMARY_TAINT: {"source_param": "${param.name}", "source_index": ${param.index}, "sink_call": "${call.name}", "sink_arg_index": ${argIdx}, "hop_count": ${flow.elements.size}}"""
          println(line)
        }
      }
    }
  }
}
