// summary_taint_rules.sc — extract param→callee taint propagation for summaries.
//
// For a given function: which parameters flow to which callee arguments?
// Emits SUMMARY_TAINT: JSON lines for each discovered flow — println'd
// for the subprocess transport AND carried in the final expression's
// string echo for the server transport (/query-sync drops println
// output).

import io.joern.dataflowengineoss.queryengine._
import io.joern.dataflowengineoss.language._
import io.shiftleft.semanticcpg.language._
import scala.util.Try

// jsonEsc — the one escape helper for every value interpolated into a
// JSON-string context: backslash before quote; \r stripped; \n, the
// remaining C0 controls (tab included — strict json.loads rejects all
// raw control chars) and U+0085/U+2028/U+2029 (Python str.splitlines
// splits on these) flatten to single spaces so a record stays one
// MARKER:{json} line. Parameter and callee names come from the
// SCANNED repo: unescaped they can forge or destroy records.
def jsonEsc(v: String): String = v.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", "").replace("\n", " ").flatMap(c => if (c.toInt < 0x20 || c.toInt == 0x85 || c.toInt == 0x2028 || c.toInt == 0x2029) " " else c.toString)

val targetMethod = cpg.method.name("__TARGET_METHOD__").head

val params = targetMethod.parameter.l
val callsInMethod = targetMethod.call.l

val summaryLines = params.flatMap { param =>
  callsInMethod.flatMap { call =>
    Try {
      val flows = call.argument.reachableByFlows(param).l
      flows.map { flow =>
        val argIdx = Try(flow.elements.last.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call].argumentIndex).getOrElse(-1)
        s"""SUMMARY_TAINT: {"source_param": "${jsonEsc(param.name)}", "source_index": ${param.index}, "sink_call": "${jsonEsc(call.name)}", "sink_arg_index": $argIdx, "hop_count": ${flow.elements.size}}"""
      }
    }.getOrElse(List.empty[String])
  }
}

summaryLines.foreach(println)
summaryLines.mkString("\n")
