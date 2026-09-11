// sink_arg_index.sc — identify which argument position at a sink is tainted.
//
// For memcpy(dst, src, len), knowing arg 2 (src) is tainted vs arg 3
// (len) changes the vulnerability class entirely.
//
// Template slots:
//   __FUNCTION__ — the source function whose parameters are traced
//   __SINK__     — the dangerous callee
//
// Output: JOERN_SINK_ARG: JSON with argument index and name —
// println'd for the subprocess transport AND carried in the final
// expression's string echo for the server transport (/query-sync
// drops println output).

import io.joern.dataflowengineoss.queryengine._
import io.joern.dataflowengineoss.language._
import io.shiftleft.semanticcpg.language._

// jsonEsc — the one escape helper for every value interpolated into a
// JSON-string context: backslash before quote; \r stripped; \n, the
// remaining C0 controls (tab included — strict json.loads rejects all
// raw control chars) and U+0085/U+2028/U+2029 (Python str.splitlines
// splits on these) flatten to single spaces so a record stays one
// MARKER:{json} line.
def jsonEsc(v: String): String = v.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", "").replace("\n", " ").flatMap(c => if (c.toInt < 0x20 || c.toInt == 0x85 || c.toInt == 0x2028 || c.toInt == 0x2029) " " else c.toString)

val methodName = "__FUNCTION__"
val sinkName = "__SINK__"

val source = cpg.method.name(methodName).parameter
val sinkArgs = cpg.call.name(sinkName).argument

val flows = sinkArgs.reachableByFlows(source).l

val results = flows.flatMap { flow =>
  flow.elements.lastOption.map { lastElem =>
    // flow.elements are AstNode-typed; argumentIndex lives on
    // Expression — an untyped call fails compilation (E008), which
    // silently zeroed this emitter's records.
    val argIdx = lastElem match {
      case e: io.shiftleft.codepropertygraph.generated.nodes.Expression => e.argumentIndex
      case _ => -1
    }
    // .take(N) on the RAW string BEFORE jsonEsc — escape-then-truncate
    // can bisect an injected \" and leave a dangling backslash.
    val argCode = jsonEsc(lastElem.code.take(100))
    val srcParamEsc = jsonEsc(flow.elements.headOption.map(_.code.take(50)).getOrElse(""))
    s"""JOERN_SINK_ARG:{"sink":"${jsonEsc(sinkName)}","arg_index":$argIdx,"arg_code":"$argCode","source_param":"$srcParamEsc"}"""
  }
}

results.distinct.foreach(println)
results.distinct.mkString("\n")
