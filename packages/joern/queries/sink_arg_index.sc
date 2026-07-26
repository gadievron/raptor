// sink_arg_index.sc — identify which argument position at a sink is tainted.
//
// For memcpy(dst, src, len), knowing arg 2 (src) is tainted vs arg 3
// (len) changes the vulnerability class entirely.
//
// Template slots:
//   __FUNCTION__ — the source function whose parameters are traced
//   __SINK__     — the dangerous callee
//
// Output: JOERN_SINK_ARG: JSON with argument index and name.

import io.joern.dataflowengineoss.queryengine._
import io.joern.dataflowengineoss.language._
import io.shiftleft.semanticcpg.language._

val methodName = "__FUNCTION__"
val sinkName = "__SINK__"

val source = cpg.method.name(methodName).parameter
val sinkArgs = cpg.call.name(sinkName).argument

val flows = sinkArgs.reachableByFlows(source).l

val results = flows.flatMap { flow =>
  flow.elements.lastOption.map { lastElem =>
    val argIdx = lastElem.argumentIndex.getOrElse(-1)
    val argCode = lastElem.code.take(100).replace("\\", "\\\\").replace("\"", "\\\"")
    val srcParam = flow.elements.headOption.map(_.code.take(50)).getOrElse("")
    val srcParamEsc = srcParam.replace("\\", "\\\\").replace("\"", "\\\"")
    s"""JOERN_SINK_ARG:{"sink":"$sinkName","arg_index":$argIdx,"arg_code":"$argCode","source_param":"$srcParamEsc"}"""
  }
}

results.distinct.foreach(println)
results.distinct.mkString("\n")
