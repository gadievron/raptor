// standard_sinks.sc — bulk taint query for all dangerous API targets.
//
// Runs once at CPG build time. For each function whose parameter flows
// to a dangerous callee argument, emits a JOERN_FLOW: JSON line.
//
// Dual transport: every record line is println'd (the `joern --script`
// subprocess transport sees stdout but not the final expression) AND
// carried in the final expression's sentinel-wrapped string (the
// server's /query-sync returns the final expression echo but not
// println output — println-only emission made the server-mode
// pre-sweep return zero flows).
//
// Template slots:
//   __SINK_NAMES__ — sink-name list body, rendered by the caller from
//                    packages/joern/lang_config.py STANDARD_SWEEP_SINKS
//                    (the single authority; this file used to hardcode
//                    a drifting copy of it)

import io.joern.dataflowengineoss.queryengine._
import io.joern.dataflowengineoss.language._
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode
import scala.util.Try

implicit val engineContext: EngineContext = EngineContext()

val dangerousSinks = List(__SINK_NAMES__)

// jsonEsc — the one escape helper for every value interpolated into a
// JSON-string context: backslash before quote; \r stripped; \n, the
// remaining C0 controls (tab included — strict json.loads rejects all
// raw control chars) and U+0085/U+2028/U+2029 (Python str.splitlines
// splits on these) flatten to single spaces so a record stays one
// MARKER:{json} line.
def jsonEsc(v: String): String = v.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", "").replace("\n", " ").flatMap(c => if (c.toInt < 0x20 || c.toInt == 0x85 || c.toInt == 0x2028 || c.toInt == 0x2029) " " else c.toString)

val flowLines = dangerousSinks.flatMap { sinkName =>
  val sinks = cpg.call.name(sinkName).argument
  val sources = cpg.method.parameter
  // .take(500) BEFORE .l bounds materialisation per sink (mirror of
  // tiered_taint.sc — this runs inside a per-sink loop). Higher =
  // more flows materialised per sink and unbounded transport bytes
  // across the whole sink list; lower = real flows silently dropped
  // past the cap (the JOERN_FLOW protocol has no truncation marker).
  val flows = sinks.reachableByFlows(sources).take(500).l

  flows.map { flow =>
    val steps = flow.elements.map { e =>
      val ln = e.lineNumber.getOrElse(0)
      // .take(200) on the RAW string BEFORE jsonEsc — escape-then-
      // truncate can bisect an injected \" and leave a dangling
      // backslash.
      val cd = jsonEsc(e.code.take(200))
      val (fn, fl) = e match {
        case n: CfgNode =>
          (Try(n.method.name).getOrElse(""), Try(n.method.filename).getOrElse(""))
        case _ => ("", "")
      }
      val fnEsc = jsonEsc(fn)
      val flEsc = jsonEsc(fl)
      s"""{"line":$ln,"code":"$cd","function":"$fnEsc","file":"$flEsc"}"""
    }.mkString(",")
    "JOERN_FLOW:[" + steps + "]"
  }
}

flowLines.foreach(println)
"JOERN_FLOWS_START\n" + flowLines.mkString("\n") + "\nJOERN_FLOWS_END"
