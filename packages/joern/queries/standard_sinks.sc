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

// flowRecordLines — the one record emitter for JOERN_FLOW lines: one
// classic single line for a short record, ordered chunk lines
// (marker JOERN_FLOW_PART, header i/n/len; len counts code points
// and the cut never splits a surrogate pair) for an oversized one —
// REPL rendering caps wrap/truncate a single overlong line and the
// record is lost in transit. Neither marker is spelled with its
// trailing colon here: an echoed comment line carrying the verbatim
// marker form would abort a live chunk sequence in the parser. The
// parser reassembles chunks before JSON parsing
// (core.analysis._joern_lines.MarkerChunkAssembler).
def flowRecordLines(steps: String): List[String] = { val rec = "[" + steps + "]"; if (rec.length <= 1000) List("JOERN_FLOW:" + rec) else { val ps = List.unfold(0) { s => if (s >= rec.length) None else { val c = math.min(s + 1000, rec.length); val e = if (c < rec.length && Character.isHighSurrogate(rec.charAt(c - 1))) c - 1 else c; Some((rec.substring(s, e), e)) } }; ps.zipWithIndex.map { case (p, i) => "JOERN_FLOW_PART:" + (i + 1) + "/" + ps.size + "/" + p.codePointCount(0, p.length) + ":" + p } } }

val flowLines = dangerousSinks.flatMap { sinkName =>
  val sinks = cpg.call.name(sinkName).argument
  val sources = cpg.method.parameter
  // .take(500) BEFORE .l bounds materialisation per sink (mirror of
  // tiered_taint.sc — this runs inside a per-sink loop). Higher =
  // more flows materialised per sink and unbounded transport bytes
  // across the whole sink list; lower = real flows silently dropped
  // past the cap (the JOERN_FLOW protocol has no truncation marker).
  val flows = sinks.reachableByFlows(sources).take(500).l

  flows.flatMap { flow =>
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
    flowRecordLines(steps)
  }
}

flowLines.foreach(println)
"JOERN_FLOWS_START\n" + flowLines.mkString("\n") + "\nJOERN_FLOWS_END"
