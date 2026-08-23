// tiered_taint.sc — gated taint analysis that avoids full-depth queries
// on functions that can be resolved cheaply.
//
// Tier 0: Syntactic — methods with sink calls + transitive callers
// Tier 1: Intra-procedural (depth=0) — parameter → sink within same fn
// Tier 2: Inter-procedural (depth=N) — only for Tier 1 survivors
//
// Placeholders substituted by Python layer for per-language tuning:
//   __DANGEROUS_SINKS__    — Scala List(...) literal
//   __EFFECTIVE_DEPTH__    — int, inter-procedural call depth
//   __MAX_ARGS__           — int, maxArgsToAllow for Tier 2
//   __MAX_OUTPUT_ARGS__    — int, maxOutputArgsExpansion for Tier 2
//   SEMANTICS_DECL (line slot)  — learned FlowSemantic installation, or empty
//   CTX_SEMANTICS (arg slot)    — semantics= EngineContext argument, or empty
//
// maxArgsToAllow is all-or-nothing: when ANY parameter maps to more
// call sites than the cap, the engine drops ALL expansion for that
// parameter — not truncated, dropped entirely.  Too low risks losing
// entire parameter tracking for heavily-used functions.

import io.joern.dataflowengineoss.queryengine._
import io.joern.dataflowengineoss.language._
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode
import scala.collection.mutable
import scala.util.Try

val dangerousSinks = __DANGEROUS_SINKS__
__SEMANTICS_DECL__

def flowToJson(flow: io.joern.dataflowengineoss.language.Path): String = {
  val steps = flow.elements.map { e =>
    val ln = e.lineNumber.getOrElse(0)
    val cd = e.code.take(200).replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ").replace("\r", "")
    val (fn, fl) = e match {
      case n: CfgNode =>
        (Try(n.method.name).getOrElse(""), Try(n.method.filename).getOrElse(""))
      case _ => ("", "")
    }
    val fnEsc = fn.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ")
    val flEsc = fl.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ")
    s"""{"line":$ln,"code":"$cd","function":"$fnEsc","file":"$flEsc"}"""
  }.mkString(",")
  "JOERN_FLOW:[" + steps + "]"
}

// --- Tier 0: indexed discovery (E2/E5 — O(1) per name via inverse index) ---
// nameExact uses the flatgraph inverse index (hash lookup) instead of
// regex scan over all call sites.
val sinkCallNodes = dangerousSinks.flatMap(name => cpg.call.nameExact(name).l)
val directSinkMethods = sinkCallNodes.flatMap(c => Try(c.method.name).toOption).toSet

// Expand to transitive callers via cheap call-graph walk (no dataflow).
val transitiveCallers = if (directSinkMethods.nonEmpty) {
  cpg.method.filter(m => directSinkMethods.contains(m.name))
    .repeat(_.caller)(_.maxDepth(4).emit)
    .dedup
    .name.toSet
} else Set.empty[String]

val methodsWithSinks = directSinkMethods ++ transitiveCallers

val t0Count = methodsWithSinks.size
val t0Direct = directSinkMethods.size
val t0Total = cpg.method.name.toSet.size
println(s"JOERN_TIER:0:$t0Count candidate methods ($t0Direct direct + ${t0Count - t0Direct} transitive callers, of $t0Total total)")

// ALL sinks via indexed lookups — not restricted to candidate methods.
// reachableByFlows traces BACKWARDS from sinks to sources.
val allSinkArgs = dangerousSinks.flatMap(name => cpg.call.nameExact(name).argument.l)
println(s"JOERN_TIER:sinks:${allSinkArgs.size} sink arguments across ${sinkCallNodes.size} call sites")

// --- Diagnostic: dark methods (E4) ---
// Methods that lost reaching-def coverage due to --max-num-def bail-out.
// These are invisible to taint analysis — any flow through them is missed.
val darkMethods = Try {
  cpg.method.filter { m =>
    m.parameter.nonEmpty && m.cfgNode.outE("REACHING_DEF").isEmpty
  }.name.l
}.getOrElse(List.empty[String])

if (darkMethods.nonEmpty) {
  println(s"JOERN_DIAG:dark_methods:${darkMethods.size}:${darkMethods.take(10).mkString(",")}")
}

if (methodsWithSinks.isEmpty) {
  println("JOERN_TIER_STATS:{\"t0_candidates\":0,\"t0_total\":" + t0Total + "}")
  "JOERN_FLOWS_START\nJOERN_FLOWS_END"
} else {

  val effectiveDepth = __EFFECTIVE_DEPTH__

  // Shared result cache: Tier 1 populates depth-0 entries, Tier 2 reuses them.
  val sharedTable = mutable.Map.empty[TaskFingerprint, Vector[ReachableByResult]]

  // --- Tier 1: Intra-procedural (maxCallDepth=0) ---
  val tier1Config = EngineConfig(maxCallDepth = 0, initialTable = Some(sharedTable))
  val tier1Ctx = EngineContext(__CTX_SEMANTICS__config = tier1Config)
  val tier1Sources = cpg.method
    .filter(m => methodsWithSinks.contains(m.name))
    .parameter

  // .take(N) BEFORE .l limits materialisation (E3)
  val tier1Flows = allSinkArgs.iterator
    .reachableByFlows(tier1Sources)(tier1Ctx)
    .take(500).l
  val tier1Lines = tier1Flows.map(flowToJson)

  val resolvedT1 = tier1Flows.flatMap { f =>
    f.elements.headOption.flatMap {
      case n: CfgNode => Try(n.method.name).toOption
      case _ => None
    }
  }.toSet

  val t1Unresolved = methodsWithSinks -- resolvedT1
  println(s"JOERN_TIER:1:${resolvedT1.size} resolved intra-proc, ${t1Unresolved.size} need deeper analysis")

  // --- Tier 2: Inter-procedural (maxCallDepth=effectiveDepth) ---
  val tier2Lines = if (t1Unresolved.isEmpty) {
    List.empty[String]
  } else {
    val tier2Config = EngineConfig(
      maxCallDepth = effectiveDepth,
      initialTable = Some(sharedTable),
      shareCacheBetweenTasks = true,
      maxArgsToAllow = __MAX_ARGS__,
      maxOutputArgsExpansion = __MAX_OUTPUT_ARGS__
    )
    val tier2Ctx = EngineContext(__CTX_SEMANTICS__config = tier2Config)
    val tier2Sources = cpg.method
      .filter(m => t1Unresolved.contains(m.name))
      .parameter

    val tier2Flows = allSinkArgs.iterator
      .reachableByFlows(tier2Sources)(tier2Ctx)
      .take(500).l

    val resolvedT2 = tier2Flows.flatMap { f =>
      f.elements.headOption.flatMap {
        case n: CfgNode => Try(n.method.name).toOption
        case _ => None
      }
    }.toSet

    val t2Unresolved = t1Unresolved -- resolvedT2
    println(s"JOERN_TIER:2:${resolvedT2.size} resolved at depth $effectiveDepth, ${t2Unresolved.size} no flow found")

    tier2Flows.map(flowToJson)
  }

  val allLines = tier1Lines ++ tier2Lines
  val darkCount = darkMethods.size
  val stats = s"""JOERN_TIER_STATS:{"t0_candidates":$t0Count,"t0_direct":$t0Direct,"t0_total":$t0Total,"t1_resolved":${resolvedT1.size},"t1_unresolved":${t1Unresolved.size},"effective_depth":$effectiveDepth,"total_flows":${allLines.size},"dark_methods":$darkCount,"sink_args":${allSinkArgs.size}}"""

  allLines.foreach(println)
  println(stats)
  "JOERN_FLOWS_START\n" + allLines.mkString("\n") + "\n" + stats + "\nJOERN_FLOWS_END"
}
