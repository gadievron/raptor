// standard_sinks.sc — bulk taint query for all dangerous API targets.
//
// Runs once at CPG build time. For each function whose parameter flows
// to a dangerous callee argument, emits a JOERN_FLOW: JSON line.
//
// Template slots: none (sink list is hardcoded from DANGEROUS_TARGETS).

import io.joern.dataflowengineoss.queryengine._
import io.joern.dataflowengineoss.language._
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode
import scala.util.Try

implicit val engineContext: EngineContext = EngineContext()

val dangerousSinks = List(
  // Command execution
  "system", "popen", "exec", "execve", "execvp", "execl", "execlp",
  "execle", "fexecve", "posix_spawn", "posix_spawnp",
  // Memory operations
  "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat",
  "strncat", "sprintf", "snprintf", "vsprintf", "vsnprintf",
  // Format strings
  "printf", "fprintf", "syslog",
  // File operations
  "fopen", "freopen", "open",
  // SQL / injection surfaces
  "query", "execute", "raw",
  // Deserialization
  "loads", "load", "unserialize", "pickle"
)

println("JOERN_FLOWS_START")

for (sinkName <- dangerousSinks) {
  val sinks = cpg.call.name(sinkName).argument
  val sources = cpg.method.parameter
  val flows = sinks.reachableByFlows(sources).l

  val flowLines = flows.map { flow =>
    val steps = flow.elements.map { e =>
      val ln = e.lineNumber.getOrElse(0)
      val cd = e.code.take(200).replace("\\", "\\\\").replace("\"", "\\\"")
      val (fn, fl) = e match {
        case n: CfgNode =>
          (Try(n.method.name).getOrElse(""), Try(n.method.filename).getOrElse(""))
        case _ => ("", "")
      }
      val fnEsc = fn.replace("\\", "\\\\").replace("\"", "\\\"")
      val flEsc = fl.replace("\\", "\\\\").replace("\"", "\\\"")
      s"""{"line":$ln,"code":"$cd","function":"$fnEsc","file":"$flEsc"}"""
    }.mkString(",")
    "JOERN_FLOW:[" + steps + "]"
  }
  flowLines.foreach(println)
}

println("JOERN_FLOWS_END")
