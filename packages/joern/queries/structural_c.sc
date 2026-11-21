// structural_c.sc — structural C/C++ vulnerability queries for the
// /agentic Joern scan phase (consumed by core.orchestration.joern_scan,
// which maps each query name to a CWE-tagged SARIF rule).
//
// Six queries ported from the upstream Joern query database (querydb,
// Apache-2.0) and adapted to the RAPTOR record transport. Traversals
// are kept as close to upstream as the transport allows so upstream
// precision characteristics carry over. Each query runs inside Try so
// one failing traversal cannot cost the others; a failure emits one
// error record naming the query instead of aborting the script.
//
// Dual transport (same contract as standard_sinks.sc): every record
// line is println'd (the `joern --script` subprocess transport sees
// stdout but not the final expression) AND carried in the final
// expression's sentinel-wrapped string (the server's /query-sync
// returns the final expression echo but not println output).
//
// Record shapes, one JSON object per line (markers spelled without
// their trailing colon here by sibling-script convention — an echoed
// comment carrying the verbatim marker form would parse as a record):
//   JOERN_SCANHIT   {"query","file","line","function","code"}
//   JOERN_SCANERR   {"query","error"}
//   JOERN_SCAN_DONE {"queries","failed"} — completion sentinel; its
//                   absence means the script never ran to the end
//                   (compile error, interrupted window) and the
//                   consumer must read zero hits as "not scanned",
//                   never as "clean".

import io.joern.dataflowengineoss.queryengine._
import io.joern.dataflowengineoss.language._
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.{Call, CfgNode, Local, MethodParameterIn}
import scala.util.{Failure, Success, Try}

implicit val engineContext: EngineContext = EngineContext()

// jsonEsc — same contract as standard_sinks.sc (mirrored BYTE-EXACT
// per script — each submission is one self-contained compilation
// unit, and the census test pins every copy to runner.py's
// SCALA_JSON_ESC_DEF): backslash before quote; \r stripped; \n, the
// remaining C0 controls, NEL and U+2028/U+2029 flatten to single
// spaces so a record stays one MARKER:{json} line through both
// transports. Other non-printables (DEL/C1) are display-layer
// concerns handled Python-side by sanitise_for_terminal.
def jsonEsc(v: String): String = v.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", "").replace("\n", " ").flatMap(c => if (c.toInt < 0x20 || c.toInt == 0x85 || c.toInt == 0x2028 || c.toInt == 0x2029) " " else c.toString)

// Per-query hit cap: bounds transport bytes on a pathological target
// (hits past the cap are silently dropped — the record protocol has
// no truncation marker, mirroring the standard_sinks flow cap).
val perQueryCap = 200

// .take(200) on the RAW code string BEFORE jsonEsc — escape-then-
// truncate can bisect an injected \" and leave a dangling backslash.
// Bounded fields keep every record under the oversized-record
// threshold, so the classic single-line form always suffices here.
def hitLine(query: String, n: CfgNode): String = {
  val qn = jsonEsc(query)
  val ln = n.lineNumber.getOrElse(0)
  val cd = jsonEsc(n.code.take(200))
  val fn = jsonEsc(Try(n.method.name).getOrElse(""))
  val fl = jsonEsc(Try(n.method.filename).getOrElse(""))
  s"""JOERN_SCANHIT:{"query":"$qn","file":"$fl","line":$ln,"function":"$fn","code":"$cd"}"""
}

var failedQueries = 0

def runStructural(name: String)(body: => IterableOnce[CfgNode]): List[String] =
  Try(body.iterator.take(perQueryCap).toList) match {
    case Success(nodes) => nodes.map(n => hitLine(name, n))
    case Failure(e) =>
      failedQueries += 1
      val qn = jsonEsc(name)
      val msg = jsonEsc(Option(e.getMessage).getOrElse(e.getClass.getName).take(300))
      List(s"""JOERN_SCANERR:{"query":"$qn","error":"$msg"}""")
  }

val scanLines = List(
  // use-after-free: a freed identifier is reused on a path with no
  // intervening reassignment (querydb free-follows-value-reuse).
  runStructural("free-follows-value-reuse") {
    cpg.method
      .name("(.*_)?free")
      .filter(_.parameter.size == 1)
      .callIn
      .where(_.argument(1).isIdentifier)
      .flatMap { f =>
        val freedIdentifierCode = f.argument(1).code
        val postDom             = f.postDominatedBy.toSetImmutable

        val assignedPostDom = postDom.isIdentifier
          .where(_.inAssignment)
          .codeExact(freedIdentifierCode)
          .flatMap(id => Iterator.single(id) ++ id.postDominatedBy)

        postDom
          .removedAll(assignedPostDom)
          .isIdentifier
          .codeExact(freedIdentifierCode)
      }
  },
  // use-after-free: a value returned to the caller through an output
  // parameter is freed on a path (querydb free-returned-value).
  runStructural("free-returned-value") {
    def outParams =
      cpg.parameter
        .code(".+\\*.+")
        .whereNot(
          _.referencingIdentifiers
            .argumentIndex(1)
            .inCall
            .nameExact(Operators.assignment, Operators.addressOf)
        )

    def assignedValues =
      outParams.referencingIdentifiers
        .argumentIndex(1)
        .inCall
        .nameExact(Operators.indirectFieldAccess, Operators.indirection, Operators.indirectIndexAccess)
        .argumentIndex(1)
        .inCall
        .nameExact(Operators.assignment)
        .argument(2)
        .isIdentifier

    def freeAssigned =
      assignedValues.map(id =>
        (
          id,
          id.refsTo
            .flatMap {
              case p: MethodParameterIn => p.referencingIdentifiers
              case v: Local             => v.referencingIdentifiers
              // A declaration of any other kind (member, global) must
              // not MatchError the whole query on a hostile repo.
              case _                    => Iterator.empty
            }
            .inCall
            .name("(.*_)?free")
        )
      )

    freeAssigned
      .filter { case (id, freeCall) =>
        freeCall.dominatedBy.exists(_ == id)
      }
      .flatMap(_._1)
  },
  // use-after-free: a struct field reached through a parameter is
  // freed and not reassigned on all paths while the struct outlives
  // the call (querydb free-field-no-reassign).
  runStructural("free-field-no-reassign") {
    val freeOfStructField = cpg
      .method("free")
      .callIn
      .where(
        _.argument(1)
          .isCallTo("<operator>.*[fF]ieldAccess.*")
          // Traversal-level argumentIndex, not node-level argument(1):
          // a degenerate field access must not abort the whole query.
          .filter { x =>
            val params = x.method.parameter.name.toSet
            x.argument.argumentIndex(1).code.exists(params.contains)
          }
      )
      .whereNot(_.argument(1).isCall.argument(1).filter { struct =>
        struct.method.ast.isCall
          .name(".*free$", "memset", "bzero")
          .argument(1)
          .codeExact(struct.code)
          .nonEmpty
      })
      .l

    freeOfStructField.argument(1).filter { arg =>
      arg.method.methodReturn.reachableBy(arg).nonEmpty
    }
  },
  // TOCTOU: two file operations on the same non-literal path argument
  // inside one function (querydb file-operation-race).
  runStructural("file-operation-race") {
    val operations: Map[String, Seq[Int]] = Map(
      "access"     -> Seq(1),
      "chdir"      -> Seq(1),
      "chmod"      -> Seq(1),
      "chown"      -> Seq(1),
      "creat"      -> Seq(1),
      "faccessat"  -> Seq(2),
      "fchmodat"   -> Seq(2),
      "fopen"      -> Seq(1),
      "fstatat"    -> Seq(2),
      "lchown"     -> Seq(1),
      "linkat"     -> Seq(2, 4),
      "link"       -> Seq(1, 2),
      "lstat"      -> Seq(1),
      "mkdirat"    -> Seq(2),
      "mkdir"      -> Seq(1),
      "mkfifoat"   -> Seq(2),
      "mkfifo"     -> Seq(1),
      "mknodat"    -> Seq(2),
      "mknod"      -> Seq(1),
      "openat"     -> Seq(2),
      "open"       -> Seq(1),
      "readlinkat" -> Seq(2),
      "readlink"   -> Seq(1),
      "renameat"   -> Seq(2, 4),
      "rename"     -> Seq(1, 2),
      "rmdir"      -> Seq(1),
      "stat"       -> Seq(1),
      "unlinkat"   -> Seq(2),
      "unlink"     -> Seq(1)
    )

    def fileCalls(calls: Iterator[Call]) =
      calls.nameExact(operations.keys.toSeq*)

    def fileArgs(c: Call) =
      c.argument.whereNot(_.isLiteral).argumentIndex(operations(c.name)*)

    fileCalls(cpg.call)
      .filter(call => {
        val otherCalls = fileCalls(call.method.ast.isCall).filter(_ != call)
        val argsForOtherCalls =
          otherCalls.flatMap(c => fileArgs(c)).code.toSet

        fileArgs(call).code.exists(arg => argsForOtherCalls.contains(arg))
      })
  },
  // integer-overflow-to-heap-overflow: memcpy into a buffer whose
  // malloc size was computed arithmetically, with a different length
  // expression (querydb malloc-memcpy-int-overflow).
  runStructural("malloc-memcpy-int-overflow") {
    val src =
      cpg.method(".*malloc$").callIn.where(_.argument(1).arithmetic)

    // Node-level argument(i) throws on a degenerate call — one
    // hostile `memcpy();` in the repo must not abort the traversal
    // and suppress every genuine hit, so gate on arity first.
    cpg.method("(?i)memcpy").callIn
      .filter(_.argument.size >= 3)
      .filter { memcpyCall =>
        memcpyCall
          .argument(1)
          .reachableBy(src)
          .where(_.inAssignment.target.codeExact(memcpyCall.argument(1).code))
          .whereNot(_.argument(1).codeExact(memcpyCall.argument(3).code))
          .hasNext
      }
  },
  // truncation: strlen result (size_t) assigned into a plain int
  // target (querydb strlen-truncation).
  runStructural("strlen-truncation") {
    cpg.method
      .name("(?i)strlen")
      .callIn
      .inAssignment
      .target
      .evalType("(g?)int")
  }
).flatten

val doneLine = s"""JOERN_SCAN_DONE:{"queries":6,"failed":$failedQueries}"""
val allLines = scanLines :+ doneLine
allLines.foreach(println)
"JOERN_SCAN_START\n" + allLines.mkString("\n") + "\nJOERN_SCAN_END"
