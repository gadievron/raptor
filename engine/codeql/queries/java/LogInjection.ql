/**
 * @name Log injection via untrusted input
 * @description User-controlled data written to application logs
 *              without sanitisation can forge log entries via
 *              CRLF injection, enabling log spoofing and audit
 *              trail manipulation.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision high
 * @id raptor/java/log-injection
 * @tags security
 *       external/cwe/cwe-117
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import LogInjFlow::PathGraph

/**
 * A call to a logging method where the first argument is the
 * message/format string — this is the taint-relevant position.
 */
class LogMessageSink extends DataFlow::Node {
  LogMessageSink() {
    exists(MethodCall mc, Method m |
      mc.getMethod() = m and
      this.asExpr() = mc.getArgument(0)
    |
      // java.util.logging.Logger
      m.getDeclaringType().hasQualifiedName("java.util.logging", "Logger") and
      m.getName() = ["info", "warning", "severe", "fine", "finer", "finest", "log"]
      or
      // SLF4J / Logback / Log4j2 Logger
      m.getDeclaringType()
          .getAnAncestor()
          .hasQualifiedName(["org.slf4j", "org.apache.logging.log4j"], "Logger") and
      m.getName() = ["info", "warn", "error", "debug", "trace", "fatal"]
      or
      // Apache Commons Logging
      m.getDeclaringType()
          .getAnAncestor()
          .hasQualifiedName("org.apache.commons.logging", "Log") and
      m.getName() = ["info", "warn", "error", "debug", "trace", "fatal"]
    )
  }
}

/** Holds if `mc` is a `String.replace` call removing the character `c`. */
private predicate removesChar(MethodCall mc, string c) {
  mc.getMethod().hasName("replace") and
  c = ["\n", "\r"] and
  (
    mc.getArgument(0).(StringLiteral).getValue() = c
    or
    mc.getArgument(0).(CharacterLiteral).getValue().charAt(0) = c.charAt(0)
  )
}

/** A method call in `mc`'s qualifier chain (transitive). */
private MethodCall chainQualifier(MethodCall mc) {
  result = mc.getQualifier()
  or
  result = chainQualifier(mc.getQualifier().(MethodCall))
}

/**
 * Holds if `mc` completes a sanitiser that removes BOTH `\n` and `\r`.
 * A single-character replace is NOT a sanitiser — the other bare
 * character still forges log entries (the same both-characters
 * contract the semgrep log-injection and header-injection rules
 * state). Accepted spellings: chained per-character replaces (either
 * order) and a `replaceAll` whose regex names both characters.
 */
private predicate handlesBothCrlf(MethodCall mc) {
  exists(string c1, string c2 |
    c1 = "\n" and c2 = "\r"
    or
    c1 = "\r" and c2 = "\n"
  |
    removesChar(mc, c1) and
    removesChar(chainQualifier(mc), c2)
  )
  or
  // Character-class (or alternation) regex covering both characters,
  // in either the raw ("[\r\n]") or regex-escaped ("\\r|\\n")
  // spelling.
  mc.getMethod().hasName("replaceAll") and
  exists(string rx | rx = mc.getArgument(0).(StringLiteral).getValue() |
    (rx.matches("%\n%") or rx.matches("%\\n%")) and
    (rx.matches("%\r%") or rx.matches("%\\r%"))
  )
}

/** Taint configuration for log injection. */
module LogInjConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof LogMessageSink
  }

  predicate isBarrier(DataFlow::Node node) {
    // A replace-based CRLF sanitiser must handle both characters.
    exists(MethodCall mc |
      node.asExpr() = mc and
      handlesBothCrlf(mc)
    )
    or
    // OWASP encoder
    exists(MethodCall mc |
      mc.getMethod().getDeclaringType().hasName("Encode") and
      mc.getMethod().hasName("forJava") and
      node.asExpr() = mc
    )
  }
}

module LogInjFlow = TaintTracking::Global<LogInjConfig>;

from LogInjFlow::PathNode source, LogInjFlow::PathNode sink
where LogInjFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Untrusted data from $@ flows into a log message — " +
    "CRLF injection can forge log entries (CWE-117).",
  source.getNode(), "remote source"
