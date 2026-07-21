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

/** Taint configuration for log injection. */
module LogInjConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof LogMessageSink
  }

  predicate isBarrier(DataFlow::Node node) {
    // String.replace removing CRLF is a sanitiser
    exists(MethodCall mc |
      mc.getMethod().hasName("replace") and
      node.asExpr() = mc and
      (
        mc.getArgument(0).(StringLiteral).getValue() = "\n" or
        mc.getArgument(0).(StringLiteral).getValue() = "\r" or
        mc.getArgument(0).(CharacterLiteral).getValue().charAt(0) = "\n".charAt(0) or
        mc.getArgument(0).(CharacterLiteral).getValue().charAt(0) = "\r".charAt(0)
      )
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
