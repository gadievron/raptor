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

import LogInjectionFlow
import LogInjFlow::PathGraph

from LogInjFlow::PathNode source, LogInjFlow::PathNode sink
where LogInjFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Untrusted data from $@ flows into a log message — " +
    "CRLF injection can forge log entries (CWE-117).",
  source.getNode(), "remote source"
