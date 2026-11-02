/**
 * @name Format string from untrusted source
 * @description A printf-family format string that originates from an
 *              external source (file read, network recv, environment
 *              variable, command-line argument) allows an attacker to
 *              read/write arbitrary memory via %n and %x directives.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id raptor/cpp/format-string-untrusted
 * @tags security
 *       external/cwe/cwe-134
 */

import FormatStringFlow
import FmtStringFlow::PathGraph

from FmtStringFlow::PathNode source, FmtStringFlow::PathNode sink
where FmtStringFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Format string from $@ reaches printf-family call — attacker-controlled format string (CWE-134).",
  source.getNode(), "untrusted source"
