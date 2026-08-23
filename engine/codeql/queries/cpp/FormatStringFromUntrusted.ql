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

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.security.FlowSources
import FmtStringFlow::PathGraph

/** A call to a printf-family function where the format string is a parameter. */
class PrintfFormatSink extends DataFlow::Node {
  FunctionCall call;

  PrintfFormatSink() {
    call = this.asExpr().getParent*() and
    exists(int fmtIdx |
      (
        call.getTarget().getName() = "printf" and fmtIdx = 0
        or
        call.getTarget().getName() = "fprintf" and fmtIdx = 1
        or
        call.getTarget().getName() = "sprintf" and fmtIdx = 1
        or
        call.getTarget().getName() = "snprintf" and fmtIdx = 2
        or
        call.getTarget().getName() = "vprintf" and fmtIdx = 0
        or
        call.getTarget().getName() = "vfprintf" and fmtIdx = 1
        or
        call.getTarget().getName() = "vsprintf" and fmtIdx = 1
        or
        call.getTarget().getName() = "vsnprintf" and fmtIdx = 2
        or
        call.getTarget().getName() = "syslog" and fmtIdx = 1
        or
        call.getTarget().getName() = "dprintf" and fmtIdx = 1
        or
        // Kernel printk
        call.getTarget().getName() = "printk" and fmtIdx = 0
        or
        call.getTarget().getName() = "dev_err" and fmtIdx = 1
        or
        call.getTarget().getName() = "dev_warn" and fmtIdx = 1
        or
        call.getTarget().getName() = "dev_info" and fmtIdx = 1
        or
        call.getTarget().getName() = "pr_err" and fmtIdx = 0
        or
        call.getTarget().getName() = "pr_warn" and fmtIdx = 0
        or
        call.getTarget().getName() = "pr_info" and fmtIdx = 0
      ) and
      this.asExpr() = call.getArgument(fmtIdx)
    )
  }
}

/** Taint configuration for format string injection. */
module FmtStringConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof FlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof PrintfFormatSink
  }

  predicate isBarrier(DataFlow::Node node) {
    // String literal constants are not tainted
    node.asExpr() instanceof StringLiteral
  }
}

module FmtStringFlow = TaintTracking::Global<FmtStringConfig>;

from FmtStringFlow::PathNode source, FmtStringFlow::PathNode sink
where FmtStringFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Format string from $@ reaches printf-family call — attacker-controlled format string (CWE-134).",
  source.getNode(), "untrusted source"
