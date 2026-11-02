/** Track untrusted string contents into the format argument, not variadic data. */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.security.FlowSources

/** A call to a printf-family function where the format string is a parameter. */
class PrintfFormatSink extends DataFlow::Node {
  FunctionCall call;

  PrintfFormatSink() {
    call = this.asIndirectExpr(1).getParent*() and
    call.getTarget() instanceof TopLevelFunction and
    exists(int fmtIdx |
      (
        call.getTarget().hasGlobalOrStdOrBslName("printf") and fmtIdx = 0
        or
        call.getTarget().hasGlobalOrStdOrBslName("fprintf") and fmtIdx = 1
        or
        call.getTarget().hasGlobalOrStdOrBslName("sprintf") and fmtIdx = 1
        or
        call.getTarget().hasGlobalOrStdOrBslName("snprintf") and fmtIdx = 2
        or
        call.getTarget().hasGlobalOrStdOrBslName("vprintf") and fmtIdx = 0
        or
        call.getTarget().hasGlobalOrStdOrBslName("vfprintf") and fmtIdx = 1
        or
        call.getTarget().hasGlobalOrStdOrBslName("vsprintf") and fmtIdx = 1
        or
        call.getTarget().hasGlobalOrStdOrBslName("vsnprintf") and fmtIdx = 2
        or
        call.getTarget().hasGlobalOrStdOrBslName("syslog") and fmtIdx = 1
        or
        call.getTarget().hasGlobalOrStdOrBslName("dprintf") and fmtIdx = 1
        or
        // Kernel printk
        call.getTarget().hasGlobalOrStdOrBslName("printk") and fmtIdx = 0
        or
        call.getTarget().hasGlobalOrStdOrBslName("dev_err") and fmtIdx = 1
        or
        call.getTarget().hasGlobalOrStdOrBslName("dev_warn") and fmtIdx = 1
        or
        call.getTarget().hasGlobalOrStdOrBslName("dev_info") and fmtIdx = 1
        or
        call.getTarget().hasGlobalOrStdOrBslName("pr_err") and fmtIdx = 0
        or
        call.getTarget().hasGlobalOrStdOrBslName("pr_warn") and fmtIdx = 0
        or
        call.getTarget().hasGlobalOrStdOrBslName("pr_info") and fmtIdx = 0
      ) and
      this.asIndirectExpr(1) = call.getArgument(fmtIdx).getUnconverted()
    )
  }

  FunctionCall getCall() { result = call }
}

/** Taint configuration for format string injection. */
module FmtStringConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof FlowSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof PrintfFormatSink }

  predicate isBarrier(DataFlow::Node node) {
    // Literals cannot introduce attacker-controlled format directives.
    node.asIndirectExpr(1) instanceof StringLiteral
  }
}

module FmtStringFlow = TaintTracking::Global<FmtStringConfig>;
