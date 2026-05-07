/**
 * @name IRIS LocalFlowSource: XSS from local input
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id raptor/iris/java/xss-local
 * @tags security
 *       external/cwe/cwe-79
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.XSS
import Raptor.LocalFlowSource

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node n) { n instanceof XssSink }

  // Note: `XssSinkBarrier` is a Sink subclass that flags safe-by-shape
  // sinks, not a flow barrier. Keeping it out of isBarrier matches the
  // stdlib XssQuery.qll usage pattern.
  predicate isBarrier(DataFlow::Node n) { n instanceof XssSanitizer }
  predicate observeDiffInformedIncrementalMode() { any() }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Local user input flows to an HTTP response body."
