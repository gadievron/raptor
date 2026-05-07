/**
 * @name IRIS LocalFlowSource: reflected XSS from local input
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id raptor/iris/go/reflected-xss-local
 * @tags security
 *       external/cwe/cwe-79
 */

import go
import semmle.go.dataflow.DataFlow
import semmle.go.dataflow.TaintTracking
import semmle.go.security.ReflectedXssCustomizations
import Raptor.LocalFlowSource

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node n) { n instanceof ReflectedXss::Sink }

  predicate isBarrier(DataFlow::Node n) { n instanceof ReflectedXss::Sanitizer }
  predicate observeDiffInformedIncrementalMode() { any() }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Local user input flows to an HTTP response body."
