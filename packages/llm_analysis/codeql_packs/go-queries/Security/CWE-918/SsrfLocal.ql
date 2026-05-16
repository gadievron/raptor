/**
 * @name IRIS LocalFlowSource: SSRF from local input
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id raptor/iris/go/ssrf-local
 * @tags security
 *       external/cwe/cwe-918
 */

import go
import semmle.go.dataflow.DataFlow
import semmle.go.dataflow.TaintTracking
import semmle.go.security.RequestForgeryCustomizations
import Raptor.LocalFlowSource

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node n) { n instanceof RequestForgery::Sink }

  predicate isBarrier(DataFlow::Node n) { n instanceof RequestForgery::Sanitizer }
  predicate observeDiffInformedIncrementalMode() { any() }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Local user input flows to an outbound HTTP request URL."
