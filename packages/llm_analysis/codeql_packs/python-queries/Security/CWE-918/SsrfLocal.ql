/**
 * @name IRIS LocalFlowSource: SSRF from local input
 * @description Reuses the stdlib ServerSideRequestForgery sink and
 *              sanitiser models with RAPTOR's `LocalFlowSource` so
 *              CLI / env / stdin-driven URLs reaching outbound HTTP
 *              calls are caught.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id raptor/iris/python/ssrf-local
 * @tags security
 *       external/cwe/cwe-918
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.ServerSideRequestForgeryCustomizations
import Raptor.LocalFlowSource

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node n) {
    n instanceof ServerSideRequestForgery::Sink
  }

  predicate isBarrier(DataFlow::Node n) {
    n instanceof ServerSideRequestForgery::Sanitizer
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Local user input from $@ flows to an outbound HTTP request URL.",
  source.getNode(), source.getNode().toString()
