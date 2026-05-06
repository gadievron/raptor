/**
 * @name IRIS LocalFlowSource: path traversal from local input
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id raptor/iris/go/tainted-path-local
 * @tags security
 *       external/cwe/cwe-22
 *       external/cwe/cwe-23
 *       external/cwe/cwe-36
 */

import go
import semmle.go.dataflow.DataFlow
import semmle.go.dataflow.TaintTracking
import semmle.go.security.TaintedPathCustomizations
import Raptor.LocalFlowSource

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node n) { n instanceof TaintedPath::Sink }

  predicate isBarrier(DataFlow::Node n) { n instanceof TaintedPath::Sanitizer }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Local user input flows to a filesystem path."
