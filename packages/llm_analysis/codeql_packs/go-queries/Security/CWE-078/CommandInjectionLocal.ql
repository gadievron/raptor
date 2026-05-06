/**
 * @name IRIS LocalFlowSource: command injection from local input
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id raptor/iris/go/command-injection-local
 * @tags security
 *       external/cwe/cwe-78
 *       external/cwe/cwe-88
 */

import go
import semmle.go.dataflow.DataFlow
import semmle.go.dataflow.TaintTracking
import semmle.go.security.CommandInjectionCustomizations
import Raptor.LocalFlowSource

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node n) { n instanceof CommandInjection::Sink }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Local user input flows to a command-execution sink."
