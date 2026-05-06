/**
 * @name IRIS LocalFlowSource: SQL injection from local input
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id raptor/iris/go/sql-injection-local
 * @tags security
 *       external/cwe/cwe-89
 */

import go
import semmle.go.dataflow.DataFlow
import semmle.go.dataflow.TaintTracking
import semmle.go.security.SqlInjectionCustomizations
import Raptor.LocalFlowSource

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node n) { n instanceof SqlInjection::Sink }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Local user input flows to a SQL query."
