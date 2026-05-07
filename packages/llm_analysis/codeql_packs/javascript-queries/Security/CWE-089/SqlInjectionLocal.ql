/**
 * @name IRIS LocalFlowSource: SQL injection from local input
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id raptor/iris/javascript/sql-injection-local
 * @tags security
 *       external/cwe/cwe-89
 */

import javascript
import semmle.javascript.dataflow.DataFlow
import semmle.javascript.dataflow.TaintTracking
import semmle.javascript.security.dataflow.SqlInjectionCustomizations
import Raptor.LocalFlowSource

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node n) { n instanceof SqlInjection::Sink }

  predicate isBarrier(DataFlow::Node n) { n instanceof SqlInjection::Sanitizer }
  predicate observeDiffInformedIncrementalMode() { any() }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Local user input flows to a SQL query."
