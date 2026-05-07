/**
 * @name IRIS LocalFlowSource: SQL injection from local input
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id raptor/iris/java/sql-injection-local
 * @tags security
 *       external/cwe/cwe-89
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.QueryInjection
import semmle.code.java.security.Sanitizers
import Raptor.LocalFlowSource

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node n) { n instanceof QueryInjectionSink }

  predicate isBarrier(DataFlow::Node n) { n instanceof SimpleTypeSanitizer }
  predicate observeDiffInformedIncrementalMode() { any() }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Local user input flows to a SQL query."
