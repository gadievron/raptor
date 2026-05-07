/**
 * @name IRIS LocalFlowSource: XXE from local input
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id raptor/iris/java/xxe-local
 * @tags security
 *       external/cwe/cwe-611
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
// Note: import XxeQuery (not just Xxe) so the concrete `DefaultXxeSink`
// class definition is in scope. `Xxe.qll` only declares the abstract
// `XxeSink`; the concrete subclass that catches default-configured
// XML parsers lives in `XxeQuery.qll`, and abstract-class population
// requires that file to be in the import graph.
import semmle.code.java.security.XxeQuery
import Raptor.LocalFlowSource

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node n) { n instanceof XxeSink }
  predicate observeDiffInformedIncrementalMode() { any() }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Local user input is parsed by an XML parser vulnerable to XXE."
