/**
 * @name IRIS LocalFlowSource: path traversal from local input
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id raptor/iris/java/tainted-path-local
 * @tags security
 *       external/cwe/cwe-22
 *       external/cwe/cwe-23
 *       external/cwe/cwe-36
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.TaintedPathQuery
import semmle.code.java.security.PathSanitizer
import Raptor.LocalFlowSource

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node n) { n instanceof TaintedPathSink }

  predicate isBarrier(DataFlow::Node n) { n instanceof PathInjectionSanitizer }
  predicate observeDiffInformedIncrementalMode() { any() }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Local user input flows to a filesystem path."
