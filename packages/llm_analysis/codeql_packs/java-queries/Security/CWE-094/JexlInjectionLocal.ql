/**
 * @name IRIS LocalFlowSource: JEXL expression injection from local input
 * @description Reuses the stdlib JEXL evaluation sink with RAPTOR's
 *              `LocalFlowSource` to catch args[]- / System.getenv- /
 *              stdin-driven values reaching JEXL `Engine.createScript`,
 *              `JxltEngine.createTemplate`, and friends.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id raptor/iris/java/jexl-injection-local
 * @tags security
 *       external/cwe/cwe-94
 *       external/cwe/cwe-95
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.JexlInjectionQuery
import Raptor.LocalFlowSource

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node n) { n instanceof JexlEvaluationSink }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Local user input flows to a JEXL expression evaluation."
