/**
 * @name IRIS LocalFlowSource: command injection from local input
 * @description Reuses the stdlib JS CommandInjection sink and sanitiser
 *              models with RAPTOR's `LocalFlowSource` so CLI / env /
 *              stdin-driven flows the stock `ActiveThreatModelSource`
 *              configuration excludes are caught.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id raptor/iris/javascript/command-injection-local
 * @tags security
 *       external/cwe/cwe-78
 *       external/cwe/cwe-88
 */

import javascript
import semmle.javascript.dataflow.DataFlow
import semmle.javascript.dataflow.TaintTracking
import semmle.javascript.security.dataflow.CommandInjectionCustomizations
import Raptor.LocalFlowSource

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node n) { n instanceof CommandInjection::Sink }

  predicate isBarrier(DataFlow::Node n) { n instanceof CommandInjection::Sanitizer }
  predicate observeDiffInformedIncrementalMode() { any() }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Local user input flows to a command-execution sink."
