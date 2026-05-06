/**
 * @name IRIS LocalFlowSource: command injection from local input
 * @description Reuses the stdlib CommandInjection sink and sanitiser
 *              models, but pairs them with RAPTOR's `LocalFlowSource`
 *              so CLI- / env- / stdin-driven flows that the stdlib's
 *              `RemoteFlowSource`-based query misses are caught.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id raptor/iris/python/command-injection-local
 * @tags security
 *       external/cwe/cwe-78
 *       external/cwe/cwe-88
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.CommandInjectionCustomizations
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
  "Local user input from $@ flows to a command-execution sink.",
  source.getNode(), source.getNode().toString()
