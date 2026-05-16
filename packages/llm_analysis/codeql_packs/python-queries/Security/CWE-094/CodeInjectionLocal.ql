/**
 * @name IRIS LocalFlowSource: code injection from local input
 * @description Reuses the stdlib CodeInjection sink and sanitiser
 *              models with RAPTOR's `LocalFlowSource` to catch
 *              CLI / env / stdin-driven `eval` / `exec` / `compile`
 *              flows that the stdlib RemoteFlowSource-based query
 *              misses.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id raptor/iris/python/code-injection-local
 * @tags security
 *       external/cwe/cwe-94
 *       external/cwe/cwe-95
 *       external/cwe/cwe-116
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.CodeInjectionCustomizations
import Raptor.LocalFlowSource

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node n) { n instanceof CodeInjection::Sink }

  predicate isBarrier(DataFlow::Node n) { n instanceof CodeInjection::Sanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Local user input from $@ flows to a code-execution sink.",
  source.getNode(), source.getNode().toString()
