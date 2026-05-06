/**
 * @name IRIS LocalFlowSource: path traversal from local input
 * @description Reuses the stdlib PathInjection sink and sanitiser
 *              models with RAPTOR's `LocalFlowSource` to catch
 *              CLI / env / stdin-driven path traversal that the
 *              stdlib RemoteFlowSource-based query misses.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id raptor/iris/python/path-injection-local
 * @tags security
 *       external/cwe/cwe-22
 *       external/cwe/cwe-23
 *       external/cwe/cwe-36
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.PathInjectionCustomizations
import Raptor.LocalFlowSource

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node n) { n instanceof PathInjection::Sink }

  predicate isBarrier(DataFlow::Node n) { n instanceof PathInjection::Sanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Local user input from $@ flows to a filesystem path.",
  source.getNode(), source.getNode().toString()
