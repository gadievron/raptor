/**
 * @name IRIS LocalFlowSource: reflected XSS from local input
 * @description Reuses the stdlib ReflectedXss sink and sanitiser
 *              models with RAPTOR's `LocalFlowSource` so CLI / env /
 *              stdin-driven flows landing in HTTP response bodies are
 *              caught alongside the stdlib's RemoteFlowSource-only
 *              defaults.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id raptor/iris/python/reflected-xss-local
 * @tags security
 *       external/cwe/cwe-79
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.ReflectedXSSCustomizations
import Raptor.LocalFlowSource

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node n) { n instanceof ReflectedXss::Sink }

  predicate isBarrier(DataFlow::Node n) { n instanceof ReflectedXss::Sanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Local user input from $@ flows to an HTTP response body.",
  source.getNode(), source.getNode().toString()
