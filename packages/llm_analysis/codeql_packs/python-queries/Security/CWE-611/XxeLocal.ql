/**
 * @name IRIS LocalFlowSource: XXE from local input
 * @description Reuses the stdlib Xxe sink and sanitiser models with
 *              RAPTOR's `LocalFlowSource` so CLI / env / stdin- /
 *              file-driven XML content reaching unsafe parsers is
 *              caught alongside the stdlib's RemoteFlowSource-only
 *              defaults.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id raptor/iris/python/xxe-local
 * @tags security
 *       external/cwe/cwe-611
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.XxeCustomizations
import Raptor.LocalFlowSource

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node n) { n instanceof Xxe::Sink }

  predicate isBarrier(DataFlow::Node n) { n instanceof Xxe::Sanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Local user input from $@ is parsed by an XML parser vulnerable to XXE.",
  source.getNode(), source.getNode().toString()
