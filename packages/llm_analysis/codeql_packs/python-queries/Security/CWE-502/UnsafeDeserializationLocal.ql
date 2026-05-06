/**
 * @name IRIS LocalFlowSource: unsafe deserialization from local input
 * @description Reuses the stdlib UnsafeDeserialization sink and
 *              sanitiser models with RAPTOR's `LocalFlowSource` to
 *              catch CLI / env / stdin / file-driven deserialization
 *              flows that the stdlib RemoteFlowSource-based query
 *              misses (e.g. `pickle.loads(open(argv[1]).read())`).
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id raptor/iris/python/unsafe-deserialization-local
 * @tags security
 *       external/cwe/cwe-502
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.UnsafeDeserializationCustomizations
import Raptor.LocalFlowSource

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node n) { n instanceof UnsafeDeserialization::Sink }

  predicate isBarrier(DataFlow::Node n) { n instanceof UnsafeDeserialization::Sanitizer }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Local user input from $@ is deserialized.",
  source.getNode(), source.getNode().toString()
