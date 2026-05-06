/**
 * @name IRIS LocalFlowSource: unsafe deserialization from local input
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id raptor/iris/java/unsafe-deserialization-local
 * @tags security
 *       external/cwe/cwe-502
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.UnsafeDeserializationQuery
import Raptor.LocalFlowSource

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node n) { n instanceof UnsafeDeserializationSink }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Local user input is deserialized."
