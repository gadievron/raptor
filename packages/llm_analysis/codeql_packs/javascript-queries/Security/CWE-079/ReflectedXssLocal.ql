/**
 * @name IRIS LocalFlowSource: reflected XSS from local input
 * @description Reuses the stdlib ReflectedXss sink (HTTP response writes)
 *              with RAPTOR's `LocalFlowSource` so SSR / Node-CLI flows
 *              landing in HTTP response bodies are caught. DOM-based XSS
 *              has a separate sink class (`DomBasedXss::Sink`); a
 *              companion query can be added if browser-side flows from
 *              process.argv / process.env ever materialise as a real
 *              vector.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id raptor/iris/javascript/reflected-xss-local
 * @tags security
 *       external/cwe/cwe-79
 */

import javascript
import semmle.javascript.dataflow.DataFlow
import semmle.javascript.dataflow.TaintTracking
import semmle.javascript.security.dataflow.ReflectedXssCustomizations
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
  "Local user input flows to an HTTP response body."
