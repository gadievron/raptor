/**
 * @name IRIS LocalFlowSource: code injection from local input
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id raptor/iris/javascript/code-injection-local
 * @tags security
 *       external/cwe/cwe-94
 *       external/cwe/cwe-95
 *       external/cwe/cwe-116
 */

import javascript
import semmle.javascript.dataflow.DataFlow
import semmle.javascript.dataflow.TaintTracking
import semmle.javascript.security.dataflow.CodeInjectionCustomizations
import Raptor.LocalFlowSource

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof LocalFlowSource }

  predicate isSink(DataFlow::Node n) { n instanceof CodeInjection::Sink }

  predicate isBarrier(DataFlow::Node n) { n instanceof CodeInjection::Sanitizer }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Local user input flows to a code-execution sink (eval / Function / vm.run)."
