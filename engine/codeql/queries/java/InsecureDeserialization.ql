/**
 * @name Insecure deserialization via ObjectInputStream
 * @description Creating an ObjectInputStream from untrusted input and
 *              calling readObject() without a type filter allows
 *              arbitrary code execution through gadget chains.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id raptor/java/insecure-deserialization
 * @tags security
 *       external/cwe/cwe-502
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import DeserFlow::PathGraph

/**
 * A constructor call `new ObjectInputStream(input)` where `input`
 * originates from an external source.
 */
class ObjectInputStreamCreation extends ClassInstanceExpr {
  ObjectInputStreamCreation() {
    this.getConstructedType().hasQualifiedName("java.io", "ObjectInputStream")
  }
}

/**
 * A call to `readObject()` or `readUnshared()` on an ObjectInputStream.
 */
class ReadObjectCall extends MethodCall {
  ReadObjectCall() {
    this.getMethod().getDeclaringType().hasQualifiedName("java.io", "ObjectInputStream") and
    this.getMethod().getName() = ["readObject", "readUnshared"]
  }
}

/**
 * An ObjectInputStream that has been hardened with a
 * `setObjectInputFilter` call (Java 9+ / JEP 290).
 */
predicate hasInputFilter(Variable oisVar) {
  exists(MethodCall mc |
    mc.getQualifier().(VarAccess).getVariable() = oisVar and
    mc.getMethod().getName() = "setObjectInputFilter"
  )
}

/** Taint from external sources to ObjectInputStream constructor argument. */
module DeserConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node sink) {
    exists(ObjectInputStreamCreation ois |
      sink.asExpr() = ois.getArgument(0)
    )
  }
}

module DeserFlow = TaintTracking::Global<DeserConfig>;

from
  DeserFlow::PathNode source, DeserFlow::PathNode sink,
  ObjectInputStreamCreation oisCreation, Variable oisVar,
  ReadObjectCall readCall
where
  DeserFlow::flowPath(source, sink) and
  sink.getNode().asExpr() = oisCreation.getArgument(0) and
  oisVar.getAnAssignedValue() = oisCreation and
  readCall.getQualifier().(VarAccess).getVariable() = oisVar and
  not hasInputFilter(oisVar)
select readCall, source, sink,
  "Untrusted data from $@ is deserialized via ObjectInputStream.readObject() " +
    "without a type filter — arbitrary code execution via gadget chains (CWE-502).",
  source.getNode(), "remote source"
