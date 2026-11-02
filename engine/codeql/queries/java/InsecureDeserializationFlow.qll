/** Shared flow and filter checks for ObjectInputStream deserialization. */

import java
import semmle.code.java.controlflow.Dominance
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

class ObjectInputStreamCreation extends ClassInstanceExpr {
  ObjectInputStreamCreation() {
    this.getConstructedType().hasQualifiedName("java.io", "ObjectInputStream")
  }
}

class ReadObjectCall extends MethodCall {
  ReadObjectCall() {
    this.getMethod().getDeclaringType().hasQualifiedName("java.io", "ObjectInputStream") and
    this.getMethod().getName() = ["readObject", "readUnshared"]
  }
}

/** Follow only single-valued local aliases, not fields or merged assignments. */
private Expr stableValue(Expr use) {
  result = use
  or
  exists(LocalVariableDecl variable, Expr value |
    use.(VarAccess).getVariable() = variable and
    value = variable.getAnAssignedValue() and
    not exists(Expr other | other = variable.getAnAssignedValue() and other != value) and
    result = stableValue(value)
  )
}

/**
 * Recognize closed, exact-class pattern filters ending in reject-all.
 * No wildcard allow rules, denylist-only policies, resource-only limits,
 * arbitrary lambdas or unknown filter implementations establish safety.
 * This proves a closed class policy, not that every allowed class is benign.
 */
private predicate restrictiveFilter(Expr argument) {
  exists(MethodCall factory, string pattern |
    factory = stableValue(argument) and
    factory.getMethod().getDeclaringType().hasQualifiedName("java.io", "ObjectInputFilter$Config") and
    factory.getMethod().getName() = "createFilter" and
    pattern = factory.getArgument(0).(CompileTimeConstantExpr).getStringValue() and
    pattern.regexpMatch("(!?[A-Za-z_$][A-Za-z0-9_$.]*;)*!\\*")
  )
}

/**
 * Both receivers must resolve to the same unambiguous creation. A filter
 * must dominate this read, rather than merely occur somewhere on a variable.
 */
private predicate hasInputFilter(ObjectInputStreamCreation creation, ReadObjectCall readCall) {
  exists(MethodCall filter |
    stableValue(readCall.getQualifier()) = creation and
    stableValue(filter.getQualifier()) = creation and
    filter.getMethod().getDeclaringType().hasQualifiedName("java.io", "ObjectInputStream") and
    filter.getMethod().getName() = "setObjectInputFilter" and
    restrictiveFilter(filter.getArgument(0)) and
    strictlyDominates(filter.getControlFlowNode(), readCall.getControlFlowNode()) and
    not filter.getControlFlowNode().getAnExceptionSuccessor().getASuccessor*() =
      readCall.getControlFlowNode()
  )
}

/** A read reachable by local object flow from this stream creation. */
predicate isUnfilteredRead(ObjectInputStreamCreation creation, ReadObjectCall readCall) {
  DataFlow::localFlow(DataFlow::exprNode(creation), DataFlow::exprNode(readCall.getQualifier())) and
  not hasInputFilter(creation, readCall)
}

module DeserConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) {
    exists(ObjectInputStreamCreation creation | sink.asExpr() = creation.getArgument(0))
  }
}

module DeserFlow = TaintTracking::Global<DeserConfig>;
