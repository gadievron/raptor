/** Consuming moves and local control-flow state after them. */

import cpp

/** Resolve local reference aliases' declared object type, without tracking aliases across variables. */
private Class objectClass(Type type) {
  result = type.getUnspecifiedType()
  or
  result = objectClass(type.getUnspecifiedType().(ReferenceType).getBaseType())
}

/** A cast request on a named local object; the cast alone does not consume it. */
class MoveCall extends FunctionCall {
  StackVariable variable;

  MoveCall() {
    this.getTarget().hasQualifiedName("std", "move") and
    exists(Class object | object = objectClass(variable.getType()) and not object.isPod()) and
    this.getNumberOfArguments() = 1 and
    this.getArgument(0).getUnconverted().(VariableAccess).getTarget() = variable
  }

  StackVariable getMovedVariable() { result = variable }
}

/** Direct language moves and standard container insertion through an rvalue overload. */
class ConsumingMove extends MoveCall {
  FunctionCall consumption;

  ConsumingMove() {
    not this.isUnevaluated() and
    not consumption.isUnevaluated() and
    this.getEnclosingFunction().getEntryPoint().getASuccessor*() = consumption and
    consumption.getEnclosingFunction() = this.getEnclosingFunction() and
    exists(int index |
      consumption.getArgument(index).getUnconverted() = this and
      (
        index = 0 and
        (
          consumption.getTarget() instanceof MoveConstructor or
          consumption.getTarget() instanceof MoveAssignmentOperator
        )
        or
        consumption.getTarget().(MemberFunction).getDeclaringType().getNamespace() instanceof
          StdNamespace and
        consumption.getTarget().getName() = ["push_back", "push_front", "insert"] and
        consumption.getTarget().getParameter(index).getUnspecifiedType() instanceof
          RValueReferenceType
      )
    )
  }

  FunctionCall getConsumption() { result = consumption }
}

private predicate accesses(Expr expression, Variable variable) {
  exists(VariableAccess access |
    access.getTarget() = variable and
    access = expression.getUnconverted().getAChild*()
  )
}

private predicate assignmentReceiver(VariableAccess access) {
  exists(AssignExpr assignment | assignment.getLValue().getUnconverted() = access)
  or
  exists(FunctionCall call |
    call.getTarget().hasName("operator=") and call.getQualifier().getUnconverted() = access
  )
}

private predicate stdResetter(FunctionCall call) {
  call.getTarget().(MemberFunction).getDeclaringType().getNamespace() instanceof StdNamespace and
  call.getTarget().getName() = ["clear", "reset", "resize", "assign", "emplace", "swap"]
}

private predicate stdObservation(FunctionCall call) {
  call.getTarget().(MemberFunction).getDeclaringType().getNamespace() instanceof StdNamespace and
  call.getTarget().getName() = ["empty", "size", "capacity", "get_allocator", "operator bool"]
}

/** Comparing the stored pointer with nullptr observes a moved-from unique_ptr. */
private predicate stdUniquePointerNullObservation(FunctionCall call) {
  call.getTarget().getName() = "get" and
  call.getNumberOfArguments() = 0 and
  call.getTarget().(MemberFunction).getDeclaringType().hasQualifiedName("std", "unique_ptr") and
  exists(EqualityOperation comparison, Expr pointer, Expr nullValue |
    comparison.hasOperands(pointer, nullValue) and
    pointer.getUnconverted() = call and
    nullValue.getUnconverted().getType().getUnspecifiedType() instanceof NullPointerType
  )
}

/** Only completion of an assignment/reset, not evaluation of its receiver, clears state. */
private predicate reinitializes(ControlFlowNode node, StackVariable variable) {
  exists(AssignExpr assignment |
    node = assignment and
    assignment.getLValue().getUnconverted().(VariableAccess).getTarget() = variable and
    not accesses(assignment.getRValue(), variable)
  )
  or
  exists(FunctionCall call |
    node = call and
    call.getQualifier().getUnconverted().(VariableAccess).getTarget() = variable and
    (
      call.getTarget().hasName("operator=") and not accesses(call.getArgument(0), variable)
      or
      stdResetter(call) and not accesses(call.getAnArgument(), variable)
    )
  )
}

/** A syntactic use that may depend on the consumed value. This is a warning, not a UB proof. */
class PostMoveUse extends VariableAccess {
  PostMoveUse() {
    not assignmentReceiver(this) and
    not exists(FunctionCall call |
      call.getQualifier().getUnconverted() = this and
      (stdResetter(call) or stdObservation(call) or stdUniquePointerNullObservation(call))
    ) and
    not exists(DestructorCall destructor | destructor.getQualifier().getUnconverted() = this) and
    not this.getEnclosingFunction() instanceof Destructor
  }
}

/** Reachability retains the moved state only along paths with no intervening reset. */
private predicate movedState(ConsumingMove move, ControlFlowNode node) {
  node = move.getConsumption().getASuccessor()
  or
  exists(ControlFlowNode previous |
    movedState(move, previous) and
    not reinitializes(previous, move.getMovedVariable()) and
    node = previous.getASuccessor()
  )
}

predicate useAfterMove(ConsumingMove move, PostMoveUse use) {
  use.getTarget() = move.getMovedVariable() and
  use.getEnclosingFunction() = move.getEnclosingFunction() and
  movedState(move, use)
}
