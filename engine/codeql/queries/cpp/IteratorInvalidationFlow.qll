/** Container-specific invalidation followed by a live iterator use. */

import cpp

private predicate containerFamily(Class type, string family) {
  family =
    [
      "vector", "deque", "list", "forward_list", "set", "multiset", "map", "multimap",
      "unordered_set", "unordered_multiset", "unordered_map", "unordered_multimap", "basic_string"
    ] and
  type.hasQualifiedName(["std", "bsl"], family)
}

class ContainerMutation extends FunctionCall {
  StackVariable container;
  string family;

  ContainerMutation() {
    this.getQualifier().getUnconverted().(VariableAccess).getTarget() = container and
    containerFamily(this.getTarget().(MemberFunction).getDeclaringType(), family) and
    this.getTarget().getName() =
      [
        "erase", "insert", "emplace", "emplace_back", "push_back", "push_front", "emplace_front",
        "pop_back", "pop_front", "resize", "reserve", "rehash", "shrink_to_fit", "clear", "assign"
      ] and
    not this.isUnevaluated()
  }

  StackVariable getContainer() { result = container }

  string getFamily() { result = family }
}

/**
 * Associations still originate at begin/end. Exclude independent range-built containers,
 * without requiring operator++ to be instantiated in dereference-only functions.
 */
private predicate iteratorType(Type type) {
  type.getUnspecifiedType() instanceof PointerType
  or
  exists(Class candidate |
    candidate = type.getUnspecifiedType() and
    not containerFamily(candidate, _)
  )
}

/** Assignment completion is a new binding, not iterator increment/arithmetic. */
private predicate rawBinding(ControlFlowNode node, StackVariable iterator, Expr value) {
  iteratorType(iterator.getType()) and
  not iterator.getType().getUnspecifiedType() instanceof ReferenceType and
  (
    node = iterator.getInitializer() and value = iterator.getInitializer().getExpr()
    or
    exists(AssignExpr assignment |
      node = assignment and
      assignment.getLValue().getUnconverted().(VariableAccess).getTarget() = iterator and
      value = assignment.getRValue()
    )
    or
    exists(FunctionCall assignment |
      node = assignment and
      assignment.getTarget().hasName("operator=") and
      assignment.getQualifier().getUnconverted().(VariableAccess).getTarget() = iterator and
      value = assignment.getArgument(0)
    )
  ) and
  node.getControlFlowScope().getEntryPoint().getASuccessor*() = node
}

private predicate writesIterator(ControlFlowNode node, StackVariable iterator) {
  rawBinding(node, iterator, _)
}

/** A binding remains the current association until another assignment completes. */
private predicate bindingLive(ControlFlowNode binding, StackVariable iterator, ControlFlowNode node) {
  node = binding.getASuccessor()
  or
  exists(ControlFlowNode previous |
    bindingLive(binding, iterator, previous) and
    not writesIterator(previous, iterator) and
    node = previous.getASuccessor()
  )
}

private predicate iteratorValue(
  Expr value, StackVariable container, boolean pastEnd, ControlFlowNode at
) {
  exists(FunctionCall call, string family |
    call = value.getUnconverted() and
    containerFamily(call.getTarget().(MemberFunction).getDeclaringType(), family) and
    call.getQualifier().getUnconverted().(VariableAccess).getTarget() = container and
    (
      pastEnd = false and call.getTarget().getName() = ["begin", "cbegin", "erase"]
      or
      pastEnd = true and call.getTarget().getName() = ["end", "cend"]
    )
  )
  or
  exists(ConstructorCall copy | copy = value.getUnconverted() |
    iteratorValue(copy.getArgument(0), container, pastEnd, at)
  )
  or
  exists(StackVariable source, ControlFlowNode binding |
    value.getUnconverted().(VariableAccess).getTarget() = source and
    iteratorBinding(binding, source, container, pastEnd) and
    bindingLive(binding, source, at)
  )
}

private predicate iteratorBinding(
  ControlFlowNode binding, StackVariable iterator, StackVariable container, boolean pastEnd
) {
  exists(Expr value | rawBinding(binding, iterator, value) |
    iteratorValue(value, container, pastEnd, binding)
  )
  or
  exists(RangeBasedForStmt loop |
    loop.getRange().getUnconverted().(VariableAccess).getTarget() = container and
    (
      pastEnd = false and iterator = loop.getBeginVariable()
      or
      pastEnd = true and iterator = loop.getEndVariable()
    ) and
    binding = iterator.getInitializer()
  )
}

/** Follow iterator-to-const_iterator constructor conversions, not arbitrary calls. */
private predicate erasedPosition(Expr expression, StackVariable iterator, boolean advanced) {
  expression.getUnconverted().(VariableAccess).getTarget() = iterator and advanced = false
  or
  exists(ConstructorCall conversion | conversion = expression.getUnconverted() |
    erasedPosition(conversion.getArgument(0), iterator, advanced)
  )
  or
  expression
      .getUnconverted()
      .(PrefixIncrExpr)
      .getOperand()
      .getUnconverted()
      .(VariableAccess)
      .getTarget() = iterator and
  advanced = false
  or
  expression
      .getUnconverted()
      .(PostfixIncrExpr)
      .getOperand()
      .getUnconverted()
      .(VariableAccess)
      .getTarget() = iterator and
  advanced = true
  or
  exists(FunctionCall increment |
    increment = expression.getUnconverted() and
    increment.getTarget().hasName("operator++") and
    increment.getQualifier().getUnconverted().(VariableAccess).getTarget() = iterator and
    (
      increment.getNumberOfArguments() = 0 and advanced = false
      or
      increment.getNumberOfArguments() = 1 and advanced = true
    )
  )
}

private predicate changesPosition(ControlFlowNode node, StackVariable iterator) {
  writesIterator(node, iterator)
  or
  exists(CrementOperation step |
    node = step and step.getOperand().getUnconverted().(VariableAccess).getTarget() = iterator
  )
  or
  exists(AssignOperation step |
    node = step and step.getLValue().getUnconverted().(VariableAccess).getTarget() = iterator
  )
  or
  exists(FunctionCall step |
    node = step and
    (
      step.getTarget().getName() = ["operator++", "operator--", "operator+=", "operator-="] and
      step.getQualifier().getUnconverted().(VariableAccess).getTarget() = iterator
      or
      step.getTarget().hasQualifiedName("std", "advance") and
      step.getArgument(0).getUnconverted().(VariableAccess).getTarget() = iterator
    )
  )
}

private predicate positionsUnchanged(
  ControlFlowNode copy, StackVariable first, StackVariable second, ControlFlowNode node
) {
  node = copy.getASuccessor()
  or
  exists(ControlFlowNode previous |
    positionsUnchanged(copy, first, second, previous) and
    not changesPosition(previous, first) and
    not changesPosition(previous, second) and
    node = previous.getASuccessor()
  )
}

/** A simple copied iterator still denotes the same position until either copy changes. */
private predicate samePosition(StackVariable first, StackVariable second, ControlFlowNode at) {
  first = second
  or
  exists(ControlFlowNode copy, Expr value |
    (
      rawBinding(copy, first, value) and erasedPosition(value, second, false)
      or
      rawBinding(copy, second, value) and erasedPosition(value, first, false)
    ) and
    positionsUnchanged(copy, first, second, at)
  )
}

/** In a set the dereferenced iterator is also the key erased by erase(key). */
private StackVariable keyIterator(Expr expression) {
  exists(FunctionCall dereference |
    dereference = expression.getUnconverted() and
    dereference.getTarget().hasName("operator*") and
    result = dereference.getQualifier().getUnconverted().(VariableAccess).getTarget()
  )
  or
  exists(ConstructorCall conversion | conversion = expression.getUnconverted() |
    result = keyIterator(conversion.getArgument(0))
  )
}

/** A direct begin value, including iterator copy/conversion construction. */
private predicate listFrontValue(Expr value, StackVariable container) {
  exists(FunctionCall call |
    call = value.getUnconverted() and
    containerFamily(call.getTarget().(MemberFunction).getDeclaringType(), "list") and
    call.getTarget().getName() = ["begin", "cbegin"] and
    call.getQualifier().getUnconverted().(VariableAccess).getTarget() = container
  )
  or
  exists(ConstructorCall copy | copy = value.getUnconverted() |
    listFrontValue(copy.getArgument(0), container)
  )
}

/** Node insertion preserves existing iterators; erasure invalidates the erased position. */
private predicate invalidates(ContainerMutation mutation, StackVariable iterator, boolean pastEnd) {
  pastEnd = [true, false] and
  not (
    mutation.getTarget().hasName("erase") and
    exists(StackVariable position |
      erasedPosition(mutation.getArgument(0), position, false) and
      erasedPosition(mutation.getArgument(1), position, false)
    )
  ) and
  exists(string name, string family |
    name = mutation.getTarget().getName() and
    family = mutation.getFamily() and
    (
      family = ["vector", "deque", "basic_string"] and
      name =
        [
          "insert", "emplace", "emplace_back", "push_back", "push_front", "emplace_front", "resize",
          "reserve", "shrink_to_fit", "assign", "clear"
        ]
      or
      family = ["unordered_set", "unordered_multiset", "unordered_map", "unordered_multimap"] and
      name = ["insert", "emplace", "rehash", "reserve", "clear"]
      or
      name = ["clear", "assign"] and pastEnd = false
      or
      name = "erase" and
      (
        exists(StackVariable erased |
          erasedPosition(mutation.getArgument(0), erased, false) and
          samePosition(erased, iterator, mutation)
        )
        or
        family = ["vector", "deque", "basic_string"]
        or
        family = ["set", "multiset", "unordered_set", "unordered_multiset"] and
        mutation.getNumberOfArguments() = 1 and
        samePosition(keyIterator(mutation.getArgument(0)), iterator, mutation)
      )
      or
      name = "pop_back" and family = ["vector", "deque", "basic_string"] and pastEnd = true
      or
      name = "pop_front" and family = "list" and pastEnd = false and
      exists(ControlFlowNode binding, Expr value |
        rawBinding(binding, iterator, value) and
        listFrontValue(value, mutation.getContainer()) and
        positionsUnchanged(binding, iterator, iterator, mutation)
      )
    )
  )
}

class IteratorUse extends VariableAccess {
  IteratorUse() {
    not exists(AssignExpr assignment | assignment.getLValue().getUnconverted() = this) and
    not exists(FunctionCall assignment |
      assignment.getTarget().hasName("operator=") and
      assignment.getQualifier().getUnconverted() = this
    ) and
    not exists(DestructorCall destructor | destructor.getQualifier().getUnconverted() = this) and
    not this.isUnevaluated()
  }
}

private predicate invalidState(
  ContainerMutation mutation, StackVariable iterator, ControlFlowNode node
) {
  node = mutation.getASuccessor()
  or
  exists(ControlFlowNode previous |
    invalidState(mutation, iterator, previous) and
    not writesIterator(previous, iterator) and
    node = previous.getASuccessor()
  )
}

predicate invalidIteratorUse(ContainerMutation mutation, IteratorUse use) {
  exists(ControlFlowNode binding, StackVariable iterator, boolean pastEnd |
    iteratorBinding(binding, iterator, mutation.getContainer(), pastEnd) and
    bindingLive(binding, iterator, mutation) and
    invalidates(mutation, iterator, pastEnd) and
    use.getTarget() = iterator and
    invalidState(mutation, iterator, use) and
    use.getEnclosingFunction() = mutation.getEnclosingFunction()
  )
}
