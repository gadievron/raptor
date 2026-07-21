/**
 * @name Iterator invalidation by container mutation during iteration
 * @description Calling a mutating method (erase, insert, push_back,
 *              emplace_back, resize) on an STL container while iterating
 *              over it invalidates outstanding iterators, leading to
 *              use-after-free or undefined behaviour.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id raptor/cpp/iterator-invalidation
 * @tags security
 *       correctness
 *       external/cwe/cwe-416
 *       external/cwe/cwe-825
 */

import cpp

/*
 * ---- Container identification ----
 *
 * We match STL sequence and associative containers whose mutating
 * methods invalidate iterators.  Node-based containers (list,
 * forward_list, set, map) only invalidate the erased element's
 * iterator -- but erasing the current element in a for-loop still
 * produces UB unless the caller captures the return value.
 */

/** An STL container type whose mutation may invalidate iterators. */
class StlContainerType extends Class {
  StlContainerType() {
    this.hasQualifiedName(["std", "bsl"],
      [
        "vector", "deque", "list", "forward_list", "set", "multiset", "map", "multimap",
        "unordered_set", "unordered_multiset", "unordered_map", "unordered_multimap",
        "basic_string"
      ])
  }
}

/**
 * Holds when `c` is a node-based container where `erase` only invalidates
 * the erased element (not all iterators).
 */
predicate isNodeBasedContainer(StlContainerType c) {
  c.hasQualifiedName(["std", "bsl"],
    [
      "list", "forward_list", "set", "multiset", "map", "multimap", "unordered_set",
      "unordered_multiset", "unordered_map", "unordered_multimap"
    ])
}

/** A call to a method that can invalidate iterators on the container. */
class ContainerMutatingCall extends FunctionCall {
  Variable containerVar;

  ContainerMutatingCall() {
    exists(MemberFunction mf |
      mf = this.getTarget() and
      mf.getDeclaringType() instanceof StlContainerType and
      mf.getName() =
        [
          "erase", "insert", "emplace", "emplace_back", "push_back", "push_front",
          "emplace_front", "pop_back", "pop_front", "resize", "reserve", "clear",
          "assign", "swap"
        ] and
      containerVar = this.getQualifier().(VariableAccess).getTarget()
    )
  }

  /** Gets the container variable being mutated. */
  Variable getContainerVariable() { result = containerVar }

  /** Gets the name of the mutating method. */
  string getMutatingMethodName() { result = this.getTarget().getName() }
}

/*
 * ---- Loop detection ----
 *
 * We look for two shapes:
 *
 * 1. Explicit iterator loops: a Loop whose condition or update
 *    references an iterator variable, and whose body contains the
 *    mutating call on the same container.
 *
 * 2. Range-for loops (RangeBasedForStmt) that iterate over the
 *    container and mutate it in the body.
 */

/** A `for`, `while`, or `do-while` loop. */
class IterationLoop extends Loop {
  IterationLoop() {
    this instanceof ForStmt or
    this instanceof WhileStmt or
    this instanceof DoStmt
  }
}

/**
 * Holds when `loop` iterates over `containerVar` via an explicit
 * iterator pattern -- the loop condition or update mentions the
 * container or an iterator obtained from it.
 */
predicate iteratesOverWithIterator(IterationLoop loop, Variable containerVar) {
  exists(FunctionCall beginCall |
    // Look for `container.begin()` or `container.end()` in the loop
    // init, condition, or update, linking the container variable.
    beginCall.getTarget().getName() = ["begin", "end", "cbegin", "cend"] and
    beginCall.getQualifier().(VariableAccess).getTarget() = containerVar and
    (
      // In the loop initialiser (for-loop)
      loop.(ForStmt).getInitialization().getAChild*() = beginCall
      or
      // In the condition
      loop.getCondition().getAChild*() = beginCall
      or
      // In the update
      loop.(ForStmt).getUpdate().getAChild*() = beginCall
    )
  )
}

/**
 * Holds if `mutCall` is inside `loop` (directly or in a nested block,
 * but NOT inside a nested function/lambda).
 */
predicate mutationInLoopBody(Loop loop, ContainerMutatingCall mutCall) {
  mutCall.getEnclosingStmt().getParentStmt*() = loop.getStmt()
}

/**
 * Holds when the mutating call's return value is captured (assigned
 * to a variable).  For node-based containers, `it = container.erase(it)`
 * is the idiomatic safe pattern -- we exclude these.
 */
predicate returnValueCaptured(ContainerMutatingCall mutCall) {
  exists(AssignExpr assign | assign.getRValue() = mutCall)
  or
  exists(Variable v | v.getInitializer().getExpr() = mutCall)
}

/*
 * ---- Main query ----
 */

from ContainerMutatingCall mutCall, Loop loop, Variable containerVar, string loopKind
where
  mutCall.getContainerVariable() = containerVar and
  mutationInLoopBody(loop, mutCall) and
  (
    // Case 1: explicit iterator loop
    iteratesOverWithIterator(loop, containerVar) and
    loopKind = "iterator loop"
    or
    // Case 2: range-based for loop over the same container
    loop instanceof RangeBasedForStmt and
    loop.(RangeBasedForStmt).getRange().(VariableAccess).getTarget() = containerVar and
    loopKind = "range-for loop"
  ) and
  // Exclude the safe `it = container.erase(it)` pattern — the returned
  // iterator is valid for all container types (sequence and node-based).
  not (
    mutCall.getMutatingMethodName() = "erase" and
    returnValueCaptured(mutCall)
  )
select mutCall,
  "Container '" + containerVar.getName() + "' is mutated by " + mutCall.getMutatingMethodName() +
    "() while being iterated in a " + loopKind +
    ", which may invalidate outstanding iterators (CWE-416/CWE-825)."
