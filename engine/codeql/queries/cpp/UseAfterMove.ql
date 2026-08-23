/**
 * @name Use of object after std::move
 * @description Accessing an object after it has been moved from leaves
 *              the object in a valid-but-unspecified state.  Reading
 *              its value is almost always a logic bug; writing through
 *              moved-from iterators or pointers is undefined behaviour.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.0
 * @precision high
 * @id raptor/cpp/use-after-move
 * @tags security
 *       correctness
 *       external/cwe/cwe-416
 */

import cpp
import semmle.code.cpp.controlflow.Dominance

/**
 * A call to `std::move(x)` where `x` is a local variable or parameter.
 */
class MoveCall extends FunctionCall {
  Variable movedVar;

  MoveCall() {
    this.getTarget().hasQualifiedName("std", "move") and
    this.getNumberOfArguments() = 1 and
    movedVar = this.getArgument(0).(VariableAccess).getTarget()
  }

  Variable getMovedVariable() { result = movedVar }
}

/**
 * Holds if `va` re-establishes a known state for its variable: the
 * left-hand side of a built-in assignment, or the qualifier of a call
 * to an assignment operator. Class types — the common moved-from case
 * — assign through `operator=` (a FunctionCall), not an AssignExpr,
 * so both forms must count as reassignment.
 */
predicate isReassignmentAccess(VariableAccess va) {
  exists(AssignExpr assign | assign.getLValue() = va)
  or
  exists(FunctionCall fc |
    fc.getQualifier() = va and
    fc.getTarget().getName() = "operator="
  )
}

/**
 * An access to a variable (read or non-const method call) that is NOT
 * an assignment (which would re-establish a known state) and NOT a
 * call to `.clear()`, `.reset()`, or destructor (which are safe
 * post-move operations).
 */
class UnsafePostMoveAccess extends VariableAccess {
  UnsafePostMoveAccess() {
    // Not a reassignment (re-initialisation is safe)
    not isReassignmentAccess(this) and
    // Not a call to a known-safe resetter
    not exists(FunctionCall fc |
      fc.getQualifier() = this and
      fc.getTarget().getName() = ["clear", "reset", "resize", "assign", "swap", "emplace"]
    ) and
    // Not the qualifier of a destructor call — destroying a
    // moved-from object is well-defined. This covers the implicit
    // end-of-scope destructor calls the extractor synthesises at the
    // closing brace, which otherwise flag every moved-from local.
    not exists(DestructorCall dc | dc.getQualifier() = this) and
    // Not inside a destructor for this variable
    not this.getEnclosingFunction() instanceof Destructor
  }
}

from MoveCall moveCall, UnsafePostMoveAccess useAccess, Variable v
where
  v = moveCall.getMovedVariable() and
  v = useAccess.getTarget() and
  // The use is in the same function as the move
  moveCall.getEnclosingFunction() = useAccess.getEnclosingFunction() and
  // The use is after the move (by source location — conservative)
  useAccess.getLocation().getStartLine() > moveCall.getLocation().getStartLine() and
  // Exclude cases where the variable is reassigned between move and use
  not exists(VariableAccess reassign |
    isReassignmentAccess(reassign) and
    reassign.getTarget() = v and
    reassign.getLocation().getStartLine() > moveCall.getLocation().getStartLine() and
    reassign.getLocation().getStartLine() < useAccess.getLocation().getStartLine()
  ) and
  // The move must execute before the use on every path reaching the
  // use. This replaces a getParentStmt*() equality between the two
  // statements' ancestor sets, which always shares the function body
  // block and so held for ANY two statements in one function —
  // including a move in one branch of an if/else and a use in the
  // other. Dominance also rejects that branch case: neither branch
  // dominates the other.
  strictlyDominates(moveCall, useAccess)
select useAccess,
  "Variable '" + v.getName() + "' is accessed after being moved at $@. " +
    "The object is in a valid-but-unspecified state (CWE-416).",
  moveCall, "std::move"
