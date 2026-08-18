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
 * An access to a variable (read or non-const method call) that is NOT
 * an assignment (which would re-establish a known state) and NOT a
 * call to `.clear()`, `.reset()`, or destructor (which are safe
 * post-move operations).
 */
class UnsafePostMoveAccess extends VariableAccess {
  UnsafePostMoveAccess() {
    // Not the left-hand side of an assignment (re-initialisation is safe)
    not exists(AssignExpr assign | assign.getLValue() = this) and
    // Not a call to a known-safe resetter
    not exists(FunctionCall fc |
      fc.getQualifier() = this and
      fc.getTarget().getName() = ["clear", "reset", "resize", "assign", "swap", "emplace"]
    ) and
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
  not exists(AssignExpr reassign |
    reassign.getLValue().(VariableAccess).getTarget() = v and
    reassign.getLocation().getStartLine() > moveCall.getLocation().getStartLine() and
    reassign.getLocation().getStartLine() < useAccess.getLocation().getStartLine()
  ) and
  // Exclude move in a branch where the use is in a different branch
  // (conservative: require same enclosing block or nested)
  moveCall.getEnclosingStmt().getParentStmt*() =
    useAccess.getEnclosingStmt().getParentStmt*()
select useAccess,
  "Variable '" + v.getName() + "' is accessed after being moved at $@. " +
    "The object is in a valid-but-unspecified state (CWE-416).",
  moveCall, "std::move"
