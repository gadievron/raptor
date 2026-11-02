/**
 * @name Use of object after a consuming move
 * @description A local object is used after a move constructor, move assignment,
 *              or modeled standard-library insertion may consume its value.
 *              Depending on the operation and type this can cause a logic error
 *              or invalid memory access; not every post-move use is undefined.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.0
 * @precision medium
 * @id raptor/cpp/use-after-move
 * @tags security
 *       correctness
 *       external/cwe/cwe-416
 */

import UseAfterMoveFlow

from ConsumingMove move, PostMoveUse use
where useAfterMove(move, use)
select use,
  "Variable '" + move.getMovedVariable().getName() + "' is used after a consuming move at $@. " +
    "This operation may depend on the value consumed by that move.", move.getConsumption(),
  "move consumption"
