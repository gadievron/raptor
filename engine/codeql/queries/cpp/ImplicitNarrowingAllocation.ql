/**
 * @name Implicit integer narrowing in an allocation size
 * @description An implicit conversion loses integer width before its result
 *              influences an allocation size, without a proved input bound.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id raptor/cpp/implicit-narrowing-allocation
 * @tags security
 *       external/cwe/cwe-197
 *       external/cwe/cwe-131
 */

import ImplicitAllocationNarrowingFlow

from ImplicitSizeNarrowing conversion, Expr size
where implicitAllocationNarrowing(conversion, size)
select conversion,
  "Implicit conversion to " + conversion.getType().toString() +
    " may truncate the value used in this $@, producing an undersized allocation.", size,
  "allocation size"
