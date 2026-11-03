/** Implicit width loss whose result influences an allocation size. */

import IntegerTruncationFlow

/**
 * Supplement the classic bounds for small unsigned size expressions. Every derived bound
 * stays within 32-bit endpoints. Add one after arithmetic to round outward:
 * at this scale it exceeds any floating-point rounding error.
 * Unsupported operators and signed inputs retain the classic analysis only.
 */
private float smallUnsignedUpperBound(Expr expression) {
  expression.getType().getUnspecifiedType().(IntegralType).isUnsigned() and
  result >= 0 and
  result <= 4294967295.0 and
  (
    lowerBound(expression) >= 0 and result = upperBound(expression)
    or
    exists(DivExpr division, float numerator, float divisor |
      expression = division and
      numerator = smallUnsignedUpperBound(division.getLeftOperand().getFullyConverted()) and
      divisor = division.getRightOperand().getFullyConverted().getValue().toFloat() and
      divisor >= 1 and
      divisor <= 4294967295.0 and
      result = numerator / divisor + 1
    )
    or
    exists(AddExpr addition, float left, float right |
      expression = addition and
      left = smallUnsignedUpperBound(addition.getLeftOperand().getFullyConverted()) and
      right = smallUnsignedUpperBound(addition.getRightOperand().getFullyConverted()) and
      result = left + right + 1
    )
    or
    exists(ConditionalExpr conditional, float left, float right |
      expression = conditional and
      left = smallUnsignedUpperBound(conditional.getThen().getFullyConverted()) and
      right = smallUnsignedUpperBound(conditional.getElse().getFullyConverted()) and
      (
        left >= right and result = left
        or
        right >= left and result = right
      )
    )
    or
    exists(Conversion conversion |
      expression = conversion and
      conversion.getExpr().getType().getUnspecifiedType().(IntegralType).isUnsigned() and
      getIntegralBitWidth(conversion.getExpr().getType()) <=
        getIntegralBitWidth(conversion.getType()) and
      result = smallUnsignedUpperBound(conversion.getExpr())
    )
  )
}

/** Bound the input expression; never let the narrowing result prove itself. */
private predicate fitsAllocationInput(Cast conversion) {
  smallUnsignedUpperBound(conversion.getExpr()) <=
    typeUpperBound(conversion.getType().getUnspecifiedType().(IntegralType))
}

/** An implicit integral conversion not proved to preserve its input value. */
class ImplicitSizeNarrowing extends Cast {
  ImplicitSizeNarrowing() {
    this.isImplicit() and
    isNarrowingPair(this.getExpr().getType(), this.getType()) and
    not this.getType().getUnspecifiedType() instanceof BoolType and
    not fitsDestination(this) and
    not fitsAllocationInput(this)
  }
}

/** Kernel allocation profiling macros call their `_noprof` entry points. */
private predicate allocationName(Function function, string name) {
  function.hasGlobalName(name)
  or
  name = ["vmalloc", "kmalloc", "kzalloc", "kmalloc_array", "kcalloc"] and
  function.hasGlobalName(name + "_noprof")
}

/** An allocation-size argument, rather than flags, addresses or contents. */
private predicate allocationSize(FunctionCall call, int index) {
  allocationName(call.getTarget(), ["malloc", "vmalloc", "kmalloc", "kzalloc"]) and index = 0
  or
  allocationName(call.getTarget(), ["calloc", "kmalloc_array", "kcalloc"]) and index = [0, 1]
  or
  call.getTarget().hasGlobalName("realloc") and index = 1
}

/**
 * Keep the first rule intraprocedural. Taint, rather than value flow, follows
 * size arithmetic such as bitmap rounding and shifting. IR flow respects
 * overwritten definitions; a nearby unrelated allocation is insufficient.
 */
predicate implicitAllocationNarrowing(ImplicitSizeNarrowing conversion, Expr size) {
  (
    exists(FunctionCall call, int index |
      allocationSize(call, index) and size = call.getArgument(index)
    )
    or
    size = any(NewArrayExpr array).getExtent()
  ) and
  TaintTracking::localTaint(DataFlow::convertedExprNode(conversion),
    DataFlow::convertedExprNode(size.getFullyConverted()))
}
