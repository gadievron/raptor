/** Shared narrowing-cast flow and destination-range proof. */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
import semmle.code.cpp.rangeanalysis.RangeAnalysisUtils

/*
 * ---- Width helpers ----
 */

/** Gets the bit width of an integral type, resolving typedefs. */
int getIntegralBitWidth(Type t) {
  result = t.getUnspecifiedType().getSize() * 8 and
  t.getUnspecifiedType() instanceof IntegralType
}

/** Holds when `wider` has strictly more bits than `narrower`. */
predicate isNarrowingPair(Type wider, Type narrower) {
  getIntegralBitWidth(wider) > getIntegralBitWidth(narrower)
}

/** A "wide" return type that can exceed 32-bit range. */
predicate isWideType(Type t) {
  getIntegralBitWidth(t) >= 64
  or
  // size_t / ssize_t on 64-bit are 64 bits, but on 32-bit they are 32.
  // Include them unconditionally since we are hunting the pattern.
  t.getUnspecifiedType().getName() = ["size_t", "ssize_t", "ptrdiff_t"]
}

/*
 * ---- Sources: function calls that return wide integers ----
 */

/** A call to a function returning a wide integer type. */
class WideReturnSource extends DataFlow::Node {
  WideReturnSource() {
    exists(FunctionCall fc |
      this.asExpr() = fc and
      isWideType(fc.getTarget().getType().getUnspecifiedType())
    )
  }
}

/*
 * ---- Sinks: explicit casts that narrow the value ----
 *
 * We look for C-style casts, static_cast, and functional casts
 * where the source type is strictly wider than the target type.
 */

/** An explicit narrowing cast expression. */
class NarrowingCastSink extends DataFlow::Node {
  Cast cast;

  NarrowingCastSink() {
    // The sink is the cast OPERAND (what flows in), not the cast result.
    // IR-based TaintTracking propagates taint to the operand node;
    // targeting the cast result itself means source-to-sink never connects.
    this.asExpr() = cast.getExpr() and
    not cast.isImplicit() and
    isNarrowingPair(cast.getExpr().getType(), cast.getType()) and
    not cast.getType().getUnspecifiedType() instanceof BoolType and
    not fitsDestination(cast)
  }

  /** Gets the underlying cast expression. */
  Cast getCast() { result = cast }
}

/**
 * Prove the value BEFORE this particular cast fits its destination type.
 * getFullyConverted() would include the narrowing cast itself and could
 * turn an unsafe conversion into its own proof of safety.
 *
 * Range bounds use floating point. At wide integer endpoints require
 * strict interior bounds, avoiding rounded 64-bit maxima/minima hiding
 * an out-of-range 128-bit source. Exact endpoint proofs remain conservative.
 */
predicate fitsDestination(Cast cast) {
  exists(IntegralType destination, float lower, float upper, float minimum, float maximum |
    destination = cast.getType().getUnspecifiedType() and
    lower = lowerBound(cast.getExpr()) and
    upper = upperBound(cast.getExpr()) and
    minimum = typeLowerBound(destination) and
    maximum = typeUpperBound(destination) and
    (
      maximum < 9007199254740992.0 and lower >= minimum and upper <= maximum
      or
      maximum >= 9007199254740992.0 and
      upper < maximum and
      (
        destination.isUnsigned() and lower >= minimum
        or
        destination.isSigned() and lower > minimum
      )
    )
  )
}

/*
 * ---- Configuration ----
 */

module IntTruncConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof WideReturnSource }

  predicate isSink(DataFlow::Node sink) { sink instanceof NarrowingCastSink }
}

module IntTruncFlow = TaintTracking::Global<IntTruncConfig>;

/*
 * ---- Severity escalation: does the truncated value flow to a
 *      memory operation? ----
 */

/**
 * Holds if `castExpr` is the source of a value that eventually reaches
 * an allocation or buffer-length parameter.
 */
predicate flowsToMemoryOperation(Cast castExpr) {
  exists(FunctionCall fc, int argIdx |
    // The cast result (or a variable it was assigned to) reaches the call.
    DataFlow::localFlow(DataFlow::convertedExprNode(castExpr),
      DataFlow::convertedExprNode(fc.getArgument(argIdx).getFullyConverted()))
  |
    // Allocation functions: malloc(size), calloc(n, size), realloc(p, size)
    fc.getTarget().getName() = "malloc" and argIdx = 0
    or
    fc.getTarget().getName() = "calloc" and argIdx = [0, 1]
    or
    fc.getTarget().getName() = "realloc" and argIdx = 1
    or
    fc.getTarget().getName() = "kmalloc" and argIdx = 0
    or
    // Buffer operations: memcpy(d, s, n), memmove(d, s, n)
    fc.getTarget().getName() = ["memcpy", "memmove", "memset"] and argIdx = 2
    or
    // I/O operations: read(fd, buf, count), recv(fd, buf, len, flags)
    fc.getTarget().getName() = "read" and argIdx = 2
    or
    fc.getTarget().getName() = "recv" and argIdx = 2
  )
  or
  // operator new[](size)
  exists(NewArrayExpr nae |
    DataFlow::localFlow(DataFlow::convertedExprNode(castExpr),
      DataFlow::convertedExprNode(nae.getExtent().getFullyConverted()))
  )
}
