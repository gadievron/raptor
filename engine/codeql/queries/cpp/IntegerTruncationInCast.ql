/**
 * @name Integer truncation in explicit cast flowing to allocation or buffer operation
 * @description An explicit cast from a wider integer type (long, long long,
 *              size_t, uint64_t, ssize_t) to a narrower type (int, short,
 *              uint16_t, uint32_t) without a prior range check.  When the
 *              truncated value reaches an allocation (malloc, calloc, new[])
 *              or a buffer-size parameter (memcpy, read, recv), the result
 *              can be a heap overflow from an undersized allocation.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision medium
 * @id raptor/cpp/integer-truncation-in-cast
 * @tags security
 *       external/cwe/cwe-681
 *       external/cwe/cwe-190
 *       external/cwe/cwe-122
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
import semmle.code.cpp.controlflow.IRGuards
import semmle.code.cpp.security.FlowSources
import IntTruncFlow::PathGraph

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
    isNarrowingPair(cast.getExpr().getType(), cast.getType())
  }

  /** Gets the underlying cast expression. */
  Cast getCast() { result = cast }
}

/*
 * ---- Barriers: range checks before the cast ----
 */

/**
 * Holds if `node` is guarded by a relational comparison that
 * upper-bounds the value (e.g. `if (len > INT_MAX) return;`).
 */
predicate hasRangeGuard(DataFlow::Node node) {
  exists(Variable v, RelationalOperation cmp, VariableAccess va |
    node.asExpr().(VariableAccess).getTarget() = v and
    cmp.getAnOperand() = va and
    va.getTarget() = v and
    // The comparison is against a non-zero constant (a real bound).
    cmp.getAnOperand().getValue().toInt() > 0 and
    // And it dominates the use.
    cmp.getEnclosingStmt().getParentStmt*() = node.asExpr().getEnclosingStmt().getParentStmt*()
  )
}

/*
 * ---- Configuration ----
 */

module IntTruncConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof WideReturnSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof NarrowingCastSink
  }

  predicate isBarrier(DataFlow::Node node) {
    // If the value has been range-checked, suppress.
    hasRangeGuard(node)
    or
    // If SimpleRangeAnalysis proves the value fits, suppress.
    exists(Expr e |
      e = node.asExpr() and
      e.getType().getUnspecifiedType() instanceof IntegralType and
      upperBound(e) <= 2147483647.0 and // INT_MAX
      lowerBound(e) >= -2147483648.0 // INT_MIN
    )
  }
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
    DataFlow::localExprFlow(castExpr, fc.getArgument(argIdx))
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
    DataFlow::localExprFlow(castExpr, nae.getExtent())
  )
}

from
  IntTruncFlow::PathNode source, IntTruncFlow::PathNode sink, NarrowingCastSink sinkNode,
  string extra
where
  IntTruncFlow::flowPath(source, sink) and
  sinkNode = sink.getNode() and
  (
    if flowsToMemoryOperation(sinkNode.getCast())
    then
      extra =
        " The truncated value flows to a memory allocation or buffer operation, " +
          "risking a heap overflow from an undersized buffer."
    else extra = ""
  )
select sinkNode.getCast(), source, sink,
  "Value from $@ (wide integer) is explicitly cast to a narrower type (" +
    sinkNode.getCast().getType().getName() + "), risking truncation." + extra, source.getNode(),
  "this wide-integer source"
