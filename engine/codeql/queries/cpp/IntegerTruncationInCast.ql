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

import IntegerTruncationFlow
import IntTruncFlow::PathGraph

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
