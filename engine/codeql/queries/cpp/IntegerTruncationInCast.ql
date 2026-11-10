/**
 * @name Potential integer truncation in an explicit cast
 * @description An explicit cast converts a wider integral value to a narrower
 *              destination without sufficient static evidence that the value
 *              fits. Allocation or buffer-size use adds risk context when
 *              observed; it is not required for a finding.
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
