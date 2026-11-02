import cpp
import IntegerTruncationFlow

private predicate unsafeCast(Function function) {
  exists(DataFlow::Node source, NarrowingCastSink sink |
    IntTruncFlow::flow(source, sink) and sink.getCast().getEnclosingFunction() = function
  )
}

private predicate memoryRisk(Function function) {
  exists(DataFlow::Node source, NarrowingCastSink sink |
    IntTruncFlow::flow(source, sink) and
    sink.getCast().getEnclosingFunction() = function and
    flowsToMemoryOperation(sink.getCast())
  )
}

from Function function, boolean unsafe, boolean memory
where
  function.hasDefinition() and
  (function.getName().matches("unsafe_%") or function.getName().matches("safe_%")) and
  (
    unsafe = true and unsafeCast(function)
    or
    unsafe = false and not unsafeCast(function)
  ) and
  (
    memory = true and memoryRisk(function)
    or
    memory = false and not memoryRisk(function)
  )
select function.getName(), unsafe, memory
