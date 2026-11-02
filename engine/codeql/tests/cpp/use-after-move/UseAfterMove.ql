import cpp
import UseAfterMoveFlow

private predicate reported(Function function) {
  exists(ConsumingMove move, PostMoveUse use |
    useAfterMove(move, use) and use.getEnclosingFunction() = function
  )
}

from Function function, boolean unsafe
where
  function.hasDefinition() and
  (function.getName().matches("unsafe_%") or function.getName().matches("safe_%")) and
  (
    unsafe = true and reported(function)
    or
    unsafe = false and not reported(function)
  )
select function.getName(), unsafe
