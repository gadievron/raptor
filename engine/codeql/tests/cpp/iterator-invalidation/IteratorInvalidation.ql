import cpp
import IteratorInvalidationFlow

private predicate reported(Function function) {
  exists(ContainerMutation mutation, IteratorUse use |
    invalidIteratorUse(mutation, use) and use.getEnclosingFunction() = function
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
