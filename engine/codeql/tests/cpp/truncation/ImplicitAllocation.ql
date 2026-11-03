import ImplicitAllocationNarrowingFlow

from Function function, boolean alerts
where
  function.hasDefinition() and
  function.getName().matches("allocation_%") and
  (
    alerts = true and
    exists(ImplicitSizeNarrowing conversion, Expr size |
      implicitAllocationNarrowing(conversion, size) and
      conversion.getEnclosingFunction() = function
    )
    or
    alerts = false and
    not exists(ImplicitSizeNarrowing conversion, Expr size |
      implicitAllocationNarrowing(conversion, size) and
      conversion.getEnclosingFunction() = function
    )
  )
select function.getName(), alerts
