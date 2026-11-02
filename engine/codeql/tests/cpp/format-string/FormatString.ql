import cpp
import FormatStringFlow

private predicate reported(Function function) {
  exists(DataFlow::Node source, PrintfFormatSink sink |
    FmtStringFlow::flow(source, sink) and sink.getCall().getEnclosingFunction() = function
  )
}

from Function function, boolean reported
where
  function.hasDefinition() and
  (
    function.getName().matches("unsafe_%") or
    function.getName().matches("safe_%") or
    function.getName() = ["main", "use_format"]
  ) and
  (
    reported = true and reported(function)
    or
    reported = false and not reported(function)
  )
select function.getName(), reported
