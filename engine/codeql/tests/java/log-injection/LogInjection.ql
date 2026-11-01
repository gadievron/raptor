import java
import LogInjectionFlow

private predicate reachesLog(Method method) {
  exists(DataFlow::Node source, DataFlow::Node sink |
    LogInjFlow::flow(source, sink) and
    sink.getEnclosingCallable() = method
  )
}

from Method method, boolean reaches
where method.getDeclaringType().hasQualifiedName("fixtures", "LogCases") and
  (method.getName().matches("unsafe_%") or method.getName().matches("safe_%")) and
  (reaches = true and reachesLog(method) or reaches = false and not reachesLog(method))
select method.getName(), reaches
