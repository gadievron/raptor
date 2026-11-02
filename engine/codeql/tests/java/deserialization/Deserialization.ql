import java
import InsecureDeserializationFlow

private predicate unsafeRead(Method method) {
  exists(
    DataFlow::Node source, DataFlow::Node sink, ObjectInputStreamCreation creation,
    ReadObjectCall readCall
  |
    DeserFlow::flow(source, sink) and
    sink.asExpr() = creation.getArgument(0) and
    isUnfilteredRead(creation, readCall) and
    readCall.getEnclosingCallable() = method
  )
}

from Method method, boolean unsafe
where
  method.getDeclaringType().hasQualifiedName("fixtures", "DeserCases") and
  (method.getName().matches("unsafe_%") or method.getName().matches("safe_%")) and
  (
    unsafe = true and unsafeRead(method)
    or
    unsafe = false and not unsafeRead(method)
  )
select method.getName(), unsafe
