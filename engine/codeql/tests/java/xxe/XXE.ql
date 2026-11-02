import java
import XXEDocumentBuilderFlow

private predicate unsafeParse(Method method) {
  exists(DocumentBuilderFactoryCreation factory, DocumentParseCall parse |
    unsafeDocumentParse(factory, parse) and parse.getEnclosingCallable() = method
  )
}

from Method method, boolean unsafe
where
  method.getDeclaringType().hasQualifiedName("fixtures", "XxeCases") and
  (method.getName().matches("unsafe_%") or method.getName().matches("safe_%")) and
  (
    unsafe = true and unsafeParse(method)
    or
    unsafe = false and not unsafeParse(method)
  )
select method.getName(), unsafe
