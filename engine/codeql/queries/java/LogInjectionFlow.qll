/** Logging sinks with explicit CR/LF neutralization contracts. */
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.LogInjection

/** A constant string or char, decoded by the Java extractor. */
private string constantText(Expr expr) {
  result = expr.(CompileTimeConstantExpr).getStringValue()
  or
  exists(int code |
    expr.getType().hasName("char") and
    code = expr.(CompileTimeConstantExpr).getIntValue()
  |
    if code = 10 then result = "\n"
    else if code = 13 then result = "\r"
    else result = "_" // Other chars are equivalent for this CR/LF contract.
  )
}

/** An actual java.lang.String operation, rather than a same-named method. */
private predicate stringCall(MethodCall call, string name) {
  call.getMethod().getDeclaringType() instanceof TypeString and
  call.getMethod().hasName(name) and
  call.getNumArgument() = 2
}

/** A replacement must remove its target without reintroducing it. */
private predicate replacesControl(MethodCall call, string control) {
  stringCall(call, "replace") and
  constantText(call.getArgument(0)) = control and
  exists(string replacement | replacement = constantText(call.getArgument(1)) |
    not replacement.matches("%" + control + "%")
  )
}

/** Only adjacent operations may establish the combined value contract. */
private predicate stripsBoth(MethodCall outer) {
  exists(MethodCall inner, string first, string second |
    inner = outer.getQualifier() and
    (first = "\n" and second = "\r" or first = "\r" and second = "\n") and
    replacesControl(inner, first) and
    replacesControl(outer, second) and
    not constantText(outer.getArgument(1)).matches("%" + first + "%")
  )
}

/** Exact regexes that replace every occurrence of either control. */
private predicate bothControlsRegex(string regex) {
  exists(string first, string second |
    (first = ["\r", "\\r"] and second = ["\n", "\\n"] or
     first = ["\n", "\\n"] and second = ["\r", "\\r"])
  |
    regex = "[" + first + second + "]" + ["", "+"]
    or
    regex = first + "|" + second
  )
  or
  regex = "\\R"
}

/** Regex replacement syntax must not copy the match back into the result. */
private predicate stripsBothRegex(MethodCall call) {
  stringCall(call, "replaceAll") and
  bothControlsRegex(constantText(call.getArgument(0))) and
  exists(string replacement | replacement = constantText(call.getArgument(1)) |
    not replacement.matches(["%\r%", "%\n%", "%$%"])
  )
}

/** SLF4J always uses {} placeholders; constants permit argument-use proofs. */
private predicate slf4jFormat(MethodCall call, int messageIndex, string format) {
  call.getMethod().getDeclaringType().getAnAncestor().hasQualifiedName("org.slf4j", "Logger") and
  (if call.getMethod().getParameter(0).getType().(RefType).hasQualifiedName("org.slf4j", "Marker")
   then messageIndex = 1 else messageIndex = 0) and
  format = constantText(call.getArgument(messageIndex))
}

/** SLF4J consumes {} unless singly escaped; two backslashes reactivate it. */
bindingset[format]
private predicate activePlaceholder(string format, int offset) {
  offset in [0 .. format.length() - 2] and
  format.charAt(offset) = "{" and format.charAt(offset + 1) = "}" and
  (offset = 0 or format.charAt(offset - 1) != "\\" or
   offset >= 2 and format.charAt(offset - 2) = "\\")
}

bindingset[format]
private int placeholderCount(string format) {
  result = count(int offset | activePlaceholder(format, offset))
}

/** Replace aggregate varargs sinks only when each used element is identifiable. */
private predicate expandedSlf4jArray(DataFlow::Node sink, MethodCall call) {
  call.getMethod().isVarargs() and
  exists(int index, string format | slf4jFormat(call, index, format) |
    sink.(DataFlow::ImplicitVarargsArray).getCall() = call
    or
    call.getNumArgument() = index + 2 and
    sink.asExpr() = call.getArgument(index + 1).(ArrayCreationExpr)
  )
}

/** Known unused formatting values must not create findings. */
private predicate unusedArgument(DataFlow::Node sink) {
  exists(MethodCall call, int index, int position, string format |
    slf4jFormat(call, index, format) and
    sink.asExpr() = call.getArgument(position) and
    position > index and not call.getArgument(position).getType() instanceof Array and
    position - index > placeholderCount(format)
  )
  or
  // JUL's plain literal messages do not interpolate their parameter array.
  exists(MethodCall call, string format |
    call.getMethod().getDeclaringType().getAnAncestor().hasQualifiedName("java.util.logging", "Logger") and
    call.getMethod().hasName("log") and
    format = constantText(call.getArgument(1)) and not format.matches("%{%") and
    (sink.asExpr() = call.getArgument(2) or
     sink.(DataFlow::ImplicitVarargsArray).getCall() = call)
  )
}

/** Per-element sinks retain used varargs without tainting unused elements. */
private predicate usedSlf4jElement(DataFlow::Node sink) {
  exists(MethodCall call, int index, string format, int element |
    slf4jFormat(call, index, format) and call.getMethod().isVarargs() and
    element in [0 .. placeholderCount(format) - 1]
  |
    if call.getNumArgument() = index + 2 and
       call.getArgument(index + 1).getType() instanceof Array
    then sink.asExpr() = call.getArgument(index + 1).(ArrayCreationExpr).getInit().getInit(element)
    else sink.asExpr() = call.getArgument(index + 1 + element)
  )
}

/**
 * Model argument positions using the standard logging API models: JUL levels,
 * SLF4J/Log4j markers and formatting arguments, varargs and Commons Logging.
 * The configured output handler/encoder still determines exploitability.
 */
module LogInjConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof LogInjectionSink and
    not expandedSlf4jArray(sink, _) and not unusedArgument(sink)
    or usedSlf4jElement(sink)
  }

  predicate isBarrier(DataFlow::Node node) {
    // Numeric/boolean rendering cannot emit CR/LF. Character rendering can.
    node.getType() instanceof PrimitiveType and not node.getType().hasName("char")
    or node.getType() instanceof BoxedType and
       not node.getType().(RefType).hasQualifiedName("java.lang", "Character")
    or exists(MethodCall call |
      node.asExpr() = call and
      (stripsBoth(call) or stripsBothRegex(call))
    )
  }
}

module LogInjFlow = TaintTracking::Global<LogInjConfig>;
