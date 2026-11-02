/** Factory state at DocumentBuilder creation and local parser object flow. */

import java
import semmle.code.java.controlflow.Dominance
import semmle.code.java.dataflow.DataFlow

class DocumentBuilderFactoryCreation extends MethodCall {
  DocumentBuilderFactoryCreation() {
    this.getMethod().hasName("newInstance") and
    this.getMethod()
        .getDeclaringType()
        .hasQualifiedName("javax.xml.parsers", "DocumentBuilderFactory")
  }
}

class DocumentBuilderCreation extends MethodCall {
  DocumentBuilderCreation() {
    this.getMethod().hasName("newDocumentBuilder") and
    this.getMethod()
        .getDeclaringType()
        .hasQualifiedName("javax.xml.parsers", "DocumentBuilderFactory")
  }
}

class DocumentParseCall extends MethodCall {
  DocumentParseCall() {
    this.getMethod().hasName("parse") and
    this.getMethod().getDeclaringType().hasQualifiedName("javax.xml.parsers", "DocumentBuilder")
  }
}

/** Only single-valued local aliases establish definite receiver identity. */
private Expr stableValue(Expr use) {
  result = use
  or
  exists(LocalVariableDecl variable, Expr value |
    use.(VarAccess).getVariable() = variable and
    value = variable.getAnAssignedValue() and
    not exists(Expr other | other = variable.getAnAssignedValue() and other != value) and
    result = stableValue(value)
  )
}

private string externalDtdProperty() {
  result = "http://javax.xml.XMLConstants/property/accessExternalDTD"
}

private string propertyName(Expr expression) {
  result = stableValue(expression).(CompileTimeConstantExpr).getStringValue()
  or
  exists(Field field |
    field = stableValue(expression).(FieldRead).getField() and
    field.getDeclaringType().hasQualifiedName("javax.xml", "XMLConstants") and
    field.hasName("ACCESS_EXTERNAL_DTD") and
    result = externalDtdProperty()
  )
}

/** An unknown property name might overwrite any tracked setting of its kind. */
private predicate mayWriteProperty(MethodCall call, string property) {
  property =
    [
      "http://apache.org/xml/features/disallow-doctype-decl",
      "http://xml.org/sax/features/external-general-entities",
      "http://xml.org/sax/features/external-parameter-entities",
      "http://apache.org/xml/features/nonvalidating/load-external-dtd", externalDtdProperty(),
      "validation"
    ] and
  call.getMethod()
      .getDeclaringType()
      .hasQualifiedName("javax.xml.parsers", "DocumentBuilderFactory") and
  (
    property = "validation" and call.getMethod().hasName("setValidating")
    or
    property = externalDtdProperty() and call.getMethod().hasName("setAttribute")
    or
    property != externalDtdProperty() and
    property != "validation" and
    call.getMethod().hasName("setFeature")
  ) and
  (
    property = "validation" or
    propertyName(call.getArgument(0)) = property or
    not exists(propertyName(call.getArgument(0)))
  )
}

private predicate writesProtection(MethodCall call, string property) {
  mayWriteProperty(call, property) and
  (
    property = "validation" and
    stableValue(call.getArgument(0)).(CompileTimeConstantExpr).getBooleanValue() = false
    or
    propertyName(call.getArgument(0)) = property and
    (
      property = externalDtdProperty() and
      stableValue(call.getArgument(1)).(CompileTimeConstantExpr).getStringValue() = ""
      or
      property = "http://apache.org/xml/features/disallow-doctype-decl" and
      stableValue(call.getArgument(1)).(CompileTimeConstantExpr).getBooleanValue() = true
      or
      property =
        [
          "http://xml.org/sax/features/external-general-entities",
          "http://xml.org/sax/features/external-parameter-entities",
          "http://apache.org/xml/features/nonvalidating/load-external-dtd"
        ] and
      stableValue(call.getArgument(1)).(CompileTimeConstantExpr).getBooleanValue() = false
    )
  )
}

/**
 * A successful protective write must dominate builder creation. No possibly
 * weakening write may follow it on a path to this particular creation.
 */
private predicate protectedAtCreation(
  DocumentBuilderFactoryCreation factory, DocumentBuilderCreation builder, string property
) {
  stableValue(builder.getQualifier()) = factory and
  exists(MethodCall setting |
    stableValue(setting.getQualifier()) = factory and
    writesProtection(setting, property) and
    strictlyDominates(setting.getControlFlowNode(), builder.getControlFlowNode()) and
    not setting.getControlFlowNode().getAnExceptionSuccessor().getASuccessor*() =
      builder.getControlFlowNode() and
    not exists(MethodCall weakening |
      mayWriteProperty(weakening, property) and
      not writesProtection(weakening, property) and
      DataFlow::localFlow(DataFlow::exprNode(factory), DataFlow::exprNode(weakening.getQualifier())) and
      setting.getControlFlowNode().getASuccessor*() = weakening.getControlFlowNode() and
      weakening.getControlFlowNode().getASuccessor*() = builder.getControlFlowNode()
    )
  )
}

/** Validation can force external DTD loading despite the nonvalidating flag. */
private predicate validationMayBeEnabled(
  DocumentBuilderFactoryCreation factory, DocumentBuilderCreation builder
) {
  exists(MethodCall setting |
    mayWriteProperty(setting, "validation") and
    not writesProtection(setting, "validation") and
    DataFlow::localFlow(DataFlow::exprNode(factory), DataFlow::exprNode(setting.getQualifier())) and
    setting.getControlFlowNode().getASuccessor*() = builder.getControlFlowNode()
  ) and
  not protectedAtCreation(factory, builder, "validation")
}

private predicate hardenedBeforeCreation(
  DocumentBuilderFactoryCreation factory, DocumentBuilderCreation builder
) {
  protectedAtCreation(factory, builder, "http://apache.org/xml/features/disallow-doctype-decl")
  or
  protectedAtCreation(factory, builder, externalDtdProperty())
  or
  protectedAtCreation(factory, builder, "http://xml.org/sax/features/external-general-entities") and
  protectedAtCreation(factory, builder, "http://xml.org/sax/features/external-parameter-entities") and
  protectedAtCreation(factory, builder,
    "http://apache.org/xml/features/nonvalidating/load-external-dtd") and
  not validationMayBeEnabled(factory, builder)
}

predicate unsafeDocumentParse(DocumentBuilderFactoryCreation factory, DocumentParseCall parse) {
  exists(DocumentBuilderCreation builder |
    DataFlow::localFlow(DataFlow::exprNode(factory), DataFlow::exprNode(builder.getQualifier())) and
    DataFlow::localFlow(DataFlow::exprNode(builder), DataFlow::exprNode(parse.getQualifier())) and
    not hardenedBeforeCreation(factory, builder)
  )
}
