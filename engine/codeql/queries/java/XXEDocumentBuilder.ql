/**
 * @name XML External Entity (XXE) injection via DocumentBuilder
 * @description A DocumentBuilder parses XML input without disabling
 *              external entity resolution.  An attacker can use a
 *              crafted DTD to read local files (file:///etc/passwd),
 *              perform SSRF, or cause denial of service (billion
 *              laughs).
 * @kind problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @id raptor/java/xxe-document-builder
 * @tags security
 *       external/cwe/cwe-611
 */

import java

/**
 * A call to `DocumentBuilderFactory.newInstance()` that is NOT
 * subsequently hardened with the disallow-doctype-decl feature.
 */
class UnsafeDocumentBuilderFactory extends MethodCall {
  UnsafeDocumentBuilderFactory() {
    this.getMethod().hasName("newInstance") and
    this.getMethod().getDeclaringType().hasQualifiedName("javax.xml.parsers", "DocumentBuilderFactory")
  }
}

/**
 * A call to `factory.setFeature(DISALLOW_DTD, true)` that hardens
 * the factory against XXE.
 */
class SafeFeatureCall extends MethodCall {
  SafeFeatureCall() {
    this.getMethod().hasName("setFeature") and
    this.getMethod().getDeclaringType().hasQualifiedName("javax.xml.parsers", "DocumentBuilderFactory") and
    (
      // Disallow DOCTYPE declarations entirely (strongest defence)
      this.getArgument(0).(StringLiteral).getValue() =
        "http://apache.org/xml/features/disallow-doctype-decl" and
      this.getArgument(1).(BooleanLiteral).getBooleanValue() = true
      or
      // Disable external general entities
      this.getArgument(0).(StringLiteral).getValue() =
        "http://xml.org/sax/features/external-general-entities" and
      this.getArgument(1).(BooleanLiteral).getBooleanValue() = false
    )
  }
}

/**
 * Holds when `factory` (a variable holding the DocumentBuilderFactory)
 * has been hardened with a safe setFeature call.
 */
predicate isFactoryHardened(Variable factory) {
  exists(SafeFeatureCall sfc |
    sfc.getQualifier().(VarAccess).getVariable() = factory
  )
}

/**
 * A call to `factory.newDocumentBuilder().parse(...)` where the
 * factory has not been hardened.
 */
from
  UnsafeDocumentBuilderFactory factoryCreation, Variable factoryVar,
  MethodCall newDocBuilder, MethodCall parseCall
where
  factoryVar.getAnAssignedValue() = factoryCreation and
  newDocBuilder.getQualifier().(VarAccess).getVariable() = factoryVar and
  newDocBuilder.getMethod().hasName("newDocumentBuilder") and
  (
    // Chained: factory.newDocumentBuilder().parse(input)
    parseCall.getQualifier() = newDocBuilder and
    parseCall.getMethod().hasName("parse")
    or
    // Stored: DocumentBuilder db = factory.newDocumentBuilder(); db.parse(input)
    exists(Variable dbVar |
      dbVar.getAnAssignedValue() = newDocBuilder and
      parseCall.getQualifier().(VarAccess).getVariable() = dbVar and
      parseCall.getMethod().hasName("parse")
    )
  ) and
  not isFactoryHardened(factoryVar)
select parseCall,
  "XML parser created from $@ without disabling external entities — " +
    "attacker-controlled XML can read local files or perform SSRF (CWE-611).",
  factoryCreation, "this DocumentBuilderFactory"
