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
 * A `factory.setFeature(feature, value)` call setting the named XXE
 * feature to the given boolean value.
 */
predicate setsFeature(MethodCall mc, Variable factory, string feature, boolean value) {
  mc.getMethod().hasName("setFeature") and
  mc.getMethod().getDeclaringType().hasQualifiedName("javax.xml.parsers", "DocumentBuilderFactory") and
  mc.getQualifier().(VarAccess).getVariable() = factory and
  mc.getArgument(0).(StringLiteral).getValue() = feature and
  mc.getArgument(1).(BooleanLiteral).getBooleanValue() = value
}

/**
 * Holds when `factory` (a variable holding the DocumentBuilderFactory)
 * has been hardened against XXE. Disabling external-general-entities
 * alone is NOT sufficient — parameter entities still allow blind XXE /
 * SSRF via a crafted DTD. The factory must either disallow DOCTYPE
 * declarations entirely, or disable BOTH the general and parameter
 * external-entity features.
 */
predicate isFactoryHardened(Variable factory) {
  // Disallow DOCTYPE declarations entirely (strongest defence)
  setsFeature(_, factory, "http://apache.org/xml/features/disallow-doctype-decl", true)
  or
  // Both external entity classes disabled
  setsFeature(_, factory, "http://xml.org/sax/features/external-general-entities", false) and
  setsFeature(_, factory, "http://xml.org/sax/features/external-parameter-entities", false)
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
