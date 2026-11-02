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

import XXEDocumentBuilderFlow

from DocumentBuilderFactoryCreation factory, DocumentParseCall parse
where unsafeDocumentParse(factory, parse)
select parse,
  "XML parser created from $@ without verified external-entity protection at builder creation — " +
    "attacker-controlled XML may read local files or perform SSRF (CWE-611).", factory,
  "this DocumentBuilderFactory"
