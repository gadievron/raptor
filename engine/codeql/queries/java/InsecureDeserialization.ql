/**
 * @name Insecure deserialization via ObjectInputStream
 * @description Creating an ObjectInputStream from untrusted input and
 *              calling readObject() without a verified restrictive type filter allows
 *              arbitrary code execution through gadget chains.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id raptor/java/insecure-deserialization
 * @tags security
 *       external/cwe/cwe-502
 */

import InsecureDeserializationFlow
import DeserFlow::PathGraph

from
  DeserFlow::PathNode source, DeserFlow::PathNode sink, ObjectInputStreamCreation creation,
  ReadObjectCall readCall
where
  DeserFlow::flowPath(source, sink) and
  sink.getNode().asExpr() = creation.getArgument(0) and
  isUnfilteredRead(creation, readCall)
select readCall, source, sink,
  "Untrusted data from $@ is deserialized via ObjectInputStream." + readCall.getMethod().getName() +
    "() without a verified restrictive type filter " +
    "— potential gadget-chain execution (CWE-502).", source.getNode(), "remote source"
