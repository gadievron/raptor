// free_nonbase_ptr.cocci — Find suspicious pointer arithmetic at deallocation.
//
// Arithmetic does not establish the allocation base: an interior pointer can
// legitimately be adjusted back to its owner. These are detection candidates,
// and need allocation-origin and effective-offset evidence for CWE-761.
// Postfix increment passes the original value to the call; prefix increment
// passes the advanced value. Literal zero offsets preserve the pointer.
// @role: detection

@free_plus_offset@
expression P, E;
position p;
@@

(
// Recognized offsetof() recovery is excluded from this syntactic rule.
// Arbitrary pointer origins still need independent review.
  \(free\|kfree\|vfree\|kvfree\|kfree_sensitive\|kzfree\)(P - offsetof(...))
|
  \(free\|kfree\|vfree\|kvfree\|kfree_sensitive\|kzfree\)(P + 0)
|
  \(free\|kfree\|vfree\|kvfree\|kfree_sensitive\|kzfree\)(P - 0)
|
* \(free\|kfree\|vfree\|kvfree\|kfree_sensitive\|kzfree\)(P + E)@p
|
* \(free\|kfree\|vfree\|kvfree\|kfree_sensitive\|kzfree\)(P - E)@p
)

@script:python free_plus_report depends on free_plus_offset@
p << free_plus_offset.p;
offset << free_plus_offset.E;
@@
import json
import re

_free_nonbase_zero_literal = re.compile(r"\A(?:0[xX]0+|0[bB]0+|0+)[uUlL]*\Z")
_free_nonbase_cast_words = frozenset((
    "unsigned", "signed", "short", "long", "int", "char", "_Bool", "bool"
))

def free_nonbase_zero_offset(expression):
    # Only a bounded literal with parentheses, signs and builtin integer casts.
    # No evaluation of expressions, identifiers, calls or typedef conversions.
    text = str(expression)
    if len(text) > 256:
        return False
    text = re.sub(r"/\*.*?\*/|//[^\n]*", " ", text, flags=re.S)
    for token in ("(", ")", "+", "-"):
        text = text.replace(token, " " if token in ("(", ")") else " " + token + " ")
    tokens = text.split()
    return bool(tokens and _free_nonbase_zero_literal.match(tokens[-1]) and all(
        token in _free_nonbase_cast_words or token in ("+", "-")
        for token in tokens[:-1]
    ))

if not free_nonbase_zero_offset(offset):
    msg = {
      "rule":  "free_nonbase_ptr",
      "file":  p[0].file,
      "line":  int(p[0].line),
      "col":   int(p[0].column),
      "message":   "Pointer arithmetic reaches deallocation; verify the allocation base and effective offset (CWE-761 candidate)"
    }
    print("COCCIRESULT:" + json.dumps(msg))

@free_preinc@
expression P;
position p;
@@

* \(free\|kfree\|vfree\|kvfree\|kfree_sensitive\|kzfree\)(++P)@p

@script:python free_preinc_report depends on free_preinc@
p << free_preinc.p;
@@
import json
msg = {
  "rule":  "free_nonbase_ptr_inc",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "Prefix increment changes the deallocation argument; verify the allocation base and effective offset (CWE-761 candidate)"
}
print("COCCIRESULT:" + json.dumps(msg))
