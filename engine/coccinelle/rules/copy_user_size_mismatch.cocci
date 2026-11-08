// copy_user_size_mismatch.cocci — Detect copy_to_user/copy_from_user
// with suspicious size arguments that require target-layout review.
//
// Common patterns:
//  - copy_to_user(dst, &local, sizeof(*dst)) — compare pointee/object extents
//  - copy_from_user(&local, src, sizeof(src)) — pointer size may be unintended
//
// CWE-805: Buffer Access with Incorrect Length Value
// @role: detection
// raptor: confirm-only

// Different type spellings do not establish different byte sizes. Keep
// unresolved layouts as candidates, while excluding equivalent scalar
// signedness and qualifiers. Never use the scanner host's ABI as evidence
// about the target's object sizes.
// C scalar/qualifier storage rules: ISO C 6.2.5, not an ABI size table.
// https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf
@copy_to_sizeof_star_dst@
type TD, TL;
TD *USR_DST;
TL LOCAL;
position p;
@@

* copy_to_user(USR_DST, &LOCAL, sizeof(*USR_DST)@p)

@script:python copy_to_report depends on copy_to_sizeof_star_dst@
p << copy_to_sizeof_star_dst.p;
TD << copy_to_sizeof_star_dst.TD;
TL << copy_to_sizeof_star_dst.TL;
LOCAL << copy_to_sizeof_star_dst.LOCAL;
@@
import json
def usercopy_size_spelling(value):
  tokens = [token for token in str(value).split()
            if token not in ("const", "volatile", "restrict")]
  if tokens and set(tokens) <= {"char", "short", "int", "long", "signed", "unsigned"}:
    return tuple(token for token in tokens if token not in ("signed", "unsigned", "int")) or ("int",)
  return tuple(tokens)

if usercopy_size_spelling(TD) != usercopy_size_spelling(TL):
  msg = {
    "rule":  "copy_user_size_mismatch",
    "file":  p[0].file,
    "line":  int(p[0].line),
    "col":   int(p[0].column),
    "message":   "Candidate: copy_to_user sizes source '%s' (%s) using the userspace pointee type %s; review target sizes and the intended copy extent (CWE-805)" % (LOCAL, TL, TD)
  }
  print("COCCIRESULT:" + json.dumps(msg))

// Same-typed pointer objects have the same size; this is not a size error.
@copy_from_pointer_object@
type T;
T *LOCAL;
T *USR_SRC;
position pointer_copy;
@@
copy_from_user(&LOCAL, USR_SRC, sizeof(USR_SRC)@pointer_copy)

@copy_from_sizeof_src@
type TS, TL;
TS *USR_SRC;
TL LOCAL;
position p != copy_from_pointer_object.pointer_copy;
@@

* copy_from_user(&LOCAL, USR_SRC, sizeof(USR_SRC)@p)

@script:python copy_from_report depends on copy_from_sizeof_src@
p << copy_from_sizeof_src.p;
@@
import json
msg = {
  "rule":  "copy_from_user_sizeof_ptr",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "Candidate: copy_from_user uses sizeof(source pointer) for the destination object; review target sizes and whether a partial copy is intended (CWE-805)"
}
print("COCCIRESULT:" + json.dumps(msg))

// A block-local array can shadow an array-spelled parameter. Its sizeof
// still measures the actual array rather than the adjusted parameter.
@copy_from_local_array_size@
type T;
identifier SRC;
expression LOCAL;
position local_array_copy;
@@
{
... when any
T SRC[...];
... when any
copy_from_user(&LOCAL, SRC, sizeof(SRC)@local_array_copy)
... when any
}

// An array declarator in a function parameter is adjusted to a pointer;
// sizeof(parameter) therefore does not measure the written array bound.
@copy_from_array_parameter@
type T, TL;
identifier FUNC, SRC;
TL LOCAL;
position p != {copy_from_sizeof_src.p, copy_from_local_array_size.local_array_copy};
@@
FUNC(..., T SRC[...], ...) {
... when any
* copy_from_user(&LOCAL, SRC, sizeof(SRC)@p)
... when any
}

@script:python copy_from_array_report depends on copy_from_array_parameter@
p << copy_from_array_parameter.p;
T << copy_from_array_parameter.T;
TL << copy_from_array_parameter.TL;
@@
import json
source_pointer = tuple(str(T).replace("*", " * ").split()) + ("*",)
destination_type = tuple(str(TL).replace("*", " * ").split())
if source_pointer != destination_type:
  msg = {
    "rule": "copy_from_user_sizeof_ptr",
    "file": p[0].file,
    "line": int(p[0].line),
    "col": int(p[0].column),
    "message": "Candidate: copy_from_user uses sizeof(array parameter), which is pointer-sized; review target sizes and the intended copy extent (CWE-805)"
  }
  print("COCCIRESULT:" + json.dumps(msg))
