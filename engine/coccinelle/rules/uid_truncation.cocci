// uid_truncation.cocci — Review UID/GID casts to legacy or narrow forms.
// A cast does not prove that the input exceeds the destination range or
// that the conversion violates the caller's ABI/identity contract.
//
// Generic unsigned-short/__u16 casts require UID/GID static provenance or
// a direct accessor. Legacy UID/GID destination types supply that context
// themselves. Casts in assignments, declarations, returns and arguments
// are covered. In-range integer literals and already-narrow operands are
// excluded; caller range checks, aliases and implicit conversions require
// independent review. No host ABI sizes are used.
// Legacy typedefs can be wider than 16 bits on some targets; see
// include/uapi/asm-generic/posix_types.h and the architecture overrides.
// CWE-681: Incorrect Conversion between Numeric Types
// @role: detection
// raptor: confirm-only

@uid_cast@
typedef __old_uid_t, __old_gid_t, __kernel_old_uid_t, __kernel_old_gid_t;
typedef __u16, uid_t, gid_t, kuid_t, kgid_t;
expression value;
position p;
@@
  (\(__old_uid_t\|__old_gid_t\|__kernel_old_uid_t\|__kernel_old_gid_t\|unsigned short\|__u16\)) value@p

@uid_generic_cast@
expression uid_cast.value;
position uid_cast.p;
@@
  (\(unsigned short\|__u16\)) value@p

@uid_typed_source@
{uid_t, gid_t, kuid_t, kgid_t, __old_uid_t, __old_gid_t, __kernel_old_uid_t, __kernel_old_gid_t} value;
position uid_cast.p;
@@
value@p

@uid_accessor_source@
expression uid_cast.value;
identifier ACCESSOR =~ "^\(getuid\|geteuid\|getgid\|getegid\|from_kuid\|from_kgid\|__kuid_val\|__kgid_val\)$";
@@
ACCESSOR(...)@value

@uid_identity_cast@
type T;
T value;
position uid_cast.p;
@@
  (T) value@p

@uid_narrow_source@
{unsigned short, __u16} value;
position uid_cast.p;
@@
value@p

@script:python uid_report depends on uid_cast && (!uid_generic_cast || uid_typed_source || uid_accessor_source) && !uid_narrow_source && !uid_identity_cast@
p << uid_cast.p;
value << uid_cast.value;
@@
import json, sys
# Parse only a standalone integer literal, never an expression. Support C
# integer suffixes and octal spelling without evaluating target code.
literal = str(value).strip().rstrip("uUlL")
try:
    number = int(literal, 8 if literal.startswith("0") and literal.isdigit() else 0)
except ValueError:
    number = None
if number is None or not 0 <= number <= 65535:
    for location in p:
        msg = {
            "file": location.file,
            "line": int(location.line),
            "col": int(location.column),
            "line_end": int(location.line_end),
            "col_end": int(location.column_end),
            "rule": "uid_truncation",
            "message": "Candidate: UID/GID narrowing of '%s' to a legacy UID/GID or unsigned-short representation; verify target widths, the value range and identity/ABI contract (CWE-681)" % value,
        }
        sys.stderr.write("COCCIRESULT:" + json.dumps(msg) + "\n")
