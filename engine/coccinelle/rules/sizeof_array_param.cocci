// sizeof_array_param.cocci — Detect sizeof() on a function parameter
// that decays from array to pointer.
//
// void f(char buf[256]) { memcpy(dst, buf, sizeof(buf)); }
// sizeof(buf) is sizeof(char*), not 256. The array notation in the
// parameter is misleading — C always decays it to a pointer.
//
// CWE-467: Use of sizeof() on a Pointer Type (array-decay variant)
// 0xdea catches sizeof-on-pointer but not this specific array-decay case.

@sizeof_param_array@
identifier FUNC, PARAM;
type T;
constant C;
position p;
@@

  FUNC(..., T PARAM[C], ...)
  {
    ... when any
    sizeof(PARAM)@p
    ... when any
  }

@script:python sizeof_param_report depends on sizeof_param_array@
p << sizeof_param_array.p;
@@
import json
msg = {
  "rule":  "sizeof_array_param",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "sizeof() on array parameter — parameter decays to pointer, sizeof returns pointer size not array size (CWE-467)"
}
print("COCCIRESULT:" + json.dumps(msg))

@sizeof_param_unsized@
identifier FUNC, PARAM;
type T;
position p;
@@

  FUNC(..., T PARAM[], ...)
  {
    ... when any
    sizeof(PARAM)@p
    ... when any
  }

@script:python sizeof_unsized_report depends on sizeof_param_unsized@
p << sizeof_param_unsized.p;
@@
import json
msg = {
  "rule":  "sizeof_array_param_unsized",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message":   "sizeof() on unsized array parameter — parameter is a pointer, sizeof returns pointer size (CWE-467)"
}
print("COCCIRESULT:" + json.dumps(msg))
