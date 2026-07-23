// use_after_close.cocci — Detect file descriptor operations after
// close(fd) without fd reassignment.
//
// After close(fd), the descriptor is invalid. Any subsequent
// read/write/ioctl/recv/send on that fd is undefined behaviour:
// the fd may have been reused by another thread, so the operation
// silently targets an unrelated resource — data corruption, info
// leak, or privilege escalation.
//
// CWE-672: Operation on a Resource after Expiration or Release
// Zero-FP: using a closed fd without reassignment is always wrong.

@close_then_read@
expression FD;
position p;
@@

  close(FD);
  ... when != FD = ...
      when != FD
* read@p(FD, ...)

@script:python report_read depends on close_then_read@
p << close_then_read.p;
@@
import json
msg = {
  "rule":  "use_after_close",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "read() on closed file descriptor — use after close (CWE-672)"
}
print("COCCIRESULT:" + json.dumps(msg))

@close_then_write@
expression FD;
position p;
@@

  close(FD);
  ... when != FD = ...
      when != FD
* write@p(FD, ...)

@script:python report_write depends on close_then_write@
p << close_then_write.p;
@@
import json
msg = {
  "rule":  "use_after_close",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "write() on closed file descriptor — use after close (CWE-672)"
}
print("COCCIRESULT:" + json.dumps(msg))

@close_then_ioctl@
expression FD;
position p;
@@

  close(FD);
  ... when != FD = ...
      when != FD
* ioctl@p(FD, ...)

@script:python report_ioctl depends on close_then_ioctl@
p << close_then_ioctl.p;
@@
import json
msg = {
  "rule":  "use_after_close",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "ioctl() on closed file descriptor — use after close (CWE-672)"
}
print("COCCIRESULT:" + json.dumps(msg))

@close_then_recv@
expression FD;
position p;
@@

  close(FD);
  ... when != FD = ...
      when != FD
* recv@p(FD, ...)

@script:python report_recv depends on close_then_recv@
p << close_then_recv.p;
@@
import json
msg = {
  "rule":  "use_after_close",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "recv() on closed file descriptor — use after close (CWE-672)"
}
print("COCCIRESULT:" + json.dumps(msg))

@close_then_send@
expression FD;
position p;
@@

  close(FD);
  ... when != FD = ...
      when != FD
* send@p(FD, ...)

@script:python report_send depends on close_then_send@
p << close_then_send.p;
@@
import json
msg = {
  "rule":  "use_after_close",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "send() on closed file descriptor — use after close (CWE-672)"
}
print("COCCIRESULT:" + json.dumps(msg))

@close_then_recvfrom@
expression FD;
position p;
@@

  close(FD);
  ... when != FD = ...
      when != FD
* recvfrom@p(FD, ...)

@script:python report_recvfrom depends on close_then_recvfrom@
p << close_then_recvfrom.p;
@@
import json
msg = {
  "rule":  "use_after_close",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "recvfrom() on closed file descriptor — use after close (CWE-672)"
}
print("COCCIRESULT:" + json.dumps(msg))

@close_then_sendto@
expression FD;
position p;
@@

  close(FD);
  ... when != FD = ...
      when != FD
* sendto@p(FD, ...)

@script:python report_sendto depends on close_then_sendto@
p << close_then_sendto.p;
@@
import json
msg = {
  "rule":  "use_after_close",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "sendto() on closed file descriptor — use after close (CWE-672)"
}
print("COCCIRESULT:" + json.dumps(msg))
