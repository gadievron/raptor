// double_byteswap.cocci — Detect double byte-order conversion that
// cancels out (mathematical identity).
//
// htons(htons(x)) == x, ntohl(htonl(x)) == x, etc. The inner swap
// converts to network order; the outer converts back to host order
// (or vice versa). The result is the original value, meaning no
// conversion actually happened. This is always a logic error —
// the programmer either wanted a single conversion or confused
// which direction they were converting.
//
// CWE-683: Function Call With Incorrect Order of Arguments
// Zero-FP: double swap is a mathematical identity, never intentional.

// POSIX/BSD network byte-order functions
@double_swap_net@
identifier swap1 = {htons, htonl, ntohs, ntohl};
identifier swap2 = {htons, htonl, ntohs, ntohl};
expression E;
position p;
@@

* swap1@p(swap2(E))

@script:python report_net depends on double_swap_net@
p << double_swap_net.p;
swap1 << double_swap_net.swap1;
swap2 << double_swap_net.swap2;
@@
import json
msg = {
  "rule":  "double_byteswap",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "%s(%s(x)) — double byte-swap is a no-op identity, no conversion actually happens (CWE-683)" % (swap1, swap2)
}
print("COCCIRESULT:" + json.dumps(msg))

// POSIX endian.h functions
@double_swap_endian@
identifier swap1 = {htobe16, htobe32, htobe64, htole16, htole32, htole64, be16toh, be32toh, be64toh, le16toh, le32toh, le64toh};
identifier swap2 = {htobe16, htobe32, htobe64, htole16, htole32, htole64, be16toh, be32toh, be64toh, le16toh, le32toh, le64toh};
expression E;
position p;
@@

* swap1@p(swap2(E))

@script:python report_endian depends on double_swap_endian@
p << double_swap_endian.p;
swap1 << double_swap_endian.swap1;
swap2 << double_swap_endian.swap2;
@@
import json
msg = {
  "rule":  "double_byteswap",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "%s(%s(x)) — double byte-swap is a no-op identity, no conversion actually happens (CWE-683)" % (swap1, swap2)
}
print("COCCIRESULT:" + json.dumps(msg))

// Linux kernel byte-order macros
@double_swap_kernel@
identifier swap1 = {cpu_to_be16, cpu_to_be32, cpu_to_be64, cpu_to_le16, cpu_to_le32, cpu_to_le64, be16_to_cpu, be32_to_cpu, be64_to_cpu, le16_to_cpu, le32_to_cpu, le64_to_cpu};
identifier swap2 = {cpu_to_be16, cpu_to_be32, cpu_to_be64, cpu_to_le16, cpu_to_le32, cpu_to_le64, be16_to_cpu, be32_to_cpu, be64_to_cpu, le16_to_cpu, le32_to_cpu, le64_to_cpu};
expression E;
position p;
@@

* swap1@p(swap2(E))

@script:python report_kernel depends on double_swap_kernel@
p << double_swap_kernel.p;
swap1 << double_swap_kernel.swap1;
swap2 << double_swap_kernel.swap2;
@@
import json
msg = {
  "rule":  "double_byteswap",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "%s(%s(x)) — double byte-swap is a no-op identity, no conversion actually happens (CWE-683)" % (swap1, swap2)
}
print("COCCIRESULT:" + json.dumps(msg))

// Linux kernel __-prefixed variants
@double_swap_kernel_under@
identifier swap1 = {__cpu_to_be16, __cpu_to_be32, __cpu_to_be64, __cpu_to_le16, __cpu_to_le32, __cpu_to_le64, __be16_to_cpu, __be32_to_cpu, __be64_to_cpu, __le16_to_cpu, __le32_to_cpu, __le64_to_cpu};
identifier swap2 = {__cpu_to_be16, __cpu_to_be32, __cpu_to_be64, __cpu_to_le16, __cpu_to_le32, __cpu_to_le64, __be16_to_cpu, __be32_to_cpu, __be64_to_cpu, __le16_to_cpu, __le32_to_cpu, __le64_to_cpu};
expression E;
position p;
@@

* swap1@p(swap2(E))

@script:python report_kernel_under depends on double_swap_kernel_under@
p << double_swap_kernel_under.p;
swap1 << double_swap_kernel_under.swap1;
swap2 << double_swap_kernel_under.swap2;
@@
import json
msg = {
  "rule":  "double_byteswap",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "%s(%s(x)) — double byte-swap is a no-op identity, no conversion actually happens (CWE-683)" % (swap1, swap2)
}
print("COCCIRESULT:" + json.dumps(msg))

// glibc/Linux bswap_* functions
@double_swap_bswap@
identifier swap1 = {bswap_16, bswap_32, bswap_64, __bswap_16, __bswap_32, __bswap_64};
identifier swap2 = {bswap_16, bswap_32, bswap_64, __bswap_16, __bswap_32, __bswap_64};
expression E;
position p;
@@

* swap1@p(swap2(E))

@script:python report_bswap depends on double_swap_bswap@
p << double_swap_bswap.p;
swap1 << double_swap_bswap.swap1;
swap2 << double_swap_bswap.swap2;
@@
import json
msg = {
  "rule":  "double_byteswap",
  "file":  p[0].file,
  "line":  int(p[0].line),
  "col":   int(p[0].column),
  "message": "%s(%s(x)) — double byte-swap is a no-op identity, no conversion actually happens (CWE-683)" % (swap1, swap2)
}
print("COCCIRESULT:" + json.dumps(msg))
