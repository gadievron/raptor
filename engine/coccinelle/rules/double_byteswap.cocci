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
// A nested pair is only an identity when BOTH calls operate on the
// same width and the same byte-order family (network/big-endian,
// little-endian, or unconditional bswap). Cross-family or mixed-width
// nesting — e.g. converting big-endian wire data to little-endian, or
// widening chains — performs a real conversion and must not be
// flagged; the syntactic match is therefore filtered down to true
// identity pairs in the reporting script below.
//
// CWE-683: Function Call With Incorrect Order of Arguments
// Zero-FP: a same-width, same-family double swap is a mathematical
// identity, never intentional.
// @role: verification

@double_swap@
identifier swap1 = {htons, htonl, ntohs, ntohl,
                    htobe16, htobe32, htobe64, htole16, htole32, htole64,
                    be16toh, be32toh, be64toh, le16toh, le32toh, le64toh,
                    cpu_to_be16, cpu_to_be32, cpu_to_be64,
                    cpu_to_le16, cpu_to_le32, cpu_to_le64,
                    be16_to_cpu, be32_to_cpu, be64_to_cpu,
                    le16_to_cpu, le32_to_cpu, le64_to_cpu,
                    __cpu_to_be16, __cpu_to_be32, __cpu_to_be64,
                    __cpu_to_le16, __cpu_to_le32, __cpu_to_le64,
                    __be16_to_cpu, __be32_to_cpu, __be64_to_cpu,
                    __le16_to_cpu, __le32_to_cpu, __le64_to_cpu,
                    bswap_16, bswap_32, bswap_64,
                    __bswap_16, __bswap_32, __bswap_64};
identifier swap2 = {htons, htonl, ntohs, ntohl,
                    htobe16, htobe32, htobe64, htole16, htole32, htole64,
                    be16toh, be32toh, be64toh, le16toh, le32toh, le64toh,
                    cpu_to_be16, cpu_to_be32, cpu_to_be64,
                    cpu_to_le16, cpu_to_le32, cpu_to_le64,
                    be16_to_cpu, be32_to_cpu, be64_to_cpu,
                    le16_to_cpu, le32_to_cpu, le64_to_cpu,
                    __cpu_to_be16, __cpu_to_be32, __cpu_to_be64,
                    __cpu_to_le16, __cpu_to_le32, __cpu_to_le64,
                    __be16_to_cpu, __be32_to_cpu, __be64_to_cpu,
                    __le16_to_cpu, __le32_to_cpu, __le64_to_cpu,
                    bswap_16, bswap_32, bswap_64,
                    __bswap_16, __bswap_32, __bswap_64};
expression E;
position p;
@@

* swap1@p(swap2(E))

@script:python report_identity depends on double_swap@
p << double_swap.p;
swap1 << double_swap.swap1;
swap2 << double_swap.swap2;
@@
import json

def _classify(name):
    """Map a byte-order helper to (family, width).

    Every helper is its own inverse (a fixed-width byte swap, or the
    identity on machines already in the target order), so two nested
    calls cancel exactly when family and width both match. 'be' covers
    the POSIX network functions too — network order IS big-endian.
    """
    n = name.lstrip("_")
    if n in ("htons", "ntohs"):
        return ("be", 16)
    if n in ("htonl", "ntohl"):
        return ("be", 32)
    for fam in ("be", "le"):
        for width in ("16", "32", "64"):
            if n in ("hto%s%s" % (fam, width),
                     "%s%stoh" % (fam, width),
                     "cpu_to_%s%s" % (fam, width),
                     "%s%s_to_cpu" % (fam, width)):
                return (fam, int(width))
    for width in ("16", "32", "64"):
        if n == "bswap_%s" % width:
            return ("swap", int(width))
    return (None, None)

_f1, _w1 = _classify(str(swap1))
_f2, _w2 = _classify(str(swap2))
if _f1 is not None and (_f1, _w1) == (_f2, _w2):
    msg = {
      "rule":  "double_byteswap",
      "file":  p[0].file,
      "line":  int(p[0].line),
      "col":   int(p[0].column),
      "message": "%s(%s(x)) — double byte-swap is a no-op identity, no conversion actually happens (CWE-683)" % (swap1, swap2)
    }
    print("COCCIRESULT:" + json.dumps(msg))
