"""Shared taxonomy of function-name categories with security significance.

One source of truth for "dangerous string function", "exec sink", "parser
entry point", etc. — consumers (packages/binary_analysis,
packages/exploit_feasibility) compose the union they need from these
primitive frozensets. Replaces three previously-divergent lists:

  - packages/binary_analysis/radare2_understand._DANGEROUS_IMPORTS
  - packages/exploit_feasibility/constants.{COMMON,INPUT,STRING_TERMINATING}_FUNCTIONS
  - packages/binary_analysis/radare2_understand._DANGEROUS_MACOS_SUBSTRINGS

Curation policy (why some "obvious" entries are missing):

  - **Ubiquitous functions are deliberately excluded from the categories
    that drive fuzz-prioritisation signal.** `malloc`, `realloc`, `free`,
    `open`, `fopen`, `read`, `write`, `printf`, `fprintf`, `vprintf`
    appear in essentially every binary — if every binary "imports a
    dangerous function" then the signal value is zero. These functions
    are added back where they ARE useful (e.g. `COMMON_FUNCTIONS` for
    ROP target enumeration in exploit_feasibility) by the consumer's
    composition, not by this module.

  - **The CVE-shape determines category, not the function family.**
    `snprintf` is in `FORMAT_STRING_FUNCS` rather than
    `STRING_OVERFLOW_FUNCS` because its dominant CVE shape is
    format-string when the format is tainted; the bounded-size param
    actually prevents the classic overflow.

  - **"Safe" variants are NOT in the dangerous categories.** Microsoft's
    `wcscpy_s` / `wcsncpy_s` (`_s` suffix = explicit size param) and
    safe temp-file APIs (`tmpfile`, `mkstemp`) are deliberately omitted.
    Banned-by-design APIs (`mktemp`, `tempnam`) ARE included.

  - **Category membership is closed-list, not pattern-matched.** macOS
    Swift/ObjC symbols use substring matching (see
    `MACOS_DANGEROUS_SUBSTRINGS`) because demangled Swift names embed
    type/parameter info that breaks exact equality. Everything else is
    plain function-name equality.

Per-consumer compositions live in the consumer files
(`packages/binary_analysis/radare2_understand.py`,
`packages/exploit_feasibility/constants.py`) so the consumer's intent
is visible at the use site.
"""

from __future__ import annotations

from typing import FrozenSet


# === Bounded-string functions with classic overflow CVE shapes ===
# Note: snprintf/vsnprintf and their wide-char cousins are NOT here —
# their dominant CVE shape is format-string (see FORMAT_STRING_FUNCS),
# not overflow. The bounded-size param actually prevents the classic
# CWE-120 overflow.
STRING_OVERFLOW_FUNCS: FrozenSet[str] = frozenset({
    # No bounds checking at all
    "strcpy", "strcat", "sprintf", "vsprintf",
    "gets",  # banned by C11 Annex K, still found in legacy code

    # Bounded but off-by-one / no-NUL-termination CVEs are common
    "strncpy", "strncat",

    # BSD variants — same risk shape as strcpy
    "stpcpy", "stpncpy",

    # Wide-char variants — overflow patterns identical to char* siblings
    "wcscpy", "wcsncpy", "wcscat", "wcsncat",

    # Windows ANSI/Unicode equivalents — Microsoft has both
    # safe (`_s` suffix) and unsafe variants. The unsafe ones below
    # have the same risk shape as strcpy.
    "lstrcpyA", "lstrcpyW", "lstrcatA", "lstrcatW",
})


# === scanf-family parsing ===
# Format-string driven input parsing — overlaps conceptually with
# FORMAT_STRING_FUNCS (when the format is tainted) and with INTEGER_
# PARSE_FUNCS (when %d / %u is the only parser). Kept as own category
# because the analysis pattern differs from atoi/strto* (scanf has its
# own bounded vs unbounded %s rules).
SCAN_FAMILY_FUNCS: FrozenSet[str] = frozenset({
    "scanf", "vscanf", "sscanf", "fscanf", "vsscanf", "vfscanf",
    "wscanf", "swscanf",
})


# === Size-tainted memory copy operations ===
# memcpy is itself ubiquitous, but the pattern
# `memcpy(buf, attacker_data, attacker_size)` is THE classic CVE so
# the import IS signal — every binary uses memcpy, but a binary that
# uses memcpy on caller-supplied size is worth fuzzing more aggressively.
MEMORY_COPY_FUNCS: FrozenSet[str] = frozenset({
    "memcpy", "memmove", "bcopy",
    # Wide-char variants
    "wmemcpy", "wmemmove",
})


# === Format-string sinks (rare/distinguishing only) ===
# printf / fprintf / vprintf are DELIBERATELY EXCLUDED — they're
# ubiquitous so importing them is zero signal. Consumers that need
# exhaustive format-string detection (e.g. exploit_feasibility's
# format-string constraint analysis) should compose this set with
# the common-ones in their own file.
#
# snprintf / vsnprintf are included here (not in STRING_OVERFLOW)
# because their dominant CVE shape is format-string-when-tainted,
# not overflow (the size param prevents the overflow).
FORMAT_STRING_FUNCS: FrozenSet[str] = frozenset({
    "vfprintf",
    "syslog",
    "snprintf", "vsnprintf",

    # BSD format-string wrappers — frequently called with user input
    "err", "errx", "warn", "warnx",

    # Apple equivalents (macOS / iOS native code)
    "NSLog", "CFLog", "os_log", "os_log_with_type",

    # Windows ANSI/Unicode wsprintf — format-string variants of
    # sprintf. (Windows safe variants like StringCchPrintf are NOT
    # included — explicit size param.)
    "wsprintfA", "wsprintfW",
})


# === Process execution / command injection sinks ===
EXEC_FUNCS: FrozenSet[str] = frozenset({
    "system", "popen",
    "execl", "execv", "execlp", "execvp", "execle", "execve",
    "posix_spawn", "posix_spawnp",
    "fexecve", "execvpe",

    # Windows
    "CreateProcessA", "CreateProcessW",
    "CreateProcessAsUserA", "CreateProcessAsUserW",
    "CreateProcessWithLogonW",
    "ShellExecuteA", "ShellExecuteW",
    "ShellExecuteExA", "ShellExecuteExW",
    "WinExec",
})


# === Size-tainted allocation ===
# malloc / realloc REMOVED (ubiquitous). Strong-signal entries:
#   calloc:  nmemb * size integer-overflow CWE-190 → CWE-122
#   alloca:  stack-allocation CWE-770, unbounded if size is tainted
# The remaining entries are uncommon enough that the import is still
# signal even though their individual CVE history is thinner.
ALLOC_FUNCS: FrozenSet[str] = frozenset({
    "calloc",
    "alloca",
    "posix_memalign", "aligned_alloc",
    "valloc", "memalign", "pvalloc",
})


# === Network ingestion / server-side indicators ===
# read REMOVED (ubiquitous; network ingestion uses recv* explicitly).
# accept / bind / listen are server-side markers — different semantic
# from recv* but bundled together because both answer "is this binary
# doing network I/O" (fuzz-priority interest is similar).
NETWORK_INGEST_FUNCS: FrozenSet[str] = frozenset({
    "recv", "recvfrom", "recvmsg", "recvmmsg",
    "accept", "bind", "listen",
    # OpenSSL
    "SSL_read", "BIO_read",
})


# === High-CVE-density parser entry points ===
# The biggest single signal source for fuzz prioritisation. A binary
# that imports any of these is processing structured external input
# and is worth aggressive coverage.
PARSER_FUNCS: FrozenSet[str] = frozenset({
    # Generic parser-generator output (yacc/bison/flex/lex)
    "yyparse",

    # XML — expat + libxml2
    "XML_Parse", "XML_ParseBuffer",
    "xmlReadMemory", "xmlReadDoc", "xmlReadFile",
    "xmlSAXUserParseMemory", "xmlParseDoc",

    # JSON — jansson, json-c, cJSON
    "json_loads", "json_loadb", "json_load_file",
    "json_object_from_file",
    "cJSON_Parse",

    # OpenSSL ASN.1 — historically extremely vuln-rich. Limited to the
    # two most-common entries (X509 + PrivateKey) because the wider
    # d2i_* family has dozens of variants with vanishingly small
    # individual CVE history.
    "d2i_X509", "d2i_X509_bio",
    "d2i_PrivateKey",

    # OpenSSL PEM — same restriction
    "PEM_read_X509", "PEM_read_PrivateKey",
    "PEM_read_bio_X509", "PEM_read_bio_PrivateKey",

    # Embedded scripting — RCE-prone if input is attacker-controlled
    "lua_load", "lua_loadbuffer",
    "luaL_loadstring", "luaL_dostring", "luaL_dofile",
    "Py_CompileString", "PyRun_String", "PyRun_File",

    # Image format parsers — high fuzz yield historically
    "png_read_info", "png_read_image",
    "jpeg_read_header", "jpeg_read_scanlines",
    "TIFFOpen", "TIFFReadDirectory",
    "WebPDecode", "WebPDecodeRGBA", "WebPDecodeBGRA",

    # Compression library decoders
    "inflate",                       # zlib
    "BZ2_bzDecompress",             # bzip2
    "lzma_code",                     # xz
    "LZ4_decompress_safe", "LZ4_decompress_fast",
    "ZSTD_decompress", "ZSTD_decompressStream",
    "BrotliDecoderDecompress", "BrotliDecoderDecompressStream",
})


# === Integer parsing (CWE-190 / -191 hints) ===
# atoi family: no overflow checking, classic source of integer bugs
# strto* family: overflow detectable via errno but the "didn't check
#   errno" pattern is common — the import is still signal.
# Float parsing (atof / strto[d,f,ld]) is DELIBERATELY EXCLUDED —
# float-overflow CVE pattern is fundamentally different from integer
# overflow and doesn't usually map to memory corruption.
INTEGER_PARSE_FUNCS: FrozenSet[str] = frozenset({
    "atoi", "atol", "atoll",
    "strtoul", "strtol", "strtoull", "strtoll",
})


# === TOCTOU + path-traversal pattern markers ===
# Includes the BANNED-BY-DESIGN temp-file APIs (mktemp, tempnam) which
# CWE-377-guarantee a race condition by construction. tmpfile and
# mkstemp are NOT here — they're race-free when used correctly.
# stat / lstat / chdir excluded — too common to signal anything.
TOCTOU_FUNCS: FrozenSet[str] = frozenset({
    "access", "faccessat",
    "realpath", "readlink", "readlinkat",
    "chroot",
    "mktemp", "tempnam",
})


# === macOS Swift / Objective-C dangerous symbols ===
# Different match semantics from the above — Swift symbol mangling
# embeds type/parameter info so exact-equality match misses real call
# sites. Consumers must do `substring in demangled_name` checking,
# not `name in MACOS_DANGEROUS_SUBSTRINGS`.
MACOS_DANGEROUS_SUBSTRINGS: FrozenSet[str] = frozenset({
    # CoreFoundation parsers
    "CFPropertyListCreateWithData", "CFPropertyListCreateFromXMLData",
    "CFReadStreamRead", "CFDataGetBytes",
    "CFStringCreateWithBytes", "CFURLCreateWithBytes",
    "CFXMLParserCreate", "CFXMLTreeCreateFromData",

    # Swift Foundation parsing / IO entry points
    "Foundation.Data.contentsOf",
    "Foundation.Data.base64Encoded",
    "Foundation.Data.write",
    "Foundation.Data.Iterator",
    "Foundation.URL.fileURLWithPath",
    "Foundation.URL.absoluteString",
    "Foundation.JSONSerialization",
    "Foundation.PropertyListSerialization",
    "Foundation.PropertyListDecoder",
    "Foundation.JSONDecoder",

    # Apple security framework / keychain
    "SecPolicyCreateSSL",
    "SecTrustEvaluate",
    "SecItemCopyMatching",
    "SecKeychainItem",

    # NSData / NSString interop — option/byte-buffer parameters often
    # carry tainted input (base64 decode flags, byte ranges).
    "NSDataReadingOptions",
    "NSDataBase64DecodingOptions",
    "NSStringFromBytes",

    # Process execution via Foundation (NSTask / Swift Process)
    "NSTask",
    "Foundation.Process",
})


# === Entry-point name exact matches ===
# Function-name EXACT matches that suggest the function is an entry
# point worth exploring. Used by radare2_understand for membership
# check; the consumer separately applies a suffix-pattern check for
# `*main`/`*init`/`*Main`/`*Init`/`*Entry` patterns (those don't
# belong here — they're patterns, not names).
ENTRY_POINT_HINTS: FrozenSet[str] = frozenset({
    "main", "_start", "wmain",
    "WinMain", "DllMain", "DriverEntry",
    "LLVMFuzzerTestOneInput",   # libFuzzer harness convention
    "do_main",                   # common alias seen in real codebases
})


# === Helpers ===

def fortified(base: FrozenSet[str]) -> FrozenSet[str]:
    """Return the FORTIFY_SOURCE __*_chk variants of every function in
    `base`. Exact-match set — useful for consumers that need to
    recognise `__strcpy_chk` as the bounded variant of `strcpy`
    (e.g. distinguishing fortified-build vs non-fortified-build
    behaviour during exploit primitive selection).

    No current consumer uses this; substring-matching `__chk` against
    objdump output covers the most common case (packages/exploit_
    feasibility/analyzer.py). Kept here for future consumers that need
    exact-match semantics — if a downstream wants to map a
    `__strcpy_chk` symbol back to the unfortified `strcpy`, doing
    `name in fortified(STRING_OVERFLOW_FUNCS)` is the right shape.
    """
    return frozenset(f"__{name}_chk" for name in base)


__all__ = [
    "STRING_OVERFLOW_FUNCS",
    "SCAN_FAMILY_FUNCS",
    "MEMORY_COPY_FUNCS",
    "FORMAT_STRING_FUNCS",
    "EXEC_FUNCS",
    "ALLOC_FUNCS",
    "NETWORK_INGEST_FUNCS",
    "PARSER_FUNCS",
    "INTEGER_PARSE_FUNCS",
    "TOCTOU_FUNCS",
    "MACOS_DANGEROUS_SUBSTRINGS",
    "ENTRY_POINT_HINTS",
    "fortified",
]
