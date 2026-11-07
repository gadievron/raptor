// strncpy_no_nul.cocci — Review string reads after possibly unterminated copies.
// strncpy may omit NUL when the source length reaches the copy count. A later
// string read is a candidate, not proof: source length, existing termination,
// and formatted-argument conversion/bounds require independent review.
// Track direct destinations, ending at replacement, update, address escape,
// another strncpy or an explicit NUL write. Alias writes remain outside scope.
// strncmp and the source of strncat bounded by the unchanged copy count do not
// need NUL within that range; the destination of strncat is still unbounded.
// Formatted uses are checked against supported literal conversion slots.
// Unknown formats/escapes remain candidates; no source-format code is executed.
// Format contract: https://man7.org/linux/man-pages/man3/printf.3.html
// https://man7.org/linux/man-pages/man3/strncpy.3.html
// https://man7.org/linux/man-pages/man3/strncmp.3.html
// @role: detection

// Match the copied prefix on every path, not a same-spelled count changed
// after copying. Explicit forall keeps a clean path from hiding a changed one.
@bounded_use forall@
expression DST, SRC, OTHER;
identifier N;
assignment operator op_dst, op_n;
position p;
@@

strncpy(DST, SRC, N);
... when != DST op_dst ...
    when != &DST
    when != DST++
    when != ++DST
    when != DST--
    when != --DST
    when != strncpy(DST, ...)
    when != N op_n ...
    when != &N
    when != N++
    when != ++N
    when != N--
    when != --N
(
strncmp(DST, OTHER, N)@p
|
strncmp(OTHER, DST, N)@p
|
strncat(OTHER, DST, N)@p
)

@bounded_constant_use forall@
expression DST, SRC, OTHER;
constant N;
assignment operator op_dst;
position p;
@@

strncpy(DST, SRC, N);
... when != DST op_dst ...
    when != &DST
    when != DST++
    when != ++DST
    when != DST--
    when != --DST
    when != strncpy(DST, ...)
(
strncmp(DST, OTHER, N)@p
|
strncmp(OTHER, DST, N)@p
|
strncat(OTHER, DST, N)@p
)

@strncpy_then_string_use@
expression DST, SRC, N, F, SZ;
assignment operator op_dst;
constant COUNT =~ "^[1-9][0-9]*[uUlL]*$";
position p_copy;
position p_use != {bounded_use.p, bounded_constant_use.p};
@@

(
  strncpy(DST, SRC, strlen(SRC) + 1);
|
  strncpy@p_copy(DST, SRC, N);
... when != DST op_dst ...
    when != &DST
    when != DST++
    when != ++DST
    when != DST--
    when != --DST
    when != strncpy(DST, ...)
    when != DST[...] = '\0'
    when != DST[...] = 0
    when != memset(DST, 0, sizeof(...))
    when != memset(DST, '\0', sizeof(...))
    when != memset(DST, 0, COUNT)
    when != memset(DST, '\0', COUNT)
(
* strlen(DST)@p_use
|
* strcmp(DST, ...)@p_use
|
* strcmp(..., DST)@p_use
|
* strncmp(DST, ...)@p_use
|
* strncmp(F, DST, SZ)@p_use
|
* strcat(DST, ...)@p_use
|
* strcat(..., DST)@p_use
|
* strncat(DST, ...)@p_use
|
* strncat(F, DST, SZ)@p_use
|
* printf(DST, ...)@p_use
|
* fprintf(F, DST, ...)@p_use
|
* snprintf(F, SZ, DST, ...)@p_use
|
* syslog(F, DST, ...)@p_use
)
)

@script:python strncpy_nul_report depends on strncpy_then_string_use@
p_copy << strncpy_then_string_use.p_copy;
p_use << strncpy_then_string_use.p_use;
@@
import json
for pos in p_use:
    print("COCCIRESULT:" + json.dumps({
        "rule": "strncpy_no_nul", "file": pos.file,
        "line": int(pos.line), "col": int(pos.column),
        "message": "Candidate: buffer from strncpy (line %s) reaches a string or format argument; review source length, termination, conversion and read bounds (CWE-170)" % p_copy[0].line,
    }))

@strncpy_then_format_use@
expression DST, SRC, N, F, SZ, FMT;
expression list BEFORE, AFTER;
assignment operator op_dst;
constant COUNT =~ "^[1-9][0-9]*[uUlL]*$";
position p_copy;
position p_use;
@@

(
  strncpy(DST, SRC, strlen(SRC) + 1);
|
  strncpy@p_copy(DST, SRC, N);
... when != DST op_dst ...
    when != &DST
    when != DST++
    when != ++DST
    when != DST--
    when != --DST
    when != strncpy(DST, ...)
    when != DST[...] = '\0'
    when != DST[...] = 0
    when != memset(DST, 0, sizeof(...))
    when != memset(DST, '\0', sizeof(...))
    when != memset(DST, 0, COUNT)
    when != memset(DST, '\0', COUNT)
(
* printf(FMT, BEFORE, DST@p_use, AFTER)
|
* fprintf(F, FMT, BEFORE, DST@p_use, AFTER)
|
* snprintf(F, SZ, FMT, BEFORE, DST@p_use, AFTER)
|
* syslog(F, FMT, BEFORE, DST@p_use, AFTER)
)
)

@script:python strncpy_format_report depends on strncpy_then_format_use@
p_copy << strncpy_then_format_use.p_copy;
p_use << strncpy_then_format_use.p_use;
fmt << strncpy_then_format_use.FMT;
count << strncpy_then_format_use.N;
before << strncpy_then_format_use.BEFORE;
after << strncpy_then_format_use.AFTER;
dst << strncpy_then_format_use.DST;
@@
import json

def literal_format(text):
    # Parse only ordinary adjacent literals with JSON-compatible C escapes.
    # Unsupported encodings/escapes stay unknown, never a reason to drop a hit.
    if len(text) > 8192:
        return None
    import re
    if re.search("\\\\[^\"\\\\/bfnrt]", text):
        return None
    decoder, parts, offset = json.JSONDecoder(), [], 0
    try:
        while offset < len(text):
            while offset < len(text) and text[offset].isspace():
                offset += 1
            if offset == len(text):
                break
            if text[offset] != "\"":
                return None
            part, offset = decoder.raw_decode(text, offset)
            parts.append(part)
    except ValueError:
        return None
    return "".join(parts) if parts else None


def integer_literal(text):
    text = text.strip().rstrip("uUlL")
    if not text or len(text) > 10:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def needs_termination(fmt_text, count_text, arguments, target):
    fmt = literal_format(fmt_text)
    if fmt is None:
        return True
    copied = integer_literal(count_text)
    offset, next_argument, mode, reads = 0, 0, None, []
    used = set()

    def digits(start):
        end = start
        while end < len(fmt) and "0" <= fmt[end] <= "9":
            end += 1
        return end

    def argument(position):
        nonlocal next_argument, mode
        wanted = "positional" if position is not None else "sequential"
        if mode is not None and mode != wanted:
            raise ValueError("mixed argument numbering")
        mode = wanted
        index = position - 1 if position is not None else next_argument
        if position is None:
            next_argument += 1
        if index < 0 or index >= len(arguments):
            raise ValueError("missing argument")
        used.add(index)
        return index

    try:
        while offset < len(fmt):
            if fmt[offset] != "%":
                offset += 1
                continue
            offset += 1
            if offset < len(fmt) and fmt[offset] == "%":
                offset += 1
                continue
            end = digits(offset)
            position = None
            if end < len(fmt) and fmt[end] == "$":
                if end == offset or end - offset > 5:
                    return True
                position = int(fmt[offset:end])
                offset = end + 1
            while offset < len(fmt) and fmt[offset] in "-+ #0'I":
                offset += 1
            # Each star consumes an int argument before the conversion value.
            precision = None
            for is_precision in (False, True):
                if is_precision:
                    if offset == len(fmt) or fmt[offset] != ".":
                        break
                    offset += 1
                    precision = 0
                if offset < len(fmt) and fmt[offset] == "*":
                    offset += 1
                    end = digits(offset)
                    star_position = None
                    if end != offset:
                        if end == len(fmt) or fmt[end] != "$" or end - offset > 5:
                            return True
                        star_position = int(fmt[offset:end])
                        offset = end + 1
                    index = argument(star_position)
                    if is_precision:
                        precision = integer_literal(str(arguments[index]))
                        # A negative precision behaves as if omitted.
                        if precision is not None and precision < 0:
                            precision = None
                else:
                    end = digits(offset)
                    if is_precision and end != offset:
                        if end - offset > 8:
                            return True
                        precision = int(fmt[offset:end])
                    offset = end
            length = ""
            if fmt[offset:offset + 2] in ("hh", "ll"):
                length = fmt[offset:offset + 2]
                offset += 2
            elif offset < len(fmt) and fmt[offset] in "hlLjztqZ":
                length = fmt[offset]
                offset += 1
            if offset == len(fmt):
                return True
            conversion = fmt[offset]
            offset += 1
            if conversion == "m":
                if position is not None or length:
                    return True
                continue
            if conversion not in "diouxXfFeEgGaAcCspnS":
                return True
            if (conversion in "sc" and length not in ("", "l")
                    or conversion in "SCp" and length
                    or conversion in "fFeEgGaA" and length not in ("", "l", "L")
                    or conversion in "diouxXn" and length == "L"):
                return True
            index = argument(position)
            if conversion in "sS" and index == target:
                bounded = (conversion == "s" and not length and precision is not None
                           and (precision == 0 or copied is not None and 0 <= precision <= copied))
                reads.append(not bounded)
    except ValueError:
        return True
    if mode == "positional" and used != set(range(max(used) + 1)):
        return True
    return any(reads)

# TermList elements come from the parsed C argument list, not comma splitting.
# Bound Python work; larger calls stay candidates instead of dropping evidence.
from itertools import islice
prefix = list(islice(before, 129))
suffix = list(islice(after, 129))
arguments = prefix + [dst] + suffix
if len(arguments) > 128 or needs_termination(str(fmt), str(count), arguments, len(prefix)):
    for pos in p_use:
        print("COCCIRESULT:" + json.dumps({
            "rule": "strncpy_no_nul", "file": pos.file,
            "line": int(pos.line), "col": int(pos.column),
            "message": "Candidate: buffer from strncpy (line %s) reaches a string conversion or unknown format; review termination and read bounds (CWE-170)" % p_copy[0].line,
        }))
