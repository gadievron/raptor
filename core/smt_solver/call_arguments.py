"""C-family lexical boundaries for opaque SMT call arguments.

Numbers remain opaque: recognising a preprocessing-number token prevents its
C23/C++ digit separators from being mistaken for character-literal quotes.
This is structural admission, not a C expression, type or effect model.
"""

from dataclasses import dataclass
import re


_NUMBER = re.compile(r"(?<![A-Za-z0-9_])(?:[0-9]|\.[0-9])(?:[eEpP][+-]|[A-Za-z0-9_.]|'[A-Za-z0-9_])*")
_RAW_HEAD = re.compile(r'(?<![A-Za-z0-9_])(?:u8|u|U|L)?R"')


@dataclass(frozen=True)
class LexicalSpan:
    start: int
    end: int
    closed: bool
    comment: bool = False


_LINE_END = re.compile(r"[\r\n]")
_LINE_SPLICE = re.compile(r"\\[ \t\v\f]*(?:\r\n?|\n)")
_TRIGRAPH = re.compile(r"\?\?[=/'()!<>-]")


def _lexeme_at(text, index):
    """Consume one code character, preprocessing number or non-code span."""
    number = _NUMBER.match(text, index)
    if number is not None:
        return number.end(), None
    raw = _RAW_HEAD.match(text, index)
    if raw is not None:
        opening = text.find("(", raw.end(), raw.end() + 17)
        delimiter = text[raw.end():opening] if opening >= 0 else ""
        if opening < 0 or any(not 33 <= ord(char) <= 126 or char in "()\\" for char in delimiter):
            return len(text), LexicalSpan(index, len(text), False)
        terminator = ")" + delimiter + '"'
        closing = text.find(terminator, opening + 1)
        end = closing + len(terminator) if closing >= 0 else len(text)
        return end, LexicalSpan(index, end, closing >= 0)
    if text.startswith("/*", index):
        closing = text.find("*/", index + 2)
        end = closing + 2 if closing >= 0 else len(text)
        return end, LexicalSpan(index, end, closing >= 0, comment=True)
    if text.startswith("//", index):
        closing = _LINE_END.search(text, index + 2)
        end = closing.start() if closing is not None else len(text)
        return end, LexicalSpan(index, end, True, comment=True)
    if text[index] not in {"'", '"'}:
        return index + 1, None
    begin, quote = index, text[index]
    index += 1
    admitted = True
    while index < len(text):
        char = text[index]
        index += 1
        if char == "\\":
            index = min(index + 1, len(text))
        elif char == quote:
            return index, LexicalSpan(begin, index, admitted)
        elif char in "\r\n":
            admitted = False
    return index, LexicalSpan(begin, index, False)


def non_code_spans(text: str, start: int = 0):
    """Yield literal/comment spans, retaining offsets and lexical closure.

    Raw delimiters are bounded to C++'s 16 characters. Incomplete literals
    and comments decline; ordinary C literals cannot cross bare newlines.
    """
    index = start
    while index < len(text):
        index, span = _lexeme_at(text, index)
        if span is not None:
            yield span


def _requires_translation_normalisation(text):
    # Translation settings are not part of this opaque-argument model.
    # Include whitespace before a newline, as accepted by GCC extensions.
    return _LINE_SPLICE.search(text) is not None or _TRIGRAPH.search(text) is not None


def mask_non_code(text: str) -> tuple[str, bool]:
    """Return visible code and whether its lexical structure was admitted.

    Literal and comment bytes become spaces, except the ambiguous //=
    assignment marker. Line splices and trigraphs require translation-phase
    normalisation and decline rather than hiding effects.
    """
    out = list(text)
    complete = not _requires_translation_normalisation(text)
    for span in non_code_spans(text):
        complete = complete and span.closed
        start = span.start
        # Shared users also supply Python floor assignments. The //=
        # marker cannot be silently classified as an inert C comment.
        if span.comment and text.startswith("//=", start):
            start += 3
        out[start:span.end] = [" "] * (span.end - start)
    return "".join(out), complete


def split_call_arguments(text: str) -> tuple[str, ...] | None:
    """Split code commas, preserving raw argument text and declining empty slots."""
    if _requires_translation_normalisation(text):
        return None
    closing = {"(": ")", "[": "]", "{": "}"}
    stack, parts = [], []
    start = index = 0
    seen_token = False
    while index < len(text):
        end, span = _lexeme_at(text, index)
        if span is not None:
            if not span.closed:
                return None
            seen_token = seen_token or not span.comment
            index = end
            continue
        if end > index + 1:
            seen_token = True
            index = end
            continue
        char = text[index]
        if char == "," and not stack:
            if not seen_token:
                return None
            parts.append(text[start:index].strip())
            start, seen_token = index + 1, False
        else:
            seen_token = seen_token or not char.isspace()
            if char in closing:
                stack.append(closing[char])
            elif char in closing.values():
                if not stack or stack.pop() != char:
                    return None
        index += 1
    if stack:
        return None
    if not seen_token:
        return None if parts else ()
    return (*parts, text[start:].strip())


def find_call_end(text: str, opening: int) -> int | None:
    """Return the exclusive balanced call end, ignoring literal/comment data."""
    if not 0 <= opening < len(text) or text[opening] != "(":
        return None
    closing = {"(": ")", "[": "]", "{": "}"}
    stack = [")"]
    index = opening + 1
    while index < len(text):
        end, span = _lexeme_at(text, index)
        if span is not None:
            if not span.closed:
                return None
            index = end
            continue
        if end > index + 1:
            index = end
            continue
        char = text[index]
        if char in closing:
            stack.append(closing[char])
        elif char in closing.values():
            if not stack or stack.pop() != char:
                return None
            if not stack:
                end = index + 1
                return None if _requires_translation_normalisation(text[opening:end]) else end
        index += 1
    return None
