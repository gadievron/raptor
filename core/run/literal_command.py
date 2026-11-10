"""Recognize a literal POSIX-shell invocation without evaluating shell text.

This accepts quoted/escaped metacharacters as argv data, but refuses active
expansions, comments, redirects and compound syntax. It is a conservative
subset, not a shell interpreter. Receipts must still authenticate actual argv.
"""
from pathlib import Path


def _literal_words(command: str) -> list[str] | None:
    if (not isinstance(command, str) or len(command) > 16000
            or any(c in command for c in ('\0', '\n', '\r'))):
        return None
    words, part = [], []
    quote = None
    started = False
    index = 0
    while index < len(command):
        char = command[index]
        if quote == "'":
            if char == "'":
                quote = None
            else:
                part.append(char)
        elif char == '\\':
            if index + 1 == len(command):
                return None
            following = command[index + 1]
            # Inside double quotes, POSIX retains backslashes except before
            # $, backtick, double quote and backslash. shlex.split differs on
            # escaped $/backticks, so decode this small literal subset here.
            if quote == '"' and following not in '$`"\\':
                part.append('\\')
            else:
                index += 1
                part.append(following)
            started = True
        elif quote == '"':
            if char == '"':
                quote = None
            elif char in '$`':
                return None
            else:
                part.append(char)
        elif char in "'\"":
            quote = char
            started = True
        elif char in ' \t':
            if started:
                words.append(''.join(part))
                part = []
                started = False
        elif char in ';&|()<>$`*?[]#~{}!':
            return None
        else:
            part.append(char)
            started = True
        index += 1
    if quote:
        return None
    if started:
        words.append(''.join(part))
    return words


def literal_invocation_argv(command: str, executable: Path, *, cwd: Path) -> list[str] | None:
    """Return argv for exactly *executable*, or None for unsupported syntax.

    cwd is the installed checkout's expected command root, not a guessed
    native tool workdir. A receipt must match the returned executable/argv.
    """
    words = _literal_words(command)
    if not words:
        return None
    first = Path(words[0])
    if not first.is_absolute():
        first = cwd / first
    if first != executable:
        return None
    return [str(executable.resolve()), *words[1:]]
