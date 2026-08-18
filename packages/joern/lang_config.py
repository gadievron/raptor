"""Per-language Joern tuning: EngineConfig params, sink patterns, frontends.

Each language has different CPG characteristics — dynamic dispatch depth,
argument expansion, and dangerous-sink naming conventions. Using the same
EngineConfig for Python and C wastes time on Python (depth 4 when 2 suffices)
and misses flows in C (generic sinks like 'load' match noise).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LangProfile:
    """Joern tuning profile for a target language."""

    max_call_depth: int
    max_call_depth_targeted: int
    max_args_to_allow: int
    max_output_args_expansion: int
    sinks: tuple[str, ...]
    joern_parse_language: str = ""


PYTHON = LangProfile(
    max_call_depth=2,
    max_call_depth_targeted=2,
    max_args_to_allow=300,
    max_output_args_expansion=300,
    sinks=(
        "system", "popen", "exec", "execve", "execvp",
        "subprocess_call", "subprocess_run", "subprocess_Popen",
        "execute", "executemany", "raw",
        "loads", "load", "unserialize",
        "open",
        "render_template_string", "from_string",
        "urlopen",
    ),
    joern_parse_language="pythonsrc",
)

C_CPP = LangProfile(
    max_call_depth=4,
    max_call_depth_targeted=3,
    max_args_to_allow=200,
    max_output_args_expansion=200,
    sinks=(
        "system", "popen", "exec", "execve", "execvp", "execl", "execlp",
        "execle", "fexecve", "posix_spawn", "posix_spawnp",
        "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat",
        "strncat", "sprintf", "snprintf", "vsprintf", "vsnprintf",
        "gets", "scanf", "sscanf", "fscanf",
        "printf", "fprintf", "syslog", "dprintf", "vprintf", "vfprintf",
        "fopen", "freopen", "open", "creat",
        "connect", "bind", "send", "sendto", "sendmsg", "write",
    ),
    joern_parse_language="c",
)

JAVA = LangProfile(
    max_call_depth=4,
    max_call_depth_targeted=3,
    max_args_to_allow=200,
    max_output_args_expansion=200,
    sinks=(
        "exec", "start",
        "executeQuery", "executeUpdate", "execute", "prepareStatement",
        "createQuery", "createNativeQuery",
        "readObject", "readResolve", "fromJson", "readValue",
        "openConnection", "openStream", "connect",
        "FileInputStream", "FileOutputStream", "FileWriter", "FileReader",
        "search", "lookup",
        "evaluate", "eval", "createExpression",
        "merge", "process",
    ),
    joern_parse_language="javasrc",
)

JAVASCRIPT = LangProfile(
    max_call_depth=3,
    max_call_depth_targeted=2,
    max_args_to_allow=100,
    max_output_args_expansion=100,
    sinks=(
        "exec", "execSync", "spawn", "spawnSync", "execFile",
        "eval", "Function", "setTimeout", "setInterval",
        "query", "raw",
        "innerHTML", "outerHTML", "insertAdjacentHTML", "write", "writeln",
        "dangerouslySetInnerHTML",
        "fetch", "request",
        "readFile", "readFileSync", "writeFile", "writeFileSync",
        "createReadStream", "createWriteStream",
        "deserialize", "unserialize",
    ),
    joern_parse_language="jssrc",
)

GO = LangProfile(
    max_call_depth=3,
    max_call_depth_targeted=2,
    max_args_to_allow=50,
    max_output_args_expansion=100,
    sinks=(
        "Command", "CommandContext",
        "Query", "QueryRow", "Exec", "Prepare",
        "Open", "Create", "OpenFile", "ReadFile", "WriteFile",
        "Execute", "ExecuteTemplate",
        "Get", "Post", "Do", "NewRequest",
        "Unmarshal", "Decode", "NewDecoder",
    ),
    joern_parse_language="gosrc",
)

_PROFILES: dict[str, LangProfile] = {
    "python": PYTHON,
    "pythonsrc": PYTHON,
    "c": C_CPP,
    "cpp": C_CPP,
    "c++": C_CPP,
    "java": JAVA,
    "javasrc": JAVA,
    "javascript": JAVASCRIPT,
    "js": JAVASCRIPT,
    "jssrc": JAVASCRIPT,
    "typescript": JAVASCRIPT,
    "ts": JAVASCRIPT,
    "go": GO,
    "gosrc": GO,
}

DEFAULT = PYTHON

# Sink names for the bulk pre-sweep query (standard_sinks.sc). One
# cross-language list: the sweep runs once at CPG build time before
# the target language routing kicks in, so it mixes the C/C++ and
# dynamic-language surfaces. This is the single authority — the .sc
# template renders it through its __SINK_NAMES__ slot (the script
# used to hardcode a drifting copy).
STANDARD_SWEEP_SINKS: tuple[str, ...] = (
    # Command execution
    "system", "popen", "exec", "execve", "execvp", "execl", "execlp",
    "execle", "fexecve", "posix_spawn", "posix_spawnp",
    # Memory operations
    "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat",
    "strncat", "sprintf", "snprintf", "vsprintf", "vsnprintf",
    # Format strings
    "printf", "fprintf", "syslog",
    # File operations
    "fopen", "freopen", "open",
    # SQL / injection surfaces
    "query", "execute", "raw",
    # Deserialization
    "loads", "load", "unserialize", "pickle",
)


def scala_string_list(names: tuple[str, ...]) -> str:
    """Render a name tuple as the body of a Scala List(...) literal."""
    return ", ".join(f'"{n}"' for n in names)


def profile_for(language: str) -> LangProfile:
    """Return the tuning profile for a language, defaulting to Python."""
    return _PROFILES.get(language.lower(), DEFAULT)


def parse_languages_for(target_path: str) -> set[str] | None:
    """``joern-parse --language`` value for the target's dominant
    language, or ``None`` to let joern-parse auto-detect.

    Pins the frontend deterministically from the same extension census
    the rest of the tuning uses, instead of trusting joern-parse's own
    guess — the curated ``joern_parse_language`` values exist for
    exactly this.
    """
    lang = profile_for(detect_language(str(target_path))).joern_parse_language
    return {lang} if lang else None


def detect_language(target_path: str) -> str:
    """Best-effort language detection from file extensions in target."""
    from pathlib import Path

    counts: dict[str, int] = {}
    ext_map = {
        ".py": "python",
        ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp",
        ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
        ".java": "java",
        ".js": "javascript", ".jsx": "javascript",
        ".ts": "typescript", ".tsx": "typescript",
        ".go": "go",
    }

    _EXCLUDED_DIRS = {
        ".git", "node_modules", "vendor", "__pycache__",
        ".tox", "target", "build",
    }

    p = Path(target_path)
    if not p.is_dir():
        ext = p.suffix.lower()
        return ext_map.get(ext, "python")

    for f in p.rglob("*"):
        if any(part in _EXCLUDED_DIRS for part in f.parts):
            continue
        if f.is_file():
            lang = ext_map.get(f.suffix.lower())
            if lang:
                counts[lang] = counts.get(lang, 0) + 1

    if not counts:
        return "python"
    return max(counts, key=counts.get)
