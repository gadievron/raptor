"""Multi-language taint approximation for audit summaries.

Per-language extractors that identify function signatures, parameter
flows to dangerous sinks, and basic precondition patterns.  Each
produces FunctionSummary objects consumed by the audit orchestrator.

Supported languages: Java, JavaScript/TypeScript, Go, Rust.
(C/C++ covered by taint_approx.py + Joern; Python by taint_summaries.py)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Set, Tuple

from core.evidence import EvidenceTier

import logging

logger = logging.getLogger(__name__)


# -- Dangerous sinks per language --

_JAVA_SINKS: Set[str] = {
    "Runtime.exec", "ProcessBuilder", "exec",
    "Statement.execute", "Statement.executeQuery", "Statement.executeUpdate",
    "PreparedStatement.execute", "executeQuery", "executeUpdate",
    "ObjectInputStream.readObject", "readObject",
    "sendRedirect", "forward", "include",
    "Files.write", "FileOutputStream", "FileWriter",
    "Class.forName", "Method.invoke", "invoke",
    "getRuntime", "loadLibrary", "System.load",
    "Cipher.getInstance", "MessageDigest.getInstance",
    "XPath.evaluate", "evaluate",
    "DocumentBuilder.parse", "SAXParser.parse",
    "Runtime.getRuntime",
}

_JS_SINKS: Set[str] = {
    "eval", "Function", "setTimeout", "setInterval",
    "exec", "execSync", "spawn", "spawnSync", "fork",
    "child_process.exec", "child_process.spawn",
    "innerHTML", "outerHTML", "document.write", "insertAdjacentHTML",
    "fs.writeFile", "fs.writeFileSync", "fs.appendFile",
    "require", "import",
    "sql", "query", "raw",
    "res.redirect", "res.send", "res.render",
    "JSON.parse", "deserialize", "unserialize",
    "crypto.createCipher",
}

_GO_SINKS: Set[str] = {
    "exec.Command", "exec.CommandContext",
    "os.Create", "os.OpenFile", "os.WriteFile",
    "ioutil.WriteFile", "os.Remove",
    "sql.Query", "sql.Exec", "db.Query", "db.Exec",
    "db.QueryRow", "db.Prepare",
    "http.Redirect", "template.HTML",
    "fmt.Fprintf", "fmt.Sprintf",
    "io.Copy", "io.ReadAll",
    "json.Unmarshal", "xml.Unmarshal", "gob.Decode",
    "reflect.ValueOf",
    "unsafe.Pointer",
}

_RUST_SINKS: Set[str] = {
    "Command::new", "process::Command",
    "File::create", "File::open", "fs::write",
    "std::fs::remove_file", "std::fs::remove_dir",
    "from_raw_parts", "transmute", "read_unaligned",
    "write_unaligned",
    "unsafe",
    "sqlx::query", "diesel::sql_query",
    "serde_json::from_str", "bincode::deserialize",
    "hyper::body::to_bytes",
    "ptr::read", "ptr::write", "ptr::copy",
    "slice::from_raw_parts",
    "String::from_utf8_unchecked",
}

# -- Precondition patterns per language --

_JAVA_NULL_CHECK = re.compile(r"if\s*\(\s*(\w+)\s*(?:==\s*null|!=\s*null)")
_JAVA_BOUNDS_CHECK = re.compile(
    r"if\s*\(\s*(\w+)\s*(?:[<>]=?\s*\d+|\.\s*(?:length|size)\s*\(\s*\))"
)

_JS_NULL_CHECK = re.compile(
    r"if\s*\(\s*!?\s*(\w+)\s*(?:===?\s*(?:null|undefined)|!==?\s*(?:null|undefined))"
)
_JS_TYPE_CHECK = re.compile(r"typeof\s+(\w+)\s*(?:===?|!==?)")

_GO_NIL_CHECK = re.compile(r"if\s+(\w+)\s*(?:==\s*nil|!=\s*nil)")
_GO_ERR_CHECK = re.compile(r"if\s+(?:err|(\w+))\s*!=\s*nil")

_RUST_OPTION_CHECK = re.compile(
    r"(?:\.unwrap\(\)|\.expect\(|\.is_some\(\)|\.is_none\(\))"
    r"|if\s+let\s+Some\((\w+)\)"
)


# -- Function extraction patterns --

_JAVA_FUNC = re.compile(
    r"(?:public|private|protected|static|\s)+\s+"
    r"(?:\w+(?:<[^>]*>)?)\s+"
    r"(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[^{]*)?\{"
)

_JS_FUNC = re.compile(
    r"(?:(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)"
    r"|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?"
    r"(?:\([^)]*\)|(\w+))\s*=>"
    r"|(\w+)\s*\(([^)]*)\)\s*\{)"
)

_GO_FUNC = re.compile(
    r"func\s+(?:\(\s*\w+\s+\*?\w+\s*\)\s+)?(\w+)\s*\(([^)]*)\)"
)

_RUST_FUNC = re.compile(
    r"(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)"
)


def _extract_summaries_generic(
    content: str,
    file_path: str,
    extract_functions: Callable,
    sinks: Set[str],
    extract_preconditions: Callable,
    extract_callees: Callable,
) -> Dict[str, Any]:
    """Shared extraction logic for all language extractors."""
    from core.analysis.summaries import FunctionSummary, TaintRule, Precondition

    results: Dict[str, FunctionSummary] = {}

    for func_name, params, body_start, body_end in extract_functions(content):
        body = content[body_start:body_end]
        taint_rules = _find_flows_to_sinks(params, body, sinks)
        preconditions = extract_preconditions(params, body)
        callees = extract_callees(body)

        if not taint_rules and not preconditions and not callees:
            continue

        summary = FunctionSummary(
            function=func_name,
            file=file_path,
            taint_rules=[
                TaintRule(
                    source_param=params[pi],
                    source_index=pi,
                    sink_call=sink,
                    sink_arg_index=ai,
                    evidence_tier=EvidenceTier.HEURISTIC,
                )
                for pi, sink, ai in taint_rules
            ],
            preconditions=[
                Precondition(
                    param=p, param_index=params.index(p),
                    conditions=[cond],
                    evidence_tier=EvidenceTier.HEURISTIC,
                )
                for p, cond in preconditions
                if p in params
            ],
            callees=callees[:20],
            source="mechanical",
            confidence="medium",
            evidence_tier=EvidenceTier.HEURISTIC,
        )
        results[func_name] = summary

    return results


def extract_java_summaries(content: str, file_path: str) -> Dict[str, Any]:
    """Extract taint summaries from Java source."""
    return _extract_summaries_generic(
        content, file_path, _extract_java_functions, _JAVA_SINKS,
        _extract_java_preconditions, _extract_callees_java,
    )


def extract_js_summaries(content: str, file_path: str) -> Dict[str, Any]:
    """Extract taint summaries from JavaScript/TypeScript source."""
    return _extract_summaries_generic(
        content, file_path, _extract_js_functions, _JS_SINKS,
        _extract_js_preconditions, _extract_callees_js,
    )


def extract_go_summaries(content: str, file_path: str) -> Dict[str, Any]:
    """Extract taint summaries from Go source."""
    return _extract_summaries_generic(
        content, file_path, _extract_go_functions, _GO_SINKS,
        _extract_go_preconditions, _extract_callees_go,
    )


def extract_rust_summaries(content: str, file_path: str) -> Dict[str, Any]:
    """Extract taint summaries from Rust source."""
    return _extract_summaries_generic(
        content, file_path, _extract_rust_functions, _RUST_SINKS,
        _extract_rust_preconditions, _extract_callees_rust,
    )


# -- Shared taint flow detection --


def _find_flows_to_sinks(
    params: List[str],
    body: str,
    sinks: Set[str],
) -> List[Tuple[int, str, int]]:
    """Find parameter→sink flows in a function body.

    Returns (param_index, sink_name, arg_position) tuples.
    Uses simple regex-based tracking: if a parameter name appears
    as an argument to a known sink call, record the flow.
    """
    flows: List[Tuple[int, str, int]] = []

    for sink in sinks:
        sink_short = sink.split(".")[-1] if "." in sink else sink
        pattern = re.compile(
            rf"\b{re.escape(sink_short)}\s*\(([^){{}}]*)\)",
        )
        for match in pattern.finditer(body):
            args_str = match.group(1)
            args = [a.strip() for a in args_str.split(",")]
            for arg_idx, arg in enumerate(args):
                for param_idx, param in enumerate(params):
                    if re.search(rf"\b{re.escape(param)}\b", arg):
                        flows.append((param_idx, sink, arg_idx))

    seen: Set[Tuple[int, str, int]] = set()
    deduped = []
    for flow in flows:
        if flow not in seen:
            seen.add(flow)
            deduped.append(flow)
    return deduped[:30]


# -- Java helpers --


def _extract_java_functions(
    content: str,
) -> List[Tuple[str, List[str], int, int]]:
    """Extract Java function definitions with bodies."""
    results = []
    for match in _JAVA_FUNC.finditer(content):
        name = match.group(1)
        params_str = match.group(2)
        params = _parse_java_params(params_str)
        body_start = match.end()
        body_end = _find_brace_end(content, body_start - 1)
        if body_end > body_start:
            results.append((name, params, body_start, body_end))
    return results


def _parse_java_params(params_str: str) -> List[str]:
    """Parse Java parameter list into parameter names."""
    params = []
    for part in params_str.split(","):
        part = part.strip()
        if not part:
            continue
        # "Type name" or "Type<Generic> name" or "final Type name"
        tokens = part.split()
        if tokens:
            name = tokens[-1]
            # Strip annotations
            if name.startswith("@"):
                continue
            params.append(name)
    return params


def _extract_java_preconditions(
    params: List[str],
    body: str,
) -> List[Tuple[str, str]]:
    """Extract precondition patterns from Java function body."""
    preconditions = []
    for match in _JAVA_NULL_CHECK.finditer(body):
        var = match.group(1)
        if var in params:
            preconditions.append((var, "must not be null"))
    for match in _JAVA_BOUNDS_CHECK.finditer(body):
        var = match.group(1)
        if var in params:
            preconditions.append((var, "bounds checked"))
    return preconditions


def _extract_callees_java(body: str) -> List[str]:
    """Extract method calls from Java function body."""
    pattern = re.compile(r"(?:(\w+)\.)?(\w+)\s*\(")
    callees: List[str] = []
    seen: Set[str] = set()
    for match in pattern.finditer(body):
        obj = match.group(1) or ""
        method = match.group(2)
        if method in ("if", "for", "while", "switch", "catch", "return"):
            continue
        callee = f"{obj}.{method}" if obj else method
        if callee not in seen:
            seen.add(callee)
            callees.append(callee)
    return callees[:30]


# -- JavaScript/TypeScript helpers --


def _extract_js_functions(
    content: str,
) -> List[Tuple[str, List[str], int, int]]:
    """Extract JS/TS function definitions."""
    results = []

    # Named functions (with optional TS return type annotation)
    named_re = re.compile(
        r"(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)\s*(?::\s*\S+)?\s*\{",
    )
    for match in named_re.finditer(content):
        name = match.group(1)
        params = _parse_js_params(match.group(2))
        body_start = match.end()
        body_end = _find_brace_end(content, match.end() - 1)
        if body_end > body_start:
            results.append((name, params, body_start, body_end))

    # Arrow functions and methods
    method_re = re.compile(
        r"(?:(?:const|let|var)\s+)?(\w+)\s*(?:=\s*(?:async\s*)?"
        r"(?:\(([^)]*)\)|(\w+))\s*=>|:\s*(?:async\s+)?function\s*\(([^)]*)\)\s*\{"
        r"|\(([^)]*)\)\s*\{)",
    )
    for match in method_re.finditer(content):
        name = match.group(1)
        if not name or name in ("if", "for", "while", "return"):
            continue
        params_str = (
            match.group(2) or match.group(3) or
            match.group(4) or match.group(5) or ""
        )
        params = _parse_js_params(params_str)
        body_start = match.end()
        body_end = _find_brace_end(content, match.end() - 1)
        if body_end > body_start and name not in [r[0] for r in results]:
            results.append((name, params, body_start, body_end))

    return results


def _parse_js_params(params_str: str) -> List[str]:
    """Parse JS parameter list into names."""
    params = []
    for part in params_str.split(","):
        part = part.strip()
        if not part:
            continue
        # Handle destructuring, defaults, type annotations
        name = re.match(r"(\w+)", part)
        if name:
            params.append(name.group(1))
    return params


def _extract_js_preconditions(
    params: List[str],
    body: str,
) -> List[Tuple[str, str]]:
    """Extract precondition patterns from JS function body."""
    preconditions = []
    for match in _JS_NULL_CHECK.finditer(body):
        var = match.group(1)
        if var in params:
            preconditions.append((var, "null/undefined check"))
    for match in _JS_TYPE_CHECK.finditer(body):
        var = match.group(1)
        if var in params:
            preconditions.append((var, "type checked"))
    return preconditions


def _extract_callees_js(body: str) -> List[str]:
    """Extract function/method calls from JS body."""
    pattern = re.compile(r"(?:(\w+(?:\.\w+)*))\s*\(")
    callees: List[str] = []
    seen: Set[str] = set()
    for match in pattern.finditer(body):
        callee = match.group(1)
        if callee in ("if", "for", "while", "switch", "catch", "return",
                      "function", "async", "class"):
            continue
        if callee not in seen:
            seen.add(callee)
            callees.append(callee)
    return callees[:30]


# -- Go helpers --


def _extract_go_functions(
    content: str,
) -> List[Tuple[str, List[str], int, int]]:
    """Extract Go function definitions."""
    results = []
    for match in _GO_FUNC.finditer(content):
        name = match.group(1)
        params = _parse_go_params(match.group(2))
        # Find opening brace after the signature
        rest = content[match.end():]
        brace_offset = rest.find("{")
        if brace_offset < 0:
            continue
        body_start = match.end() + brace_offset + 1
        body_end = _find_brace_end(content, match.end() + brace_offset)
        if body_end > body_start:
            results.append((name, params, body_start, body_end))
    return results


def _parse_go_params(params_str: str) -> List[str]:
    """Parse Go parameter list into names."""
    params = []
    for part in params_str.split(","):
        part = part.strip()
        if not part:
            continue
        # Go: "name type" or "name, name type"
        tokens = part.split()
        if tokens:
            name = tokens[0]
            if name.startswith("*") or name.startswith("..."):
                name = name.lstrip("*.")
            params.append(name)
    return params


def _extract_go_preconditions(
    params: List[str],
    body: str,
) -> List[Tuple[str, str]]:
    """Extract precondition patterns from Go function body."""
    preconditions = []
    for match in _GO_NIL_CHECK.finditer(body):
        var = match.group(1)
        if var in params:
            preconditions.append((var, "nil check"))
    for match in _GO_ERR_CHECK.finditer(body):
        var = match.group(1)
        if var and var in params:
            preconditions.append((var, "error check"))
    return preconditions


def _extract_callees_go(body: str) -> List[str]:
    """Extract function calls from Go body."""
    pattern = re.compile(r"(\w+(?:\.\w+)*)\s*\(")
    callees: List[str] = []
    seen: Set[str] = set()
    for match in pattern.finditer(body):
        callee = match.group(1)
        if callee in ("if", "for", "switch", "select", "go", "defer",
                      "return", "range", "func", "make", "len", "cap",
                      "append", "copy", "delete", "close", "new"):
            continue
        if callee not in seen:
            seen.add(callee)
            callees.append(callee)
    return callees[:30]


# -- Rust helpers --


def _extract_rust_functions(
    content: str,
) -> List[Tuple[str, List[str], int, int]]:
    """Extract Rust function definitions."""
    results = []
    for match in _RUST_FUNC.finditer(content):
        name = match.group(1)
        params = _parse_rust_params(match.group(2))
        # Find opening brace
        rest = content[match.end():]
        brace_offset = rest.find("{")
        if brace_offset < 0:
            continue
        body_start = match.end() + brace_offset + 1
        body_end = _find_brace_end(content, match.end() + brace_offset)
        if body_end > body_start:
            results.append((name, params, body_start, body_end))
    return results


def _parse_rust_params(params_str: str) -> List[str]:
    """Parse Rust parameter list into names."""
    params = []
    for part in params_str.split(","):
        part = part.strip()
        if not part or part == "self" or part.startswith("&self"):
            continue
        # Rust: "name: Type" or "mut name: Type"
        colon_idx = part.find(":")
        if colon_idx > 0:
            name_part = part[:colon_idx].strip()
            name_part = name_part.lstrip("&").removeprefix("mut").strip()
            if name_part:
                params.append(name_part)
    return params


def _extract_rust_preconditions(
    params: List[str],
    body: str,
) -> List[Tuple[str, str]]:
    """Extract precondition patterns from Rust function body."""
    preconditions = []
    # assert! / debug_assert!
    assert_re = re.compile(r"(?:debug_)?assert!\s*\(\s*([^,)]+)")
    for match in assert_re.finditer(body):
        expr = match.group(1)
        for param in params:
            if re.search(rf"\b{re.escape(param)}\b", expr):
                preconditions.append((param, f"asserted: {expr.strip()[:60]}"))
    # Option/Result checks
    for param in params:
        if re.search(rf"\b{re.escape(param)}\b\s*\.\s*(?:is_some|is_none|is_ok|is_err)\s*\(", body):
            preconditions.append((param, "option/result checked"))
    return preconditions


def _extract_callees_rust(body: str) -> List[str]:
    """Extract function/method calls from Rust body."""
    pattern = re.compile(r"(\w+(?:::\w+)*)\s*[!(]\s*")
    callees: List[str] = []
    seen: Set[str] = set()
    for match in pattern.finditer(body):
        callee = match.group(1)
        if callee in ("if", "for", "while", "loop", "match", "return",
                      "let", "mut", "fn", "pub", "use", "mod",
                      "impl", "struct", "enum", "trait", "type"):
            continue
        if callee not in seen:
            seen.add(callee)
            callees.append(callee)
    return callees[:30]


# -- Shared utilities --


def _find_brace_end(content: str, open_pos: int) -> int:
    """Find the matching close brace for an open brace at open_pos."""
    if open_pos >= len(content) or content[open_pos] != "{":
        return open_pos
    depth = 1
    pos = open_pos + 1
    length = len(content)
    in_string = False
    string_char = ""
    while pos < length and depth > 0:
        ch = content[pos]
        if in_string:
            if ch == string_char:
                n_bs = 0
                scan = pos - 1
                while scan >= 0 and content[scan] == "\\":
                    n_bs += 1
                    scan -= 1
                if n_bs % 2 == 0:
                    in_string = False
        elif ch in ('"', "'", "`"):
            in_string = True
            string_char = ch
        elif ch == "/" and pos + 1 < length:
            nxt = content[pos + 1]
            if nxt == "/":
                pos = content.find("\n", pos + 2)
                if pos < 0:
                    break
            elif nxt == "*":
                end = content.find("*/", pos + 2)
                pos = end + 1 if end >= 0 else length
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        pos += 1
    return pos


# -- Dispatch --


_LANG_EXTENSIONS: Dict[str, str] = {
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mjs": "javascript",
    ".go": "go",
    ".rs": "rust",
}


def extract_summaries_for_file(
    content: str,
    file_path: str,
) -> Dict[str, Any]:
    """Dispatch to the appropriate language extractor based on file extension."""
    ext = Path(file_path).suffix.lower()
    lang = _LANG_EXTENSIONS.get(ext)

    if lang == "java":
        return extract_java_summaries(content, file_path)
    elif lang in ("javascript", "typescript"):
        return extract_js_summaries(content, file_path)
    elif lang == "go":
        return extract_go_summaries(content, file_path)
    elif lang == "rust":
        return extract_rust_summaries(content, file_path)

    return {}
