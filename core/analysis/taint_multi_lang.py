"""Multi-language taint approximation for audit summaries.

Per-language extractors that identify function signatures, parameter
flows to dangerous sinks, and basic precondition patterns.  Each
produces FunctionSummary objects consumed by the audit orchestrator.

Supported languages: Java, JavaScript/TypeScript, Go, Rust, PHP.
(C/C++ covered by taint_approx.py + Joern; Python by taint_summaries.py)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, TYPE_CHECKING

from core.evidence import EvidenceTier

import logging

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

# Per-function callee cap — single authority shared by every
# per-language extractor and the generic consumer (they used to
# disagree: extractors capped at 30, the consumer re-sliced to 20).
_MAX_CALLEES = 20


# -- Dangerous sinks per language --

_JAVA_SINKS: set[str] = {
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

_JS_SINKS: set[str] = {
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

_GO_SINKS: set[str] = {
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

_RUST_SINKS: set[str] = {
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

_PHP_SINKS: set[str] = {
    "eval", "assert",
    "system", "exec", "passthru", "popen", "proc_open", "shell_exec",
    "include", "include_once", "require", "require_once",
    "unserialize", "header",
    "fopen", "file_get_contents", "file_put_contents", "unlink",
    "mysql_query", "mysqli_query", "query", "print",
    "call_user_func", "call_user_func_array",
}

# Request superglobals plus the stream/env source shapes the sink
# scan looks for inside sink arguments. These are not function
# parameters — matching taint rules carry source_index -1 (the
# LLM-summary convention for "no positional parameter"), which the
# upward propagation already skips.
_PHP_SUPERGLOBALS = ("$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER")
_PHP_GETENV_RE = re.compile(r"\bgetenv\s*\(")

# echo / print / include / require take no parentheses — the shared
# call-shaped sink scan never sees them.
_PHP_KEYWORD_SINK_RE = re.compile(
    r"\b(echo|print|include_once|include|require_once|require)"
    r"\s+([^;]{1,400});"
)

# The backtick operator executes its contents via the shell —
# semantically shell_exec (labelled as such in the taint rule).
_PHP_BACKTICK_RE = re.compile(r"`([^`\n]{1,400})`")


# -- Precondition patterns per language --

_JAVA_NULL_CHECK = re.compile(r"if\s*\(\s*(\w+)\s*(?:==\s*null|!=\s*null)")
_JAVA_BOUNDS_CHECK = re.compile(
    r"if\s*\(\s*(\w+)\s*(?:[<>]=?\s*\d+|\.\s*(?:length|size)\s*\(\s*\))"
)

# The whitespace after ``!`` rides inside the optional group: with a
# bare ``!?`` between them, the two ``\s*`` runs are adjacent and a
# whitespace flood after ``if (`` is quadratic. Matched language is
# unchanged — whitespace runs concatenate.
_JS_NULL_CHECK = re.compile(
    r"if\s*\(\s*(?:!\s*)?(\w+)\s*(?:===?\s*(?:null|undefined)|!==?\s*(?:null|undefined))"
)
_JS_TYPE_CHECK = re.compile(r"typeof\s+(\w+)\s*(?:===?|!==?)")

_GO_NIL_CHECK = re.compile(r"if\s+(\w+)\s*(?:==\s*nil|!=\s*nil)")
_GO_ERR_CHECK = re.compile(r"if\s+(?:err|(\w+))\s*!=\s*nil")

_PHP_ISSET_CHECK = re.compile(r"\b(?:isset|empty|is_null)\s*\(\s*\$(\w+)")
_PHP_NULL_CMP = re.compile(r"\$(\w+)\s*(?:===?|!==?)\s*null", re.IGNORECASE)
# Sanitizer application is the PHP-idiomatic guard shape; recorded as
# a precondition (same evidence granularity as the null/type checks
# above), never as flow suppression — the reviewer adjudicates.
_PHP_SANITIZER_CALL = re.compile(
    r"\b(htmlspecialchars|htmlentities|intval|escapeshellarg"
    r"|escapeshellcmd|preg_quote|basename)\s*\(\s*\$(\w+)"
)
_PHP_INT_CAST = re.compile(r"\(\s*int(?:eger)?\s*\)\s*\$(\w+)")


# -- Function extraction patterns --

# Every variable-length class in these patterns is bounded at 400
# chars (the cap the sink-argument scans already carry): an unbounded
# class re-scans to EOF from every candidate position, so an
# unclosed-paren or unclosed-generics flood is quadratic. Trade-off:
# a parameter list, generics text, or throws clause past the cap
# leaves that function unmatched — the accepted bound for these
# heuristic-tier extractors.

# No modifier prefix (same reasoning as _PHP_FUNC below): the captures
# and the body-search anchor are carried by the return-type/name/params
# tail, so when modifiers precede the return type the tail simply
# matches one word later — identical groups either way — while a
# repeated-modifier prefix is quadratic on hostile keyword floods.
# ``throws`` consumes a single whitespace char, not ``\s+``: the
# clause class also matches whitespace, and the overlap made a
# whitespace flood after ``throws`` quadratic.
_JAVA_FUNC = re.compile(
    r"\b(?:\w+(?:<[^>]{0,400}>)?)\s+"
    r"(\w+)\s*\(([^)]{0,400})\)\s*(?:throws\s[^{]{0,400})?\{"
)

_GO_FUNC = re.compile(
    r"func\s+(?:\(\s*\w+\s+\*?\w+\s*\)\s+)?(\w+)\s*\(([^)]{0,400})\)"
)

# The whitespace before the parameter list rides inside the optional
# generics group: two adjacent ``\s*`` runs separated only by an
# optional group are quadratic on a whitespace flood after ``fn name``
# (the same run splits between them every possible way). Matched
# language is unchanged — whitespace runs concatenate.
_RUST_FUNC = re.compile(
    r"(?:pub\s+)?(?:async\s+)?fn\s+(\w+)\s*(?:<[^>]{0,400}>\s*)?\(([^)]{0,400})\)"
)

# No modifier prefix: visibility keywords before ``function`` don't
# need consuming — the captures and the body-search anchor both start
# at the keyword, so a prefix adds nothing while a repeated-keyword
# alternation is quadratic on hostile keyword floods.
_PHP_FUNC = re.compile(
    r"\bfunction\s+&?(\w+)\s*\(([^)]{0,400})\)"
)


def _extract_summaries_generic(
    content: str,
    file_path: str,
    extract_functions: Callable,
    sinks: set[str],
    extract_preconditions: Callable,
    extract_callees: Callable,
    extract_extra_flows: Callable | None = None,
) -> dict[str, Any]:
    """Shared extraction logic for all language extractors.

    ``extract_extra_flows(params, body)`` covers flow shapes the
    shared param→call-sink scan cannot express — named non-parameter
    sources (PHP superglobals) and keyword-shaped sinks. It returns
    ``(source_name, source_index, sink_call, arg_index)`` tuples;
    ``source_index`` is -1 for non-parameter sources.
    """
    from core.analysis.summaries import FunctionSummary, TaintRule, Precondition

    results: dict[str, FunctionSummary] = {}

    for func_name, params, body_start, body_end in extract_functions(content):
        body = content[body_start:body_end]
        taint_rules = _find_flows_to_sinks(params, body, sinks)
        extra_flows = (
            extract_extra_flows(params, body) if extract_extra_flows else []
        )
        preconditions = extract_preconditions(params, body)
        callees = extract_callees(body)

        if (
            not taint_rules and not extra_flows
            and not preconditions and not callees
        ):
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
            ] + [
                TaintRule(
                    source_param=source_name,
                    source_index=source_index,
                    sink_call=sink,
                    sink_arg_index=ai,
                    evidence_tier=EvidenceTier.HEURISTIC,
                )
                for source_name, source_index, sink, ai in extra_flows
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
            callees=callees[:_MAX_CALLEES],
            source="mechanical",
            confidence="medium",
            evidence_tier=EvidenceTier.HEURISTIC,
        )
        results[func_name] = summary

    return results


def extract_java_summaries(content: str, file_path: str) -> dict[str, Any]:
    """Extract taint summaries from Java source."""
    return _extract_summaries_generic(
        content, file_path, _extract_java_functions, _JAVA_SINKS,
        _extract_java_preconditions, _extract_callees_java,
    )


def extract_js_summaries(content: str, file_path: str) -> dict[str, Any]:
    """Extract taint summaries from JavaScript/TypeScript source."""
    return _extract_summaries_generic(
        content, file_path, _extract_js_functions, _JS_SINKS,
        _extract_js_preconditions, _extract_callees_js,
    )


def extract_go_summaries(content: str, file_path: str) -> dict[str, Any]:
    """Extract taint summaries from Go source."""
    return _extract_summaries_generic(
        content, file_path, _extract_go_functions, _GO_SINKS,
        _extract_go_preconditions, _extract_callees_go,
    )


def extract_rust_summaries(content: str, file_path: str) -> dict[str, Any]:
    """Extract taint summaries from Rust source."""
    return _extract_summaries_generic(
        content, file_path, _extract_rust_functions, _RUST_SINKS,
        _extract_rust_preconditions, _extract_callees_rust,
    )


def extract_php_summaries(content: str, file_path: str) -> dict[str, Any]:
    """Extract taint summaries from PHP source."""
    return _extract_summaries_generic(
        content, file_path, _extract_php_functions, _PHP_SINKS,
        _extract_php_preconditions, _extract_callees_php,
        extract_extra_flows=_extract_php_extra_flows,
    )


# -- Shared taint flow detection --


def _find_flows_to_sinks(
    params: list[str],
    body: str,
    sinks: set[str],
) -> list[tuple[int, str, int]]:
    """Find parameter→sink flows in a function body.

    Returns (param_index, sink_name, arg_position) tuples.
    Uses simple regex-based tracking: if a parameter name appears
    as an argument to a known sink call, record the flow.
    """
    flows: list[tuple[int, str, int]] = []

    for sink in sinks:
        sink_short = sink.split(".")[-1] if "." in sink else sink
        # Bounded argument class (mirrors _PHP_KEYWORD_SINK_RE's cap):
        # an unbounded class is quadratic on unclosed-paren floods.
        # Trade-off: argument text past 400 chars goes unmatched —
        # same accepted bound as the keyword-sink and extra-flows
        # scans.
        pattern = re.compile(
            rf"\b{re.escape(sink_short)}\s*\(([^){{}}]{{0,400}})\)",
        )
        for match in pattern.finditer(body):
            args_str = match.group(1)
            args = [a.strip() for a in args_str.split(",")]
            for arg_idx, arg in enumerate(args):
                for param_idx, param in enumerate(params):
                    if re.search(rf"\b{re.escape(param)}\b", arg):
                        flows.append((param_idx, sink, arg_idx))

    seen: set[tuple[int, str, int]] = set()
    deduped = []
    for flow in flows:
        if flow not in seen:
            seen.add(flow)
            deduped.append(flow)
    return deduped[:30]


# -- Java helpers --


def _extract_java_functions(
    content: str,
) -> list[tuple[str, list[str], int, int]]:
    """Extract Java function definitions with bodies."""
    results = []
    matches = list(_JAVA_FUNC.finditer(content))
    scan_state = _new_scan_state(content)
    for i, match in enumerate(matches):
        name = match.group(1)
        params_str = match.group(2)
        params = _parse_java_params(params_str)
        body_start = match.end()
        next_start = (
            matches[i + 1].start() if i + 1 < len(matches) else None
        )
        body_end = _bounded_body_end(
            content, body_start - 1, next_start, scan_state,
        )
        if body_end > body_start:
            results.append((name, params, body_start, body_end))
    return results


def _parse_java_params(params_str: str) -> list[str]:
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
    params: list[str],
    body: str,
) -> list[tuple[str, str]]:
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


# Shared callee-scan bounds. Word-start anchoring (the lookbehind in
# each scanner) stops the scan re-anchoring at every character of a
# long word run, and the segment/chain caps bound the work per
# anchor — unanchored and unbounded, a hostile body of one long
# identifier or dotted chain was quadratic. Trade-off: identifiers
# past 200 chars or chains past 21 segments go unmatched — the
# accepted bound for these heuristic-tier scans.
_JAVA_CALLEE_RE = re.compile(r"(?<!\w)(\w{1,200}(?:\.\w{1,200}){0,20})\s*\(")


def _extract_callees_java(body: str) -> list[str]:
    """Extract method calls from Java function body."""
    callees: list[str] = []
    seen: set[str] = set()
    for match in _JAVA_CALLEE_RE.finditer(body):
        # Last two segments reproduce the previous obj.method shape
        # (the single-level ``(?:(\w+)\.)?(\w+)`` scan recorded only
        # the final receiver segment of a longer chain).
        segs = match.group(1).split(".")
        obj = segs[-2] if len(segs) >= 2 else ""
        method = segs[-1]
        if method in ("if", "for", "while", "switch", "catch", "return"):
            continue
        callee = f"{obj}.{method}" if obj else method
        if callee not in seen:
            seen.add(callee)
            callees.append(callee)
    return callees[:_MAX_CALLEES]


# -- JavaScript/TypeScript helpers --


def _extract_js_functions(
    content: str,
) -> list[tuple[str, list[str], int, int]]:
    """Extract JS/TS function definitions."""
    results = []

    # Named functions (with optional TS return type annotation). The
    # whitespace after the annotation rides inside the optional group
    # — two ``\s*`` runs adjacent through a skipped optional are
    # quadratic on a whitespace flood after the parameter list.
    # Parameter classes bounded like the module-level patterns': an
    # unbounded class is quadratic on unclosed-paren floods.
    named_re = re.compile(
        r"(?:async\s+)?function\s+(\w+)\s*\(([^)]{0,400})\)\s*(?::\s*\S+\s*)?\{",
    )
    named_matches = list(named_re.finditer(content))
    scan_state = _new_scan_state(content)
    for i, match in enumerate(named_matches):
        name = match.group(1)
        params = _parse_js_params(match.group(2))
        body_start = match.end()
        next_start = (
            named_matches[i + 1].start()
            if i + 1 < len(named_matches) else None
        )
        body_end = _bounded_body_end(
            content, match.end() - 1, next_start, scan_state,
        )
        if body_end > body_start:
            results.append((name, params, body_start, body_end))

    # Arrow functions and methods
    # The leading name capture anchors at a word start (lookbehind):
    # unanchored, the scan re-anchored at every character of a long
    # word run (any long identifier/base64/hex blob in a source
    # file), which is quadratic. A match starting mid-word is always
    # subsumed by the word-start attempt, so anchoring drops no
    # matches.
    method_re = re.compile(
        r"(?<!\w)(?:(?:const|let|var)\s+)?(\w+)\s*(?:=\s*(?:async\s*)?"
        r"(?:\(([^)]{0,400})\)|(\w+))\s*=>"
        r"|:\s*(?:async\s+)?function\s*\(([^)]{0,400})\)\s*\{"
        r"|\(([^)]{0,400})\)\s*\{)",
    )
    seen = {r[0] for r in results}
    method_matches = list(method_re.finditer(content))
    for i, match in enumerate(method_matches):
        name = match.group(1)
        # Keyword guard: the method regex's bare ``(...) {`` arm also
        # matches control-flow headers — ``switch (x) {`` and
        # ``catch (e) {`` read as functions named switch/catch
        # without their entries here.
        if not name or name in (
            "if", "for", "while", "return", "switch", "catch",
            "do", "else",
        ):
            continue
        params_str = (
            match.group(2) or match.group(3) or
            match.group(4) or match.group(5) or ""
        )
        params = _parse_js_params(params_str)
        body_start = match.end()
        next_start = (
            method_matches[i + 1].start()
            if i + 1 < len(method_matches) else None
        )
        body_end = _bounded_body_end(
            content, match.end() - 1, next_start, scan_state,
        )
        if body_end > body_start and name not in seen:
            seen.add(name)
            results.append((name, params, body_start, body_end))

    return results


def _parse_js_params(params_str: str) -> list[str]:
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
    params: list[str],
    body: str,
) -> list[tuple[str, str]]:
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


# Word-start anchor + bounded chain — see _JAVA_CALLEE_RE.
_JS_CALLEE_RE = re.compile(r"(?<!\w)(\w{1,200}(?:\.\w{1,200}){0,20})\s*\(")


def _extract_callees_js(body: str) -> list[str]:
    """Extract function/method calls from JS body."""
    pattern = _JS_CALLEE_RE
    callees: list[str] = []
    seen: set[str] = set()
    for match in pattern.finditer(body):
        callee = match.group(1)
        if callee in ("if", "for", "while", "switch", "catch", "return",
                      "function", "async", "class"):
            continue
        if callee not in seen:
            seen.add(callee)
            callees.append(callee)
    return callees[:_MAX_CALLEES]


# -- Go helpers --


def _extract_go_functions(
    content: str,
) -> list[tuple[str, list[str], int, int]]:
    """Extract Go function definitions."""
    results = []
    matches = list(_GO_FUNC.finditer(content))
    scan_state = _new_scan_state(content)
    for i, match in enumerate(matches):
        name = match.group(1)
        params = _parse_go_params(match.group(2))
        # Opening brace after the signature — searched in place (the
        # per-match remainder slice was itself O(L) memory traffic)
        # and only within the signature-plausible window.
        open_pos = content.find("{", match.end(), match.end() + 1000)
        if open_pos < 0:
            continue
        body_start = open_pos + 1
        next_start = (
            matches[i + 1].start() if i + 1 < len(matches) else None
        )
        body_end = _bounded_body_end(
            content, open_pos, next_start, scan_state,
        )
        if body_end > body_start:
            results.append((name, params, body_start, body_end))
    return results


def _parse_go_params(params_str: str) -> list[str]:
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
    params: list[str],
    body: str,
) -> list[tuple[str, str]]:
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


# Word-start anchor + bounded chain — see _JAVA_CALLEE_RE.
_GO_CALLEE_RE = re.compile(r"(?<!\w)(\w{1,200}(?:\.\w{1,200}){0,20})\s*\(")


def _extract_callees_go(body: str) -> list[str]:
    """Extract function calls from Go body."""
    pattern = _GO_CALLEE_RE
    callees: list[str] = []
    seen: set[str] = set()
    for match in pattern.finditer(body):
        callee = match.group(1)
        if callee in ("if", "for", "switch", "select", "go", "defer",
                      "return", "range", "func", "make", "len", "cap",
                      "append", "copy", "delete", "close", "new"):
            continue
        if callee not in seen:
            seen.add(callee)
            callees.append(callee)
    return callees[:_MAX_CALLEES]


# -- Rust helpers --


def _extract_rust_functions(
    content: str,
) -> list[tuple[str, list[str], int, int]]:
    """Extract Rust function definitions."""
    results = []
    matches = list(_RUST_FUNC.finditer(content))
    scan_state = _new_scan_state(content)
    for i, match in enumerate(matches):
        name = match.group(1)
        params = _parse_rust_params(match.group(2))
        # Opening brace after the signature — in-place bounded search
        # (see the Go extractor's rationale).
        open_pos = content.find("{", match.end(), match.end() + 1000)
        if open_pos < 0:
            continue
        body_start = open_pos + 1
        next_start = (
            matches[i + 1].start() if i + 1 < len(matches) else None
        )
        body_end = _bounded_body_end(
            content, open_pos, next_start, scan_state,
            rust_lifetimes=True,
        )
        if body_end > body_start:
            results.append((name, params, body_start, body_end))
    return results


def _parse_rust_params(params_str: str) -> list[str]:
    """Parse Rust parameter list into names."""
    params = []
    for part in params_str.split(","):
        part = part.strip()
        if not part or part == "self" or part.startswith("&self"):
            continue
        # Rust: "name: Type" or "mut name: Type". ``mut`` is a
        # whole token — a bare removeprefix("mut") truncated names
        # that merely START with it ("mutation" -> "ation", breaking
        # every body match for the param).
        colon_idx = part.find(":")
        if colon_idx > 0:
            name_part = part[:colon_idx].strip()
            name_part = name_part.lstrip("&").strip()
            name_part = re.sub(r"^mut\s+", "", name_part).strip()
            if name_part:
                params.append(name_part)
    return params


def _extract_rust_preconditions(
    params: list[str],
    body: str,
) -> list[tuple[str, str]]:
    """Extract precondition patterns from Rust function body."""
    preconditions: list[tuple[str, str]] = []
    # assert! / debug_assert!
    assert_re = re.compile(r"(?:debug_)?assert!\s*\(\s*([^,)]+)")
    for match in assert_re.finditer(body):
        expr = match.group(1)
        preconditions.extend((param, f"asserted: {expr.strip()[:60]}") for param in params if re.search(rf"\b{re.escape(param)}\b", expr))
    # Option/Result checks
    preconditions.extend((param, "option/result checked") for param in params if re.search(rf"\b{re.escape(param)}\b\s*\.\s*(?:is_some|is_none|is_ok|is_err)\s*\(", body))
    return preconditions


# Word-start anchor + bounded chain — see _JAVA_CALLEE_RE.
_RUST_CALLEE_RE = re.compile(r"(?<!\w)(\w{1,200}(?:::\w{1,200}){0,20})\s*[!(]\s*")


def _extract_callees_rust(body: str) -> list[str]:
    """Extract function/method calls from Rust body."""
    pattern = _RUST_CALLEE_RE
    callees: list[str] = []
    seen: set[str] = set()
    for match in pattern.finditer(body):
        callee = match.group(1)
        if callee in ("if", "for", "while", "loop", "match", "return",
                      "let", "mut", "fn", "pub", "use", "mod",
                      "impl", "struct", "enum", "trait", "type"):
            continue
        if callee not in seen:
            seen.add(callee)
            callees.append(callee)
    return callees[:_MAX_CALLEES]


# -- PHP helpers --


def _extract_php_functions(
    content: str,
) -> list[tuple[str, list[str], int, int]]:
    """Extract PHP function/method definitions with bodies."""
    results = []
    for match in _PHP_FUNC.finditer(content):
        name = match.group(1)
        params = _parse_php_params(match.group(2))
        # Opening brace after the signature (skips a return type).
        rest = content[match.end():]
        brace_offset = rest.find("{")
        if brace_offset < 0:
            continue
        # Body-less declarations (interface/abstract methods) end in
        # ';' before any brace — the next '{' belongs to a later
        # definition and must not be claimed as this one's body.
        semi_offset = rest.find(";")
        if 0 <= semi_offset < brace_offset:
            continue
        body_start = match.end() + brace_offset + 1
        body_end = _find_brace_end(
            content, match.end() + brace_offset, hash_comments=True,
        )
        if body_end > body_start:
            results.append((name, params, body_start, body_end))
    return results


def _parse_php_params(params_str: str) -> list[str]:
    """Parse a PHP parameter list into names (without the ``$``).

    The sigil is dropped so the shared body matchers' ``\\b<name>\\b``
    searches work (``\\b`` never matches before ``$``); defaults are
    constant expressions, so the first ``$name`` in a part is always
    the parameter itself.
    """
    params = []
    for part in params_str.split(","):
        m = re.search(r"\$(\w+)", part)
        if m:
            params.append(m.group(1))
    return params


def _extract_php_preconditions(
    params: list[str],
    body: str,
) -> list[tuple[str, str]]:
    """Extract precondition patterns from a PHP function body."""
    preconditions = []
    for match in _PHP_ISSET_CHECK.finditer(body):
        var = match.group(1)
        if var in params:
            preconditions.append((var, "isset/empty checked"))
    for match in _PHP_NULL_CMP.finditer(body):
        var = match.group(1)
        if var in params:
            preconditions.append((var, "null check"))
    for match in _PHP_SANITIZER_CALL.finditer(body):
        fn, var = match.group(1), match.group(2)
        if var in params:
            preconditions.append((var, f"sanitized: {fn}"))
    for match in _PHP_INT_CAST.finditer(body):
        var = match.group(1)
        if var in params:
            preconditions.append((var, "cast to int"))
    return preconditions


# Word-start anchor + bounded segments — see _JAVA_CALLEE_RE.
_PHP_CALLEE_RE = re.compile(r"(?<!\w)((?:\w{1,200}::)?\w{1,200})\s*\(")


def _extract_callees_php(body: str) -> list[str]:
    """Extract function/method calls from a PHP body."""
    pattern = _PHP_CALLEE_RE
    callees: list[str] = []
    seen: set[str] = set()
    for match in pattern.finditer(body):
        callee = match.group(1)
        if callee in ("if", "for", "foreach", "while", "switch",
                      "catch", "return", "function", "fn", "match",
                      "array", "list", "isset", "unset", "empty",
                      "use", "exit", "die", "echo", "print"):
            continue
        if callee not in seen:
            seen.add(callee)
            callees.append(callee)
    return callees[:_MAX_CALLEES]


def _php_sources_in(text: str) -> list[str]:
    """Non-parameter taint sources named inside an expression."""
    out = [sg for sg in _PHP_SUPERGLOBALS if sg in text]
    if "php://input" in text:
        out.append("php://input")
    if _PHP_GETENV_RE.search(text):
        out.append("getenv")
    return out


def _extract_php_extra_flows(
    params: list[str],
    body: str,
) -> list[tuple[str, int, str, int]]:
    """PHP flow shapes outside the shared param→call-sink scan.

    Three shapes: superglobal/stream/env sources into call-shaped
    sinks, keyword-shaped sinks (echo/print/include/require take no
    parentheses), and the backtick operator (labelled ``shell_exec``,
    which the manual defines it as identical to). Non-parameter
    sources carry index -1.
    """
    flows: list[tuple[str, int, str, int]] = []
    seen: set[tuple[str, str, int]] = set()

    def _add(name: str, idx: int, sink: str, ai: int) -> None:
        key = (name, sink, ai)
        if key not in seen:
            seen.add(key)
            flows.append((name, idx, sink, ai))

    for sink in _PHP_SINKS:
        # Bounded argument class (mirrors _PHP_KEYWORD_SINK_RE's cap):
        # an unbounded class is quadratic on unclosed-paren floods.
        pattern = re.compile(rf"\b{re.escape(sink)}\s*\(([^){{}}]{{0,400}})\)")
        for match in pattern.finditer(body):
            args = [a.strip() for a in match.group(1).split(",")]
            for ai, arg in enumerate(args):
                for src in _php_sources_in(arg):
                    _add(src, -1, sink, ai)

    def _expr_flows(expr: str, sink: str) -> None:
        for src in _php_sources_in(expr):
            _add(src, -1, sink, 0)
        for pi, param in enumerate(params):
            if re.search(rf"\${re.escape(param)}\b", expr):
                _add(param, pi, sink, 0)

    for match in _PHP_KEYWORD_SINK_RE.finditer(body):
        _expr_flows(match.group(2), match.group(1))
    for match in _PHP_BACKTICK_RE.finditer(body):
        _expr_flows(match.group(1), "shell_exec")

    return flows[:30]


# -- Shared utilities --


# Hard per-body extent cap. Heuristic-tier summaries only feed audit
# prompt context, so truncating an implausibly long body loses hint
# coverage, never suppression authority; without a cap one unclosed
# brace makes a "body" out of the rest of the file.
_MAX_BODY_CHARS = 20000

# Per-file amortised brace-scan budget: legitimate nesting scans each
# byte once per nesting level (total ≈ depth × file size, well under
# 8×), while N hostile unclosed headers would each scan up to the
# per-body cap — the budget lets the first few pay full price and
# clamps the rest at the next header for free.
_SCAN_BUDGET_FLOOR = 1_000_000
_SCAN_BUDGET_FACTOR = 8


def _bounded_body_end(
    content: str,
    open_pos: int,
    next_start: int | None,
    scan_state: dict[str, int],
    *,
    rust_lifetimes: bool = False,
) -> int:
    """Body end for the brace at ``open_pos``, bounded two ways.

    A PROPERLY CLOSED body within the per-body cap keeps its true
    extent even when later function headers sit inside it (nested
    named functions are pervasive legitimate code — clamping them at
    the next header truncated real outer bodies). An UNCLOSED body
    (hostile flood, minified/truncated source) — or any body once the
    per-file scan budget is spent — clamps at the next header's start
    so N overlapping extents can never re-scan the file N times.
    """
    cap_limit = min(len(content), open_pos + 1 + _MAX_BODY_CHARS)
    clamp = cap_limit
    if next_start is not None:
        clamp = min(clamp, max(next_start, open_pos + 1))
    if scan_state["used"] >= scan_state["budget"]:
        return clamp
    end = _find_brace_end(
        content, open_pos, rust_lifetimes=rust_lifetimes,
        limit=cap_limit,
    )
    scan_state["used"] += max(0, end - open_pos)
    if end >= cap_limit:
        # Ran to the bound without closing — treat as unclosed.
        return clamp
    return end


def _new_scan_state(content: str) -> dict[str, int]:
    return {
        "used": 0,
        "budget": max(_SCAN_BUDGET_FLOOR,
                      _SCAN_BUDGET_FACTOR * len(content)),
    }


# A Rust character literal at a given position: 'x', '\n', '\'',
# '\u{1F600}'. Anything else starting with an apostrophe is a
# lifetime ('a, 'static) or a loop label ('outer:) — NOT a string
# opener.
_RUST_CHAR_LITERAL = re.compile(
    r"'(?:\\u\{[0-9a-fA-F_]{1,6}\}|\\.|[^\\'])'"
)


def _find_brace_end(
    content: str, open_pos: int, *, rust_lifetimes: bool = False,
    hash_comments: bool = False,
    limit: int | None = None,
) -> int:
    """Find the matching close brace for an open brace at open_pos.

    ``rust_lifetimes=True`` (the Rust extractor) changes apostrophe
    handling: ``'`` opens a character literal only when a complete
    one starts at that position; otherwise it is a lifetime or loop
    label. Treating every apostrophe as a string opener made
    ``&'static str`` swallow all following braces up to the next
    stray apostrophe, corrupting the extracted body extents.

    ``hash_comments=True`` (the PHP extractor) treats ``#`` as a
    line comment opener, so a brace or quote in a ``#`` comment
    cannot corrupt the extents. PHP's backtick operator is masked by
    the shared string handling.

    ``limit`` bounds the SCAN, not just the result: an unclosed body
    (hostile or truncated/minified source) otherwise runs to EOF, and
    N overlapping such bodies re-scan the file N times — O(N·L) at
    26.9s for 2000 unclosed headers in a 48KB file, ~50 min for one
    file at the 500KB audit-prep cap. Callers pass the next function
    header's start (plus a hard per-body character cap); the return
    value never exceeds it.
    """
    if open_pos >= len(content) or content[open_pos] != "{":
        return open_pos
    depth = 1
    pos = open_pos + 1
    length = len(content)
    if limit is not None:
        length = min(length, max(limit, open_pos + 1))
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
        elif rust_lifetimes and ch == "'":
            m = _RUST_CHAR_LITERAL.match(content, pos)
            if m is not None:
                # Skip the whole char literal in one step (the -1
                # compensates for the shared pos += 1 below).
                pos = m.end() - 1
            # else: lifetime / label — no state change.
        elif ch in ('"', "'", "`"):
            in_string = True
            string_char = ch
        elif hash_comments and ch == "#":
            pos = content.find("\n", pos + 1)
            if pos < 0:
                # Unterminated line comment at EOF — same treatment
                # as the // branch below.
                pos = length
                break
        elif ch == "/" and pos + 1 < length:
            nxt = content[pos + 1]
            if nxt == "/":
                pos = content.find("\n", pos + 2)
                if pos < 0:
                    # Unterminated line comment at EOF — same
                    # treatment as an unterminated block comment.
                    pos = length
                    break
            elif nxt == "*":
                end = content.find("*/", pos + 2)
                pos = end + 1 if end >= 0 else length
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        pos += 1
    # Comment skips can jump past the bound — never report beyond it.
    return min(pos, length)


# -- Dispatch --


_LANG_EXTENSIONS: dict[str, str] = {
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mjs": "javascript",
    ".go": "go",
    ".rs": "rust",
    ".php": "php",
}


def extract_summaries_for_file(
    content: str,
    file_path: str,
) -> dict[str, Any]:
    """Dispatch to the appropriate language extractor based on file extension."""
    ext = Path(file_path).suffix.lower()
    lang = _LANG_EXTENSIONS.get(ext)

    if lang == "java":
        return extract_java_summaries(content, file_path)
    if lang in ("javascript", "typescript"):
        return extract_js_summaries(content, file_path)
    if lang == "go":
        return extract_go_summaries(content, file_path)
    if lang == "rust":
        return extract_rust_summaries(content, file_path)
    if lang == "php":
        return extract_php_summaries(content, file_path)

    return {}
