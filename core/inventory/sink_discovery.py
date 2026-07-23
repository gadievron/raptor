"""Mechanical sink discovery from call graphs.

Given a project's per-file call graphs, this module:

1. Identifies functions that directly call known dangerous targets
   (``os.execute``, ``subprocess.run``, ``eval``, etc.)
2. Computes transitive reverse reachability — which functions can
   transitively reach a dangerous sink through the call chain
3. Discovers framework APIs autonomously from call-target frequency
4. Returns structured data for context-map.json enrichment

Language-agnostic: works on any call graph produced by
:mod:`core.inventory.call_graph` (Python, JS, C, Lua, Go, etc.).

For C/C++ binary-level sinks, see :mod:`core.function_taxonomy` —
that module catalogs dangerous functions for binary analysis. This
module covers source-level call patterns across all languages.

Primary consumers:
- ``/understand --map`` (MAP-5f) — enriches context-map with
  mechanically-discovered sinks and reverse reachability
- ``/audit`` — identifies functions that need injection review
"""

from __future__ import annotations

import functools
import heapq
import logging
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from core.inventory.call_graph import FileCallGraph

logger = logging.getLogger(__name__)

# ── Source-level dangerous call targets ─────────────────────────────
# Qualified dotted names matched against the full call chain. Only
# targets where attacker-controlled input reaching the call is
# categorically a security bug. Broad names ("open", "execute",
# "raw") are deliberately excluded — they fire too often on benign
# calls.
#
# C/C++ bare names (system, popen, execve, ...) are in
# core.function_taxonomy.EXEC_FUNCS. They're merged at runtime
# to avoid duplication.

_SOURCE_LEVEL_SINKS: FrozenSet[str] = frozenset({
    # Python — shell execution
    "os.system",
    "os.popen",
    "subprocess.call",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.check_output",
    "subprocess.check_call",
    # Python — code execution / deserialization
    "eval",
    "exec",
    "compile",
    "pickle.loads",
    "pickle.load",
    "yaml.load",
    "marshal.loads",
    # Lua — shell / code execution
    "os.execute",
    "io.popen",
    "loadstring",
    "dofile",
    "loadfile",
    "nixio.exec",
    "nixio.execp",
    # JS — code execution
    "Function",
    # Ruby — shell / code execution / deserialization
    "Kernel.system",
    "Kernel.exec",
    "Kernel.eval",
    "Kernel.send",
    "system",
    "Marshal.load",
    # Java — process execution
    "Runtime.exec",
    "ProcessBuilder",
    # PHP — shell / code execution
    "passthru",
    "shell_exec",
    "popen",
    # Go
    "exec.Command",
    "os/exec.Command",
    # Rust — process execution
    "Command::new",
    # Python — file / path sinks (attacker-controlled path = traversal / overwrite)
    "open",
    "io.open",
    "os.open",
    "os.remove",
    "os.unlink",
    "os.rename",
    "os.symlink",
    "os.chmod",
    "shutil.rmtree",
    "shutil.copy",
    "shutil.copyfile",
    "shutil.move",
    "tempfile.mktemp",
    # Python — deserialization (missing from above)
    "yaml.unsafe_load",
    "yaml.full_load",
    "jsonpickle.decode",
    "shelve.open",
    # Python — dynamic import (code execution)
    "__import__",
    "importlib.import_module",
    # ── SSRF / outbound request with user-controlled URL ──────────
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.patch",
    "requests.head",
    "requests.request",
    "urllib.request.urlopen",
    "urllib.request.urlretrieve",
    "urllib.request.Request",
    "http.client.HTTPConnection",
    "http.client.HTTPSConnection",
    "httpx.get",
    "httpx.post",
    "httpx.request",
    "aiohttp.ClientSession",
    # JS — SSRF
    "fetch",
    "axios.get",
    "axios.post",
    "axios.request",
    "http.get",
    "http.request",
    "https.get",
    "https.request",
    "got",
    "node-fetch",
    # Go — SSRF
    "http.Get",
    "http.Post",
    "http.NewRequest",
    # Java — SSRF
    "URL.openConnection",
    "URL.openStream",
    "HttpURLConnection",
    "HttpClient.send",
    "RestTemplate.getForObject",
    "RestTemplate.postForObject",
    "WebClient.create",
    # ── XXE / XML parsing with external entities ──────────────────
    "xml.etree.ElementTree.parse",
    "xml.etree.ElementTree.fromstring",
    "xml.dom.minidom.parse",
    "xml.dom.minidom.parseString",
    "xml.sax.parse",
    "xml.sax.parseString",
    "lxml.etree.parse",
    "lxml.etree.fromstring",
    "lxml.etree.XML",
    # Java — XXE
    "DocumentBuilderFactory.newInstance",
    "SAXParserFactory.newInstance",
    "XMLInputFactory.newInstance",
    # ── Template injection ────────────────────────────────────────
    "jinja2.Template",
    "jinja2.from_string",
    "Template",
    "mako.template.Template",
    "string.Template",
    # Ruby — template injection
    "ERB.new",
    # JS — template injection
    "ejs.render",
    "pug.render",
    "Handlebars.compile",
    # ReDoS: re.compile / RegExp omitted — too common for mechanical
    # discovery. Taint analysis catches user-controlled patterns.
    # ── LDAP injection ────────────────────────────────────────────
    "ldap.search_s",
    "ldap.search",
    "ldap.search_ext_s",
    "ldap3.Connection.search",
    # Java — LDAP
    "DirContext.search",
    "InitialDirContext.search",
    # ── Deserialization with class instantiation ──────────────────
    # json.loads omitted — only dangerous with object_hook; too noisy
    "msgpack.unpackb",
    "msgpack.unpack",
    "cbor2.loads",
    # Java — deserialization
    "ObjectInputStream.readObject",
    "XMLDecoder.readObject",
    "XStream.fromXML",
    # PHP — deserialization
    "unserialize",
    # Ruby — deserialization
    "YAML.load",
    "Marshal.load",
    # .NET — deserialization
    "BinaryFormatter.Deserialize",
    "JsonConvert.DeserializeObject",
    # ── Path traversal (additional) ───────────────────────────────
    # os.path.join / pathlib.Path omitted — too common for mechanical
    # discovery. Taint analysis catches user-controlled paths.
    "zipfile.ZipFile.extractall",
    "tarfile.TarFile.extractall",
    "shutil.unpack_archive",
    # ── SQL injection (additional ORMs / drivers) ─────────────────
    "cursor.execute",
    "connection.execute",
    "engine.execute",
    "Session.execute",
    "db.execute",
    "db.executemany",
    "psycopg2.extensions.cursor.execute",
    # MongoDB — NoSQL injection
    "collection.find",
    "collection.find_one",
    "collection.update",
    "collection.delete",
    "collection.aggregate",
})


def _build_dangerous_set() -> FrozenSet[str]:
    """Merge source-level sinks with C-level sinks from function_taxonomy."""
    combined = set(_SOURCE_LEVEL_SINKS)
    try:
        from core.function_taxonomy import (
            EXEC_FUNCS,
            MEMORY_COPY_FUNCS,
            SCAN_FAMILY_FUNCS,
            STRING_OVERFLOW_FUNCS,
        )
        combined |= EXEC_FUNCS | MEMORY_COPY_FUNCS | SCAN_FAMILY_FUNCS | STRING_OVERFLOW_FUNCS
    except ImportError:
        pass
    return frozenset(combined)


DANGEROUS_TARGETS: FrozenSet[str] = _build_dangerous_set()


@dataclass(slots=True)
class SinkInfo:
    """A mechanically-discovered dangerous sink."""
    file: str
    function: str
    line: int
    target: str          # the dangerous callee (e.g. "os.execute")
    direct: bool = True  # True = direct caller, False = transitive


@dataclass(slots=True)
class ChainHop:
    """One hop in a mechanical call chain toward a dangerous sink."""
    file: str
    function: str


@dataclass(slots=True)
class TransitiveReach:
    """A function that transitively reaches a dangerous sink."""
    file: str
    function: str
    distance: int        # hop count to nearest dangerous sink
    sinks: List[str]     # dangerous targets reachable (transitively)
    chain: Optional[List[ChainHop]] = None  # forward path toward sink


@dataclass(slots=True)
class FrameworkAPI:
    """An autonomously discovered framework API target."""
    name: str            # dotted name (e.g. "luci.http.formvalue")
    caller_count: int    # number of distinct callers
    files: List[str]     # files that call it (sample)


@dataclass(slots=True)
class UnreachableVerdict:
    """Per-function verdict for sink unreachability eligibility."""
    file: str
    function: str
    eligible: bool
    reason: str
    narrowed_classes: List[str]


@dataclass
class SinkDiscoveryResult:
    """Complete result of mechanical sink discovery."""
    direct_sinks: List[SinkInfo]
    transitive_reach: List[TransitiveReach]
    framework_apis: List[FrameworkAPI]
    dangerous_target_counts: Dict[str, int]
    unreachable_eligible: Optional[Dict[Tuple[str, str], UnreachableVerdict]] = None

    def as_dict(self) -> dict:
        """Serialise for JSON output / context-map enrichment."""
        return {
            "direct_sinks": [
                {
                    "file": s.file,
                    "function": s.function,
                    "line": s.line,
                    "target": s.target,
                }
                for s in self.direct_sinks
            ],
            "transitive_reach": [
                {
                    "file": t.file,
                    "function": t.function,
                    "distance": t.distance,
                    "reachable_sinks": t.sinks,
                    **({"chain": [
                        {"file": h.file, "function": h.function}
                        for h in t.chain
                    ]} if t.chain else {}),
                }
                for t in self.transitive_reach
            ],
            "framework_apis": [
                {
                    "name": f.name,
                    "caller_count": f.caller_count,
                    "sample_files": f.files[:5],
                }
                for f in self.framework_apis
            ],
            "dangerous_target_usage": {
                k: v for k, v in sorted(
                    self.dangerous_target_counts.items(),
                    key=lambda x: -x[1],
                )
            },
        }


def _reconstruct_chain(
    start: FuncKey,
    successor: Dict[FuncKey, FuncKey],
    max_depth: int,
) -> List[ChainHop]:
    """Walk the successor links to build a forward chain toward a sink."""
    hops: List[ChainHop] = []
    node = start
    seen: Set[FuncKey] = set()
    for _ in range(max_depth + 1):
        if node in seen:
            break
        seen.add(node)
        nxt = successor.get(node)
        if nxt is None:
            break
        hops.append(ChainHop(file=nxt[0], function=nxt[1]))
        node = nxt
    return hops


def _is_dangerous(chain: List[str]) -> Optional[str]:
    """Check if a call chain targets a dangerous function.

    Returns the matched target name, or None.  Matching order:
    1. Full dotted chain (e.g. ``subprocess.Popen``)
    2. Last two elements qualified (e.g. ``os.system``)
    3. Bare tail name for single-element chains only (e.g. C's
       ``popen``, ``execve``) — skipped for method calls to avoid
       false positives on ``self.system()`` or ``model.eval()``
    """
    if not chain:
        return None
    return _is_dangerous_cached(tuple(chain))


@functools.lru_cache(maxsize=1024)
def _is_dangerous_cached(chain: Tuple[str, ...]) -> Optional[str]:
    dotted = ".".join(chain)
    if dotted in DANGEROUS_TARGETS:
        return dotted
    if len(chain) >= 2:
        qualified = f"{chain[-2]}.{chain[-1]}"
        if qualified in DANGEROUS_TARGETS:
            return qualified
    if len(chain) == 1 and chain[0] in DANGEROUS_TARGETS:
        return chain[0]
    return None


_LANGUAGE_BUILTINS: FrozenSet[str] = frozenset({
    # JS builtins — high-frequency but not framework signals
    "Promise.all", "Promise.resolve", "Promise.reject", "Promise.race",
    "Array.isArray", "Array.from", "Array.of",
    "Object.keys", "Object.values", "Object.entries", "Object.assign",
    "Object.freeze", "Object.create", "Object.defineProperty",
    "JSON.parse", "JSON.stringify",
    "Math.max", "Math.min", "Math.floor", "Math.ceil", "Math.round",
    "Math.abs", "Math.random", "Math.pow", "Math.sqrt", "Math.log",
    "String.fromCharCode", "Number.parseInt", "Number.parseFloat",
    "console.log", "console.error", "console.warn",
    "document.createElement", "document.getElementById",
    "document.querySelector", "document.querySelectorAll",
    "window.setTimeout", "window.setInterval",
    "window.clearTimeout", "window.clearInterval",
    "window.requestAnimationFrame",
    # Python builtins
    "os.path.join", "os.path.exists", "os.path.dirname",
    "os.path.basename", "os.path.isfile", "os.path.isdir",
    "os.path.abspath", "os.path.realpath",
    "os.listdir", "os.makedirs", "os.walk",
    "json.loads", "json.dumps", "json.load", "json.dump",
    "re.compile", "re.match", "re.search", "re.findall", "re.sub",
    "logging.getLogger",
    # Lua builtins
    "string.format", "string.match", "string.gmatch", "string.gsub",
    "string.find", "string.sub", "string.byte", "string.char",
    "string.len", "string.rep", "string.reverse", "string.upper",
    "string.lower",
    "table.insert", "table.remove", "table.sort", "table.concat",
    "table.unpack", "table.pack", "table.move",
    "math.max", "math.min", "math.floor", "math.ceil", "math.abs",
    "math.sqrt", "math.random", "math.huge",
    "io.open", "io.close", "io.read", "io.write", "io.lines",
    "os.time", "os.date", "os.clock", "os.getenv",
    "type", "tostring", "tonumber", "pairs", "ipairs", "next",
    "print", "error", "assert", "require", "pcall", "xpcall",
    "setmetatable", "getmetatable", "rawget", "rawset",
})


def _is_language_builtin(target: str) -> bool:
    """Return True if the target is a well-known language builtin."""
    return target in _LANGUAGE_BUILTINS


FuncKey = Tuple[str, str]  # (file, function)


def discover_sinks(
    call_graphs: Dict[str, FileCallGraph],
    *,
    max_depth: int = 10,
    framework_threshold: int = 5,
    framework_min_files: int = 3,
) -> SinkDiscoveryResult:
    """Run mechanical sink discovery over a set of per-file call graphs.

    Parameters
    ----------
    call_graphs
        Mapping of relative file path → FileCallGraph.
    max_depth
        Maximum transitive depth for reverse reachability.
    framework_threshold
        Minimum number of distinct callers for a dotted target to be
        considered a framework API.
    framework_min_files
        Minimum number of distinct files containing callers for a
        target to be considered a framework API (filters out
        file-local helper patterns).

    Returns
    -------
    SinkDiscoveryResult
        Direct sinks, transitive reachability, and framework APIs.
    """
    # Phase 1: Find direct dangerous callers
    direct_sinks: List[SinkInfo] = []
    # Build forward call graph: (file, caller) → set of (file, callee)
    forward_edges: Dict[FuncKey, Set[FuncKey]] = defaultdict(set)
    # Build reverse call graph: (file, callee) → set of (file, caller)
    reverse_edges: Dict[FuncKey, Set[FuncKey]] = defaultdict(set)
    # Track which functions directly call dangerous targets
    direct_dangerous: Dict[FuncKey, Set[str]] = defaultdict(set)
    # Track all call targets for framework discovery
    target_callers: Dict[str, Set[FuncKey]] = defaultdict(set)
    target_files: Dict[str, Set[str]] = defaultdict(set)
    # Build cross-file function index: function name → files where it is
    # defined (approximated by where it appears as a caller in call graphs).
    # This enables cross-file edge building below.
    _func_defined_in: Dict[str, Set[str]] = defaultdict(set)
    for filepath, graph in call_graphs.items():
        for call in graph.calls:
            if call.caller and call.caller != "<module>":
                _func_defined_in[call.caller].add(filepath)

    for filepath, graph in call_graphs.items():
        for call in graph.calls:
            caller = call.caller or "<module>"
            caller_key: FuncKey = (filepath, caller)
            dotted = ".".join(call.chain)

            # Track for framework discovery
            if "." in dotted or ":" in dotted:
                target_callers[dotted].add(caller_key)
                target_files[dotted].add(filepath)

            # Check if this is a dangerous call
            danger = _is_dangerous(call.chain)
            if danger:
                direct_sinks.append(SinkInfo(
                    file=filepath,
                    function=caller,
                    line=call.line,
                    target=danger,
                ))
                direct_dangerous[caller_key].add(danger)

            # Build inter-function edges — same-file and cross-file.
            # Cross-file edges are added when a bare function call
            # matches a function defined in another file within the
            # inventory.  Import-qualified resolution (e.g. resolving
            # ``from pkg import func`` to the defining file) is not
            # yet handled — that requires the import resolver in
            # core.analysis.reachability.
            # TODO: use import resolution from core.analysis.reachability
            # to resolve qualified cross-file calls (e.g. module.func).
            if len(call.chain) == 1:
                callee_name = call.chain[0]
                callee_key: FuncKey = (filepath, callee_name)
                forward_edges[caller_key].add(callee_key)
                reverse_edges[callee_key].add(caller_key)
                # Cross-file: callee defined in other inventory files
                resolved = False
                for other_file in _func_defined_in.get(callee_name, ()):
                    resolved = True
                    if other_file != filepath:
                        cross_key: FuncKey = (other_file, callee_name)
                        forward_edges[caller_key].add(cross_key)
                        reverse_edges[cross_key].add(caller_key)
                if not resolved and callee_name in _func_defined_in:
                    resolved = True
            elif len(call.chain) == 2 and call.chain[0] in ("self", "this"):
                callee_key = (filepath, call.chain[1])
                forward_edges[caller_key].add(callee_key)
                reverse_edges[callee_key].add(caller_key)

    # Phase 2: Transitive reverse reachability from dangerous callers
    # BFS backwards from every function that directly calls a dangerous target
    transitive_reach: List[TransitiveReach] = []
    visited: Dict[FuncKey, int] = {}  # key → distance
    reachable_sinks: Dict[FuncKey, Set[str]] = defaultdict(set)
    # successor[caller] = next hop toward sink (reverse BFS predecessor
    # = forward call chain successor). Used to reconstruct chains.
    successor: Dict[FuncKey, FuncKey] = {}

    # Seed: all direct dangerous callers at distance 0
    queue: List[Tuple[FuncKey, int]] = []
    for key, targets in direct_dangerous.items():
        visited[key] = 0
        reachable_sinks[key] = set(targets)
        queue.append((key, 0))

    # BFS — propagate sink sets backwards through the call graph.
    # Sinks are merged unconditionally on every edge traversal so a
    # function that is itself a direct dangerous caller AND transitively
    # reaches other sinks gets the full set.  When new sinks arrive via
    # a longer path, the node is re-enqueued at its existing distance
    # so the additions propagate to its callers.
    head = 0
    while head < len(queue):
        current, dist = queue[head]
        head += 1
        if dist >= max_depth:
            continue
        if visited.get(current, dist) < dist:
            continue
        for caller_key in reverse_edges.get(current, set()):
            new_dist = dist + 1
            prev_dist = visited.get(caller_key)
            old_count = len(reachable_sinks.get(caller_key, set()))
            reachable_sinks[caller_key] |= reachable_sinks[current]
            sinks_grew = len(reachable_sinks[caller_key]) > old_count
            if prev_dist is None or prev_dist > new_dist:
                visited[caller_key] = new_dist
                successor[caller_key] = current
                queue.append((caller_key, new_dist))
            elif sinks_grew:
                queue.append((caller_key, prev_dist))

    for key, dist in sorted(visited.items()):
        if dist == 0:
            continue  # direct callers are in direct_sinks already
        chain = _reconstruct_chain(key, successor, max_depth)
        transitive_reach.append(TransitiveReach(
            file=key[0],
            function=key[1],
            distance=dist,
            sinks=sorted(reachable_sinks[key]),
            chain=chain,
        ))

    # Phase 3: Framework API discovery
    # Filter: must have enough distinct callers AND span multiple files.
    # Exclude well-known language builtins — they're not framework signals.
    framework_apis: List[FrameworkAPI] = []
    for target, callers in target_callers.items():
        n_callers = len(callers)
        n_files = len(target_files[target])
        if n_callers < framework_threshold:
            continue
        if n_files < framework_min_files:
            continue
        if _is_language_builtin(target):
            continue
        framework_apis.append(FrameworkAPI(
            name=target,
            caller_count=n_callers,
            files=heapq.nsmallest(5, target_files[target]),
        ))
    framework_apis.sort(key=lambda f: -f.caller_count)

    # Dangerous target usage summary
    dangerous_counts: Dict[str, int] = defaultdict(int)
    for si in direct_sinks:
        dangerous_counts[si.target] += 1

    # Phase 4: 3-layer FN defense for sink_unreachable eligibility
    #
    # Functions with zero transitive reach are candidates for
    # scope-narrowing (fewer CWE classes reviewed), but only if they
    # pass both layers:
    #   L1: no indirection flags on the function's file
    #   L2: (covered by call_graph via INDIRECTION_FN_POINTER)
    #
    # External callees not in DANGEROUS_TARGETS are already classified
    # by the catalog — blocking on them made tier 0 a no-op for C code
    # (every function calls libc).

    all_func_keys: Set[FuncKey] = set()
    for filepath, graph in call_graphs.items():
        for call in graph.calls:
            c = call.caller or "<module>"
            all_func_keys.add((filepath, c))

    reachable_keys = set(visited.keys())

    file_has_indirection: Dict[str, Set[str]] = {}
    for filepath, graph in call_graphs.items():
        if graph.indirection:
            file_has_indirection[filepath] = graph.indirection

    unreachable_eligible: Dict[Tuple[str, str], UnreachableVerdict] = {}
    for key in all_func_keys:
        if key in reachable_keys:
            continue
        filepath, funcname = key
        indir = file_has_indirection.get(filepath)
        if indir:
            unreachable_eligible[key] = UnreachableVerdict(
                file=filepath,
                function=funcname,
                eligible=False,
                reason=f"indirection flags: {sorted(indir)}",
                narrowed_classes=[],
            )
            continue
        unreachable_eligible[key] = UnreachableVerdict(
            file=filepath,
            function=funcname,
            eligible=True,
            reason="no transitive reach, no indirection",
            narrowed_classes=[],
        )

    logger.info(
        "sink_discovery: %d direct sinks, %d transitive, %d framework APIs, "
        "%d unreachable verdicts (%d eligible)",
        len(direct_sinks), len(transitive_reach), len(framework_apis),
        len(unreachable_eligible),
        sum(1 for v in unreachable_eligible.values() if v.eligible),
    )

    return SinkDiscoveryResult(
        direct_sinks=direct_sinks,
        transitive_reach=transitive_reach,
        framework_apis=framework_apis,
        dangerous_target_counts=dict(dangerous_counts),
        unreachable_eligible=unreachable_eligible,
    )


def discover_sinks_for_target(
    target: Path,
    *,
    languages: Optional[Set[str]] = None,
    max_depth: int = 10,
    framework_threshold: int = 5,
    framework_min_files: int = 3,
) -> SinkDiscoveryResult:
    """Convenience: build call graphs for a target directory and run discovery.

    Parameters
    ----------
    target
        Root of the source tree.
    languages
        If given, only process files of these languages.
        Defaults to all supported languages.
    max_depth
        Maximum transitive depth for reverse reachability.
    framework_threshold
        Minimum callers for framework API detection.
    framework_min_files
        Minimum files for framework API detection.
    """
    if not target.is_dir():
        logger.warning("sink_discovery: target %s is not a directory", target)
        return SinkDiscoveryResult([], [], [], {})

    from core.inventory.languages import detect_language

    call_graphs: Dict[str, FileCallGraph] = {}

    # Language → extractor function
    extractors = _get_call_graph_extractors()

    for source_file in _iter_source_files(target):
        try:
            rel = str(source_file.relative_to(target))
        except ValueError:
            continue
        lang = detect_language(rel)
        if not lang:
            continue
        if languages and lang not in languages:
            continue
        extractor = extractors.get(lang)
        if not extractor:
            continue
        try:
            content = source_file.read_text(encoding="utf-8", errors="replace")
            graph = extractor(content)
            if graph.calls:
                call_graphs[rel] = graph
        except Exception:  # noqa: BLE001
            logger.debug("sink discovery: callgraph extraction failed for %s", rel, exc_info=True)
            continue

    return discover_sinks(
        call_graphs,
        max_depth=max_depth,
        framework_threshold=framework_threshold,
        framework_min_files=framework_min_files,
    )


def _get_call_graph_extractors():
    """Return available call-graph extractors keyed by language."""
    from functools import partial

    from core.inventory.call_graph import (
        extract_call_graph_python,
        extract_call_graph_javascript,
        extract_call_graph_c,
        extract_call_graph_cpp,
        extract_call_graph_csharp,
        extract_call_graph_go,
        extract_call_graph_java,
        extract_call_graph_lua,
        extract_call_graph_php,
        extract_call_graph_ruby,
        extract_call_graph_rust,
    )
    return {
        "python": extract_call_graph_python,
        "javascript": extract_call_graph_javascript,
        "typescript": partial(extract_call_graph_javascript, language="typescript"),
        "tsx": partial(extract_call_graph_javascript, language="tsx"),
        "c": extract_call_graph_c,
        "cpp": extract_call_graph_cpp,
        "csharp": extract_call_graph_csharp,
        "go": extract_call_graph_go,
        "java": extract_call_graph_java,
        "lua": extract_call_graph_lua,
        "php": extract_call_graph_php,
        "ruby": extract_call_graph_ruby,
        "rust": extract_call_graph_rust,
    }


def _iter_source_files(target: Path):
    """Yield source files under target, respecting common exclusions.

    Uses os.walk with walk-time pruning so excluded subtrees are never
    traversed (avoids hundreds of thousands of stat() calls on repos
    with large node_modules/ or vendor/ trees).
    """
    import os as _os
    skip_dirs = {
        ".git", "node_modules", "__pycache__", ".tox", ".venv",
        "venv", "vendor", "third_party", "build", "dist",
    }
    for root, dirs, files in _os.walk(target):
        dirs[:] = [d for d in dirs if d not in skip_dirs
                   and not (Path(root) / d).is_symlink()]
        for fname in files:
            yield Path(root) / fname
