"""CWE-to-tool dispatch mapping for /audit.

Single source of truth for mapping CWE classes to tool-specific
dispatch rules (SMT verbs, Coccinelle rules, Joern taint, CodeQL
queries) and sink targets.

Consumed by:
  - Step 1e CWE fallback in _hypothesis_to_tool_chain
  - Step 1e' proactive tool validation
  - Any future CWE→tool consumer
"""

from __future__ import annotations

from typing import Any

CWE_TO_TOOL_DISPATCH: dict[str, dict[str, Any]] = {
    # Memory / bounds
    "CWE-120": {
        "smt": "check-oob",
        "cocci": None,
        "joern": True,
        "codeql": "cpp/overflow-buffer",
        "sinks": ["memcpy", "strcpy", "strncpy", "sprintf", "gets"],
    },
    "CWE-122": {
        "smt": "check-oob",
        "cocci": None,
        "joern": True,
        "codeql": "cpp/overflow-buffer",
        "sinks": ["memcpy", "strcpy", "strncpy", "sprintf", "gets"],
    },
    "CWE-125": {
        "smt": "check-oob",
        "cocci": None,
        "joern": True,
        "codeql": "cpp/out-of-bounds-read",
        "sinks": ["memcmp", "strlen", "strstr", "strcmp", "strncmp", "read", "fread"],
    },
    "CWE-787": {
        "smt": "check-oob",
        "cocci": None,
        "joern": True,
        "codeql": "cpp/overflow-buffer",
        "sinks": ["memcpy", "strcpy", "strncpy", "sprintf", "gets"],
    },
    # Stack-based buffer overflow — the 120/122/787 buffer family
    # (reviews emit it for on-stack destinations; the verifying
    # channels are identical).
    "CWE-121": {
        "smt": "check-oob",
        "cocci": None,
        "joern": True,
        "codeql": "cpp/overflow-buffer",
        "sinks": ["memcpy", "strcpy", "strncpy", "sprintf", "gets",
                  "strcat", "vsprintf"],
    },
    # Length-parameter inconsistency — a stated length disagrees with
    # the actual buffer/message size (truncated-header parses, recv
    # length reuse). Bounds SMT + bounds-check Coccinelle + taint to
    # the copy/parse sinks.
    "CWE-130": {
        "smt": "check-oob",
        "cocci": "missing_bounds_check.cocci",
        "joern": True,
        "codeql": "cpp/overflow-buffer",
        "sinks": ["memcpy", "memmove", "strncpy", "recv", "recvfrom",
                  "recvmsg", "read", "fread"],
    },
    # Argument-shape consistency family (§3.6): incorrect calculation
    # of buffer size (length-vs-capacity confusion) and sizeof-on-a-
    # pointer. No dedicated dataflow channel adjudicates these; the
    # consistency channel is the verifier
    # (consistency_verify.CONSISTENCY_CWES) — the sizeof(ptr) sub-case
    # carries a declared-type witness, the rest is detection-grade
    # peer-majority evidence.
    "CWE-131": {
        "smt": None,
        "cocci": None,
        "joern": False,
        "codeql": None,
        "sinks": [],
    },
    "CWE-467": {
        "smt": None,
        "cocci": None,
        "joern": False,
        "codeql": None,
        "sinks": [],
    },
    # Integer
    "CWE-190": {
        "smt": "check-overflow",
        # Two standing shapes: multiplication overflow feeding an
        # allocation, and a 32-bit division-derived count whose
        # round-up wraps before the allocator sees the size.
        "cocci": ["integer_overflow_alloc.cocci",
                  "alloc_narrow_count.cocci"],
        "joern": False,
        "codeql": "cpp/integer-overflow",
        "sinks": [],
        "dark_verify": True,
        "dark_verify_statuses": ("dark", "suspicious", "finding"),
    },
    "CWE-191": {
        "smt": "check-overflow",
        "cocci": None,
        "joern": False,
        "codeql": "cpp/integer-overflow",
        "sinks": [],
    },
    # Injection
    "CWE-78": {
        "smt": None,
        "cocci": None,
        "joern": True,
        "codeql": "cpp/command-line-injection",
        "sinks": ["os.system", "popen", "execve", "subprocess.Popen"],
    },
    "CWE-89": {
        "smt": None,
        "cocci": None,
        "joern": True,
        "codeql": "py/sql-injection",
        "sinks": ["sqlite3_exec", "cursor.execute", "mysql_query"],
    },
    "CWE-79": {
        "smt": None,
        "cocci": None,
        "joern": True,
        "codeql": "js/xss",
        "sinks": ["document.write", "innerHTML", "eval"],
    },
    "CWE-90": {
        "smt": None,
        "cocci": None,
        "joern": True,
        "codeql": None,
        "sinks": ["ldap_search", "ldap_search_s"],
    },
    "CWE-94": {
        "smt": None,
        "cocci": None,
        "joern": True,
        "codeql": None,
        "sinks": ["eval", "exec", "loadstring", "dofile"],
        "dark_verify": True,
        "dark_verify_statuses": ("dark", "suspicious", "finding"),
    },
    "CWE-95": {
        "smt": None,
        "cocci": None,
        "joern": True,
        "codeql": "js/code-injection",
        "sinks": ["eval", "exec", "Function", "setTimeout", "setInterval",
                  "vm.runInContext"],
        "dark_verify": True,
        "dark_verify_statuses": ("dark", "suspicious", "finding"),
    },
    "CWE-77": {
        "smt": None,
        "cocci": None,
        "joern": True,
        "codeql": "cpp/command-line-injection",
        "sinks": ["system", "popen", "execve", "execl", "os.system",
                  "subprocess.Popen", "subprocess.call"],
    },
    # Path traversal
    "CWE-22": {
        "smt": None,
        "cocci": None,
        "joern": True,
        "codeql": "py/path-injection",
        "sinks": ["open", "fopen", "readFile", "readFileSync",
                  "file_get_contents", "os.path.join", "send_file",
                  "sendFile", "include", "require_once"],
        "dark_verify": True,
        "dark_verify_statuses": ("dark", "suspicious", "finding"),
    },
    "CWE-23": {
        "smt": None,
        "cocci": None,
        "joern": True,
        "codeql": "py/path-injection",
        "sinks": ["open", "fopen", "readFile", "readFileSync",
                  "file_get_contents", "os.path.join", "send_file",
                  "sendFile", "include", "require_once"],
    },
    # Deserialization
    "CWE-502": {
        "smt": None,
        "cocci": None,
        "joern": True,
        "codeql": "py/unsafe-deserialization",
        "sinks": ["pickle.loads", "pickle.load", "yaml.load", "unserialize",
                  "Marshal.load", "readObject", "ObjectInputStream", "loads"],
        "dark_verify": True,
        "dark_verify_statuses": ("dark", "suspicious", "finding"),
    },
    # Server-side request forgery
    "CWE-918": {
        "smt": None,
        "cocci": None,
        "joern": True,
        "codeql": "py/full-ssrf",
        "sinks": ["requests.get", "requests.post", "urlopen", "fetch",
                  "curl_exec", "curl_easy_setopt", "http.Get", "axios.get",
                  "file_get_contents"],
        "dark_verify": True,
        "dark_verify_statuses": ("dark", "suspicious", "finding"),
    },
    # XML external entity
    "CWE-611": {
        "smt": None,
        "cocci": None,
        "joern": True,
        "codeql": "py/xxe",
        "sinks": ["etree.parse", "fromstring", "parseString",
                  "simplexml_load_string", "XMLReader", "DocumentBuilder",
                  "xmlReadFile", "xmlParseFile", "xmlCtxtReadMemory"],
    },
    # Open redirect
    "CWE-601": {
        "smt": None,
        "cocci": None,
        "joern": True,
        "codeql": "py/url-redirection",
        "sinks": ["redirect", "sendRedirect", "header", "set_header",
                  "RedirectResponse"],
        "dark_verify": True,
        "dark_verify_statuses": ("dark", "suspicious", "finding"),
    },
    # Prototype pollution
    "CWE-1321": {
        "smt": None,
        "cocci": None,
        "joern": True,
        "codeql": "js/prototype-polluting-assignment",
        "sinks": ["merge", "extend", "assign", "defaultsDeep", "setWith",
                  "set"],
    },
    # Error handling
    # CWE-252 keeps its cocci entry; the fail_open channel joins its
    # fallback chain via fail_open_verify.FAIL_OPEN_CWES (role-bound
    # hypothesis adjudication — the contract/majority census sweep is
    # the consistency channel's leg of the CWE-252 premise split).
    "CWE-252": {
        "smt": None,
        "cocci": "unchecked_return.cocci",
        "joern": False,
        "codeql": None,
        "sinks": [],
    },
    # Improper handling of exceptional conditions — the fail-open
    # family. The fail_open channel (fallback chain, see
    # fail_open_verify.FAIL_OPEN_CWES) is the verifier; these keys
    # cover the corroborating stock tools only.
    "CWE-703": {"smt": None, "cocci": None, "joern": False,
                "codeql": None, "sinks": []},
    "CWE-636": {"smt": None, "cocci": None, "joern": False,
                "codeql": None, "sinks": []},   # not failing securely
    "CWE-391": {"smt": None, "cocci": None, "joern": False,
                "codeql": None, "sinks": []},   # unchecked error condition
    "CWE-390": {"smt": None, "cocci": None, "joern": False,
                "codeql": None, "sinks": []},   # detected error, no action
    "CWE-476": {
        "smt": "check-null-propagation",
        "cocci": "missing_null_check.cocci",
        "joern": False,
        "codeql": "cpp/null-dereference",
        "sinks": [],
    },
    # Format string
    "CWE-134": {
        "smt": None,
        "cocci": "format_string.cocci",
        "joern": True,
        "codeql": "cpp/non-constant-format",
        "sinks": ["printf", "fprintf", "sprintf", "syslog"],
        "dark_verify": True,
        "dark_verify_statuses": ("dark", "suspicious", "finding"),
    },
    # Use-after-free / double-free
    # CWE-416 keeps its full entry; the ptr_lifecycle channel joins
    # its fallback chain additively (ptr_lifecycle.PTR_LIFECYCLE_CWES
    # — the alias-hop class the flow tools miss; the consistency-
    # joins-CWE-252 precedent). dark_verify eligibility doubles as
    # the channel's dynamic-receipt escalator.
    "CWE-416": {
        "smt": "check-early-release",
        # Two standing witness shapes: sequential free-then-use, and
        # the teardown race (async callback cancel then free of the
        # callback container).
        "cocci": ["use_after_free.cocci", "teardown_lifetime.cocci"],
        "joern": True,
        "codeql": "cpp/use-after-free",
        "sinks": ["kfree", "kfree_rcu", "free", "vfree", "kvfree",
                  "kfree_sensitive", "devm_kfree"],
        "dark_verify": True,
        "dark_verify_statuses": ("dark", "suspicious", "finding"),
    },
    # Expired-pointer dereference / operation-after-release — the
    # alias-hop lifecycle family. Channel-owned: the ptr_lifecycle
    # channel (fallback chain, see
    # ptr_lifecycle.PTR_LIFECYCLE_CWES) is the verifier; no stock
    # tool adjudicates the cached-alias hop.
    "CWE-825": {"smt": None, "cocci": None, "joern": False,
                "codeql": None, "sinks": []},
    "CWE-672": {"smt": None, "cocci": None, "joern": False,
                "codeql": None, "sinks": []},
    "CWE-415": {
        "smt": "check-early-release",
        "cocci": "double_free.cocci",
        "joern": True,
        "codeql": "cpp/use-after-free",
        "sinks": ["kfree", "kfree_rcu", "free", "vfree", "kvfree"],
    },
    # Concurrency
    "CWE-362": {
        "smt": "check-lock-domain",
        # lock imbalance, plus the split access-check shape (creds
        # read under RCU, dumpability read after the section closes).
        "cocci": ["lock_imbalance.cocci", "rcu_split_decision.cocci"],
        "joern": False,
        "codeql": None,
        "sinks": [],
    },
    "CWE-367": {
        "smt": "check-toctou",
        "cocci": "toctou_stat_open.cocci",
        "joern": False,
        "codeql": None,
        "sinks": [],
    },
    # CWE-667 keeps its smt/cocci entry (lock-imbalance leg); the
    # lock_region channel joins its fallback chain additively
    # (lock_region.LOCK_REGION_CWES — the invoke-callback-while-held
    # leg).
    "CWE-667": {
        "smt": "check-lock-discipline",
        "cocci": "lock_imbalance.cocci",
        "joern": False,
        "codeql": None,
        "sinks": [],
    },
    # Deadlock — channel-owned: the lock_region channel (fallback
    # chain, see lock_region.LOCK_REGION_CWES) adjudicates the
    # callback-invoked-while-lock-held shape; blocking-call-under-lock
    # stays typestate territory.
    "CWE-833": {"smt": None, "cocci": None, "joern": False,
                "codeql": None, "sinks": []},
    # Authentication / authorisation
    "CWE-287": {
        "smt": "check-auth-bypass",
        "cocci": None,
        "joern": True,
        "codeql": None,
        "sinks": [
            "authenticate", "verify_password", "check_credentials",
            "login", "verify_token", "jwt.decode", "check_auth",
        ],
        "dark_verify": True,
    },
    "CWE-862": {
        "smt": "check-auth-bypass",
        "cocci": None,
        "joern": True,
        "codeql": None,
        "sinks": [
            "authorize", "check_permission", "has_role", "is_admin",
            "check_access", "require_auth", "can_access",
        ],
        "dark_verify": True,
    },
    "CWE-863": {
        "smt": "check-auth-bypass",
        "cocci": None,
        "joern": True,
        "codeql": None,
        "sinks": [
            "authorize", "check_permission", "has_role", "is_admin",
            "check_access", "require_auth", "can_access",
        ],
        "dark_verify": True,
    },
    # Resource management
    "CWE-401": {
        "smt": "check-resource-leak",
        "cocci": "resource_leak_err.cocci",
        "joern": False,
        "codeql": "cpp/resource-not-released-in-destructor",
        "sinks": [],
    },
    "CWE-775": {
        "smt": "check-resource-leak",
        "cocci": None,
        "joern": False,
        "codeql": None,
        "sinks": [],
    },
    # Integer narrowing
    "CWE-681": {
        "smt": "check-integer-narrowing",
        "cocci": "sign_extension_widen.cocci",
        "joern": False,
        "codeql": "cpp/integer-overflow",
        "sinks": [],
    },
    # Signed/unsigned conversion — the 190/681 signedness family
    # (narrowing SMT verb + sign-extension Coccinelle rule).
    "CWE-195": {
        "smt": "check-integer-narrowing",
        "cocci": "sign_extension_widen.cocci",
        "joern": False,
        "codeql": "cpp/integer-overflow",
        "sinks": [],
    },
    # Type confusion / strict-aliasing punning — no static dataflow
    # channel can adjudicate; the compiler channel probes with
    # -fstrict-aliasing -Wstrict-aliasing (confirm-only, see
    # compiler_sweep.COMPILER_CWE_MAP).
    "CWE-843": {
        "smt": None,
        "cocci": None,
        "joern": False,
        "codeql": None,
        "sinks": [],
    },
    # Use of uninitialised resource — the family of the programme's
    # first suspicious→finding conversion (truncated getpeername left
    # an uninitialised BIO_ADDR tail that memcpy copied out to the
    # caller). Wired to the channels that did the promotion work:
    # joern taint to the copy-out sinks (plus the joern_flow channel,
    # see joern_verify.FLOW_CWES), the consistency census
    # (consistency_verify.CONSISTENCY_CWES), and the CodeQL
    # uninitialised-local query. The precondition sweep
    # (caller_sanitizes / function_reaches_sink) runs from the
    # review's preconditions and is CWE-independent by design.
    "CWE-908": {
        "smt": None,
        "cocci": None,
        "joern": True,
        "codeql": "cpp/uninitialized-local",
        "sinks": ["memcpy", "memmove", "bcopy", "copy_to_user",
                  "put_user", "write", "send", "sendto", "sendmsg"],
    },
    # Loop with unreachable exit condition — the loop-bound family.
    # The SMT overflow verb covers the classic mechanism (counter
    # wrap / non-advancing bound arithmetic keeps the exit condition
    # unreachable); the compiler channel probes with the analyzer's
    # infinite-loop diagnostics (confirm-only, see
    # compiler_sweep.COMPILER_CWE_MAP).
    "CWE-835": {
        "smt": "check-overflow",
        "cocci": None,
        "joern": False,
        "codeql": None,
        "sinks": [],
    },
    # Insufficient verification of data authenticity — the
    # authenticity family. No static dataflow channel can adjudicate;
    # the role-bound channels are the verifiers: fail_open (a
    # verification role whose failure/absence lets data through —
    # fail_open_verify.FAIL_OPEN_CWES), the api-boundary
    # obligation check (the caller-side "must verify before passing"
    # contract — api_boundary.API_BOUNDARY_CWES), and the
    # release_order ordering leg (data released before the integrity
    # finalizer completes — release_order joins this chain additively;
    # fail_open keeps its membership).
    "CWE-345": {
        "smt": None,
        "cocci": None,
        "joern": False,
        "codeql": None,
        "sinks": [],
    },
    # Off-by-one — the truncation-boundary leg: a (v)snprintf return
    # compared with > (or flipped <) where >= is needed treats the
    # exact-fit case as untruncated (silent truncation / NUL clip).
    # Universal libc vocabulary (tier-A idiom family); CWE-193 is also
    # a consistency-census family (consistency_verify.CONSISTENCY_CWES).
    "CWE-193": {
        "smt": None,
        "cocci": "snprintf_truncation_boundary.cocci",
        "joern": False,
        "codeql": None,
        "sinks": [],
    },
    # Uninitialised variable
    "CWE-457": {
        "smt": None,
        "cocci": "uninitialized_return.cocci",
        "joern": False,
        "codeql": "cpp/uninitialized-local",
        "sinks": [],
        "dark_verify": True,
        "dark_verify_statuses": ("dark", "suspicious", "finding"),
    },
    # Unbounded allocation / accumulation family — no static dataflow
    # channel adjudicates; the resource_bounds channel (bound-witness
    # comparator, resource_bounds.RESOURCE_BOUNDS_CWES) is the
    # verifier via the fallback chain.
    "CWE-770": {
        "smt": None,
        "cocci": None,
        "joern": False,
        "codeql": None,
        "sinks": [],
    },
    "CWE-400": {
        "smt": None,
        "cocci": None,
        "joern": False,
        "codeql": None,
        "sinks": [],
    },
    "CWE-772": {
        "smt": None,
        "cocci": None,
        "joern": False,
        "codeql": None,
        "sinks": [],
    },
    # Release-before-verify family (EFAIL shape) — the release_order
    # channel (dominance comparator,
    # release_order.RELEASE_ORDER_CWES) is the verifier via the
    # fallback chain.
    "CWE-354": {
        "smt": None,
        "cocci": None,
        "joern": False,
        "codeql": None,
        "sinks": [],
    },
    "CWE-347": {
        "smt": None,
        "cocci": None,
        "joern": False,
        "codeql": None,
        "sinks": [],
    },
    # Incomplete internal state distinction — the protocol_state
    # channel (census-driven invariant harness + lead legs,
    # protocol_state.PROTOCOL_STATE_CWES) is the verifier. The
    # dead-state lead carries CWE-563 in its lead dict only (leads
    # are not hypotheses — no dispatch key).
    "CWE-372": {
        "smt": None,
        "cocci": None,
        "joern": False,
        "codeql": None,
        "sinks": [],
    },
    # Inclusion of functionality from untrusted control sphere — the
    # code-inclusion taint shape. The joern+sinks-only entry follows
    # the CWE-90 precedent; the code-loading sink vocabulary extends
    # the include/require names CWE-22 already carries. NOTE: the
    # joern runner matches dotted sinks by trailing segment
    # (``sink.split(".")[-1]``), so ``System.load`` would degrade to
    # the ultra-generic ``load`` (yaml.load/json.load/pickle.load…) —
    # deliberately omitted; ``System.loadLibrary`` keeps its
    # distinctive tail.
    "CWE-829": {
        "smt": None,
        "cocci": None,
        "joern": True,
        "codeql": None,
        "sinks": ["include", "include_once", "require", "require_once",
                  "dlopen", "LoadLibrary", "LoadLibraryA", "LoadLibraryW",
                  "System.loadLibrary",
                  "importlib.import_module", "__import__"],
    },
}

# Classes a deterministic tool CANNOT adjudicate — by policy, not by
# gap. These are quality/operational properties, not exploitability
# claims: no tool output (pattern match, taint path, SMT model) can
# state the harm, so a synthesized checker "confirming" one is always
# a shape assertion, never evidence. Suspicious verdicts in these
# families stay at hypothesis grade with the reason recorded — they
# are NOT on-demand checker-synthesis candidates (the long
# instrumented run watched synthesis promote empty-audit-hook and
# irrelevant-code shapes to finding/high on self-referential pattern
# matches).
#
# Known gap (next pass): the park is class-exact, so logging-family
# CWE drift bypasses it — a review emitting the operational-logging
# neighbours CWE-779 (logging of excessive data) or CWE-223 (omission
# of security-relevant information) is a concrete class and keeps the
# synthesis lane open. NOT CWE-117 (log injection), which is
# taint-verifiable and must never be parked. Extend the family or add
# drift telemetry when a run shows drift evidence.
CWE_NOT_TOOL_VERIFIABLE: dict[str, str] = {
    # Insufficient logging: "enough logging" is an operational
    # detectability judgment; absence of a log call names no harm
    # mechanism a tool could test.
    "CWE-778": (
        "insufficient logging is an operational/detectability "
        "property — no deterministic tool output can adjudicate "
        "'enough logging'; not an exploitability claim"
    ),
    # Irrelevant code: a code-quality property; a pattern matching
    # dead/extraneous code asserts a shape, not attacker-facing harm.
    "CWE-1164": (
        "irrelevant/extraneous code is a code-quality property with "
        "no attacker-facing harm mechanism for a tool to test"
    ),
}


def not_tool_verifiable_reason(cwe: str) -> str:
    """Policy reason a CWE class is not tool-verifiable ('' when it is).

    Classes in :data:`CWE_NOT_TOOL_VERIFIABLE` never earn tool chains
    or synthesized checkers — findings stay at hypothesis/suspicious
    grade with this reason recorded.
    """
    normalized = (cwe or "").upper().strip()
    if normalized and not normalized.startswith("CWE-"):
        normalized = f"CWE-{normalized}"
    return CWE_NOT_TOOL_VERIFIABLE.get(normalized, "")


def is_placeholder_cwe(cwe: str) -> bool:
    """True when *cwe* is a placeholder, not a real class.

    Reviews emit ``CWE-NOINFO`` / ``CWE-000`` / ``CWE-Other`` when the
    model has no class in mind. Real CWE identifiers have a positive
    numeric tail; anything else is a placeholder and must not seed
    dispatch, inference bypass, or checker synthesis. Empty input is
    "absent", not a placeholder — callers handle it separately.
    """
    normalized = (cwe or "").upper().strip()
    if not normalized:
        return False
    if normalized.startswith("CWE-"):
        normalized = normalized[4:]
    if not normalized.isdigit():
        return True
    return int(normalized) == 0


def lookup(cwe: str) -> dict[str, Any] | None:
    """Look up dispatch rules for a CWE identifier.

    Accepts "CWE-78", "cwe-78", "78", etc.
    """
    normalized = cwe.upper().strip()
    if not normalized.startswith("CWE-"):
        normalized = f"CWE-{normalized}"
    return CWE_TO_TOOL_DISPATCH.get(normalized)


_HYPOTHESIS_CWE_MAP = [
    (r"race\s+condition|data\s+race|concurrent.*(?:write|access|modif)", "CWE-362"),
    (r"toctou|time.of.check.*time.of.use|check.*then.*use.*race", "CWE-367"),
    (r"deadlock|livelock|lock.*order|double.*lock", "CWE-667"),
    (r"use.after.free|dangling.*pointer|freed.*(?:object|memory|buffer)", "CWE-416"),
    (r"double.free|free.*twice", "CWE-415"),
    (r"(?:integer|arithmetic).*overflow|integer.*wrap", "CWE-190"),
    (r"(?:integer|arithmetic).*underflow", "CWE-191"),
    (r"null.*(?:pointer|deref)|nullptr.*deref|deref.*null", "CWE-476"),
    (r"(?:buffer|heap|stack).*overflow|out.of.bounds.*(?:write|access)", "CWE-787"),
    (r"out.of.bounds.*read|oob.*read", "CWE-125"),
    (r"format.*string.*(?:vuln|inject|attack)", "CWE-134"),
    (r"(?:command|os|shell).*inject", "CWE-78"),
    (r"sql.*inject", "CWE-89"),
    (r"(?:auth|permission|privilege).*bypass", "CWE-863"),
    (r"missing.*auth|no.*auth.*check", "CWE-862"),
    (r"resource.*leak|memory.*leak|missing.*free", "CWE-401"),
    (r"(?:integer|type).*(?:truncat|narrow)", "CWE-681"),
    (r"uninitiali[sz]ed", "CWE-457"),
    # Web-facing families (P10). Appended after the memory/injection
    # entries so pre-existing first-match behaviour is unchanged.
    ((r"path.travers|directory.travers|\.\./|path.inject|"
      r"arbitrary.file.(?:read|write|access)"), "CWE-22"),
    ((r"deseriali[sz]|unpickl|pickle\.loads?|unseriali[sz]e|"
      r"marshal\.load|yaml\.load"), "CWE-502"),
    ((r"\bssrf\b|server.side.request.forgery|"
      r"forged.*(?:server|internal).*request"), "CWE-918"),
    (r"\bxxe\b|xml.external.entit|external.entity.(?:inject|expan)", "CWE-611"),
    ((r"open.redirect|unvalidated.redirect|"
      r"redirect.*attacker.(?:controlled|supplied)"), "CWE-601"),
    (r"prototype.pollution|__proto__", "CWE-1321"),
    (r"(?:code|eval).*inject", "CWE-94"),
    # Appended after all earlier entries (first match wins, so
    # pre-existing behaviour is unchanged).
    (r"type.confus|strict.alias|type.punn|punned.*pointer", "CWE-843"),
    ((r"length.*(?:field|parameter|header|prefix).*"
      r"(?:inconsisten|mismatch|truncat|exceed|larger|shorter)"),
     "CWE-130"),
    (r"sign(?:ed)?.to.unsign|unsigned.conversion|negative.*(?:length|size|count).*(?:unsigned|size_t)", "CWE-195"),
    # Fail-open family. Appended after all existing entries
    # (first-match-wins, so pre-existing behaviour is unchanged).
    (r"fail[s\-]?.?open|swallow\w*.{0,20}(?:exception|error)", "CWE-703"),
    (r"empty.{0,10}catch|except.{0,10}pass", "CWE-703"),
    ((r"(?:ignor|discard|unchecked)\w*.{0,20}"
      r"(?:error|return value|\berr\b)"), "CWE-252"),
    ((r"(?:return\s+value|result|\berr\b).{0,40}"
      r"(?:ignor|discard|not\s+checked|unchecked)"), "CWE-252"),
    # Go recover()-to-continue phrasings (the fail_open channel's
    # recover leg). Appended: first-match-wins, pre-existing behaviour
    # unchanged.
    ((r"panic\w*.{0,40}recover|recover\w*.{0,40}"
      r"(?:continue|proceed|swallow)"), "CWE-703"),
    # Midpoint-D1 long-tail families (appended: first-match-wins, so
    # pre-existing behaviour is unchanged). No CWE-908 keyword row:
    # every realistic uninitialised-resource phrasing contains
    # "uninitialized", which the earlier CWE-457 row already claims —
    # and CWE-457 carries a full dispatch entry, so the claim is
    # still mechanically tested. CWE-908 dispatch fires from the
    # review's own cwe field.
    ((r"infinite\s+loop|loop.{0,30}(?:never|unreachable|cannot)"
      r".{0,15}(?:exit|terminat)|unbounded\s+loop|endless\s+loop"),
     "CWE-835"),
    ((r"(?:v?snprintf).{0,80}truncat|truncat\w*.{0,40}"
      r"(?:boundary|exact.fit|off.by.one)|"
      r"exact.fit.{0,30}truncat"), "CWE-193"),
    ((r"authentic(?:ity)?.{0,40}(?:not|un|insufficient|missing|no)\w*"
      r".{0,15}(?:verif|check|validat)|(?:unverified|unauthenticated)"
      r".{0,25}(?:data|origin|source|message|payload|signature)|"
      r"signature.{0,25}(?:not|never|un)\w*.{0,10}(?:verif|check)"),
     "CWE-345"),
    # Five-channel programme families (appended: first-match-wins, so
    # pre-existing behaviour is unchanged).
    ((r"unbounded.{0,30}(?:alloc|growth|accumulat|list|queue)|"
      r"memory\s+exhaustion|resource\s+exhaustion|"
      r"grows?\s+without\s+(?:bound|limit|cap)|no\s+backpressure"),
     "CWE-770"),
    # Untrusted-inclusion family (appended: first-match-wins, so
    # pre-existing behaviour is unchanged; "...inject" phrasings keep
    # routing to the earlier CWE-78/94 rows).
    ((r"(?:includ|inclusion|import|load)\w*.{0,40}untrusted"
      r".{0,25}(?:content|code|source|sphere|url|librar|module)|"
      r"untrusted.{0,40}(?:inclusion|functionality)|"
      r"(?:remote|untrusted).{0,25}(?:code|script|librar\w+|module)"
      r".{0,30}(?:includ|import|load)"), "CWE-829"),
]

_HYPOTHESIS_CWE_RE = None


def infer_cwe_from_hypothesis(hypothesis: str) -> str | None:
    """Extract a CWE from hypothesis text via keyword matching.

    Returns the first matching CWE that has a dispatch entry, or None.
    Used as fallback when the LLM doesn't populate the CWE field.
    """
    global _HYPOTHESIS_CWE_RE
    if _HYPOTHESIS_CWE_RE is None:
        import re
        _HYPOTHESIS_CWE_RE = [
            (re.compile(pattern, re.IGNORECASE), cwe)
            for pattern, cwe in _HYPOTHESIS_CWE_MAP
        ]

    for regex, cwe in _HYPOTHESIS_CWE_RE:
        if regex.search(hypothesis or "") and lookup(cwe) is not None:
            return cwe
    return None


def sinks_for_cwe(cwe: str) -> list[str]:
    """Return sink targets for a CWE, or empty list."""
    entry = lookup(cwe)
    if entry is None:
        return []
    return entry.get("sinks", [])


def smt_verb_for_cwe(cwe: str) -> str | None:
    """Return the SMT verb for a CWE, or None."""
    entry = lookup(cwe)
    if entry is None:
        return None
    return entry.get("smt")


def cocci_rule_for_cwe(cwe: str) -> str | None:
    """Return the primary Coccinelle rule filename for a CWE, or None.

    A dispatch entry may carry a list of rule filenames; the first is
    the primary (back-compat single-rule consumers). Use
    :func:`cocci_rules_for_cwe` to get all of them.
    """
    rules = cocci_rules_for_cwe(cwe)
    return rules[0] if rules else None


def cocci_rules_for_cwe(cwe: str) -> list[str]:
    """Return ALL Coccinelle rule filenames for a CWE (possibly [])."""
    entry = lookup(cwe)
    if entry is None:
        return []
    val = entry.get("cocci")
    if not val:
        return []
    if isinstance(val, (list, tuple)):
        return [v for v in val if v]
    return [val]


def codeql_query_for_cwe(cwe: str) -> str | None:
    """Return the CodeQL query ID for a CWE, or None."""
    entry = lookup(cwe)
    if entry is None:
        return None
    return entry.get("codeql")


def joern_applicable(cwe: str) -> bool:
    """Return whether Joern taint tracking is useful for a CWE."""
    entry = lookup(cwe)
    if entry is None:
        return False
    return bool(entry.get("joern")) and bool(entry.get("sinks"))


def dark_verify_applicable(cwe: str) -> bool:
    """Return whether dark-verify witness execution is the primary grounding for a CWE."""
    entry = lookup(cwe)
    if entry is None:
        return False
    return bool(entry.get("dark_verify"))


def dark_verify_statuses(cwe: str):
    """Optional outcome-status filter for dark-verify eligibility.

    Returns a frozenset of eligible review statuses when the entry
    declares one (the P10 web families bound witness-call cost to
    non-clean outcomes), or ``None`` when the CWE has no filter — the
    pre-existing families keep their unfiltered behaviour.
    """
    entry = lookup(cwe)
    if entry is None:
        return None
    statuses = entry.get("dark_verify_statuses")
    if not statuses:
        return None
    return frozenset(statuses)
