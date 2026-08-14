"""Adaptive review strategy selection from function metadata.

Selects which review strategies to apply per function based on:
- File path patterns (parsers, crypto dirs, auth modules)
- Parameter types (char*, void*, size_t → input handling)
- Return types (int → error-code checking)
- Include/import patterns
- Checklist metadata (attributes, visibility)
- Context map sink reachability
"""

from __future__ import annotations

import re
from typing import Any, Dict, FrozenSet, List, Optional, Set

STRATEGY_GENERAL = "general"
STRATEGY_INPUT = "input_handling"
STRATEGY_CONCURRENCY = "concurrency"
STRATEGY_MEMORY = "memory"
STRATEGY_AUTH = "auth"
STRATEGY_CRYPTO = "crypto"
STRATEGY_ALIASING = "aliasing"
STRATEGY_INTEGER = "integer"

ALL_STRATEGIES = frozenset({
    STRATEGY_GENERAL,
    STRATEGY_INPUT,
    STRATEGY_CONCURRENCY,
    STRATEGY_MEMORY,
    STRATEGY_AUTH,
    STRATEGY_CRYPTO,
    STRATEGY_ALIASING,
    STRATEGY_INTEGER,
})

_PATH_SIGNALS: Dict[str, List[str]] = {
    STRATEGY_INPUT: [
        "parse", "decode", "deserial", "proto", "codec", "format",
        "packet", "frame", "message", "request", "handler",
        "scanner", "reader", "tokenize", "upload", "middleware",
        "servlet", "unmarshal",
    ],
    STRATEGY_CONCURRENCY: [
        "lock", "mutex", "sync", "thread", "atomic", "rcu",
        "spinlock", "rwlock", "semaphore", "concurrent",
        "worker", "executor", "scheduler", "channel",
        "async", "futures",
    ],
    STRATEGY_MEMORY: [
        "alloc", "pool", "slab", "cache", "refcount", "kref",
        "buffer", "arena", "heap",
        "gc", "destructor", "disposable",
    ],
    STRATEGY_AUTH: [
        "auth", "permission", "acl", "credential", "privilege",
        "capability", "security", "policy", "access", "login",
        "oauth", "saml", "jwt", "rbac", "certificate", "pki",
        "keystore",
    ],
    STRATEGY_CRYPTO: [
        "crypto", "cipher", "hash", "hmac", "aes", "rsa", "ssl",
        "tls", "key", "encrypt", "decrypt", "sign", "verify",
    ],
    STRATEGY_ALIASING: [
        "splice", "zero_copy", "zerocopy", "scatter", "mmap",
        "sk_buff", "skb", "page_cache", "pagecache", "sendfile",
        "scatterlist", "sg_", "aead", "frag", "page_pool",
        "pipe_buf", "vmsplice", "copy_page", "kmap",
    ],
    STRATEGY_INTEGER: [
        "overflow", "truncat", "cast", "convert", "spec_opts",
        "oci", "numeric", "arithmetic",
    ],
}

_PARAM_TYPE_SIGNALS: Dict[str, List[str]] = {
    STRATEGY_INPUT: [
        r"char\s*\*", r"const\s+char\s*\*", r"unsigned\s+char\s*\*",
        r"void\s*\*", r"const\s+void\s*\*",
        r"\bsize_t\b", r"\bssize_t\b", r"uint8_t\s*\*",
        r"\bbytes\b", r"\bbytearray\b", r"\bstr\b",
    ],
    STRATEGY_MEMORY: [
        r"void\s*\*", r"struct\s+\w+\s*\*",
    ],
}

_RETURN_TYPE_SIGNALS: Dict[str, List[str]] = {
    STRATEGY_MEMORY: [r"void\s*\*", r"char\s*\*"],
}

_ATTRIBUTE_SIGNALS: Dict[str, List[str]] = {
    STRATEGY_INPUT: ["__user"],
    STRATEGY_MEMORY: ["__must_check"],
    STRATEGY_CONCURRENCY: ["__acquires", "__releases", "__lockdep"],
}

_INCLUDE_SIGNALS: Dict[str, List[str]] = {
    STRATEGY_CONCURRENCY: [
        "pthread.h", "mutex.h", "spinlock.h", "rwlock.h",
        "threading", "asyncio", "concurrent",
        "java.util.concurrent", "tokio::", "rayon::",
    ],
    STRATEGY_CRYPTO: [
        "openssl", "crypto.h", "gcrypt", "mbedtls",
        "hashlib", "hmac", "cryptography",
        "javax.crypto", "java.security", "ring::", "rustls::",
    ],
    STRATEGY_INPUT: [
        "serde", "encoding/json", "jackson",
        "javax.servlet", "flask", "express",
    ],
}

_SOURCE_SIGNALS: Dict[str, List[str]] = {
    STRATEGY_CONCURRENCY: [
        # C/kernel
        "rcu_read_lock", "rcu_read_unlock", "rcu_dereference",
        "spin_lock", "spin_unlock", "mutex_lock", "mutex_unlock",
        "task_lock", "task_unlock", "lock_sock", "release_sock",
        "down_read", "up_read", "down_write", "up_write",
        "atomic_inc", "atomic_dec", "atomic_set",
        "READ_ONCE", "WRITE_ONCE", "smp_rmb", "smp_wmb",
        # Go
        "sync.Mutex", ".Lock()", "go func", " chan ",
        "sync.RWMutex", ".RLock()",
        # Python
        "threading.Lock", "threading.RLock",
        # Rust
        "Mutex::new", "RwLock", "Arc::new", "AtomicBool", "Ordering::",
        # Java
        "synchronized", "ReentrantLock", "AtomicInteger",
        "volatile ", "CountDownLatch",
        # JS
        "Promise.all",
        # PHP
        "flock(", "sem_acquire",
    ],
    STRATEGY_MEMORY: [
        # C/kernel
        "kfree", "kmalloc", "kzalloc", "vmalloc", "vfree",
        "refcount_inc", "refcount_dec", "kref_put", "kref_get",
        "free(", "malloc(", "calloc(", "realloc(",
        # Rust
        "unsafe {", "ManuallyDrop", "Box::from_raw",
        "std::ptr", "std::mem::forget", "Pin<",
        # Java
        "finalize()", "WeakReference",
    ],
    STRATEGY_ALIASING: [
        "sg_chain", "sg_init_table", "scatterlist",
        "memcpy_sglist", "skb_cow_data",
    ],
    STRATEGY_INTEGER: [
        # C/kernel
        "size_t", "ssize_t", "uint32_t", "check_mul_overflow",
        # Go
        "strconv.Atoi", "uint32(", "math.MaxInt",
        # Rust
        "as u32", "as u16", ".wrapping_add", ".checked_add",
        ".saturating_add",
        # Java
        "Integer.parseInt", "Integer.MAX_VALUE", "Math.toIntExact",
        "(int)", "(short)", "(byte)",
        # Python
        "ctypes.c_uint",
        # PHP
        "intval(",
    ],
    STRATEGY_AUTH: [
        "password", "credential", "session", "bearer",
        ".Host", ".Header", "headers[",
        # Java
        "@PreAuthorize", "@Secured", "SecurityContext",
        "AuthenticationManager", "ROLE_",
        # PHP
        "password_verify", "password_hash", "$_SESSION",
        "$_COOKIE", "setcookie",
        # JS
        "req.session", "req.cookies", "jwt.verify",
        "passport.", "bcrypt.",
        # Rust
        "Authorization", "set_cookie",
    ],
    STRATEGY_INPUT: [
        "Deserialize", "fromJson", "JSON.parse", "json_decode",
        "ObjectInputStream", "pickle.load", "yaml.load",
        "unserialize", "unmarshal",
        # PHP
        "$_GET", "$_POST", "$_REQUEST", "$_SERVER", "filter_input",
        # Java
        "getParameter", "getHeader", "PreparedStatement", "createQuery",
        # JS
        "innerHTML", "document.write", "child_process",
        # Rust
        "from_utf8_unchecked", "transmute",
    ],
    STRATEGY_CRYPTO: [
        # Rust
        "ring::", "rustls::", "aes::", "sha2::",
        # Java
        "Cipher.getInstance", "MessageDigest", "SecretKey",
        "KeyGenerator", "SecureRandom",
        # JS
        "crypto.createHash", "crypto.createCipher",
        # PHP
        "openssl_encrypt", "mcrypt_", "random_bytes",
    ],
}


def infer_strategies(
    *,
    file_path: str,
    function_name: str,
    parameters: Optional[List[tuple]] = None,
    return_type: Optional[str] = None,
    attributes: Optional[List[str]] = None,
    includes: Optional[List[str]] = None,
    reachable_sinks: Optional[List[str]] = None,
    shared_state: Optional[List[Any]] = None,
    crypto_inventory: Optional[List[Any]] = None,
    ownership_model: Optional[List[Any]] = None,
    kind: Optional[str] = None,
    visibility: Optional[str] = None,
    source: Optional[str] = None,
) -> FrozenSet[str]:
    """Select review strategies for a function.

    Always includes ``general``. Additional strategies are added based
    on signal matching. Multiple strategies can apply.

    Args:
        file_path: Relative path to the source file.
        function_name: Name of the function.
        parameters: List of (name, type) tuples from checklist metadata.
        return_type: Return type string from checklist metadata.
        attributes: Decorators/annotations from checklist metadata.
        includes: Include/import lines from the source file.
        reachable_sinks: Sink targets reachable from this function
            (from context-map.json entry_points[].reachable_sinks).
        shared_state: Shared state entries from context-map enrichment.
        crypto_inventory: Crypto inventory entries from context-map enrichment.
        ownership_model: Ownership model entries from context-map enrichment.
        kind: Checklist item kind (function, global, macro, class).
        visibility: Checklist item visibility (static, extern, exported, etc.).
        source: Function source text for keyword-based strategy inference.

    Returns:
        Frozen set of strategy names to apply.
    """
    strategies: Set[str] = {STRATEGY_GENERAL}

    path_lower = file_path.lower()
    name_lower = function_name.lower()
    combined = f"{path_lower}/{name_lower}"

    for strategy, keywords in _PATH_SIGNALS.items():
        if any(kw in combined for kw in keywords):
            strategies.add(strategy)

    if parameters:
        for _, param_type in parameters:
            if not param_type:
                continue
            pt = param_type.strip()
            for strategy, patterns in _PARAM_TYPE_SIGNALS.items():
                if any(re.search(p, pt) for p in patterns):
                    strategies.add(strategy)

    if return_type:
        rt = return_type.strip()
        for strategy, patterns in _RETURN_TYPE_SIGNALS.items():
            if any(re.search(p, rt) for p in patterns):
                strategies.add(strategy)

    if attributes:
        for attr in attributes:
            for strategy, signals in _ATTRIBUTE_SIGNALS.items():
                if any(s in attr for s in signals):
                    strategies.add(strategy)

    if includes:
        includes_lower = [i.lower() for i in includes]
        for strategy, signals in _INCLUDE_SIGNALS.items():
            if any(s in inc for s in signals for inc in includes_lower):
                strategies.add(strategy)

    if reachable_sinks:
        strategies.add(STRATEGY_INPUT)

    if shared_state:
        strategies.add(STRATEGY_CONCURRENCY)

    if crypto_inventory:
        strategies.add(STRATEGY_CRYPTO)

    if ownership_model:
        strategies.add(STRATEGY_MEMORY)

    if kind == "global":
        strategies.add(STRATEGY_CONCURRENCY)

    if kind == "macro":
        strategies.add(STRATEGY_INPUT)

    if visibility in ("extern", "exported", "public"):
        strategies.add(STRATEGY_INPUT)

    if source:
        for strategy, keywords in _SOURCE_SIGNALS.items():
            if any(kw in source for kw in keywords):
                strategies.add(strategy)

    return frozenset(strategies)


def strategies_from_item(
    item: Dict[str, Any],
    file_path: str,
    *,
    reachable_sinks: Optional[List[str]] = None,
    shared_state: Optional[List[Any]] = None,
    crypto_inventory: Optional[List[Any]] = None,
    ownership_model: Optional[List[Any]] = None,
    source: Optional[str] = None,
) -> FrozenSet[str]:
    """Select strategies from a checklist item dict.

    Convenience wrapper that extracts metadata fields from the
    serialized checklist item format.
    """
    metadata = item.get("metadata", {}) or {}
    parameters = None
    if metadata.get("parameters"):
        raw_params = metadata["parameters"]
        parameters = []
        for p in raw_params:
            if isinstance(p, dict):
                parameters.append((p.get("name", ""), p.get("type")))
            elif isinstance(p, (list, tuple)) and len(p) >= 2:
                parameters.append((str(p[0]), p[1]))
            elif isinstance(p, str):
                parameters.append((p, None))
            else:
                parameters.append(("", None))

    return infer_strategies(
        file_path=file_path,
        function_name=item.get("name", ""),
        parameters=parameters,
        return_type=metadata.get("return_type"),
        attributes=metadata.get("attributes"),
        reachable_sinks=reachable_sinks,
        shared_state=shared_state,
        crypto_inventory=crypto_inventory,
        ownership_model=ownership_model,
        kind=item.get("kind"),
        visibility=metadata.get("visibility"),
        source=source,
    )


STRATEGY_PRIMERS: Dict[str, str] = {
    "aliasing": (
        "ALIASING / ZERO-COPY VULNERABILITY PRIMER\n"
        "\n"
        "The pattern: a buffer is shared between two subsystems via "
        "pointer aliasing (scatterlist, sk_buff frag, splice pipe, mmap). "
        "One subsystem treats the buffer as read-only source data; the "
        "other writes through the same pointer. When the source pages "
        "come from the page cache, file-backed mmap, or another "
        "read-only origin, the write corrupts shared kernel state.\n"
        "\n"
        "What to look for:\n"
        "- req->src == req->dst (or equivalent dst = src assignment) — "
        "in-place crypto optimization that aliases input and output "
        "scatterlists.\n"
        "- splice()/vmsplice() feeding pages into a subsystem that later "
        "modifies them — the pages may be page-cache pages, not private "
        "copies.\n"
        "- skb frag pages passed to a transform (ESP, compression) that "
        "writes scratch bytes through the frag pointer.\n"
        "- Any path where get_user_pages(FOLL_WRITE) is absent but the "
        "subsystem later writes through the page — COW not triggered.\n"
        "\n"
        "The assumption that fails: 'source pages are safe to write' or "
        "'this buffer is private to the current operation.' Page-cache "
        "pages, file-backed pages, and COW-shared pages violate this.\n"
        "\n"
        "Verification steps:\n"
        "1. Trace where source pages originate — are they from splice, "
        "sendfile, page cache, or user mmap?\n"
        "2. Check whether the code copies pages before modifying them, "
        "or writes in-place.\n"
        "3. Look for the optimization branch: 'if (src == dst)' or "
        "'if (!diff_dst)' — this is where aliasing is introduced.\n"
        "4. Identify what writes through the aliased pointer: "
        "crypto_aead_encrypt/decrypt, memcpy into SGL, skb_cow_data "
        "that doesn't actually copy."
    ),
    "crypto": (
        "CRYPTO SUBSYSTEM VULNERABILITY PRIMER\n"
        "\n"
        "Common vulnerability patterns in kernel/userspace crypto code:\n"
        "\n"
        "1. IN-PLACE OPERATION ALIASING: Crypto APIs often optimize by "
        "setting dst = src to avoid a copy. When source buffers are "
        "page-cache pages (via splice/sendfile), the encrypt/decrypt "
        "operation writes through a read-only alias. Look for: "
        "req->src = req->dst, sg_init_one with the same buffer for "
        "both input and output.\n"
        "\n"
        "2. IV/NONCE REUSE: Counter modes (CTR, GCM) break catastrophically "
        "on IV reuse. Look for: static/global IV state, IV derived from "
        "predictable values, IV not incremented per operation, concurrent "
        "use of the same tfm without serialization.\n"
        "\n"
        "3. AUTHENTICATION TAG TRUNCATION: AEAD modes produce an auth tag. "
        "If the tag is truncated or not checked, the authentication "
        "guarantee is voided. Look for: tag length not validated, "
        "tag comparison with memcmp (timing side-channel), tag buffer "
        "too small.\n"
        "\n"
        "4. KEY LIFECYCLE: Use-before-set (CRYPTO_TFM_NEED_KEY flag "
        "bypass), use-after-free on tfm/key objects, key material not "
        "zeroed on free. Look for: _nokey variants that skip key checks, "
        "error paths that don't release key references.\n"
        "\n"
        "5. LENGTH CALCULATIONS: AEAD modes have complex length math: "
        "plaintext + assocdata + tag. Integer overflow in "
        "'outlen = used - as' when as > used; underflow in buffer size "
        "calculations; off-by-one in tag offset. Look for: arithmetic "
        "on user-controlled sizes without overflow checks."
    ),
    "memory": (
        "MEMORY SAFETY VULNERABILITY PRIMER\n"
        "\n"
        "1. USE-AFTER-FREE: Object freed on one path, pointer still "
        "live on another. Common in error paths (resource freed, then "
        "goto jumps to code that uses it), callback/destructor races "
        "(object freed while callback is in flight), and refcount "
        "imbalance (one path decrements twice, another doesn't "
        "increment). Look for: free() followed by any path that "
        "reaches the pointer; refcount dec without checking zero.\n"
        "\n"
        "2. DOUBLE-FREE: Two paths free the same allocation. Common "
        "when error handling and normal cleanup both free, or when "
        "ownership transfer is ambiguous. Look for: free() in both "
        "success and error paths; unclear ownership (caller vs callee "
        "frees).\n"
        "\n"
        "3. SLAB CONFUSION: Wrong kmem_cache used for free, or "
        "object used after being returned to the wrong cache. Look "
        "for: mismatched alloc/free functions (kmalloc vs kfree_rcu, "
        "sock_kmalloc vs kfree).\n"
        "\n"
        "4. REFCOUNT: Imbalanced get/put across error paths, "
        "especially when multiple resources each need independent "
        "refcount management. Look for: error paths that skip a put, "
        "or that put twice."
    ),
    "concurrency": (
        "CONCURRENCY VULNERABILITY PRIMER\n"
        "\n"
        "1. TOCTOU: A value is checked, then used after the lock is "
        "dropped (or without a lock). Another thread changes the value "
        "between check and use. Look for: lock_sock/release_sock "
        "brackets where the checked value is used outside the lock; "
        "copy_from_user followed by a second read of the same address.\n"
        "\n"
        "2. LOCK ORDERING: Nested locks acquired in different orders "
        "on different paths → deadlock. Look for: lock_sock_nested, "
        "multiple mutex_lock calls, paths that acquire A→B vs B→A.\n"
        "\n"
        "3. RCU VIOLATIONS: Dereferencing an RCU-protected pointer "
        "without rcu_read_lock, or holding it across a sleep. Look "
        "for: rcu_dereference outside rcu_read_lock; GFP_KERNEL "
        "allocation inside RCU read section.\n"
        "\n"
        "4. ATOMIC CONTEXT: Sleeping in atomic context (holding "
        "spinlock and calling kmalloc(GFP_KERNEL), copy_from_user, "
        "mutex_lock). Look for: spinlock_t + GFP_KERNEL; "
        "spin_lock_irqsave + copy_from_user.\n"
        "\n"
        "5. EARLY UNLOCK / PROTECTION GAP: A lock (mutex, "
        "RWMutex, RLock) is acquired, then released BEFORE the "
        "operation it protects completes. Code after the unlock "
        "still reads or writes shared state that was guarded. "
        "A concurrent goroutine/thread can mutate or invalidate "
        "that state in the gap. This includes INTERNAL concurrency: "
        "if the package spawns its own goroutines (context "
        "cancellation handlers, background workers, finalizers) "
        "that touch shared fields, a race between the function "
        "and those internal goroutines is a real bug even when "
        "the type says 'not safe for concurrent use by callers.' "
        "Look for: RLock/RUnlock where the unlock is conditional "
        "or early, leaving a window where subsequent reads access "
        "unprotected fields; sync.Mutex released before the full "
        "critical section completes; a lock released before a "
        "loop that still reads fields the lock was protecting."
    ),
    "integer": (
        "INTEGER VULNERABILITY PRIMER\n"
        "\n"
        "1. WRAPAROUND / OVERFLOW: Unsigned arithmetic wraps silently "
        "(uint32 0xFFFFFFFF + 1 = 0). Signed overflow is UB in C. "
        "Look for: size calculations (nmemb * size), counter increments "
        "near max, user-controlled values in arithmetic without "
        "overflow checks (check_mul_overflow, checked_add).\n"
        "\n"
        "2. TRUNCATION: Assigning a wider type to a narrower one "
        "silently drops high bits. Look for: uint64 → uint32, "
        "int → short/byte, size_t → int, strconv.Atoi → uint32(), "
        "'as u32' / 'as u16' in Rust, (int) casts in Java. "
        "The critical case: a UID/GID stored as uint32 where "
        "the input is a wider type — truncation to 0 means root.\n"
        "\n"
        "3. SIGNEDNESS: Signed/unsigned comparison or assignment. "
        "A negative signed value becomes a huge unsigned value. "
        "Look for: signed length compared against unsigned bound, "
        "ssize_t used where size_t expected, negative return codes "
        "used as array indices.\n"
        "\n"
        "4. OFF-BY-ONE: Counter or index off by exactly one. "
        "Look for: <= vs <, post-increment vs pre-increment, "
        "fence-post errors in size calculations, line/column "
        "counters that overflow before the data ends.\n"
        "\n"
        "5. PRIVILEGE / IDENTITY CONTEXT: Integer bugs in UID, GID, "
        "PID, or capability values have direct security impact. "
        "Truncation of a UID to 0 = root. Overflow of a capability "
        "mask = grant-all. Look for: type casts on identity values, "
        "arithmetic on permission masks, comparisons that can be "
        "bypassed via overflow."
    ),
    "input_handling": (
        "INPUT HANDLING VULNERABILITY PRIMER\n"
        "\n"
        "1. LENGTH MISMATCH: A length field is validated against one "
        "bound but used against a different buffer. Look for: "
        "user-supplied length checked against header size but used "
        "for payload copy; length in bytes vs elements confusion.\n"
        "\n"
        "2. INTEGER OVERFLOW IN SIZE: User-controlled size multiplied "
        "or added without overflow check, then used for allocation or "
        "copy. Look for: nmemb * size without check_mul_overflow; "
        "offset + len wrapping to small value.\n"
        "\n"
        "3. TYPE CONFUSION: Union/void* cast to wrong type based on "
        "user-controlled discriminator. Look for: switch on "
        "user-controlled type field with missing cases; void* cast "
        "without type validation.\n"
        "\n"
        "4. INJECTION: User string interpolated into a command, query, "
        "or path without escaping. Look for: snprintf with user data "
        "into a command buffer; os.path.join with user-controlled "
        "component (../ traversal)."
    ),
}


def primers_for_strategies(strategies: FrozenSet[str]) -> List[str]:
    """Return primer texts for the given strategy set."""
    result: List[str] = []
    for strategy in sorted(strategies):
        if strategy in STRATEGY_PRIMERS:
            result.append(STRATEGY_PRIMERS[strategy])
    return result
