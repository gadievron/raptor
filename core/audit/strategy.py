"""Adaptive review strategy selection from function metadata.

Selects which review strategies to apply per function based on:
- File path patterns (parsers, crypto dirs, auth modules)
- Parameter types (char*, void*, size_t → input handling)
- Return types (int → error-code checking)
- Include/import patterns
- Checklist metadata (attributes, visibility)
- Context map sink reachability

The hardcoded signal maps carry UNIVERSAL vocabulary only (libc/POSIX
plus multi-language classics). Linux-kernel token bulk lives in the
``core/audit/data/strategy_packs/linux_kernel.json`` pack, merged
additively when ``target_path`` is a detected kernel tree (the same
markers that gate the checker vocab packs); project-specific
vocabulary arrives via the study-learned DomainVocabulary
(``domain_vocab``), never by growing the maps here.
"""

from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

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

_PATH_SIGNALS: dict[str, list[str]] = {
    STRATEGY_INPUT: [
        "parse", "decode", "deserial", "proto", "codec", "format",
        "packet", "frame", "message", "request", "handler",
        "scanner", "reader", "tokenize", "upload", "middleware",
        "servlet", "unmarshal",
    ],
    STRATEGY_CONCURRENCY: [
        "lock", "mutex", "sync", "thread", "atomic",
        "spinlock", "rwlock", "semaphore", "concurrent",
        "worker", "executor", "scheduler", "channel",
        "async", "futures",
    ],
    STRATEGY_MEMORY: [
        "alloc", "pool", "cache", "refcount",
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
        "sendfile", "aead", "frag",
    ],
    STRATEGY_INTEGER: [
        "overflow", "truncat", "cast", "convert", "spec_opts",
        "oci", "numeric", "arithmetic",
    ],
}

_PARAM_TYPE_SIGNALS: dict[str, list[str]] = {
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

_RETURN_TYPE_SIGNALS: dict[str, list[str]] = {
    STRATEGY_MEMORY: [r"void\s*\*", r"char\s*\*"],
}

_ATTRIBUTE_SIGNALS: dict[str, list[str]] = {
    STRATEGY_INPUT: ["__user"],
    STRATEGY_MEMORY: ["__must_check"],
    STRATEGY_CONCURRENCY: ["__acquires", "__releases", "__lockdep"],
}

_INCLUDE_SIGNALS: dict[str, list[str]] = {
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

_SOURCE_SIGNALS: dict[str, list[str]] = {
    STRATEGY_CONCURRENCY: [
        # C (universal; "mutex_lock" substring also covers
        # pthread_mutex_lock)
        "mutex_lock", "mutex_unlock",
        "atomic_inc", "atomic_dec", "atomic_set",
        "pthread_", "sem_wait", "sem_post",
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
        # C (universal libc)
        "free(", "malloc(", "calloc(", "realloc(",
        # Rust
        "unsafe {", "ManuallyDrop", "Box::from_raw",
        "std::ptr", "std::mem::forget", "Pin<",
        # Java
        "finalize()", "WeakReference",
    ],
    STRATEGY_INTEGER: [
        # C (universal)
        "size_t", "ssize_t", "uint32_t",
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


# ---------------------------------------------------------------------------
# Target-kind signal packs + learned vocabulary
# ---------------------------------------------------------------------------

_STRATEGY_PACK_DIR = Path(__file__).resolve().parent / "data" / "strategy_packs"


@lru_cache(maxsize=4)
def _signal_pack(name: str) -> tuple | None:
    """(path_signals, source_signals) supplements from a pack file.

    Returns None (logged) when the pack is missing or malformed —
    inference then runs on the universal maps alone.
    """
    path = _STRATEGY_PACK_DIR / f"{name}.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        logger.warning("strategy pack %s unavailable (%s)", path, e)
        return None
    if not isinstance(raw, dict):
        return None

    def _sig(key: str) -> dict[str, list[str]]:
        block = raw.get(key, {})
        if not isinstance(block, dict):
            return {}
        return {
            strategy: [s for s in tokens if isinstance(s, str) and s]
            for strategy, tokens in block.items()
            if isinstance(tokens, list) and strategy in ALL_STRATEGIES
        }

    return _sig("path_signals"), _sig("source_signals")


def _pack_for_target(target_path: Any) -> tuple | None:
    """Kernel-tree gate — the same markers as the checker vocab packs."""
    if target_path is None:
        return None
    try:
        from .vocab_packs import is_kernel_tree
        if is_kernel_tree(target_path):
            return _signal_pack("linux_kernel")
    except Exception:
        logger.debug("strategy pack gating failed", exc_info=True)
    return None


def _merged_signal_map(
    base: dict[str, list[str]],
    extra: dict[str, list[str]],
) -> dict[str, list[str]]:
    """Additive union of two signal maps (base order preserved)."""
    if not extra:
        return base
    merged = {k: list(v) for k, v in base.items()}
    for strategy, tokens in extra.items():
        bucket = merged.setdefault(strategy, [])
        bucket.extend(t for t in tokens if t not in bucket)
    return merged


@lru_cache(maxsize=8)
def _learned_vocab_cached(out_dir_str: str, target_str: str) -> Any:
    try:
        from core.coverage.journal import load_domain_model

        from .condition_smt import DomainVocabulary
        return DomainVocabulary.from_domain_model(
            load_domain_model(Path(out_dir_str)),
            target_path=target_str or None,
        )
    except Exception:
        logger.debug("learned vocab load failed", exc_info=True)
        return None


def learned_vocab(out_dir: Any, target_path: Any = None) -> Any:
    """Cached study-learned DomainVocabulary for a run (or None).

    Convenience for strategy-inference callers: loads the run's
    domain model once per (out_dir, target) and merges the target-kind
    checker pack. Best-effort — returns None when there is nothing to
    load.
    """
    if out_dir is None:
        return None
    vocab = _learned_vocab_cached(
        str(out_dir), str(target_path) if target_path else "",
    )
    if vocab is not None and not vocab.has_content:
        return None
    return vocab


# Which DomainVocabulary classes route to which strategy when the
# function's source calls one of the learned names.
_VOCAB_CLASS_STRATEGIES: dict[str, tuple] = {
    STRATEGY_MEMORY: (
        "allocators", "deallocators", "refcount_gets", "refcount_puts",
        "callback_registers", "callback_cancels",
    ),
    STRATEGY_CONCURRENCY: ("lock_acquires", "lock_releases"),
    STRATEGY_INPUT: ("boundary_transfers",),
}


def _vocab_strategies(source: str, domain_vocab: Any) -> set[str]:
    """Strategies routed by learned vocabulary calls in *source*."""
    out: set[str] = set()
    for strategy, classes in _VOCAB_CLASS_STRATEGIES.items():
        for cls_attr in classes:
            names = getattr(domain_vocab, cls_attr, None) or ()
            if any(
                isinstance(n, str) and n and (n + "(") in source
                for n in names
            ):
                out.add(strategy)
                break
    auth_preds = getattr(domain_vocab, "auth_predicates", None) or ()
    for entry in auth_preds:
        name = entry[0] if isinstance(entry, tuple) else entry
        if isinstance(name, str) and name and (name + "(") in source:
            out.add(STRATEGY_AUTH)
            break
    return out


def infer_strategies(
    *,
    file_path: str,
    function_name: str,
    parameters: list[tuple] | None = None,
    return_type: str | None = None,
    attributes: list[str] | None = None,
    includes: list[str] | None = None,
    reachable_sinks: list[str] | None = None,
    shared_state: list[Any] | None = None,
    crypto_inventory: list[Any] | None = None,
    ownership_model: list[Any] | None = None,
    kind: str | None = None,
    visibility: str | None = None,
    source: str | None = None,
    target_path: Any = None,
    domain_vocab: Any = None,
) -> frozenset[str]:
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
        target_path: root of the target under analysis. A detected
            Linux kernel tree merges the linux_kernel strategy pack's
            token supplements into the path/source signal maps (the
            kernel token bulk lives in the pack, not here).
        domain_vocab: optional study-learned DomainVocabulary; calls
            to its learned names in ``source`` route the function to
            the matching strategy (allocators/refcounts/callback verbs
            → memory, lock verbs → concurrency, auth predicates →
            auth, boundary transfers → input_handling) — additively.

    Returns:
        Frozen set of strategy names to apply.
    """
    strategies: set[str] = {STRATEGY_GENERAL}

    path_signals = _PATH_SIGNALS
    source_signals = _SOURCE_SIGNALS
    pack = _pack_for_target(target_path)
    if pack is not None:
        path_signals = _merged_signal_map(_PATH_SIGNALS, pack[0])
        source_signals = _merged_signal_map(_SOURCE_SIGNALS, pack[1])

    path_lower = file_path.lower()
    name_lower = function_name.lower()
    combined = f"{path_lower}/{name_lower}"

    for strategy, keywords in path_signals.items():
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
        for strategy, keywords in source_signals.items():
            if any(kw in source for kw in keywords):
                strategies.add(strategy)
        if domain_vocab is not None:
            strategies |= _vocab_strategies(source, domain_vocab)

    return frozenset(strategies)


def strategies_from_item(
    item: dict[str, Any],
    file_path: str,
    *,
    includes: list[str] | None = None,
    reachable_sinks: list[str] | None = None,
    shared_state: list[Any] | None = None,
    crypto_inventory: list[Any] | None = None,
    ownership_model: list[Any] | None = None,
    source: str | None = None,
    target_path: Any = None,
    domain_vocab: Any = None,
) -> frozenset[str]:
    """Select strategies from a checklist item dict.

    Convenience wrapper that extracts metadata fields from the
    serialized checklist item format. Checklist metadata carries no
    include/import data, so ``includes`` must be supplied by the
    caller (e.g. from the source file's import lines).
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
        includes=includes,
        reachable_sinks=reachable_sinks,
        shared_state=shared_state,
        crypto_inventory=crypto_inventory,
        ownership_model=ownership_model,
        kind=item.get("kind"),
        visibility=metadata.get("visibility"),
        source=source,
        target_path=target_path,
        domain_vocab=domain_vocab,
    )


STRATEGY_PRIMERS: dict[str, str] = {
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
    "auth": (
        "AUTHENTICATION / AUTHORIZATION VULNERABILITY PRIMER\n"
        "\n"
        "The pattern: the check and the action live in different "
        "places, and a path exists from request to action that skips "
        "or weakens the check. Authn/authz bugs are rarely broken "
        "algorithms — they are broken PLUMBING between the credential "
        "and the privileged operation.\n"
        "\n"
        "What to look for:\n"
        "- Check/act separation: a handler that performs the "
        "privileged operation, and a decorator/middleware/filter "
        "expected to have run first. Find registrations that bypass "
        "the middleware chain (alternate routers, internal endpoints, "
        "debug handlers, websocket/upgrade paths).\n"
        "- Verification results that are computed but not enforced: "
        "jwt.verify/signature-check calls whose return value or "
        "exception is swallowed; verify=False / algorithms=['none'] "
        "reachable via config.\n"
        "- Identity from mutable sources: trusting Host/X-Forwarded-* "
        "headers, client-supplied user ids or role fields, session "
        "values written before authentication completed.\n"
        "- Comparison defects: token/secret equality via early-exit "
        "string compare on a network-observable path; case/Unicode "
        "normalisation differences between the check and the lookup.\n"
        "- State-machine gaps: password-reset, MFA, and OAuth flows "
        "where a later step does not re-verify what an earlier step "
        "established (or a step can be replayed/skipped).\n"
        "\n"
        "The assumption that fails: 'every path to this operation went "
        "through the auth layer' or 'this value was set by us'. "
        "Alternate entry points, background jobs replaying user input, "
        "and deserialised session state violate both.\n"
        "\n"
        "Verification steps:\n"
        "1. Enumerate every route/registration that reaches the "
        "privileged function; diff against the set covered by the "
        "auth middleware/decorator.\n"
        "2. For each verify/authenticate call, confirm the result is "
        "consumed on every branch (including exception paths).\n"
        "3. Trace the identity value from its origin — reject any "
        "origin the client controls.\n"
        "4. For multi-step flows, write down the state each step "
        "assumes and check the server enforces the ordering rather "
        "than trusting the client to follow it."
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


def primers_for_strategies(strategies: frozenset[str]) -> list[str]:
    """Return primer texts for the given strategy set."""
    result: list[str] = []
    for strategy in sorted(strategies):
        if strategy in STRATEGY_PRIMERS:
            result.append(STRATEGY_PRIMERS[strategy])
    return result
