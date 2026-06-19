"""RAPTOR-authored Frida agent (JS) templates.

The agent scripts are RAPTOR's own code (the *target* is the untrusted
party); they are rendered with operator/skill-supplied parameters injected
as JSON literals so target-derived strings never reach ``eval``.
"""

from __future__ import annotations

import json
from typing import List, Optional


def trace_agent(symbols: List[str]) -> str:
    """JS that hooks each named function and ``send()``s its first four
    integer-width arguments on entry. Resolves by debug symbol first (works
    for static, ``-g`` symbols), then by exported name. Unresolved symbols
    report a one-shot ``error`` so the operator sees "not found" rather than
    silent absence."""
    syms_json = json.dumps(list(symbols))
    return """
'use strict';
var SYMBOLS = %s;
function resolve(name) {
    try {
        var s = DebugSymbol.fromName(name);
        if (s && s.address && !s.address.isNull()) return s.address;
    } catch (e) {}
    try {
        var a = Module.findGlobalExportByName(name);  // Frida 17 API
        if (a && !a.isNull()) return a;
    } catch (e) {}
    return null;
}
SYMBOLS.forEach(function (name) {
    var addr = resolve(name);
    if (!addr) { send({ fn: name, error: 'symbol not found' }); return; }
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                var a = [];
                for (var i = 0; i < 4; i++) {
                    try { a.push(args[i].toInt32()); } catch (e) { a.push(null); }
                }
                send({ fn: name, addr: addr.toString(), args: a });
            }
        });
    } catch (e) {
        send({ fn: name, error: 'attach failed: ' + e });
    }
});
""" % syms_json


def coverage_agent(modules: Optional[List[str]] = None) -> str:
    """JS that enumerates loaded modules (so Python can build the drcov module
    table) and follows the main thread with Stalker, emitting basic-block
    start/end addresses. ``modules`` (substrings) optionally restricts which
    modules are reported/instrumented; ``None`` = the main module only (the
    common "cover the target binary" case).

    Emits:
      * ``{kind:'modules', modules:[{name,base,size,path}]}`` once at load
      * ``{kind:'blocks', blocks:[[startHex,endHex],...]}`` per Stalker batch
        (deduplicated agent-side to keep bridge traffic bounded)
    Python (``coverage.py``) turns these into a drcov file.

    Coverage starts at ``main`` (resolved via DWARF) and follows that thread
    with Stalker - a spawned target's threads aren't enumerable while
    suspended and its entry hook (``__libc_start_main``) has already run by
    resume, so we hook the target's own ``main`` and call ``Stalker.follow``
    from inside it (runs on the target main thread). Requires a resolvable
    ``main`` symbol (the DWARF-present context this feature targets); reports
    a ``no_main`` error otherwise.
    """
    mods_json = json.dumps(modules) if modules else "null"
    return """
'use strict';
var WANT = %s;
function moduleMatches(m) {
    if (WANT === null) return true;
    for (var i = 0; i < WANT.length; i++) {
        if (m.name.indexOf(WANT[i]) !== -1 || m.path.indexOf(WANT[i]) !== -1)
            return true;
    }
    return false;
}
var mods = Process.enumerateModules().filter(moduleMatches).map(function (m) {
    return { name: m.name, base: m.base.toString(), size: m.size, path: m.path };
});
send({ kind: 'modules', modules: mods });

// Cover the main module by default (the target binary) when WANT is null.
var mainMod = Process.enumerateModules()[0];
var lo = WANT === null ? ptr(mainMod.base) : null;
var hi = WANT === null ? ptr(mainMod.base).add(mainMod.size) : null;

// Drain the Stalker event queue aggressively so short-lived targets flush
// their blocks before exit (default interval can outlive a fast target).
try { Stalker.queueDrainInterval = 5; } catch (e) {}
var SEEN = {};   // agent-side dedup: block-start string -> 1
function onBlocks(events) {
    var parsed = Stalker.parse(events, { annotate: false, stringify: false });
    var blocks = [];
    for (var i = 0; i < parsed.length; i++) {
        var start = parsed[i][0];
        if (lo !== null && (start.compare(lo) < 0 || start.compare(hi) >= 0))
            continue;
        var key = start.toString();
        if (SEEN[key]) continue;
        SEEN[key] = 1;
        blocks.push([key, parsed[i][1].toString()]);
    }
    if (blocks.length) send({ kind: 'blocks', blocks: blocks });
}
var mainAddr = null;
try {
    var s = DebugSymbol.fromName('main');
    if (s && s.address && !s.address.isNull()) mainAddr = s.address;
} catch (e) {}
if (!mainAddr) {
    try { mainAddr = Module.findGlobalExportByName('main'); } catch (e) {}
}
if (!mainAddr) {
    send({ kind: 'blocks', error: 'no_main: cannot resolve main to start coverage' });
} else {
    var started = false;
    Interceptor.attach(mainAddr, { onEnter: function () {
        if (started) return;
        started = true;
        Stalker.follow(this.threadId, {
            events: { block: true }, onReceive: onBlocks,
        });
    }});
}
""" % mods_json
