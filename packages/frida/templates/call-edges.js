// call-edges.js - dynamic call-graph edges for reachability rescue.
//
// Stalker-collected caller→callee edges, aggregated in-process and
// emitted at detach as category=call_edge events. The reachability
// pipeline turns callee functions OWNED BY THE TARGET into
// frida_call_edge REACHABLE witnesses - the dynamic complement to the
// r2 static extraction (--binary-edges): an indirect call or vtable
// dispatch the static graph cannot resolve is ground truth here,
// because the call actually executed.
//
// Overhead control: Stalker instruments every followed thread, so
// system modules (anything not the main binary or under its
// directory) are EXCLUDED from following. Edges from target code -
// including into libraries - are captured; callbacks invoked from
// inside excluded libraries are not (api-trace backtraces cover
// those). Only edges whose CALLEE is target-owned are emitted: those
// are the ones that rescue a project function from a dead-code
// verdict.

'use strict';

var MAX_EDGE_KEYS = 65536;    // unique (from,to) pairs tracked
var MAX_RESOLVED = 4096;      // unique addresses symbolicated at exit
var MAX_EMITTED = 8192;       // call_edge events written

function mainModule() {
  if (Process.mainModule) return Process.mainModule;
  var mods = Process.enumerateModules();
  return mods.length > 0 ? mods[0] : null;
}

var main = mainModule();
if (main === null) {
  send({ _meta: 'call-edges: cannot resolve the main module' });
} else {
  var targetDir = main.path.substring(0, main.path.lastIndexOf('/'));

  function ownedModule(m) {
    return m.path === main.path
      || (targetDir.length > 0 && m.path.indexOf(targetDir + '/') === 0);
  }

  // Exclusion setup is DEFERRED to the first flush: Stalker work at
  // load time (the process is still suspended in spawn mode) has
  // wedged script.load() itself.
  var excluded = 0;
  var stalkInitDone = false;
  function stalkInit() {
    if (stalkInitDone) return;
    stalkInitDone = true;
    Process.enumerateModules().forEach(function (m) {
      if (!ownedModule(m)) {
        try {
          Stalker.exclude({ base: m.base, size: m.size });
          excluded++;
        } catch (_e) {}
      }
    });
  }

  var edgeCounts = Object.create(null);   // "from|to" → count
  var edgeKeys = 0;
  var edgesDroppedOverCap = 0;

  function onReceive(events) {
    var parsed;
    try {
      parsed = Stalker.parse(events);
    } catch (_e) {
      return;
    }
    for (var i = 0; i < parsed.length; i++) {
      var ev = parsed[i];
      if (ev[0] !== 'call') continue;
      var key = ev[1] + '|' + ev[2];
      var current = edgeCounts[key];
      if (current === undefined) {
        if (edgeKeys >= MAX_EDGE_KEYS) {
          edgesDroppedOverCap++;
          continue;
        }
        edgeKeys++;
        edgeCounts[key] = 1;
      } else {
        edgeCounts[key] = current + 1;
      }
    }
  }

  var followed = [];
  function follow(tid) {
    try {
      Stalker.follow(tid, { events: { call: true }, onReceive: onReceive });
      followed.push(tid);
    } catch (_e) {}
  }
  // NEVER follow frida's own threads: stalking the agent's JS runtime
  // thread stalls the whole script (timers stop, no events ever
  // deliver). The JS thread is the one running this code; the other
  // agent threads carry recognisable names.
  var jsTid = Process.getCurrentThreadId();
  function isAgentThread(t) {
    if (t.id === jsTid) return true;
    var n = (t.name || '').toLowerCase();
    return n.indexOf('gum-') === 0 || n.indexOf('gdbus') >= 0
      || n.indexOf('frida') >= 0 || n.indexOf('pool-') === 0;
  }
  // Process.enumerateThreads() intermittently WEDGES the agent's JS
  // thread on current builds; it is kept off the steady-state path —
  // the main thread is followed by tid (posted by the controller)
  // and enumeration runs only after the pthread_create hook flags a
  // new thread.
  var pendingNewThreads = false;

  function followAll() {
    stalkInit();
    Process.enumerateThreads().forEach(function (t) {
      if (!isAgentThread(t) && followed.indexOf(t.id) < 0) follow(t.id);
    });
  }

  // The MAIN thread follows ITSELF: remote Stalker.follow of a
  // thread parked in a syscall is unreliable (observed: zero events
  // in most spawn runs), while following the current thread from an
  // Interceptor callback is the canonical, synchronous pattern.
  // Every dynamically-linked program passes __libc_start_main before
  // main, and spawn mode loads this script while the process is still
  // gated at the dynamic linker — the hook is in place in time.
  (function hookSelfFollow() {
    var addr = null;
    if (typeof Module.findGlobalExportByName === 'function') {
      addr = Module.findGlobalExportByName('__libc_start_main');
    } else if (typeof Module.findExportByName === 'function') {
      try { addr = Module.findExportByName(null, '__libc_start_main'); } catch (_e) {}
    }
    if (addr === null) return;
    try {
      Interceptor.attach(addr, {
        onEnter: function (_args) {
          stalkInit();
          var tid = Process.getCurrentThreadId();
          if (followed.indexOf(tid) >= 0) return;
          try {
            Stalker.follow(tid, { events: { call: true },
                                  onReceive: onReceive });
            followed.push(tid);
          } catch (_e) {}
        },
      });
    } catch (_e) {}
  })();

  // Follow threads created after load (same pattern as bb-coverage).
  (function hookThreadCreate() {
    var addr = null;
    if (typeof Module.findGlobalExportByName === 'function') {
      addr = Module.findGlobalExportByName('pthread_create');
    } else if (typeof Module.findExportByName === 'function') {
      try { addr = Module.findExportByName(null, 'pthread_create'); } catch (_e) {}
    }
    if (addr === null) return;
    try {
      Interceptor.attach(addr, {
        onLeave: function (_ret) {
          // Flag only — enumerating from here would put the wedge
          // risk on a target thread.
          pendingNewThreads = true;
        },
      });
    } catch (_e) {}
  })();

  send({ _meta: 'call-edges loaded' });

  // LIMITATION: a pthread's start routine is invoked from inside
  // excluded libc, so thread-entry functions themselves never produce
  // an edge — functions they CALL do. Operators hunting a "dead"
  // worker entry point should pair this with api-trace backtraces.

  var resolveCache = Object.create(null);
  var symbolicated = 0;
  var droppedResolveBudget = 0;

  function resolve(addrStr) {
    var hit = resolveCache[addrStr];
    if (hit !== undefined) return hit;
    var addr = ptr(addrStr);
    var info = { name: null, module: null, module_path: null,
                 offset: null, owned: false };
    try {
      var m = Process.findModuleByAddress(addr);
      if (m !== null) {
        info.module = m.name;
        info.module_path = m.path;
        info.offset = addr.sub(m.base).toString();
        info.owned = ownedModule(m);
      }
    } catch (_e) {}
    // Symbolication budget is spent on TARGET-OWNED addresses only —
    // foreign addresses (the majority) must never starve the names
    // the witness actually needs. Budget exhaustion is counted.
    if (info.owned) {
      if (symbolicated < MAX_RESOLVED) {
        symbolicated++;
        try {
          var sym = DebugSymbol.fromAddress(addr);
          if (sym !== null && sym.name && sym.name.indexOf('0x') !== 0) {
            info.name = sym.name;
          }
        } catch (_e) {}
      } else {
        droppedResolveBudget++;
      }
    }
    resolveCache[addrStr] = info;
    return info;
  }

  // Emission is INCREMENTAL: each new edge is resolved and emitted at
  // the first flush cycle after it appears. Unload-time emission
  // (dispose / weak bindings) races the controller's detach and its
  // messages can be dropped — nothing may depend on it.
  var emittedKeys = Object.create(null);
  var emitted = 0;
  var skippedForeign = 0;

  function flushNewEdges() {
    try { Stalker.flush(); } catch (_e) {}
    var keys = Object.keys(edgeCounts);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      if (emittedKeys[key] !== undefined) continue;
      emittedKeys[key] = true;
      if (emitted >= MAX_EMITTED) continue;
      var parts = key.split('|');
      var callee = resolve(parts[1]);
      if (!callee.owned || callee.name === null) {
        skippedForeign++;
        continue;
      }
      var caller = resolve(parts[0]);
      send({
        category: 'call_edge',
        fn: callee.name,
        callee_module: callee.module,
        callee_module_path: callee.module_path,
        callee_offset: callee.offset,
        caller: caller.name,
        caller_module: caller.module,
        caller_offset: caller.offset,
        count: edgeCounts[key],
        tid: 0,
      });
      emitted++;
    }
    send({ _meta: 'call-edges summary', unique_edges: keys.length,
           emitted: emitted, skipped_foreign_or_unnamed: skippedForeign,
           dropped_over_cap: edgesDroppedOverCap,
           dropped_resolve_budget: droppedResolveBudget,
           excluded_modules: excluded,
           followed_threads: followed.length });
  }

  // The CONTROLLER drives the clock: the runner calls flush() every
  // ~2s and once before teardown (in-agent timers never fire on some
  // frida installs, so nothing here may depend on them). flush() also
  // re-scans threads — spawn mode loads this script while the process
  // is SUSPENDED, so the load-time pass follows nothing and the main
  // thread is picked up on the first flush after resume.
  // No unfollow at teardown: frida cleans followed threads up at
  // detach, and an explicit Stalker.unfollow racing thread death has
  // crashed the controller. The message-driven flush path is
  // preferred — script.post is fire-and-forget, so a delivery race
  // cannot wedge the controller the way a blocking rpc call can;
  // rpc.exports stays for manual/driver use.
  // Emission runs BEFORE any thread enumeration so a wedge can only
  // cost future ticks, never edges already collected.
  function doFlush(mainTid) {
    stalkInit();
    if (typeof mainTid === 'number' && mainTid > 0 && mainTid !== jsTid
        && followed.indexOf(mainTid) < 0) {
      follow(mainTid);
    }
    flushNewEdges();
    if (pendingNewThreads) {
      pendingNewThreads = false;
      followAll();
    }
  }

  function onFlushMsg(msg) {
    if (typeof registerRaptorFlushListener !== 'function') {
      recv('raptor:flush', onFlushMsg);
    }
    var mainTid = (msg !== null && typeof msg === 'object')
      ? msg.main_tid : 0;
    try { doFlush(mainTid); } catch (_e) {}
  }
  if (typeof registerRaptorFlushListener === 'function') {
    registerRaptorFlushListener(onFlushMsg);
  } else {
    recv('raptor:flush', onFlushMsg);
  }

  rpc.exports = {
    flush: function () {
      // Manual drivers have no tid to pass; enumerate on their behalf.
      pendingNewThreads = true;
      doFlush(0);
    },
  };
}
