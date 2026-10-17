// heap-trace.js - heap lifecycle evidence: double-free, invalid-free,
// freed-memory-use candidates, and outstanding-allocation summaries.
//
// Gives memory-corruption findings runtime evidence on binaries that
// cannot be rebuilt with ASAN. Hooks the allocator (malloc / calloc /
// realloc / free) plus a small set of libc data functions whose
// pointer arguments are checked against recently freed ranges.
//
// Use:
//   raptor frida --target <pid|name|binary> --template heap-trace
//
// Event categories (all `category: 'heap'`):
//   * kind=double_free   - free() of a pointer already in the freed
//                          quarantine and not re-allocated since.
//   * kind=invalid_free  - free() of a pointer never seen from any
//                          allocator hook. Spawn-mode only (hooks
//                          land at frida's spawn gate, before the
//                          target's own code runs; in attach mode a
//                          pre-attach allocation freed later is
//                          indistinguishable), and suppressed
//                          entirely when any alloc-source export
//                          failed to hook - a coverage gap would
//                          mint phantoms from legitimate frees.
//   * kind=uaf_candidate - a hooked libc call received a pointer
//                          into a freed-and-not-reallocated range.
//                          CANDIDATE: quarantine is bounded, and the
//                          allocator may have recycled the range for
//                          an allocation this script never saw.
//                          Boundary-only: compilers inline small
//                          constant memcpy/strcpy calls, and an
//                          inlined use never reaches the hook.
//   * The flush summary carries outstanding-allocation totals and
//     the top owned allocation sites (leak candidates - the last
//     flush before exit wins, mirroring bb-coverage's drcov).
//
// Reliability mechanics (inherited from the rest of the family):
//   * Per-allocation events are NEVER sent - allocator storms would
//     drown the channel. Detailed events fire only for the anomaly
//     kinds above, under a global budget; everything else aggregates
//     in-agent and leaves on the controller's flush clock
//     ('raptor:flush' message; rpc export kept for manual drivers).
//   * Attribution is by Interceptor return address, resolved against
//     a lazily built module table. Only anomalies whose call site is
//     in the TARGET module (or a same-directory library) are
//     reported as events - libc-internal churn is counted, not
//     reported. Symbolication happens at flush time for the bounded
//     top-site summary only, never per call.
//   * State is bounded: live map capped (beyond it, tracking gaps
//     are COUNTED, never silent), freed quarantine is a fixed-size
//     ring.

'use strict';

var MAX_EVENTS = 4096;          // global anomaly-event budget
var MAX_LIVE = 262144;          // live-allocation map cap
var QUARANTINE = 512;           // freed-range ring size
var TOP_SITES = 32;             // summary: top owned alloc sites

var eventCount = 0;
function sendBudgeted(obj) {
  eventCount++;
  if (eventCount > MAX_EVENTS) {
    if (eventCount === MAX_EVENTS + 1) {
      send({ _meta: 'heap-trace event cap reached', cap: MAX_EVENTS });
    }
    return false;
  }
  send(obj);
  return true;
}

// ─── module table for return-address attribution ───────────────────
var modTable = [];
var seenModules = {};
var mainPath = null;
var targetDir = '';

function refreshModules() {
  if (mainPath === null) {
    var main = Process.mainModule
      ? Process.mainModule
      : (Process.enumerateModules()[0] || null);
    if (main !== null) {
      mainPath = main.path;
      targetDir = main.path.substring(0, main.path.lastIndexOf('/'));
    }
  }
  Process.enumerateModules().forEach(function (m) {
    if (seenModules[m.path] === true) return;
    seenModules[m.path] = true;
    modTable.push({ base: m.base, end: m.base.add(m.size),
                    path: m.path,
                    name: m.path.substring(m.path.lastIndexOf('/') + 1) });
  });
}

function moduleFor(addr) {
  for (var i = 0; i < modTable.length; i++) {
    if (addr.compare(modTable[i].base) >= 0
        && addr.compare(modTable[i].end) < 0) {
      return modTable[i];
    }
  }
  return null;
}

function isOwned(mod) {
  if (mod === null || mainPath === null) return false;
  return mod.path === mainPath
    || (targetDir.length > 0 && mod.path.indexOf(targetDir + '/') === 0);
}

function siteFor(retaddr) {
  var mod = moduleFor(retaddr);
  if (mod === null) {
    refreshModules();
    mod = moduleFor(retaddr);
  }
  if (mod === null) return { key: '?', owned: false, module: null };
  var off = retaddr.sub(mod.base).toString();
  return { key: mod.name + '+' + off, owned: isOwned(mod),
           module: mod.name, offset: off,
           module_base: mod.base.toString(), module_path: mod.path };
}

// ─── allocation state ───────────────────────────────────────────────
var MAX_PENDING_INVALID = 64;
var pendingInvalidFrees = [];
var spawnedKnown = false;            // controller says spawn mode

var agentChurn = 0;                  // frida-internal alloc traffic

var live = Object.create(null);      // addr-string -> {size, site}
var liveCount = 0;
var liveOverflow = 0;                // allocations not tracked (cap)
var unknownFrees = 0;                // free() of never-seen pointer
var totals = { allocs: 0, frees: 0, bytes_out: 0 };
var ownedSites = Object.create(null); // site.key -> {count, bytes, site}

var freedRing = new Array(QUARANTINE);
var freedIdx = 0;

function quarantinePut(base, size, freeSite, allocSite) {
  freedRing[freedIdx] = { base: base, size: size,
                          free_site: freeSite, alloc_site: allocSite };
  freedIdx = (freedIdx + 1) % QUARANTINE;
}

function quarantineFind(ptr) {
  for (var i = 0; i < QUARANTINE; i++) {
    var q = freedRing[i];
    if (q !== undefined && q !== null
        && ptr.compare(q.base) >= 0
        && ptr.compare(q.base.add(q.size)) < 0) {
      return q;
    }
  }
  return null;
}

// Drop every quarantine entry overlapping the new allocation, not
// just an exact-base match: the allocator consolidates freed
// neighbours, so one malloc can span several stale entries — keeping
// them would flag writes into LIVE memory as freed-memory use.
function quarantineDropRange(base, size) {
  var end = base.add(size > 0 ? size : 1);
  for (var i = 0; i < QUARANTINE; i++) {
    var q = freedRing[i];
    if (q !== undefined && q !== null
        && base.compare(q.base.add(q.size)) < 0
        && end.compare(q.base) > 0) {
      freedRing[i] = null;
    }
  }
}

function recordAlloc(ptr, size, retaddr) {
  if (ptr.isNull()) return;
  totals.allocs++;
  // A recycled range is live again - it must stop matching the
  // freed quarantine or every reuse would read as a UAF.
  quarantineDropRange(ptr, size);
  var site = siteFor(retaddr);
  if (site.owned) {
    var agg = ownedSites[site.key];
    if (agg === undefined) {
      agg = { count: 0, bytes: 0, site: site };
      ownedSites[site.key] = agg;
    }
    agg.count++;
    agg.bytes += size;
  }
  if (liveCount >= MAX_LIVE) {
    liveOverflow++;
    return;
  }
  // bytes_outstanding counts tracked allocations only, so the
  // matching free always balances it (overflowed allocations are
  // counted in live_overflow instead of silently skewing bytes).
  totals.bytes_out += size;
  live[ptr.toString()] = { size: size, site: site };
  liveCount++;
}

function recordFree(ptr, retaddr) {
  if (ptr.isNull()) return;
  totals.frees++;
  var key = ptr.toString();
  var entry = live[key];
  var site = siteFor(retaddr);
  if (entry !== undefined) {
    delete live[key];
    liveCount--;
    totals.bytes_out -= entry.size;
    if (entry.site.owned) {
      var agg = ownedSites[entry.site.key];
      if (agg !== undefined) {
        agg.count--;
        agg.bytes -= entry.size;
      }
    }
    quarantinePut(ptr, entry.size, site, entry.site);
    return;
  }
  var q = quarantineFind(ptr);
  if (q !== null && q.base.equals(ptr)) {
    // An unresolvable caller is frida's own injected code (anonymous
    // executable range, cloaked from module enumeration): its
    // internal heap churn recycles target chunks and would read as
    // phantom double frees. Count, never report.
    if (site.module === null) {
      agentChurn++;
      return;
    }
    if (site.owned || q.free_site.owned) {
      sendBudgeted({ category: 'heap', kind: 'double_free', fn: 'free',
                     address: ptr.toString(), size: q.size,
                     caller_module: site.module,
                     caller_module_base: site.module_base,
                     caller_module_path: site.module_path,
                     caller_offset: site.offset,
                     first_free_site: q.free_site.key,
                     alloc_site: q.alloc_site.key, tid: 0 });
    }
    return;
  }
  // Never seen from an allocator hook. Only meaningful in spawn
  // mode (hooks land at frida's spawn gate, before the target's own
  // code runs; in attach mode a pre-attach allocation freed later
  // looks identical) - and the agent cannot tell the modes apart, so
  // candidates are BUFFERED and emitted at flush time once the
  // controller has said spawned=true.
  unknownFrees++;
  if (site.owned && liveOverflow === 0 && allocSourceGaps === 0
      && pendingInvalidFrees.length < MAX_PENDING_INVALID) {
    pendingInvalidFrees.push({ category: 'heap', kind: 'invalid_free',
                               fn: 'free', address: ptr.toString(),
                               caller_module: site.module,
                               caller_module_base: site.module_base,
                               caller_module_path: site.module_path,
                               caller_offset: site.offset, tid: 0 });
  }
}

// ─── allocator hooks ────────────────────────────────────────────────
function findGlobalExport(name) {
  if (typeof Module.findGlobalExportByName === 'function') {
    return Module.findGlobalExportByName(name);
  }
  if (typeof Module.findExportByName === 'function') {
    try { return Module.findExportByName(null, name); } catch (_e) { return null; }
  }
  return null;
}

var hooked = [];
var allocSourceGaps = 0;              // alloc-source exports we failed to hook
var hookedAddrs = {};                 // addr-string -> first name
// memcpy/memmove (and friends) can resolve to one shared
// implementation or tail-call each other; both paths would report
// one call twice without address- and event-level dedup.
var MAX_SEEN_ANOMALIES = 8192;
var seenAnomaliesCount = 0;
var seenAnomalies = Object.create(null);

function attachOnce(name, addr, callbacks) {
  var key = addr.toString();
  if (hookedAddrs[key] !== undefined) {
    hooked.push(name + '=' + hookedAddrs[key]);
    return;
  }
  Interceptor.attach(addr, callbacks);
  hookedAddrs[key] = name;
  hooked.push(name);
}

function hookAllocator() {
  var mallocAddr = findGlobalExport('malloc');
  if (mallocAddr !== null) {
    try {
      Interceptor.attach(mallocAddr, {
        onEnter: function (args) {
          this.sz = args[0].toUInt32();
          this.ra = this.returnAddress;
        },
        onLeave: function (retval) {
          recordAlloc(retval, this.sz, this.ra);
        },
      });
      hooked.push('malloc');
    } catch (_e) {}
  }
  var callocAddr = findGlobalExport('calloc');
  if (callocAddr !== null) {
    try {
      Interceptor.attach(callocAddr, {
        onEnter: function (args) {
          this.sz = args[0].toUInt32() * args[1].toUInt32();
          this.ra = this.returnAddress;
        },
        onLeave: function (retval) {
          recordAlloc(retval, this.sz, this.ra);
        },
      });
      hooked.push('calloc');
    } catch (_e) {}
  }
  var reallocAddr = findGlobalExport('realloc');
  if (reallocAddr !== null) {
    try {
      Interceptor.attach(reallocAddr, {
        onEnter: function (args) {
          this.old = args[0];
          this.sz = args[1].toUInt32();
          this.ra = this.returnAddress;
        },
        onLeave: function (retval) {
          if (!this.old.isNull() && !retval.isNull()) {
            recordFree(this.old, this.ra);
          }
          recordAlloc(retval, this.sz, this.ra);
        },
      });
      hooked.push('realloc');
    } catch (_e) {}
  }
  // The memalign family are alloc SOURCES too: a pointer from
  // aligned_alloc later hitting free() must not read as an invalid
  // free (C++17 aligned new and SIMD libraries use these routinely).
  [{ name: 'aligned_alloc', sizeArg: 1 },
   { name: 'memalign', sizeArg: 1 },
   { name: 'valloc', sizeArg: 0 },
   { name: 'pvalloc', sizeArg: 0 }].forEach(function (spec) {
    var a = findGlobalExport(spec.name);
    if (a === null) return;
    try {
      Interceptor.attach(a, {
        onEnter: function (args) {
          this.sz = args[spec.sizeArg].toUInt32();
          this.ra = this.returnAddress;
        },
        onLeave: function (retval) {
          recordAlloc(retval, this.sz, this.ra);
        },
      });
      hooked.push(spec.name);
    } catch (_e) { allocSourceGaps++; }
  });
  var pmAddr = findGlobalExport('posix_memalign');
  if (pmAddr !== null) {
    try {
      Interceptor.attach(pmAddr, {
        onEnter: function (args) {
          this.slot = args[0];
          this.sz = args[2].toUInt32();
          this.ra = this.returnAddress;
        },
        onLeave: function (retval) {
          if (retval.toInt32() === 0 && !this.slot.isNull()) {
            recordAlloc(this.slot.readPointer(), this.sz, this.ra);
          }
        },
      });
      hooked.push('posix_memalign');
    } catch (_e) { allocSourceGaps++; }
  }
  var freeAddr = findGlobalExport('free');
  if (freeAddr !== null) {
    try {
      Interceptor.attach(freeAddr, {
        onEnter: function (args) {
          recordFree(args[0], this.returnAddress);
        },
      });
      hooked.push('free');
    } catch (_e) {}
  }
}

// ─── freed-memory-use detection at libc boundaries ─────────────────
// Pointer arguments of common data functions are checked against the
// freed quarantine. Boundary-only by design: full use detection
// would need Stalker-level instrumentation of every memory access.
var USE_CHECKS = [
  { fn: 'memcpy', ptrArgs: [0, 1] },
  { fn: 'memmove', ptrArgs: [0, 1] },
  { fn: 'memset', ptrArgs: [0] },
  { fn: 'strcpy', ptrArgs: [0, 1] },
  { fn: 'strncpy', ptrArgs: [0, 1] },
  { fn: 'strlen', ptrArgs: [0] },
  { fn: 'write', ptrArgs: [1] },
  { fn: 'read', ptrArgs: [1] },
];

function hookUseChecks() {
  USE_CHECKS.forEach(function (spec) {
    var addr = findGlobalExport(spec.fn);
    if (addr === null) return;
    try {
      attachOnce(spec.fn, addr, {
        onEnter: function (args) {
          var ra = this.returnAddress;
          for (var i = 0; i < spec.ptrArgs.length; i++) {
            var p = args[spec.ptrArgs[i]];
            if (p.isNull()) continue;
            var q = quarantineFind(p);
            if (q === null) continue;
            var site = siteFor(ra);
            if (!site.owned) continue;
            var dk = 'u|' + p.toString() + '|' + site.key;
            if (seenAnomalies[dk] === true) continue;
            if (seenAnomaliesCount < MAX_SEEN_ANOMALIES) {
              seenAnomalies[dk] = true;
              seenAnomaliesCount++;
            }
            sendBudgeted({ category: 'heap', kind: 'uaf_candidate',
                           fn: spec.fn, arg_index: spec.ptrArgs[i],
                           address: p.toString(),
                           freed_base: q.base.toString(),
                           freed_size: q.size,
                           caller_module: site.module,
                           caller_module_base: site.module_base,
                           caller_module_path: site.module_path,
                           caller_offset: site.offset,
                           free_site: q.free_site.key,
                           alloc_site: q.alloc_site.key, tid: 0 });
          }
        },
      });
    } catch (_e) {}
  });
}

// ─── flush: aggregated summary, last one wins ───────────────────────
function symbolize(site) {
  try {
    var mod = null;
    for (var i = 0; i < modTable.length; i++) {
      if (modTable[i].name === site.module) { mod = modTable[i]; break; }
    }
    if (mod === null) return null;
    var sym = DebugSymbol.fromAddress(mod.base.add(ptr(site.offset)));
    if (sym !== null && sym.name !== null) return sym.name;
  } catch (_e) {}
  return null;
}

function doFlush() {
  refreshModules();
  if (spawnedKnown && pendingInvalidFrees.length > 0) {
    var pend = pendingInvalidFrees;
    pendingInvalidFrees = [];
    pend.forEach(sendBudgeted);
  }
  var sites = [];
  for (var key in ownedSites) {
    var agg = ownedSites[key];
    if (agg.count > 0) sites.push(agg);
  }
  sites.sort(function (a, b) { return b.bytes - a.bytes; });
  sites = sites.slice(0, TOP_SITES);
  // _meta keeps the summary out of the validation bridge's
  // call-evidence path (it is an aggregate, not a call observation);
  // the anomaly events above flow through as attributed evidence.
  send({ _meta: 'heap summary', category: 'heap', kind: 'summary',
         allocs: totals.allocs, frees: totals.frees,
         bytes_outstanding: totals.bytes_out,
         live_tracked: liveCount, live_overflow: liveOverflow,
         unknown_frees: unknownFrees, agent_churn: agentChurn,
         alloc_source_gaps: allocSourceGaps,
         anomaly_events: Math.min(eventCount, MAX_EVENTS),
         top_owned_sites: sites.map(function (agg) {
           return { site: agg.site.key,
                    symbol: symbolize(agg.site),
                    outstanding_count: agg.count,
                    outstanding_bytes: agg.bytes };
         }),
         tid: 0 });
}

function onFlushMsg(msg) {
  if (typeof registerRaptorFlushListener !== 'function') {
    recv('raptor:flush', onFlushMsg);
  }
  if (msg !== null && typeof msg === 'object' && msg.spawned === true) {
    spawnedKnown = true;
  }
  try { doFlush(); } catch (_e) {}
}
if (typeof registerRaptorFlushListener === 'function') {
  registerRaptorFlushListener(onFlushMsg);
} else {
  recv('raptor:flush', onFlushMsg);
}

rpc.exports = {
  flush: doFlush,
};

// A double free usually aborts the process moments after the hook
// records it, and the in-flight send is lost with it. Holding the
// abort path briefly lets pending events drain (empirically the
// difference between reporting the double free and losing it).
(function hookAbort() {
  ['abort', '__libc_message'].forEach(function (name) {
    var addr = findGlobalExport(name);
    if (addr === null) return;
    try {
      Interceptor.attach(addr, {
        onEnter: function (_args) {
          send({ _meta: 'target aborting; draining events' });
          try { Thread.sleep(0.3); } catch (_e) {}
        },
      });
    } catch (_e) {}
  });
})();

refreshModules();
hookAllocator();
hookUseChecks();

send({ _meta: 'heap-trace loaded', hooked: hooked,
       agent_churn_counter: true });
