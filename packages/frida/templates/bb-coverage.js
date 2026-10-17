// bb-coverage.js - basic-block coverage via Frida Stalker (drcov output).
//
// Collects basic-block start addresses hit during the trace and emits
// a drcov-format binary blob. The runner writes it to `coverage.drcov`
// in the output directory; RAPTOR's existing
// `core/coverage/collect.py:parse_drcov()` consumes it directly.
//
// Use:
//   raptor frida --target <pid|name|binary> --template bb-coverage
//
// Reliability mechanics (each earned the hard way):
//   * Emission AND thread-following happen on the CONTROLLER's flush
//     clock (rpc flush) — unload-time emission via weak bindings
//     never fires on some frida installs (silently produced no
//     coverage at all), and following a still-suspended spawn's main
//     thread at load time silently captures nothing. Each flush
//     re-follows live threads and emits the full cumulative blob;
//     the runner overwrites coverage.drcov, so the last flush wins.
//   * A __libc_start_main self-follow hook is kept as belt-and-braces
//     for builds whose spawn gating passes through it (some builds
//     never call the hook under spawn).
//   * Stalker setup is deferred off script-load (a suspended spawn
//     has wedged load itself), no Stalker.unfollow runs at teardown
//     (racing thread death has crashed the controller), and frida's
//     own threads are never followed (stalking the agent's JS thread
//     stalls the whole script).
//
// Scope: only the target module (and same-directory libraries) is
// stalked — RAPTOR's drcov consumer reads only the target module's
// offsets, and whole-process stalking has wedged the agent. Known
// limitation: a target that exits before the first flush (~0.3s
// after resume) yields little or no coverage — keep it alive via
// stdin or arguments.

'use strict';

function findGlobalExport(name) {
  if (typeof Module.findGlobalExportByName === 'function') {
    return Module.findGlobalExportByName(name);
  }
  if (typeof Module.findExportByName === 'function') {
    try { return Module.findExportByName(null, name); } catch (_e) { return null; }
  }
  return null;
}

var bbSet = {};          // "module_id:offset" -> {start, mid}
var modTable = [];       // ids append-only so transforms stay valid
var seenModules = {};    // path -> true
var stalkInitDone = false;

function mainModule() {
  if (Process.mainModule) return Process.mainModule;
  var mods = Process.enumerateModules();
  return mods.length > 0 ? mods[0] : null;
}

// Fold the current module list into the table. Called at first
// follow (NOT at load: spawn mode loads this script while the
// process is suspended mid-link, so load-time enumeration misses
// late-mapped libraries) and again on every flush, so libraries
// dlopen'd later are excluded from stalking too instead of being
// stalked-but-unattributed. Appended ids never shift.
function refreshModules() {
  var main = mainModule();
  var targetDir = main === null ? ''
    : main.path.substring(0, main.path.lastIndexOf('/'));
  var modules = Process.enumerateModules();
  for (var i = 0; i < modules.length; i++) {
    var m = modules[i];
    if (seenModules[m.path] === true) continue;
    seenModules[m.path] = true;
    modTable.push({
      id: modTable.length,
      base: m.base,
      end: m.base.add(m.size),
      size: m.size,
      path: m.path
    });
    // Exclude non-target modules from stalking: RAPTOR's drcov
    // consumer (collect_drcov) only reads the TARGET module's
    // offsets, and whole-process Stalker transform load has wedged
    // this frida build. Excluded modules stay in the table so their
    // ids remain stable for any external drcov consumer.
    var owned = main !== null
      && (m.path === main.path
          || (targetDir.length > 0
              && m.path.indexOf(targetDir + '/') === 0));
    if (!owned) {
      try { Stalker.exclude({ base: m.base, size: m.size }); } catch (_e) {}
    }
  }
}

function stalkInit() {
  if (stalkInitDone) return;
  stalkInitDone = true;
  refreshModules();
}

function findModule(addr) {
  for (var i = 0; i < modTable.length; i++) {
    if (addr.compare(modTable[i].base) >= 0 && addr.compare(modTable[i].end) < 0) {
      return modTable[i];
    }
  }
  return null;
}

// Stalker transform callback: record each basic block's start.
function transform(iterator) {
  var instruction = iterator.next();
  var startAddr = instruction.address;
  var mod = findModule(startAddr);
  if (mod !== null) {
    var offset = startAddr.sub(mod.base).toUInt32();
    var key = mod.id + ':' + offset;
    if (!(key in bbSet)) {
      bbSet[key] = { start: offset, mid: mod.id };
    }
  }

  do {
    iterator.keep();
  } while ((instruction = iterator.next()) !== null);
}

var followed = [];
function follow(tid) {
  try {
    Stalker.follow(tid, { transform: transform });
    followed.push(tid);
  } catch (_e) {}
}

var jsTid = Process.getCurrentThreadId();
function isAgentThread(t) {
  if (t.id === jsTid) return true;
  var n = (t.name || '').toLowerCase();
  return n.indexOf('gum-') === 0 || n.indexOf('gdbus') >= 0
    || n.indexOf('frida') >= 0 || n.indexOf('pool-') === 0;
}

// Process.enumerateThreads() intermittently WEDGES the agent's JS
// thread on current builds (racing thread startup and process
// death), and everything — rpc and posted messages alike — queues
// behind it forever. It is therefore never on the steady-state path:
// the main thread is followed by tid (posted by the controller), and
// enumeration runs only when the pthread_create hook has flagged a
// genuinely new thread, after the current emission is already out.
var pendingNewThreads = false;

function followAll() {
  stalkInit();
  refreshModules();
  Process.enumerateThreads().forEach(function (t) {
    if (!isAgentThread(t) && followed.indexOf(t.id) < 0) follow(t.id);
  });
}

// Belt-and-braces: synchronous self-follow at __libc_start_main for
// builds whose spawn gating calls it (not all do — the flush-clock
// re-follow above is the dependable path).
var selfFollowHook = false;
(function hookSelfFollow() {
  var addr = findGlobalExport('__libc_start_main');
  if (addr === null) return;
  try {
    Interceptor.attach(addr, {
      onEnter: function (_args) {
        stalkInit();
        var tid = Process.getCurrentThreadId();
        if (followed.indexOf(tid) >= 0) return;
        try {
          Stalker.follow(tid, { transform: transform });
          followed.push(tid);
        } catch (_e) {}
      },
    });
    selfFollowHook = true;
  } catch (_e) {}
})();

// Follow threads created after load.
var threadCreateHook = false;
(function hookThreadCreate() {
  var addr = findGlobalExport('pthread_create');
  if (addr === null) return;
  try {
    Interceptor.attach(addr, {
      onLeave: function (retval) {
        // Flag only — enumeration from here would put the wedge
        // risk on a target thread.
        if (retval.toInt32() === 0) pendingNewThreads = true;
      },
    });
    threadCreateHook = true;
  } catch (_e) {}
})();

// Inactive layers are reported, not silently absent — the flush
// clock is the dependable path either way.
send({ _meta: 'bb-coverage loaded', self_follow_hook: selfFollowHook,
       thread_create_hook: threadCreateHook });

// Sanitise module paths before embedding them in the text header.
// m.path comes from the instrumented process and the header is
// packed as charCodeAt(...) & 0xff, so the check must guarantee the
// EMITTED BYTES: only 0x20-0x7e pass through (U+010A would slip a
// 0x0a newline past a codepoint check and forge a module-table
// row). '%' is encoded for injectivity, ':' and ',' so no path can
// spoof the 'BB Table:' marker or shift a module row's columns.
function sanitizePath(p) {
  var out = '';
  for (var j = 0; j < p.length; j++) {
    var code = p.charCodeAt(j);
    var ch = p.charAt(j);
    if (code < 0x20 || code > 0x7e
        || ch === '%' || ch === ':' || ch === ',') {
      out += '%' + ('000' + code.toString(16)).slice(-4);
    } else {
      out += ch;
    }
  }
  return out;
}

function emitDrcov() {
  try { Stalker.flush(); } catch (_e) {}

  var header = 'DRCOV VERSION: 2\n';
  header += 'DRCOV FLAVOR: frida-stalker\n';
  header += 'Module Table: version 2, count ' + modTable.length + '\n';
  header += 'Columns: id, base, end, entry, checksum, timestamp, path\n';
  for (var i = 0; i < modTable.length; i++) {
    var m = modTable[i];
    header += m.id + ', ' + m.base + ', ' + m.end + ', 0x0, 0x0, 0x0, ' + sanitizePath(m.path) + '\n';
  }
  var keys = Object.keys(bbSet);
  var bbCount = keys.length;
  header += 'BB Table: ' + bbCount + ' bbs\n';

  // Pack BB entries as <IHH> (start u32, size u16, module_id u16).
  // Size is set to 1 (we only know start addresses from Stalker
  // transform; precise BB size would require disassembly).
  var headerBytes = [];
  for (var c = 0; c < header.length; c++) {
    headerBytes.push(header.charCodeAt(c));
  }
  var bbBuf = new ArrayBuffer(bbCount * 8);
  var bbView = new DataView(bbBuf);
  var idx = 0;
  for (var k = 0; k < keys.length; k++) {
    var entry = bbSet[keys[k]];
    bbView.setUint32(idx, entry.start, true);      // start offset (LE)
    bbView.setUint16(idx + 4, 1, true);             // size = 1
    bbView.setUint16(idx + 6, entry.mid, true);     // module id (LE)
    idx += 8;
  }

  var total = new Uint8Array(headerBytes.length + bbBuf.byteLength);
  total.set(headerBytes, 0);
  total.set(new Uint8Array(bbBuf), headerBytes.length);

  send({ _drcov: true, bb_count: bbCount, modules: modTable.length,
         followed_threads: followed.length }, total.buffer);
}

// The controller drives the clock: fast early cadence, every ~2s,
// and once before teardown. The message-driven path is preferred —
// script.post is fire-and-forget, so a delivery race cannot wedge
// the controller the way a blocking rpc call can. rpc.exports stays
// for manual/driver use. Emission runs BEFORE any thread
// enumeration so a wedge can only cost future ticks, never data
// already collected.
function doFlush(mainTid) {
  stalkInit();
  refreshModules();
  if (typeof mainTid === 'number' && mainTid > 0 && mainTid !== jsTid
      && followed.indexOf(mainTid) < 0) {
    follow(mainTid);
  }
  emitDrcov();
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
