// binary-flow-trace.js - input-callsite evidence for black-box binaries.
//
// This template is deliberately narrow. It records where common ingestion
// APIs and high-value parser APIs were called from so RAPTOR can upgrade
// "this binary imports recv/XML_Parse" into "this recovered function was
// observed calling recv/XML_Parse". It still does not pretend the bytes
// reached a later sink or that parser arguments were attacker-controlled.

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

function safeStr(ptr, maxLen) {
  if (ptr.isNull()) return '<null>';
  try { return Memory.readUtf8String(ptr, maxLen || 256); } catch (_e) { return '<unreadable>'; }
}

function callsite(context, returnAddress) {
  let backtrace = [];
  let backtraceFrames = [];
  let moduleInfo = {};
  try {
    backtraceFrames = Thread.backtrace(context, Backtracer.ACCURATE)
      .slice(0, 12)
      .map(addr => {
        let frame = { address: addr.toString() };
        try {
          const module = Process.findModuleByAddress(addr);
          if (module !== null) {
            frame = Object.assign(frame, {
              module: module.name,
              module_base: module.base.toString(),
              module_offset: addr.sub(module.base).toString(),
            });
          }
        } catch (_e) {}
        return frame;
      });
    backtrace = backtraceFrames.map(frame => frame.address);
  } catch (_e) {
    backtrace = [];
    backtraceFrames = [];
  }
  try {
    const module = returnAddress ? Process.findModuleByAddress(returnAddress) : null;
    if (module !== null) {
      moduleInfo = {
        caller_module: module.name,
        caller_module_base: module.base.toString(),
        caller_offset: returnAddress.sub(module.base).toString(),
      };
    }
  } catch (_e) {
    moduleInfo = {};
  }
  return {
    caller: returnAddress ? returnAddress.toString() : null,
    backtrace: backtrace,
    backtrace_frames: backtraceFrames,
    ...moduleInfo,
  };
}

function hook(name, category, readArgs) {
  const addr = findGlobalExport(name);
  if (addr === null) return false;
  Interceptor.attach(addr, {
    onEnter: function (args) {
      this.site = callsite(this.context, this.returnAddress);
      try { this.args = readArgs(args); } catch (e) { this.args = { _err: String(e) }; }
    },
    onLeave: function (retval) {
      send(Object.assign({
        category: category,
        fn: name,
        args: Object.assign({ ret: retval.isNull() ? 0 : retval.toUInt32() }, this.args || {}),
        tid: Process.getCurrentThreadId(),
      }, this.site || {}));
    },
  });
  return true;
}

const hooks = [];
function add(name, category, readArgs) {
  if (hook(name, category, readArgs)) hooks.push(name);
}

add('read', 'file', a => ({ fd: a[0].toInt32(), count: a[2].toInt32() }));
add('fread', 'file', a => ({ size: a[1].toInt32(), count: a[2].toInt32() }));
add('fgets', 'file', a => ({ count: a[1].toInt32() }));
add('open', 'file', a => ({ path: safeStr(a[0]), flags: a[1].toInt32() }));
add('openat', 'file', a => ({ dirfd: a[0].toInt32(), path: safeStr(a[1]), flags: a[2].toInt32() }));
add('recv', 'network', a => ({ fd: a[0].toInt32(), count: a[2].toInt32() }));
add('recvfrom', 'network', a => ({ fd: a[0].toInt32(), count: a[2].toInt32() }));
add('recvmsg', 'network', a => ({ fd: a[0].toInt32() }));
add('accept', 'network', a => ({ fd: a[0].toInt32() }));
add('getenv', 'process', a => ({ name: safeStr(a[0]) }));

// Parser callsites are useful for narrowing a callback or protocol handler to
// the function that actually crosses into a structured-data parser.
//
// The hook-name list is RENDERED from RAPTOR's central function taxonomy
// (core/function_taxonomy PARSER_FUNCS) into the slot below when the
// template is loaded — this file used to hand-copy a subset that silently
// drifted as the taxonomy grew. Unrendered, the list is empty and the
// template stays valid JS. The per-function argument readers stay explicit
// here: they encode arg-position knowledge, not name vocabulary, and any
// name without a reader gets a no-argument hook (absent exports are
// skipped by hook()).
const parserHookNames = /*__PARSER_HOOKS__*/ [];
const parserArgReaders = {
  'XML_Parse': a => ({ len: a[2].toInt32() }),
  'XML_ParseBuffer': a => ({ len: a[1].toInt32() }),
  'xmlReadMemory': a => ({ size: a[1].toInt32() }),
  'json_loads': a => ({ input: safeStr(a[0], 128) }),
  'json_loadb': a => ({ size: a[1].toInt32() }),
  'cJSON_Parse': a => ({ input: safeStr(a[0], 128) }),
  'ZSTD_decompress': a => ({ size: a[3].toInt32() }),
};
parserHookNames.forEach(function (name) {
  add(name, 'parser', parserArgReaders[name] || (_a => ({})));
});

send({ _meta: 'binary-flow-trace loaded', hooks: hooks });
