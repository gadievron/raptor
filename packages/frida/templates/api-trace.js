// api-trace.js - trace common syscalls + libc functions.
//
// Originally drafted by @ZephrFish for the v2 Frida integration
// (gadievron/raptor PR forthcoming). Intentionally minimal - Splinters
// will land a richer version in the same templates dir; this one is
// the starter that proves the runner's send()-capture path.
//
// Hooks: open(2)/openat(2), read(2)/write(2), connect(2),
// fork(2)/execve(2). Each hit emits a {category, fn, args} record
// via send() so the runner persists it to events.jsonl.
//
// Use:
//   raptor frida --target <pid|name|binary> --template api-trace
//
// Scope choices:
//   * libc-level (Module.findExportByName('libc', ...)) rather than
//     raw syscall numbers - portable enough between glibc/musl/macOS
//     libSystem for the common cases.
//   * No string-content capture beyond first 256 bytes of read/write
//     buffers - keeps events.jsonl line-grep-friendly; an operator
//     hunting for credentials will hook ssl-trace separately.

'use strict';

// Per-function emission cap (the exec-and-load idiom): this template
// hooks HOT functions (read/write/recv) and takes an ACCURATE
// backtrace per event — a hostile or merely busy target would
// otherwise flood events.jsonl for the whole session on the DEFAULT
// observe path. The cap is loud (one _meta marker per hook), and a
// capped hook stops paying the backtrace cost too.
var MAX_EVENTS_PER_FN = 500;
const emitted = Object.create(null);   // null-proto: cap must be unpoisonable

function capReached(fn, label) {
  emitted[fn] = (emitted[fn] || 0) + 1;
  if (emitted[fn] > MAX_EVENTS_PER_FN) {
    if (emitted[fn] === MAX_EVENTS_PER_FN + 1) {
      // Never truncate silently: one loud marker per hook.
      send({ _meta: label + ' cap reached', fn: fn, cap: MAX_EVENTS_PER_FN });
    }
    return true;
  }
  return false;
}

function safeStr(ptr, maxLen) {
  // NULL or unreadable pointers return '<null>' / '<unreadable>'
  // rather than crashing the agent. Defensive because attacker-
  // controlled input is reaching libc here.
  //
  // NUL-terminated read with output-side truncation: an explicit
  // length argument over-decodes past the terminator on Frida 17
  // (throws on interior NUL bytes), and Memory.readUtf8String was
  // removed in the 17.0 cleanup — probe for the instance method
  // first, fall back for older runtimes.
  if (ptr.isNull()) return '<null>';
  var max = maxLen || 256;
  try {
    var s = (typeof ptr.readUtf8String === 'function')
      ? ptr.readUtf8String()
      : Memory.readUtf8String(ptr);
    if (s === null) return '<null>';
    return s.length > max ? s.slice(0, max) : s;
  } catch (_e) {
    return '<unreadable>';
  }
}

function callsite(context, returnAddress) {
  let backtrace = [];
  let moduleInfo = {};
  try {
    backtrace = Thread.backtrace(context, Backtracer.ACCURATE)
      .slice(0, 8)
      .map(addr => addr.toString());
  } catch (_e) {
    backtrace = [];
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
    ...moduleInfo,
  };
}

function emit(category, fn, args, site) {
  send(Object.assign({
    category: category,
    fn: fn,
    args: args,
    tid: Process.getCurrentThreadId(),
  }, site || {}));
}

// Resolve a symbol from any loaded module. Frida 17 removed the
// `Module.findExportByName(null, name)` global-search form; the
// replacement is `Module.findGlobalExportByName(name)`. We probe for
// both so the template stays usable on Frida 16 and 17.
function findGlobalExport(name) {
  if (typeof Module.findGlobalExportByName === 'function') {
    return Module.findGlobalExportByName(name);
  }
  if (typeof Module.findExportByName === 'function') {
    try { return Module.findExportByName(null, name); } catch (_e) { return null; }
  }
  return null;
}

function hook(name, category, argHandler) {
  // findGlobalExport returns null when the symbol isn't in any loaded
  // module on this platform (e.g. openat missing on older macOS, or
  // a statically-linked Go binary that doesn't pull libc).
  const addr = findGlobalExport(name);
  if (addr === null) return;
  Interceptor.attach(addr, {
    onEnter: function (args) {
      if (capReached(name, 'api-trace')) {
        this.capped = true;
        return;   // skip the backtrace work too
      }
      this.capped = false;
      try {
        this.captured = argHandler(args);
      } catch (e) {
        this.captured = { _err: String(e) };
      }
      this.site = callsite(this.context, this.returnAddress);
    },
    onLeave: function (retval) {
      if (this.capped) return;
      emit(category, name, Object.assign({ ret: retval.toInt32() }, this.captured), this.site);
    },
  });
}

// File I/O
hook('open',   'file', a => ({ path: safeStr(a[0]), flags: a[1].toInt32() }));
hook('openat', 'file', a => ({ dirfd: a[0].toInt32(), path: safeStr(a[1]), flags: a[2].toInt32() }));
hook('read',   'file', a => ({ fd: a[0].toInt32(), count: a[2].toInt32() }));
hook('write',  'file', a => ({ fd: a[0].toInt32(), count: a[2].toInt32() }));
hook('close',  'file', a => ({ fd: a[0].toInt32() }));

// Process
hook('fork',   'process', _a => ({}));
hook('execve', 'process', a => ({ path: safeStr(a[0]) }));
hook('exit',   'process', a => ({ status: a[0].toInt32() }));

// Network - sockaddr inspection is platform-specific; emit just the fd
// and let the operator correlate via /proc or lsof if they need more.
hook('connect', 'network', a => ({ fd: a[0].toInt32() }));
hook('bind',    'network', a => ({ fd: a[0].toInt32() }));
hook('accept',  'network', a => ({ fd: a[0].toInt32() }));
hook('recv',    'network', a => ({ fd: a[0].toInt32(), count: a[2].toInt32() }));
hook('recvfrom','network', a => ({ fd: a[0].toInt32(), count: a[2].toInt32() }));

send({ _meta: 'api-trace loaded', hooks: ['open', 'openat', 'read', 'write', 'close',
                                          'fork', 'execve', 'exit',
                                          'connect', 'bind', 'accept', 'recv', 'recvfrom'] });
