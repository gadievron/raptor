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

function safeStr(ptr, maxLen) {
  // NULL or unreadable pointers return '<null>' / '<unreadable>'
  // rather than crashing the agent. Defensive because attacker-
  // controlled input is reaching libc here.
  if (ptr.isNull()) return '<null>';
  try {
    return Memory.readUtf8String(ptr, maxLen || 256);
  } catch (_e) {
    return '<unreadable>';
  }
}

function emit(category, fn, args) {
  send({ category: category, fn: fn, args: args, tid: Process.getCurrentThreadId() });
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
      try {
        this.captured = argHandler(args);
      } catch (e) {
        this.captured = { _err: String(e) };
      }
    },
    onLeave: function (retval) {
      emit(category, name, Object.assign({ ret: retval.toInt32() }, this.captured));
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

send({ _meta: 'api-trace loaded', hooks: ['open', 'openat', 'read', 'write', 'close',
                                          'fork', 'execve', 'exit',
                                          'connect', 'bind', 'accept'] });
