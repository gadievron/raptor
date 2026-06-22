// bb-coverage.js - basic-block coverage via Frida Stalker (drcov output).
//
// Collects basic-block start addresses hit during the trace duration
// and emits a drcov-format binary blob on detach. The runner writes
// it to `coverage.drcov` in the output directory; RAPTOR's existing
// `core/coverage/collect.py:parse_drcov()` consumes it directly.
//
// Use:
//   raptor frida --target <pid|name|binary> --template bb-coverage
//
// The drcov file is emitted as a binary blob via send(payload, data)
// so it arrives intact through Frida's message channel. The runner
// recognises payload._drcov and writes it to disk separately.
//
// Scope: traces ALL threads. For large/busy targets, consider
// --duration to bound collection time.

'use strict';

var modules = Process.enumerateModules();
var bbSet = {};  // "module_id:offset" -> {start, mid}

// Build module table for drcov header.
var modTable = [];
for (var i = 0; i < modules.length; i++) {
  var m = modules[i];
  modTable.push({
    id: i,
    base: m.base,
    end: m.base.add(m.size),
    size: m.size,
    path: m.path
  });
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

// Follow all existing threads.
var initialThreads = Process.enumerateThreads();
for (var t = 0; t < initialThreads.length; t++) {
  Stalker.follow(initialThreads[t].id, { transform: transform });
}

// Follow threads created after load so coverage isn't incomplete
// for targets with thread pools or workers.
Interceptor.attach(Module.findExportByName(null, 'pthread_create'), {
  onLeave: function (retval) {
    if (retval.toInt32() === 0) {
      var newThreads = Process.enumerateThreads();
      for (var i = 0; i < newThreads.length; i++) {
        try { Stalker.follow(newThreads[i].id, { transform: transform }); } catch (e) {}
      }
    }
  }
});

send({ _meta: 'bb-coverage loaded', modules: modTable.length, threads: initialThreads.length });

// On script unload (detach), build and emit the drcov file.
Script.bindWeak(Script, function () {
  // Re-enumerate to catch threads created after initial follow.
  var allThreads = Process.enumerateThreads();
  for (var t = 0; t < allThreads.length; t++) {
    try { Stalker.unfollow(allThreads[t].id); } catch (e) {}
  }
  Stalker.flush();

  // Build drcov header.
  var header = 'DRCOV VERSION: 2\n';
  header += 'DRCOV FLAVOR: frida-stalker\n';
  header += 'Module Table: version 2, count ' + modTable.length + '\n';
  header += 'Columns: id, base, end, entry, checksum, timestamp, path\n';
  for (var i = 0; i < modTable.length; i++) {
    var m = modTable[i];
    header += m.id + ', ' + m.base + ', ' + m.end + ', 0x0, 0x0, 0x0, ' + m.path + '\n';
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

  // Combine header + bb table into a single blob.
  var total = new Uint8Array(headerBytes.length + bbBuf.byteLength);
  total.set(headerBytes, 0);
  total.set(new Uint8Array(bbBuf), headerBytes.length);

  send({ _drcov: true, bb_count: bbCount, modules: modTable.length }, total.buffer);
});
