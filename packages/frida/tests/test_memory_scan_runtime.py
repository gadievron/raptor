from __future__ import annotations

import shutil
import subprocess

import pytest

from packages.frida.runner import _with_flush_dispatcher, load_script_source


HARNESS = r"""
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');

const agentPath = process.argv[2];
const mode = process.argv[3];
const agentSource = fs.readFileSync(agentPath, 'utf8');
const events = [];
const pendingReceivers = [];
const scanCalls = [];
const rangeSize = mode === 'drain' ? 150000 : mode === 'budget' ? 300 : 64;
const baseValue = mode === 'module' ? 0x2000 : 0x1000;

function pointer(value) {
  return {
    value,
    add(amount) {
      return pointer(this.value + Number(amount));
    },
    sub(other) {
      return pointer(this.value - other.value);
    },
    toString() {
      return '0x' + this.value.toString(16);
    }
  };
}

const base = pointer(baseValue);
const range = {
  base,
  size: rangeSize,
  file: mode === 'module' ? { path: '/lib/target.so' } : null,
  protection: mode === 'module' ? 'r--' : 'rw-'
};
const ranges = mode === 'budget'
  ? [
      range,
      {
        base: pointer(baseValue + 0x1000),
        size: 4,
        file: null,
        protection: 'rw-'
      },
      {
        base: pointer(baseValue + 0x2000),
        size: 4,
        file: null,
        protection: 'rw-'
      }
    ]
  : [range];

let moduleProtection = null;
const selectedModule = {
  name: 'target',
  base,
  enumerateRanges(protection) {
    moduleProtection = protection;
    return [range];
  }
};

let matchEmitted = false;

const Process = {
  enumerateRanges(options) {
    assert.strictEqual(options.protection, 'rw-');
    assert.strictEqual(options.coalesce, false);
    return ranges;
  },
  findModuleByName(name) {
    return name === 'target' ? selectedModule : null;
  },
  findModuleByAddress(address) {
    return mode === 'module' ? selectedModule : null;
  }
};

const Memory = {
  scan(start, size, pattern, callbacks) {
    const scanStart = start.value;
    scanCalls.push({ start: scanStart, size, pattern });

    setImmediate(() => {
      const signatureAddress = baseValue + 4;
      if (
        !matchEmitted &&
        pattern === '7F 45 4C 46' &&
        scanStart <= signatureAddress &&
        scanStart + size >= signatureAddress + 4
      ) {
        matchEmitted = true;
        callbacks.onMatch(pointer(signatureAddress), 4);
      }
      callbacks.onComplete();
    });
  }
};

const context = {
  Process,
  Memory,
  send(payload) {
    events.push(payload);
  },
  recv(type, callback) {
    assert.strictEqual(type, 'raptor:flush');
    pendingReceivers.push(callback);
  }
};

async function main() {
  vm.runInNewContext(agentSource, context);

  const receive = pendingReceivers.shift();
  assert.ok(receive, 'Flush dispatcher did not register a receiver');

  if (mode === 'final-race') {
    receive({
      type: 'raptor:flush',
      main_tid: 1234,
      spawned: false,
      final: false
    });
    assert.ok(
      scanCalls.length > 0,
      'Initial flush did not start an asynchronous scan'
    );
    assert.ok(
      !events.some(
        event =>
          event.category === 'memory_scan' &&
          event.event === 'summary'
      ),
      'Initial scan should still be in progress'
    );

    const receiveFinal = pendingReceivers.shift();
    assert.ok(receiveFinal, 'Next flush receiver was not registered');
    receiveFinal({
      type: 'raptor:flush',
      main_tid: 1234,
      spawned: false,
      final: true
    });
  } else {
    receive({
      type: 'raptor:flush',
      main_tid: 1234,
      spawned: false,
      final: true
    });
  }

  const deadline = Date.now() + 8000;
  while (
    Date.now() < deadline &&
    !events.some(
      event =>
        event.category === 'raptor' &&
        event.event === 'flush_summary_complete'
    )
  ) {
    await new Promise(resolve => setTimeout(resolve, 2));
  }

  const summary = events.find(
    event =>
      event.category === 'memory_scan' &&
      event.event === 'summary'
  );
  const match = events.find(
    event =>
      event.category === 'memory_scan' &&
      event.event === 'match'
  );

  assert.ok(summary, 'No memory-scan summary was emitted');
  assert.ok(match, 'No matching signature was emitted');
  if (mode === 'budget') {
    assert.strictEqual(summary.status, 'completed_with_limits');
  } else {
    assert.strictEqual(summary.status, 'complete');
  }
  assert.strictEqual(summary.scan_errors, 0);
  assert.strictEqual(summary.matches, 1);
  assert.strictEqual(
    events.filter(
      event =>
        event.category === 'memory_scan' &&
        event.event === 'match'
    ).length,
    1
  );
  assert.ok(
    events.some(
      event =>
        event.category === 'raptor' &&
        event.event === 'flush_summary_complete'
    ),
    'Final flush acknowledgement was not emitted'
  );

  if (mode === 'final-race') {
    const summaryIndex = events.findIndex(
      event =>
        event.category === 'memory_scan' &&
        event.event === 'summary'
    );
    const ackIndex = events.findIndex(
      event =>
        event.category === 'raptor' &&
        event.event === 'flush_summary_complete'
    );
    assert.ok(
      summary.scanned_bytes >= rangeSize * 8,
      'Final summary arrived before the initial scan cycle completed'
    );
    assert.ok(
      summaryIndex >= 0 && ackIndex > summaryIndex,
      'Final flush acknowledgement must follow the scan summary'
    );
  }

  if (mode === 'budget') {
    const firstLargeRangeScan = scanCalls.findIndex(
      call => call.start === baseValue
    );
    assert.ok(
      firstLargeRangeScan >= 0 && firstLargeRangeScan < 16,
      'Completed ranges are still consuming the remaining-work budget'
    );
  }

  if (mode === 'module') {
    assert.strictEqual(moduleProtection, 'r--');
    assert.strictEqual(match.module, 'target');
    assert.strictEqual(match.offset, '0x4');
  }

  if (mode === 'drain') {
    assert.ok(scanCalls.length > 8, 'Expected multiple scan cycles');
    assert.ok(
      summary.scanned_bytes >= rangeSize * 8,
      'Final flush did not drain the remaining ranges'
    );
  }

  process.stdout.write(JSON.stringify({
    mode,
    status: summary.status,
    matches: summary.matches,
    scanned_bytes: summary.scanned_bytes,
    scan_calls: scanCalls.length,
    module: match.module || null,
    offset: match.offset || null
  }));
}

main().catch(error => {
  console.error(error.stack || String(error));
  process.exitCode = 1;
});
"""


@pytest.mark.parametrize("mode", ["anonymous", "module", "drain", "budget", "final-race"])
def test_memory_scan_executes_and_emits_events(tmp_path, mode):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")

    source, _ = load_script_source("memory-scan", None)

    if mode == "module":
        old = "module: null,"
        if source.count(old) != 1:
            raise AssertionError("Module configuration was not found uniquely")
        source = source.replace(old, "module: 'target',", 1)

    if mode == "budget":
        replacements = (
            ("var MAX_SCAN_BYTES = 16 * 1024 * 1024;",
             "var MAX_SCAN_BYTES = 10000;"),
            ("var MAX_SCAN_BYTES_PER_FLUSH = 512 * 1024;",
             "var MAX_SCAN_BYTES_PER_FLUSH = 56;"),
        )
        for old, new in replacements:
            if source.count(old) != 1:
                raise AssertionError(
                    f"Budget configuration not found uniquely: {old}"
                )
            source = source.replace(old, new, 1)

    agent_path = tmp_path / "memory_scan_agent.js"
    harness_path = tmp_path / "memory_scan_harness.js"
    agent_path.write_text(source, encoding="utf-8")
    harness_path.write_text(HARNESS, encoding="utf-8")

    result = subprocess.run(
        [node, str(harness_path), str(agent_path), mode],
        check=False,
        capture_output=True,
        text=True,
        timeout=12,
    )

    assert result.returncode == 0, (
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


def test_flush_dispatcher_broadcasts_to_all_listeners():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is not installed")

    listener_source = r"""
registerRaptorFlushListener(function (message) {
  seen.push(message.final);
});
registerRaptorFlushListener(function (message) {
  seen.push(message.final);
});
"""

    program = (
        r"""
const assert = require('assert');
const pendingReceivers = [];
const seen = [];

function recv(type, callback) {
  assert.strictEqual(type, 'raptor:flush');
  pendingReceivers.push(callback);
}
"""
        + _with_flush_dispatcher(listener_source)
        + r"""
const dispatch = pendingReceivers.shift();
assert.strictEqual(typeof dispatch, 'function');
dispatch({ type: 'raptor:flush', final: true });
assert.deepStrictEqual(seen, [true, true]);
"""
    )

    result = subprocess.run(
        [node, "-e", program],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert result.returncode == 0, (
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
