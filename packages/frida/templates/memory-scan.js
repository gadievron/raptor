'use strict';

var CONFIG = {
    module: null,
    patterns: [
      { id: 'elf', pattern: '7F 45 4C 46' },
      { id: 'wasm', pattern: '00 61 73 6D' },
      { id: 'dex', pattern: '64 65 78 0A ?? ?? ?? 00' },
      { id: 'macho64-le', pattern: 'CF FA ED FE' },
      { id: 'macho32-le', pattern: 'CE FA ED FE' },
      { id: 'macho64-be', pattern: 'FE ED FA CF' },
      { id: 'macho32-be', pattern: 'FE ED FA CE' },
      { id: 'macho-fat', pattern: 'CA FE BA BE' }
    ]
  };

var MAX_RANGES = 32;
var MAX_SCAN_BYTES = 16 * 1024 * 1024;
var MAX_MATCHES = 100;

var scannedBytes = 0;
var matchCount = 0;
var scanErrorCount = 0;
var limitsApplied = false;
var stopped = false;
var finished = false;
var notedLimits = {};
var MAX_SCAN_BYTES_PER_FLUSH = 512 * 1024;
var rangeOffsets = Object.create(null);
var rangeSizes = Object.create(null);
var seenMatches = Object.create(null);
var scanInProgress = false;
var finalFlushRequested = false;
var rangeWindowStart = 0;
var startEmitted = false;

function emit(event, fields) {
  send(Object.assign({
    category: 'memory_scan',
    event: event
  }, fields || {}));
}

function noteLimit(kind, cap) {
  limitsApplied = true;

  if (notedLimits[kind]) {
    return;
  }

  notedLimits[kind] = true;
  emit('limit', {
    kind: kind,
    cap: cap
  });
}

function finish(status, moduleName) {
  if (finished) {
    return;
  }

  finished = true;
  scanInProgress = false;
  emit('summary', {
    status: status === 'complete' && scanErrorCount > 0
      ? 'completed_with_errors'
      : status,
    module: moduleName || null,
    matches: matchCount,
    scanned_bytes: scannedBytes,
    scan_errors: scanErrorCount,
    limits_applied: limitsApplied
  });
}

function patternBytes(pattern) {
  return pattern.trim().split(/\s+/).length;
}

function runScanCycle(isFinal) {
  if (finished) {
    return;
  }
  if (scanInProgress) {
    if (isFinal) {
      finalFlushRequested = true;
    }
    return;
  }

  isFinal = isFinal || finalFlushRequested;

  if (!CONFIG || !Array.isArray(CONFIG.patterns) ||
      CONFIG.patterns.length === 0) {
    emit('error', {
      reason: 'configuration_required',
      detail: 'The template has no valid scan patterns.'
    });
    finish('error', null);
    return;
  }

  if (scannedBytes >= MAX_SCAN_BYTES) {
    noteLimit('scan_byte_budget', MAX_SCAN_BYTES);
    finish(scanErrorCount > 0 ? 'completed_with_errors'
                              : 'completed_with_limits', CONFIG.module);
    return;
  }

  scanInProgress = true;

  var selectedModule = null;
  var moduleName = CONFIG.module || null;
  var allRanges = [];
  var moduleMissing = false;

  function endCycle(pendingWork, noRanges, missingModule) {
    scanInProgress = false;
    if (finished) {
      return;
    }

    if (scannedBytes >= MAX_SCAN_BYTES) {
      noteLimit('scan_byte_budget', MAX_SCAN_BYTES);
      finish(scanErrorCount > 0 ? 'completed_with_errors'
                                : 'completed_with_limits', moduleName);
      return;
    }

    // A final flush that arrived during an asynchronous scan gets its
    // own fresh enumeration before the closing summary is emitted.
    if (finalFlushRequested && !isFinal) {
      runScanCycle(true);
      return;
    }

    if (!isFinal) {
      return;
    }

    if (missingModule) {
      emit('error', {
        reason: 'module_not_found',
        module: CONFIG.module
      });
      finish('error', CONFIG.module);
      return;
    }

    if (pendingWork && !limitsApplied) {
      noteLimit('final_scan_incomplete', MAX_SCAN_BYTES_PER_FLUSH);
    }

    if (scanErrorCount > 0) {
      finish('completed_with_errors', moduleName);
    } else if (noRanges && scannedBytes === 0 && matchCount === 0) {
      finish('no_readable_ranges', moduleName);
    } else if (limitsApplied || pendingWork) {
      finish('completed_with_limits', moduleName);
    } else {
      finish('complete', moduleName);
    }
  }

  try {
    if (CONFIG.module) {
      selectedModule = Process.findModuleByName(CONFIG.module);
      if (selectedModule === null) {
        moduleMissing = true;
      } else {
        // Preserve file-backed ranges belonging to the selected module.
        // Only the default anonymous-memory mode excludes file mappings.
        moduleName = selectedModule.name;
        allRanges = selectedModule.enumerateRanges('r--');
      }
    } else {
      allRanges = Process.enumerateRanges({
        protection: 'rw-',
        coalesce: false
      });
      allRanges = allRanges.filter(function (range) {
        return !range.file;
      });
    }
  } catch (e) {
    scanErrorCount++;
    emit('error', {
      reason: 'range_enumeration_failed',
      detail: String(e)
    });
    endCycle(true, false, false);
    return;
  }

  if (moduleMissing) {
    // A module may not be loaded on an early flush. Retry until the
    // controller marks its final flush before reporting it missing.
    endCycle(false, true, true);
    return;
  }

  if (allRanges.length === 0) {
    // Do not conclude that memory is empty before the target has run.
    endCycle(false, true, false);
    return;
  }

  var ranges = allRanges;
  var cyclePendingWork = false;

  if (allRanges.length > MAX_RANGES) {
    noteLimit('range_count', MAX_RANGES);

    // Rotate the bounded window so mappings beyond the first 32 can
    // be considered on subsequent controller flushes.
    var start = rangeWindowStart % allRanges.length;
    ranges = [];
    for (var i = 0; i < MAX_RANGES; i++) {
      ranges.push(allRanges[(start + i) % allRanges.length]);
    }
    rangeWindowStart = (start + MAX_RANGES) % allRanges.length;
    cyclePendingWork = true;
  }

  if (!startEmitted) {
    emit('start', {
      module: moduleName,
      patterns: CONFIG.patterns.length,
      ranges_available: allRanges.length,
      ranges_selected: ranges.length,
      max_scan_bytes: MAX_SCAN_BYTES,
      max_scan_bytes_per_flush: MAX_SCAN_BYTES_PER_FLUSH,
      max_matches: MAX_MATCHES
    });
    startEmitted = true;
  }

  var cycleBudget = Math.min(
    MAX_SCAN_BYTES_PER_FLUSH,
    MAX_SCAN_BYTES - scannedBytes
  );
  var perPatternBudget = Math.floor(
    cycleBudget / CONFIG.patterns.length
  );

  function scanPattern(patternIndex) {
    if (finished) {
      return;
    }
    if (patternIndex >= CONFIG.patterns.length) {
      endCycle(cyclePendingWork, false, false);
      return;
    }

    var spec = CONFIG.patterns[patternIndex];
    var patternSize = patternBytes(spec.pattern);
    var budget = { remaining: perPatternBudget };
    var rangeIndex = 0;

    function nextRange() {
      if (finished) {
        return;
      }
      if (stopped) {
        finish('limit_reached', moduleName);
        return;
      }
      if (rangeIndex >= ranges.length) {
        scanPattern(patternIndex + 1);
        return;
      }
      if (budget.remaining < patternSize) {
        cyclePendingWork = true;
        scanPattern(patternIndex + 1);
        return;
      }

      var rangesRemaining = ranges.length - rangeIndex;
      var range = ranges[rangeIndex++];
      var rangeKey = range.base.toString();

      // Reset stale cursors after shrink; revisit the old boundary
      // if a fully scanned mapping grows, preserving cross-boundary hits.
      var previousSize = rangeSizes[rangeKey];
      if (typeof previousSize === 'number' && range.size < previousSize) {
        CONFIG.patterns.forEach(function (other) {
          delete rangeOffsets[other.id + '|' + rangeKey];
        });
      } else if (typeof previousSize === 'number' &&
                 range.size > previousSize) {
        CONFIG.patterns.forEach(function (other) {
          var otherKey = other.id + '|' + rangeKey;
          if (rangeOffsets[otherKey] === previousSize) {
            rangeOffsets[otherKey] = Math.max(
              0, previousSize - (patternBytes(other.pattern) - 1)
            );
          }
        });
      }
      rangeSizes[rangeKey] = range.size;

      var cursorKey = spec.id + '|' + rangeKey;
      var offset = rangeOffsets[cursorKey];
      if (typeof offset !== 'number') {
        offset = 0;
      }
      if (offset < 0 || offset > range.size) {
        offset = 0;
      }
      if (offset === range.size) {
        nextRange();
        return;
      }

      var available = range.size - offset;

      var rangeBudget = Math.floor(budget.remaining / rangesRemaining);
      var scanSize = Math.min(
        available,
        rangeBudget,
        budget.remaining,
        MAX_SCAN_BYTES - scannedBytes
      );

      // A partial chunk must be large enough to carry a complete
      // signature across the overlap with the next chunk.
      if (scanSize <= 0 ||
          (scanSize < available && scanSize <= patternSize - 1)) {
        cyclePendingWork = true;
        rangeOffsets[cursorKey] = offset;
        nextRange();
        return;
      }

      var partialRange = scanSize < available;
      var overlap = partialRange ? patternSize - 1 : 0;
      rangeOffsets[cursorKey] = partialRange
        ? offset + scanSize - overlap
        : range.size;

      if (partialRange) {
        cyclePendingWork = true;
      }

      budget.remaining -= scanSize;
      scannedBytes += scanSize;

      try {
        Memory.scan(range.base.add(offset), scanSize, spec.pattern, {
          onMatch: function (address, matchSize) {
            var matchKey = spec.id + '|' + address.toString();
            if (seenMatches[matchKey]) {
              return;
            }
            seenMatches[matchKey] = true;
            matchCount++;

            var owner = selectedModule;
            if (owner === null) {
              try {
                owner = Process.findModuleByAddress(address);
              } catch (_e) {
                owner = null;
              }
            }

            var record = {
              pattern_id: spec.id,
              size: matchSize
            };

            if (owner !== null) {
              record.module = owner.name;
              record.offset = address.sub(owner.base).toString();
            } else {
              record.address = address.toString();
            }

            emit('match', record);

            if (matchCount >= MAX_MATCHES) {
              stopped = true;
              noteLimit('match_count', MAX_MATCHES);
              return 'stop';
            }
          },

          onError: function (reason) {
            scanErrorCount++;
            emit('error', {
              reason: 'scan_error',
              pattern_id: spec.id,
              detail: String(reason)
            });
          },

          onComplete: function () {
            if (stopped) {
              finish('limit_reached', moduleName);
            } else if (scannedBytes >= MAX_SCAN_BYTES) {
              noteLimit('scan_byte_budget', MAX_SCAN_BYTES);
              finish(scanErrorCount > 0 ? 'completed_with_errors'
                                        : 'completed_with_limits', moduleName);
            } else {
              nextRange();
            }
          }
        });
      } catch (e) {
        scanErrorCount++;
        emit('error', {
          reason: 'scan_error',
          pattern_id: spec.id,
          detail: String(e)
        });
        nextRange();
      }
    }

    if (patternSize > perPatternBudget) {
      cyclePendingWork = true;
      scanPattern(patternIndex + 1);
      return;
    }

    nextRange();
  }

  scanPattern(0);
}

function onFlushMsg(msg) {
  // Re-arm before scanning; Memory.scan is asynchronous.
  recv('raptor:flush', onFlushMsg);

  if (finished) {
    return;
  }
  if (msg && msg.final === true) {
    finalFlushRequested = true;
  }
  if (scanInProgress) {
    return;
  }

  runScanCycle(finalFlushRequested);
}

recv('raptor:flush', onFlushMsg);
