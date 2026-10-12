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

function scanConfiguredMemory() {
  if (!CONFIG || !Array.isArray(CONFIG.patterns) ||
      CONFIG.patterns.length === 0) {
    emit('error', {
      reason: 'configuration_required',
      detail: 'Use --memory-scan with a validated JSON configuration file.'
    });
    finish('error', null);
    return;
  }

  var selectedModule = null;
  var ranges;

  try {
    if (CONFIG.module) {
      selectedModule = Process.findModuleByName(CONFIG.module);

      if (selectedModule === null) {
        emit('error', {
          reason: 'module_not_found',
          module: CONFIG.module
        });
        finish('error', CONFIG.module);
        return;
      }

      ranges = selectedModule.enumerateRanges('r--');
    } else {
      ranges = Process.enumerateRanges({
        protection: 'rw-',
        coalesce: false
      });
    }
  } catch (e) {
    emit('error', {
      reason: 'range_enumeration_failed',
      detail: String(e)
    });
    finish('error', CONFIG.module);
    return;
  }

  ranges = ranges.filter(function (range) {
    return !range.file;
  });

  if (ranges.length === 0) {
    finish('no_readable_ranges', CONFIG.module);
    return;
  }

  if (ranges.length > MAX_RANGES) {
    ranges = ranges.slice(0, MAX_RANGES);
    noteLimit('range_count', MAX_RANGES);
  }

  // Divide the byte budget among patterns so the first pattern cannot
  // consume the entire run budget and starve all remaining patterns.
  var perPatternBudget = Math.floor(
    MAX_SCAN_BYTES / CONFIG.patterns.length
  );

  emit('start', {
    module: CONFIG.module || null,
    patterns: CONFIG.patterns.length,
    ranges_selected: ranges.length,
    max_scan_bytes: MAX_SCAN_BYTES,
    max_matches: MAX_MATCHES
  });

  function scanPattern(patternIndex) {
    if (stopped) {
      finish('limit_reached', CONFIG.module);
      return;
    }

    if (patternIndex >= CONFIG.patterns.length) {
      finish(limitsApplied ? 'completed_with_limits' : 'complete',
             CONFIG.module);
      return;
    }

    var spec = CONFIG.patterns[patternIndex];
    var rangeIndex = 0;
    var patternScanned = 0;
    var patternSize = patternBytes(spec.pattern);

    function nextRange() {
      if (stopped) {
        finish('limit_reached', CONFIG.module);
        return;
      }

      if (rangeIndex >= ranges.length) {
        scanPattern(patternIndex + 1);
        return;
      }

      if (patternScanned >= perPatternBudget) {
        noteLimit('pattern_byte_budget', perPatternBudget);
        scanPattern(patternIndex + 1);
        return;
      }

      var remaining = perPatternBudget - patternScanned;
      var rangesRemaining = ranges.length - rangeIndex;
      var rangeBudget = Math.ceil(remaining / rangesRemaining);
      var range = ranges[rangeIndex++];
      var size = Math.min(range.size, rangeBudget, remaining);

      if (size <= 0) {
        noteLimit('pattern_byte_budget', perPatternBudget);
        scanPattern(patternIndex + 1);
        return;
      }

      var partialRange = size < range.size;
      patternScanned += size;
      scannedBytes += size;

      try {
        Memory.scan(range.base, size, spec.pattern, {
          onMatch: function (address, matchSize) {
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
              // Anonymous memory has no module-relative offset.
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
              finish('limit_reached', CONFIG.module);
            } else {
              if (partialRange) {
                noteLimit('range_byte_budget', rangeBudget);
              }
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

    // Avoid needless scanning when the configured pattern is larger
    // than every permitted range budget.
    if (patternSize > perPatternBudget) {
      emit('error', {
        reason: 'pattern_exceeds_scan_budget',
        pattern_id: spec.id
      });
      scanPattern(patternIndex + 1);
      return;
    }

    nextRange();
  }

  scanPattern(0);
}

scanConfiguredMemory();
