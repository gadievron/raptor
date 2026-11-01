"""Bounds must constrain the parsed value at the particular narrowing cast."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

_RULE = Path(__file__).resolve().parents[1] / "rules/go/go-security.yaml"
_ID = "raptor.go.parsed-int-narrowing-cast"


@pytest.mark.slow
@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_narrowing_value_and_bounds_contract(tmp_path):
    source = '''package sample
import "strconv"
func unchecked(s string) uint32 { v, _ := strconv.Atoi(s); return uint32(v) } // unsafe
func unicodeValue(s string) uint8 { ν, _ := strconv.Atoi(s); return uint8(ν) } // unsafe
func unicodeGuard(s string) uint8 { ν, _ := strconv.Atoi(s); if ν < 0 || ν > 255 { return 0 }; return uint8(ν) }
func alias(s string) uint32 { v, _ := strconv.Atoi(s); a := v; return uint32(a) } // unsafe
func harmless(s string) uint32 { v, _ := strconv.Atoi(s); if v > 0 { println(v) }; return uint32(v) } // unsafe
func parse64(s string) uint16 { v, _ := strconv.ParseInt(s,10,64); return uint16(v) } // unsafe
func unsignedNegative(s string) uint32 { v, _ := strconv.ParseInt(s,10,32); return uint32(v) } // unsafe
func positiveOnly(s string) uint32 { v, _ := strconv.Atoi(s); if v < 0 { return 0 }; return uint32(v) } // unsafe
func upperOnly(s string) uint32 { v, _ := strconv.Atoi(s); if v > 4294967295 { return 0 }; return uint32(v) } // unsafe
func weakUpper(s string) uint8 { v, _ := strconv.Atoi(s); if v < 0 || v > 65535 { return 0 }; return uint8(v) } // unsafe
func weakLower(s string) uint8 { v, _ := strconv.Atoi(s); if v < -1 || v > 255 { return 0 }; return uint8(v) } // unsafe
func afterCast(s string) uint8 { v, _ := strconv.Atoi(s); n := uint8(v); println(n); if v < 0 || v > 255 { return 0 }; return n } // unsafe
func reparse(s, other string) uint8 { v, _ := strconv.Atoi(s); if v < 0 || v > 255 { return 0 }; v, _ = strconv.Atoi(other); return uint8(v) } // unsafe
func ineffective(s string) uint8 { v, _ := strconv.Atoi(s); if v < 0 || v > 255 { println(v) }; return uint8(v) } // unsafe
func skippedGuard(s string, enabled bool) uint8 { v, _ := strconv.Atoi(s); if enabled { if v < 0 || v > 255 { return 0 } }; return uint8(v) } // unsafe
func safe32(s string) uint32 { v, err := strconv.Atoi(s); if err != nil || v < 0 || uint64(v) > 4294967295 { return 0 }; return uint32(v) }
func safeAfterCast(s string) uint8 { v, _ := strconv.Atoi(s); n := uint8(v); if v < 0 || v > 255 { return 0 }; return n }
func safe8(s string) uint8 { v, _ := strconv.Atoi(s); if v < 0 || v > 255 { return 0 }; return uint8(v) }
func safe16(s string) uint16 { v, _ := strconv.Atoi(s); if v < 0 || v > 65535 { return 0 }; n := uint16(v); return n }
func safeSigned(s string) int8 { v, _ := strconv.Atoi(s); if v < -128 || v > 127 { return 0 }; return int8(v) }
func safeParse(s string) int32 { v, err := strconv.ParseInt(s,10,32); if err != nil { return 0 }; return int32(v) }
func safeSmallParse(s string) int8 { v, _ := strconv.ParseInt(s,10,8); return int8(v) }
func wideParse(s string) int8 { v, _ := strconv.ParseInt(s,10,16); return int8(v) } // unsafe
func unknownBits(s string, bits int) int8 { v, _ := strconv.ParseInt(s,10,bits); return int8(v) } // unsafe
func safeBranch(s string) uint8 { v, _ := strconv.Atoi(s); if 0 <= v && v <= 255 { return uint8(v) }; return 0 }
func reassigned(s string) uint8 { v, _ := strconv.Atoi(s); v = 1; return uint8(v) }
func safeThenUnsafe(s, other string) uint8 {
 v, _ := strconv.Atoi(s)
 if v < 0 || v > 255 { return 0 }
 n := uint8(v)
 v, _ = strconv.Atoi(other)
 return n + uint8(v) // unsafe
}
func closure(s string) func() uint32 { return func() uint32 { v, _ := strconv.Atoi(s); return uint32(v) } } // unsafe
func guardedUnrelated(s, other string) uint8 { a, _ := strconv.Atoi(s); v, _ := strconv.Atoi(other); if a < 0 || a > 255 { return 0 }; return uint8(v) } // unsafe
func mutate(p *int) bool { *p = 99999; return false }
func sideEffect(s string) uint8 { v, _ := strconv.Atoi(s); if v < 0 || v > 255 || mutate(&v) { return 0 }; return uint8(v) } // unsafe
func shadowed(s string) uint8 { v, _ := strconv.Atoi(s); uint64 := func(int) int { return 0 }; if v < 0 || uint64(v) > 255 { return 0 }; return uint8(v) } // unsafe
func rejectCast(s string) uint8 {
 v, _ := strconv.Atoi(s)
 if v < 0 || v > 255 {
  return uint8(v) // unsafe
 }
 return uint8(v)
}
func observeError(v uint8) error { println(v); return nil }
func castInGuard(s string) uint8 {
 v, _ := strconv.Atoi(s)
 if observeError(uint8(v)) != nil || v < 0 || v > 255 { return 0 } // unsafe
 return uint8(v)
}
var slots [1]uint8
func changeValue(v *int) int { *v = 99999; return 0 }
func changedInAddress(s string) uint8 {
 v, _ := strconv.Atoi(s)
 if v < 0 || v > 255 { return 0 }
 slots[changeValue(&v)] = uint8(v) // unsafe
 return 0
}

'''
    target = tmp_path / "narrow.go"
    target.write_text(source)
    proc = subprocess.run(
        ["semgrep", "scan", "--config", str(_RULE), "--metrics", "off",
         "--disable-version-check", "--jobs", "1", "--json", str(target)],
        env={**os.environ, "SEMGREP_SETTINGS_FILE": str(tmp_path / "settings.yml"),
             "SEMGREP_LOG_FILE": str(tmp_path / "semgrep.log")},
        capture_output=True, text=True, timeout=180,
    )
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assert not report.get("errors"), report.get("errors")
    actual = {r["start"]["line"] for r in report["results"] if r["check_id"].endswith(_ID)}
    expected = {i for i, line in enumerate(source.splitlines(), 1) if "// unsafe" in line}
    assert actual == expected, f"Semgrep {report.get('version')}: {actual=} {expected=}"
