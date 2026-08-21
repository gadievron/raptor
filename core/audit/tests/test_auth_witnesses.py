"""Tests for the auth-dismissal mechanical witnesses (Java)."""

from __future__ import annotations

import textwrap

from core.audit.auth_witnesses import (
    _nullable_getters,
    scan_gaps,
    scan_null_concat,
    scan_sync_escape,
)

_SYNC_ESCAPE = textwrap.dedent("""\
    private void registerFailure(String username) {
        Record rec = null;
        synchronized (this) {
            if (!ledger.containsKey(username)) {
                rec = new Record();
                ledger.put(username, rec);
            } else {
                rec = ledger.get(username);
            }
        }
        rec.registerFailure();
    }
""")


class TestSyncEscape:
    def test_mutation_after_block_fires(self):
        findings = scan_sync_escape("A.java", "registerFailure", _SYNC_ESCAPE)
        assert len(findings) == 1
        f = findings[0]
        assert f.detector == "sync_escape"
        assert "AFTER the block" in f.description

    def test_mutation_inside_block_does_not_fire(self):
        src = textwrap.dedent("""\
            private void registerFailure(String username) {
                synchronized (this) {
                    Record rec = ledger.get(username);
                    rec.registerFailure();
                }
            }
        """)
        assert scan_sync_escape("A.java", "registerFailure", src) == []

    def test_read_accessor_after_block_does_not_fire(self):
        src = textwrap.dedent("""\
            private int failures(String username) {
                Record rec = null;
                synchronized (this) {
                    rec = ledger.get(username);
                }
                return rec.getFailures();
            }
        """)
        assert scan_sync_escape("A.java", "failures", src) == []


_FILE_WITH_GETTER = textwrap.dedent("""\
    public abstract class AuthStore {
        protected abstract String getStoredSecret(String username);

        protected String computeDigest(String username, String realmName) {
            String digestValue = username + ":" + realmName + ":" + getStoredSecret(username);
            byte[] valueBytes = digestValue.getBytes();
            return HexUtils.toHexString(MessageDigest.digest("MD5", valueBytes));
        }
    }
""")


class TestNullConcat:
    def test_nullable_getter_into_digest_fires(self):
        ng = _nullable_getters(_FILE_WITH_GETTER)
        assert "getStoredSecret" in ng
        body = "\n".join(_FILE_WITH_GETTER.split("\n")[3:8])
        findings = scan_null_concat("AuthStore.java", "computeDigest", body, ng)
        assert len(findings) == 1
        assert findings[0].detector == "null_concat"
        assert "literal" in findings[0].description

    def test_null_checked_result_does_not_fire(self):
        src = textwrap.dedent("""\
            protected String computeDigest(String u, String r) {
                String p = getStoredSecret(u);
                if (p == null) {
                    return null;
                }
                String digestValue = u + ":" + r + ":" + p;
                return MessageDigest.digest("MD5", digestValue.getBytes());
            }
        """)
        # The concat uses the checked local, not the raw call — no
        # direct `+ getStoredSecret(` concat, nothing fires.
        findings = scan_null_concat(
            "AuthStore.java", "computeDigest", src, {"getStoredSecret"},
        )
        assert findings == []

    def test_concat_without_digest_sink_does_not_fire(self):
        src = textwrap.dedent("""\
            protected String describe(String u) {
                String s = "user " + getStoredSecret(u);
                return s;
            }
        """)
        assert scan_null_concat(
            "AuthStore.java", "describe", src, {"getStoredSecret"},
        ) == []


class TestScanGaps:
    def test_lines_file_absolute_and_non_java_skipped(self):
        text = "// h\n// h\n" + _SYNC_ESCAPE
        gaps = [
            {"file": "A.java", "name": "registerFailure",
             "line_start": 3, "line_end": 3 + _SYNC_ESCAPE.count("\n")},
            {"file": "b.go", "name": "g", "line_start": 1, "line_end": 4},
        ]
        findings = scan_gaps(gaps, {"A.java": text, "b.go": "package b"})
        assert len(findings) == 1
        assert findings[0].line == 13  # 11 body-relative + offset 2
