"""Locator source-kind battery — adversarial shapes first.

Every kind's activation gate is exercised in the refusing direction
before the accepting one: a wrong source candidate is the
false-suppression direction, so these pins are the contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")

from core.analysis.sanitizer_cut_postpass import (  # noqa: E402
    _candidate_source_lines,
    _candidate_source_lines_with_kinds,
)


def _lines(tmp_path: Path, source: str, sink_line: int,
           language: str = "java"):
    f = tmp_path / "Case.java"
    f.write_text(source)
    cache: dict = {}
    return _candidate_source_lines_with_kinds(
        f, sink_line, language, cache)


_CONSOLE = """import java.io.*;
public class Case {
    void run() throws IOException {
        BufferedReader r = new BufferedReader(new InputStreamReader(System.in));
        String data = r.readLine();
        sink(data);
    }
}
"""

_STRINGREADER_ONLY = """import java.io.*;
public class Case {
    void run() throws IOException {
        BufferedReader r = new BufferedReader(new StringReader("lit"));
        String data = r.readLine();
        sink(data);
    }
}
"""

_ENV = """public class Case {
    void run() {
        String data = System.getenv("PATH");
        sink(data);
    }
}
"""

_SYSPROP = """public class Case {
    void run() {
        String data = System.getProperty("user.dir");
        sink(data);
    }
}
"""

_FILEREAD = """import java.io.*;
public class Case {
    void run() throws IOException {
        BufferedReader r = new BufferedReader(new FileReader("c.txt"));
        String data = r.readLine();
        sink(data);
    }
}
"""

_DB = """import java.sql.*;
public class Case {
    void run(Statement st) throws SQLException {
        ResultSet rs = st.executeQuery("SELECT name FROM t");
        String data = rs.getString(1);
        sink(data);
    }
}
"""

_SOCKET = """import java.net.*;
import java.io.*;
public class Case {
    void run(Socket s) throws IOException {
        InputStream in = s.getInputStream();
        sink(in);
    }
}
"""

_GETSTRING_NO_DB = """public class Case {
    void run(Bundle b) {
        String data = b.getString("k");
        sink(data);
    }
}
"""

_PROPS_UNRESOLVED = """import java.util.Properties;
public class Case {
    void run(Properties props, String key) {
        String data = props.getProperty(key);
        sink(data);
    }
}
"""

_PROPS_RESOLVED = """import java.util.*;
import java.io.*;
public class Case {
    void run() throws IOException {
        Properties props = new Properties();
        props.load(Case.class.getResourceAsStream("app.properties"));
        String data = props.getProperty("crypto.alg");
        sink(data);
    }
}
"""


class TestKindGating:
    def test_console_requires_system_in_evidence(self, tmp_path):
        got = _lines(tmp_path, _CONSOLE, sink_line=6)
        assert [ln for ln, _ in got] == [5]
        assert "console" in got[0][1]

    def test_stringreader_only_file_activates_nothing(self, tmp_path):
        assert _lines(tmp_path, _STRINGREADER_ONLY, sink_line=6) == []

    def test_environment_getenv_is_candidate(self, tmp_path):
        got = _lines(tmp_path, _ENV, sink_line=4)
        assert [ln for ln, _ in got] == [3]
        assert "environment" in got[0][1]

    def test_system_getproperty_is_environment_not_properties(self, tmp_path):
        got = _lines(tmp_path, _SYSPROP, sink_line=4)
        assert [ln for ln, _ in got] == [3]
        assert "environment" in got[0][1]
        assert "properties" not in got[0][1]

    def test_file_reader_evidence_gates_read_chain(self, tmp_path):
        got = _lines(tmp_path, _FILEREAD, sink_line=6)
        assert [ln for ln, _ in got] == [5]
        assert "file" in got[0][1]

    def test_database_getstring_gated_on_resultset(self, tmp_path):
        got = _lines(tmp_path, _DB, sink_line=6)
        assert [ln for ln, _ in got] == [5]
        assert "database" in got[0][1]

    def test_getstring_without_db_evidence_refused(self, tmp_path):
        assert _lines(tmp_path, _GETSTRING_NO_DB, sink_line=4) == []

    def test_socket_getinputstream_gated_on_socket(self, tmp_path):
        got = _lines(tmp_path, _SOCKET, sink_line=6)
        assert [ln for ln, _ in got] == [5]
        assert "socket" in got[0][1]


class TestPropertiesComposition:
    def test_unresolved_getproperty_is_source_candidate(self, tmp_path):
        got = _lines(tmp_path, _PROPS_UNRESOLVED, sink_line=5)
        assert [ln for ln, _ in got] == [4]
        assert "properties" in got[0][1]

    def test_resolved_constant_getproperty_is_not_a_source(self, tmp_path):
        # b22's strict resolver proves the value: single load of one
        # literal resource, literal key present once. Requires the
        # resource on disk next to the source.
        (tmp_path / "app.properties").write_text("crypto.alg=SHA-256\n")
        got = _lines(tmp_path, _PROPS_RESOLVED, sink_line=8)
        assert all("properties" not in kinds for _, kinds in got)


class TestBackCompat:
    def test_servlet_seed_behavior_unchanged(self, tmp_path):
        src = (
            "public class Case {\n"
            "    void doPost(HttpServletRequest request) {\n"
            "        String a = request.getParameter(\"a\");\n"
            "        sink(a);\n"
            "    }\n"
            "}\n"
        )
        f = tmp_path / "Case.java"
        f.write_text(src)
        cache: dict = {}
        assert _candidate_source_lines(f, 4, "java", cache) == [3]

    def test_python_table_unchanged(self, tmp_path):
        f = tmp_path / "case.py"
        f.write_text("a = request.args.get('a')\nsink(a)\n")
        cache: dict = {}
        assert _candidate_source_lines(f, 2, "python", cache) == [1]
