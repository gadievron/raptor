r"""The analyst is shown the \n-counted finding lines, byte-for-byte.

SARIF startLine/endLine (semgrep, CodeQL) count \n only, while
str.splitlines() also breaks on \v \f \x1c \x1d \x1e \x85 \u2028
\u2029 — bytes an attacker can plant in a string literal or comment
without changing program semantics.  A splitlines() view therefore
handed the LLM attacker-substituted code for the finding: the block
the exploitability verdict is rendered on contained no sink at all.
"""

from __future__ import annotations

from pathlib import Path

from packages.llm_analysis.agent import VulnerabilityContext

# \n model:
#  1  const char *P = "a\x0c\x0cb";        <- two FFs in a string literal
#  2  void safe_log(const char *m) {
#  3      puts(m);
#  4  }
#  5  void handle(char *dst, const char *src) {
#  6      strcpy(dst, src);                <- the finding
#  7  }
_SRC = (
    'const char *P = "a\x0c\x0cb";\n'
    "void safe_log(const char *m) {\n"
    "    puts(m);\n"
    "}\n"
    "void handle(char *dst, const char *src) {\n"
    "    strcpy(dst, src);\n"
    "}\n"
)


def _context(tmp_path: Path) -> VulnerabilityContext:
    (tmp_path / "vuln.c").write_bytes(_SRC.encode())
    finding = {
        "finding_id": "lm-1", "rule_id": "insecure-strcpy",
        "file": "vuln.c", "startLine": 6, "endLine": 6,
        "message": "strcpy into fixed buffer", "tool": "semgrep",
    }
    return VulnerabilityContext(finding, tmp_path)


class TestReadVulnerableCode:
    def test_full_code_is_the_flagged_line(self, tmp_path: Path):
        ctx = _context(tmp_path)
        assert ctx.read_vulnerable_code()
        assert ctx.full_code == "    strcpy(dst, src);"

    def test_surrounding_context_contains_the_sink(self, tmp_path: Path):
        ctx = _context(tmp_path)
        assert ctx.read_vulnerable_code()
        assert "strcpy(dst, src);" in ctx.surrounding_context

    def test_clean_twin_unchanged(self, tmp_path: Path):
        # Differential guard: on \n-only text the slice is identical
        # to the historical behaviour (modulo line-terminator join).
        (tmp_path / "vuln.c").write_bytes(
            b"int a;\nint b;\nstrcpy(d, s);\nint c;\n")
        ctx = VulnerabilityContext(
            {"finding_id": "lm-2", "rule_id": "r", "file": "vuln.c",
             "startLine": 3, "endLine": 3, "message": "m",
             "tool": "semgrep"},
            tmp_path,
        )
        assert ctx.read_vulnerable_code()
        assert ctx.full_code == "strcpy(d, s);"


class TestReadCodeAtLocation:
    def test_marker_lands_on_the_reported_line(self, tmp_path: Path):
        ctx = _context(tmp_path)
        out = ctx._read_code_at_location("vuln.c", 6, context_lines=1)
        marked = [ln for ln in out.split("\n") if ln.startswith(">>>")]
        assert len(marked) == 1
        assert "strcpy(dst, src);" in marked[0]
        assert "   6" in marked[0]


class TestBareCarriageReturn:
    def test_full_code_immune_to_bare_cr(self, tmp_path: Path):
        # semgrep/CodeQL keep a bare \r inside the line — so must the
        # read + split chain that renders the finding's code block.
        (tmp_path / "vuln.c").write_bytes(
            _SRC.replace("\x0c\x0c", "\r\r").encode())
        ctx = VulnerabilityContext(
            {"finding_id": "lm-3", "rule_id": "insecure-strcpy",
             "file": "vuln.c", "startLine": 6, "endLine": 6,
             "message": "m", "tool": "semgrep"},
            tmp_path,
        )
        assert ctx.read_vulnerable_code()
        assert ctx.full_code == "    strcpy(dst, src);"
