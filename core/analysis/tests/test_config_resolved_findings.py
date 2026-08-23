"""Additive config-resolved finding channel tests (wave b22)."""

from __future__ import annotations

import json
from collections import Counter

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.config_resolved_findings import (  # noqa: E402
    run_config_resolved_stage,
    scan_java_source,
    to_sarif,
)

_SRC = """\
import java.util.Properties;
import java.security.MessageDigest;
public class H {
    public void hash() throws Exception {
        Properties props = new Properties();
        props.load(getClass().getClassLoader()
            .getResourceAsStream("app.properties"));
        String algorithm = props.getProperty(@ARGS@);
        MessageDigest md = MessageDigest.getInstance(algorithm);
    }
}
"""

def _src(res: str, args: str, template: str = _SRC) -> str:
    return template.replace("@RES@", res).replace("@ARGS@", args)


def _scan(tmp_path, src: str):
    java = tmp_path / "H.java"
    java.write_text(src, encoding="utf-8")
    stats: Counter = Counter()
    return scan_java_source(
        src, str(java), str(tmp_path), stats), stats


class TestEmission:
    def test_weak_file_value_emits(self, tmp_path):
        (tmp_path / "app.properties").write_text("hashAlg=MD5\n")
        findings, stats = _scan(tmp_path, _src("app.properties", '"hashAlg"'))
        assert len(findings) == 1
        f = findings[0]
        assert f["rule_id"] == "raptor.config-resolved.weak-hash"
        assert f["cwe"] == "cwe-328"
        assert stats["emitted"] == 1

    def test_md2_file_value_emits(self, tmp_path):
        # Cross-surface consistency: MD2 is in the channel's weak set
        # and in the semgrep java rule — both must fire on it.
        (tmp_path / "app.properties").write_text("hashAlg=MD2\n")
        findings, stats = _scan(tmp_path, _src("app.properties", '"hashAlg"'))
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "raptor.config-resolved.weak-hash"
        assert stats["emitted"] == 1

    def test_weak_file_value_with_safe_default_emits(self, tmp_path):
        # The runtime value is the FILE value whenever the named
        # resource loads — a safe call-site default must not mask it.
        (tmp_path / "app.properties").write_text("hashAlg=MD5\n")
        findings, _ = _scan(
            tmp_path, _src("app.properties", '"hashAlg", "SHA-512"'))
        assert len(findings) == 1
        assert "default exists" in findings[0]["message"]

    def test_safe_file_value_silent(self, tmp_path):
        (tmp_path / "app.properties").write_text("hashAlg=SHA-256\n")
        findings, stats = _scan(tmp_path, _src("app.properties", '"hashAlg"'))
        assert findings == []
        assert stats["resolved_safe"] == 1

    def test_weak_default_with_missing_key_silent(self, tmp_path):
        # Runtime WOULD fall back to the weak default only when the
        # key is absent, but the resolver refuses key_missing and the
        # channel never guesses past a refusal.
        (tmp_path / "app.properties").write_text("other=x\n")
        findings, stats = _scan(
            tmp_path, _src("app.properties", '"hashAlg", "MD5"'))
        assert findings == []
        assert stats["resolver:key_missing"] == 1

    def test_literal_argument_out_of_scope(self, tmp_path):
        src = ("import java.security.MessageDigest;\n"
               "public class H { void m() throws Exception {\n"
               '    MessageDigest.getInstance("MD5");\n'
               "} }\n")
        findings, stats = _scan(tmp_path, src)
        assert findings == []
        assert stats["skipped_literal_arg"] == 1

    def test_multi_def_argument_silent(self, tmp_path):
        (tmp_path / "app.properties").write_text("hashAlg=MD5\n")
        src = _src("app.properties", '"hashAlg"').replace(
            "MessageDigest md",
            'algorithm = "SHA-256";\n        MessageDigest md')
        findings, stats = _scan(tmp_path, src)
        assert findings == []
        assert stats["skipped_multi_def"] == 1

    def test_cipher_transformation_head_matches(self, tmp_path):
        (tmp_path / "app.properties").write_text(
            "cAlg=DES/ECB/PKCS5Padding\n")
        src = _src("app.properties", '"cAlg"').replace(
            "MessageDigest.getInstance",
            "javax.crypto.Cipher.getInstance").replace(
            "MessageDigest md = ", "Object c = ")
        findings, _ = _scan(tmp_path, src)
        assert len(findings) == 1
        assert findings[0]["cwe"] == "cwe-327"


class TestSarifAndStage:
    def test_sarif_shape_carries_cwe_tag(self, tmp_path):
        doc = to_sarif([{
            "rule_id": "raptor.config-resolved.weak-hash",
            "cwe": "cwe-328", "file": str(tmp_path / "H.java"),
            "line": 9, "message": "m",
        }], str(tmp_path))
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert "external/cwe/cwe-328" in rule["properties"]["tags"]
        res = doc["runs"][0]["results"][0]
        assert res["properties"]["provenance"] == "config-resolved"
        assert res["locations"][0]["physicalLocation"][
            "artifactLocation"]["uri"] == "H.java"

    def test_stage_writes_sarif_even_when_empty(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "A.java").write_text("public class A {}")
        out = tmp_path / "out"
        out.mkdir()
        path, stats = run_config_resolved_stage(repo, out)
        assert path is not None and path.exists()
        doc = json.loads(path.read_text())
        assert doc["runs"][0]["results"] == []

    def test_stage_end_to_end_emits(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.properties").write_text("hashAlg=MD5\n")
        (repo / "H.java").write_text(_src("app.properties", '"hashAlg"'))
        out = tmp_path / "out"
        out.mkdir()
        path, stats = run_config_resolved_stage(repo, out)
        doc = json.loads(path.read_text())
        assert len(doc["runs"][0]["results"]) == 1
        assert stats["emitted"] == 1
