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

    def test_stage_scans_repo_under_skip_named_parent(self, tmp_path):
        # Skip names apply BELOW the repo root only: a checkout under
        # a parent dir named build/ (or target/, ...) must still be
        # scanned — the absolute-path check silently skipped every
        # file for such repos.
        repo = tmp_path / "build" / "checkout"
        repo.mkdir(parents=True)
        (repo / "app.properties").write_text("hashAlg=MD5\n")
        (repo / "H.java").write_text(_src("app.properties", '"hashAlg"'))
        inner = repo / "target"
        inner.mkdir()
        (inner / "Copy.java").write_text(
            _src("app.properties", '"hashAlg"'))
        out = tmp_path / "outdir"
        out.mkdir()
        path, stats = run_config_resolved_stage(repo, out)
        doc = json.loads(path.read_text())
        assert len(doc["runs"][0]["results"]) == 1  # target/ still skipped
        assert stats["emitted"] == 1

    def test_stage_skip_set_matches_resolver(self, tmp_path):
        # The walk shares the resolver's _SKIP_DIR_PARTS: a vendored
        # copy under in-repo out/ or dist/ must be invisible to BOTH
        # the source walk and locate(), never scanned-as-source with
        # its properties file unresolvable (the drift the old inline
        # 4-name tuple allowed).
        repo = tmp_path / "checkout"
        repo.mkdir()
        (repo / "app.properties").write_text("hashAlg=MD5\n")
        (repo / "H.java").write_text(_src("app.properties", '"hashAlg"'))
        for name in ("out", "dist"):
            inner = repo / name
            inner.mkdir()
            (inner / "Copy.java").write_text(
                _src("app.properties", '"hashAlg"'))
        out = tmp_path / "outdir"
        out.mkdir()
        path, stats = run_config_resolved_stage(repo, out)
        doc = json.loads(path.read_text())
        assert len(doc["runs"][0]["results"]) == 1
        assert stats["emitted"] == 1


def test_unreadable_java_is_disclosed_without_losing_readable_findings(tmp_path, monkeypatch):
    from core.analysis import config_resolved_findings as stage
    from core.sarif.parser import generate_scan_metrics

    denied = []
    read = stage.read_contained_bytes

    def deny_owned_source(root, candidate, limit):
        if candidate.name == 'Denied.java':
            denied.append(candidate.name)
            return None
        return read(root, candidate, limit)

    monkeypatch.setattr(stage, 'read_contained_bytes', deny_owned_source)
    repo = tmp_path / 'repo'
    repo.mkdir()
    (repo / 'app.properties').write_text('hashAlg=MD5\n')
    (repo / 'H.java').write_text(_src('app.properties', '"hashAlg"'))
    (repo / 'Denied.java').write_text('class Denied {}')
    out = tmp_path / 'out'
    out.mkdir()
    path, stats = run_config_resolved_stage(repo, out)
    assert denied == ['Denied.java']
    assert path is not None and stats['emitted'] == 1
    assert stats.get('files_unreadable') == 1
    document = json.loads(path.read_text())
    assert len(document['runs'][0]['results']) == 1
    metrics = generate_scan_metrics([str(path)])
    assert metrics['tool_coverage_limitations'] == {'raptor-config-resolved': 1}
    assert metrics['tool_execution_failures'] == {}


@pytest.mark.parametrize('file_count, capped', [(0, False), (1, False), (2, True)])
def test_stage_cap_discloses_only_actual_omissions(tmp_path, monkeypatch, file_count, capped):
    from core.analysis import config_resolved_findings as stage
    from core.sarif.parser import generate_scan_metrics

    monkeypatch.setattr(stage, '_FILE_CAP', 1)
    repo, out = tmp_path / 'repo', tmp_path / 'out'
    repo.mkdir(); out.mkdir()
    for index in range(file_count):
        (repo / f'Source{index}.java').write_text(f'class Source{index} {{}}')
    # Skipped build artefacts do not turn a fully examined selection partial.
    (repo / 'target').mkdir()
    (repo / 'target' / 'Ignored.java').write_text('class Ignored {}')
    path, stats = run_config_resolved_stage(repo, out)
    assert path is not None
    assert bool(stats.get('file_cap_hit')) is capped
    metrics = generate_scan_metrics([str(path)])
    assert metrics['tool_coverage_limitations'] == ({'raptor-config-resolved': 1} if capped else {})
    assert metrics['tool_execution_failures'] == {}


@pytest.mark.parametrize('escaped', ['source', 'properties'])
def test_stage_refuses_outside_symlinks(tmp_path, escaped):
    repo, out, external = tmp_path / 'repo', tmp_path / 'out', tmp_path / 'external'
    repo.mkdir(); out.mkdir(); external.mkdir()
    source = _src('app.properties', '"hashAlg"')
    for name, text, kind in [('H.java', source, 'source'), ('app.properties', 'hashAlg=MD5\n', 'properties')]:
        if escaped == kind:
            (external / name).write_text(text)
            (repo / name).symlink_to(external / name)
        else:
            (repo / name).write_text(text)
    path, stats = run_config_resolved_stage(repo, out)
    assert path is not None
    assert json.loads(path.read_text())['runs'][0]['results'] == [], (escaped, stats)
    assert stats.get('files_unreadable' if escaped == 'source' else 'resolver:grammar_unsupported') == 1


@pytest.mark.parametrize('linked', ['source', 'properties'])
def test_stage_preserves_in_root_symlinks(tmp_path, linked):
    repo, out = tmp_path / 'repo', tmp_path / 'out'
    repo.mkdir(); out.mkdir()
    for name, text, kind in [('H.java', _src('app.properties', '"hashAlg"'), 'source'),
                             ('app.properties', 'hashAlg=MD5\n', 'properties')]:
        if linked == kind:
            backing = repo / (kind + '.txt')
            backing.write_text(text)
            (repo / name).symlink_to(backing)
        else:
            (repo / name).write_text(text)
    path, stats = run_config_resolved_stage(repo, out)
    assert path is not None and stats['emitted'] == 1
    assert len(json.loads(path.read_text())['runs'][0]['results']) == 1


@pytest.mark.parametrize('delta', [0, -1])
def test_stage_requires_complete_source_within_byte_budget(tmp_path, monkeypatch, delta):
    from core.analysis import config_resolved_findings as stage
    from core.sarif.parser import generate_scan_metrics

    repo, out = tmp_path / 'repo', tmp_path / 'out'
    repo.mkdir(); out.mkdir()
    source = _src('app.properties', '"hashAlg"')
    (repo / 'H.java').write_text(source)
    (repo / 'app.properties').write_text('hashAlg=MD5\n')
    monkeypatch.setattr(stage, '_MAX_SOURCE_BYTES', len(source.encode()) + delta)
    path, stats = run_config_resolved_stage(repo, out)
    assert path is not None
    assert len(json.loads(path.read_text())['runs'][0]['results']) == (1 if delta == 0 else 0)
    assert stats.get('files_oversized', 0) == (0 if delta == 0 else 1)
    assert generate_scan_metrics([str(path)])['tool_coverage_limitations'] == (
        {} if delta == 0 else {'raptor-config-resolved': 1})


def test_stage_preserves_relative_repository_inputs(tmp_path, monkeypatch):
    repo, out = tmp_path / 'repo', tmp_path / 'out'
    repo.mkdir(); out.mkdir()
    (repo / 'H.java').write_text(_src('app.properties', '"hashAlg"'))
    (repo / 'app.properties').write_text('hashAlg=MD5\n')
    monkeypatch.chdir(tmp_path)
    path, stats = run_config_resolved_stage(type(tmp_path)('repo'), type(tmp_path)('out'))
    assert path is not None and stats.get('emitted') == 1
    assert len(json.loads(path.read_text())['runs'][0]['results']) == 1


@pytest.mark.parametrize('selector, algorithm, reports', [
    ('MessageDigest', 'MD5', True), ('MessageDigest', 'md5', True),
    ('MessageDigest', 'MD5/extra', False), ('MessageDigest', 'MD5 ', False),
    ('java.security.SecureRandom', 'SHA1PRNG', True),
    ('java.security.SecureRandom', 'SHA1PRNG/extra', False),
    ('java.security.SecureRandom', 'SHA1PRNG ', False),
    ('javax.crypto.Cipher', 'DES/ECB/PKCS5Padding', True),
    ('javax.crypto.Cipher', ' DES / ECB / PKCS5Padding ', True),
])
def test_selector_normalisation_matches_api_family(tmp_path, selector, algorithm, reports):
    (tmp_path / 'app.properties').write_text('hashAlg=' + algorithm + '\n')
    source = _src('app.properties', '"hashAlg"').replace(
        'MessageDigest.getInstance', selector + '.getInstance').replace(
        'MessageDigest md = ', 'Object configured = ')
    findings, stats = _scan(tmp_path, source)
    assert stats['resolver:resolved'] == 1
    assert bool(findings) is reports, (selector, algorithm, findings)


def test_reader_literal_cannot_bind_a_bundled_algorithm_file(tmp_path):
    (tmp_path / 'app.properties').write_text('hashAlg=MD5\n')
    src = _src('app.properties', '"hashAlg"')
    start = src.index('props.load(')
    end = src.index(';', start)
    src = src[:start] + 'props.load(new java.io.StringReader("app.properties"))' + src[end:]
    findings, stats = _scan(tmp_path, src)
    assert findings == []
    assert stats['resolver:dynamic_resource'] == 1


def test_custom_properties_receiver_cannot_establish_a_weak_selector(tmp_path):
    (tmp_path / 'app.properties').write_text('hashAlg=MD5\n')
    source = _src('app.properties', '"hashAlg"').replace('new Properties()', 'new CustomProperties()')
    source = source.replace('public class H {', '''public class H {
        static class CustomProperties extends java.util.Properties {
            @Override public String getProperty(String key) { return "SHA-256"; }
        }
''')
    findings, stats = _scan(tmp_path, source)
    assert findings == []
    assert stats['resolver:receiver_not_local'] == 1
