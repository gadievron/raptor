"""Tests for the Maven package-override data file and its loader.

The overrides used to be a dict hardcoded in ``reachability/maven.py``;
they now live in ``packages/sca/data/maven_package_map.json`` (same
pattern as ``python_module_map.json``). These tests pin the migrated
entries and the loader's graceful-degradation behaviour.
"""

from packages.sca.reachability import maven

# Exact contents of the pre-migration hardcoded dict.
_PRE_MIGRATION_OVERRIDES = {
    "com.fasterxml.jackson.core:jackson-databind":
        "com.fasterxml.jackson.databind",
    "com.fasterxml.jackson.core:jackson-core":
        "com.fasterxml.jackson.core",
    "com.fasterxml.jackson.core:jackson-annotations":
        "com.fasterxml.jackson.annotation",
    "com.google.guava:guava": "com.google.common",
    "commons-io:commons-io": "org.apache.commons.io",
    "commons-codec:commons-codec": "org.apache.commons.codec",
    "commons-cli:commons-cli": "org.apache.commons.cli",
    "commons-logging:commons-logging": "org.apache.commons.logging",
    "org.slf4j:slf4j-api": "org.slf4j",
    "ch.qos.logback:logback-classic": "ch.qos.logback.classic",
    "ch.qos.logback:logback-core": "ch.qos.logback.core",
    "org.apache.httpcomponents:httpclient": "org.apache.http",
    "org.apache.httpcomponents.client5:httpclient5":
        "org.apache.hc.client5",
    "org.springframework:spring-jcl": "org.apache.commons.logging",
}


class TestMavenPackageMap:
    def test_data_file_reproduces_pre_migration_overrides(self):
        assert maven._PACKAGE_OVERRIDES == _PRE_MIGRATION_OVERRIDES

    def test_comment_key_is_stripped(self):
        assert not any(k.startswith("_") for k in maven._PACKAGE_OVERRIDES)

    def test_override_wins_in_candidate_prefixes(self):
        prefixes = list(maven._candidate_prefixes("com.google.guava:guava"))
        assert prefixes == ["com.google.common"]

    def test_heuristics_still_fire_without_override(self):
        prefixes = list(
            maven._candidate_prefixes("org.example:example-lib"),
        )
        assert "org.example" in prefixes

    def test_missing_file_degrades_to_empty_map(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            maven, "_PACKAGE_MAP_FILE", tmp_path / "nope.json",
        )
        assert maven._load_package_overrides() == {}

    def test_malformed_file_degrades_to_empty_map(self, monkeypatch, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("[1, 2, 3]", encoding="utf-8")
        monkeypatch.setattr(maven, "_PACKAGE_MAP_FILE", bad)
        assert maven._load_package_overrides() == {}
