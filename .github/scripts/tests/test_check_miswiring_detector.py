"""Detector-correctness tests for the dead-code/miswiring scan.

Two false-positive classes the daily scan produced:

- pytest xunit / unittest module lifecycle hooks (``setup_method``,
  ``setUpModule``, ...) are resolved by name by the test runner and
  never referenced in code — the dead-symbol pass flagged them dead.
- The reference text corpus only covered core/packages/plugins/
  libexec/engine, so symbols invoked from skill instructions
  (``.claude/skills/``), documentation (``docs/``), launcher shims
  (``bin/``), personas (``tiers/``) or CI scripts (``.github/``)
  counted as dead.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "check_miswiring.py"


def _load_detector():
    spec = importlib.util.spec_from_file_location("check_miswiring", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def detector():
    return _load_detector()


def _index(detector, root: Path):
    idx = detector.RepoIndex(root)
    idx.build()
    return idx


def _dead_names(detector, root: Path) -> set[str]:
    idx = _index(detector, root)
    findings, _sup = detector.find_dead(idx)
    return {f["name"] for f in findings}


XUNIT_HOOKS = [
    "setUpModule", "tearDownModule",
    "setup_module", "teardown_module",
    "setup_function", "teardown_function",
]
XUNIT_METHOD_HOOKS = [
    "setup_class", "teardown_class",
    "setup_method", "teardown_method",
]


class TestXunitLifecycleHooks:
    def test_module_level_hooks_not_flagged_dead(self, detector, tmp_path):
        pkg = tmp_path / "core" / "foo" / "tests"
        pkg.mkdir(parents=True)
        body = "\n\n".join(
            f"def {name}():\n    pass" for name in XUNIT_HOOKS
        )
        (pkg / "test_thing.py").write_text(body + "\n", encoding="utf-8")

        dead = _dead_names(detector, tmp_path)
        for name in XUNIT_HOOKS:
            assert name not in dead, (
                f"live pytest lifecycle hook {name} classified dead"
            )

    def test_class_level_hooks_not_flagged_dead(self, detector, tmp_path):
        pkg = tmp_path / "core" / "foo" / "tests"
        pkg.mkdir(parents=True)
        methods = "\n\n".join(
            f"    def {name}(self):\n        pass"
            for name in XUNIT_METHOD_HOOKS
        )
        (pkg / "test_thing.py").write_text(
            "class TestThing:\n" + methods + "\n", encoding="utf-8",
        )

        dead = _dead_names(detector, tmp_path)
        for name in XUNIT_METHOD_HOOKS:
            assert not any(name in d for d in dead), (
                f"live pytest lifecycle hook {name} classified dead"
            )

    def test_genuinely_dead_test_helper_still_flagged(self, detector, tmp_path):
        """The hook allowlist must not blind the scan to real dead code."""
        pkg = tmp_path / "core" / "foo" / "tests"
        pkg.mkdir(parents=True)
        (pkg / "test_thing.py").write_text(
            "def orphan_helper_nobody_calls():\n    pass\n",
            encoding="utf-8",
        )
        assert "orphan_helper_nobody_calls" in _dead_names(detector, tmp_path)


class TestTextCorpusRoots:
    def _repo_with_symbol(self, tmp_path) -> Path:
        pkg = tmp_path / "core" / "api"
        pkg.mkdir(parents=True)
        (pkg / "surface.py").write_text(
            "def skill_invoked_entry():\n    return 1\n", encoding="utf-8",
        )
        return tmp_path

    def test_symbol_without_any_reference_is_dead(self, detector, tmp_path):
        root = self._repo_with_symbol(tmp_path)
        assert "skill_invoked_entry" in _dead_names(detector, root)

    @pytest.mark.parametrize("rel", [
        "docs/architecture.md",
        ".claude/skills/exploit-dev/instructions.md",
        "tiers/personas/researcher.md",
        ".github/scripts/helper_notes.md",
    ])
    def test_reference_from_text_root_keeps_symbol_alive(
        self, detector, tmp_path, rel,
    ):
        root = self._repo_with_symbol(tmp_path)
        doc = root / rel
        doc.parent.mkdir(parents=True, exist_ok=True)
        doc.write_text(
            "Call `skill_invoked_entry()` to load the context.\n",
            encoding="utf-8",
        )
        assert "skill_invoked_entry" not in _dead_names(detector, root)

    def test_bin_shim_reference_keeps_symbol_alive(self, detector, tmp_path):
        root = self._repo_with_symbol(tmp_path)
        shim = root / "bin" / "raptor-helper.sh"
        shim.parent.mkdir(parents=True)
        shim.write_text(
            "python3 -c 'from core.api.surface import skill_invoked_entry'\n",
            encoding="utf-8",
        )
        assert "skill_invoked_entry" not in _dead_names(detector, root)

    def test_text_roots_never_join_python_index(self, detector, tmp_path):
        """A .py under .github is reference text, not indexed code —
        its own defs must not become dead-symbol candidates."""
        root = self._repo_with_symbol(tmp_path)
        ci = root / ".github" / "scripts" / "ci_tool.py"
        ci.parent.mkdir(parents=True)
        ci.write_text(
            "def ci_only_helper():\n    pass\n", encoding="utf-8",
        )
        idx = _index(detector, root)
        assert all(
            ".github" not in m.path.parts for m in idx.module_list
        )
        assert "ci_only_helper" not in _dead_names(detector, root)

    def test_worktrees_under_claude_are_skipped(self, detector, tmp_path):
        root = self._repo_with_symbol(tmp_path)
        wt = root / ".claude" / "worktrees" / "scratch" / "notes.md"
        wt.parent.mkdir(parents=True)
        wt.write_text("skill_invoked_entry\n", encoding="utf-8")
        assert "skill_invoked_entry" in _dead_names(detector, root)


class TestBaselineCorpusExclusion:
    """The baseline file names every baselined symbol; if it joined the
    reference corpus it would self-suppress exactly the findings it
    records, so baselined entries could never fire or go stale again."""

    def _repo_with_dead_symbol(self, tmp_path) -> Path:
        pkg = tmp_path / "core" / "api"
        pkg.mkdir(parents=True)
        (pkg / "surface.py").write_text(
            "def orphaned_entry_nobody_calls():\n    return 1\n",
            encoding="utf-8",
        )
        return tmp_path

    def test_baseline_file_does_not_self_suppress(self, detector, tmp_path):
        root = self._repo_with_dead_symbol(tmp_path)
        bl = root / ".github" / "scripts" / "miswiring_baseline.json"
        bl.parent.mkdir(parents=True)
        bl.write_text(
            '{"entries": {"dead:dead_function:core/api/surface.py:'
            'orphaned_entry_nobody_calls": {"note": "triaged"}}}\n',
            encoding="utf-8",
        )
        assert "orphaned_entry_nobody_calls" in _dead_names(detector, root)

    def test_other_github_text_still_joins_corpus(self, detector, tmp_path):
        """The exclusion is surgical: any other .github text file still
        keeps referenced symbols alive."""
        root = self._repo_with_dead_symbol(tmp_path)
        notes = root / ".github" / "scripts" / "notes.json"
        notes.parent.mkdir(parents=True)
        notes.write_text(
            '{"hint": "call orphaned_entry_nobody_calls on boot"}\n',
            encoding="utf-8",
        )
        assert "orphaned_entry_nobody_calls" not in _dead_names(
            detector, root,
        )

    def test_baseline_mention_does_not_count_as_artifact_reference(
        self, detector, tmp_path,
    ):
        """Artifact names inside the baseline's own keys must not feed
        the artifact occurrence scan."""
        pkg = tmp_path / "core" / "foo"
        pkg.mkdir(parents=True)
        (pkg / "writer.py").write_text(
            "import json\n"
            "\n"
            "\n"
            "def emit(out_dir, rows):\n"
            "    with open(out_dir / 'run-report.json', 'w') as f:\n"
            "        json.dump(rows, f)\n",
            encoding="utf-8",
        )
        bl = tmp_path / ".github" / "scripts" / "miswiring_baseline.json"
        bl.parent.mkdir(parents=True)
        bl.write_text(
            '{"entries": {"artifacts:write_only_artifact::run-report.json":'
            ' {"note": "reader lands later"}}}\n',
            encoding="utf-8",
        )
        idx = _index(detector, tmp_path)
        findings, _sup = detector.find_artifacts(idx)
        assert any(
            f["kind"] == "write_only_artifact"
            and f["name"] == "run-report.json"
            and all("miswiring_baseline" not in m for m in f["mentions"])
            for f in findings
        )


def _plumbing(detector, root: Path):
    idx = _index(detector, root)
    findings, _sup, info = detector.find_plumbing(idx)
    orphans = {f["name"] for f in findings
               if f["kind"] == "orphan_config_field"}
    consumed = {i["name"] for i in info
                if i["kind"] == "config_field_consumed_via_serialization"}
    return orphans, consumed


class TestSerializationAwareConfigFields:
    """A config dataclass whose instances flow through wholesale
    serialization (asdict/vars/fields/json.dump/model_dump/**-unpack)
    has every field consumed by the serializer; those fields must be
    classified consumed-via-serialization, not orphaned."""

    def _write(self, tmp_path, name, body):
        pkg = tmp_path / "core" / "cfg"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / name).write_text(body, encoding="utf-8")
        return tmp_path

    def test_unserialized_config_field_is_still_orphaned(
        self, detector, tmp_path,
    ):
        root = self._write(tmp_path, "plain.py",
            "from dataclasses import dataclass\n"
            "\n"
            "\n"
            "@dataclass\n"
            "class PlainConfig:\n"
            "    unread_knob: int = 0\n"
            "\n"
            "\n"
            "def build():\n"
            "    return PlainConfig()\n",
        )
        orphans, consumed = _plumbing(detector, root)
        assert "PlainConfig.unread_knob" in orphans
        assert not consumed

    def test_asdict_at_call_site_consumes_fields(self, detector, tmp_path):
        root = self._write(tmp_path, "report.py",
            "import json\n"
            "from dataclasses import asdict, dataclass\n"
            "\n"
            "\n"
            "@dataclass\n"
            "class RunReport:\n"
            "    wall_seconds: float = 0.0\n"
            "\n"
            "\n"
            "def emit(out):\n"
            "    report = RunReport()\n"
            "    out.write_text(json.dumps(asdict(report)))\n",
        )
        orphans, consumed = _plumbing(detector, root)
        assert "RunReport.wall_seconds" in consumed
        assert "RunReport.wall_seconds" not in orphans

    def test_asdict_self_method_consumes_fields(self, detector, tmp_path):
        root = self._write(tmp_path, "model.py",
            "from dataclasses import asdict, dataclass\n"
            "\n"
            "\n"
            "@dataclass\n"
            "class StoredModel:\n"
            "    revision_tag: str = ''\n"
            "\n"
            "    def to_payload(self):\n"
            "        return asdict(self)\n",
        )
        orphans, consumed = _plumbing(detector, root)
        assert "StoredModel.revision_tag" in consumed
        assert not orphans

    def test_nested_dataclass_consumed_through_parent(
        self, detector, tmp_path,
    ):
        """asdict() recurses: serializing the parent serializes every
        dataclass-typed field, including through containers."""
        root = self._write(tmp_path, "nested.py",
            "from dataclasses import asdict, dataclass, field\n"
            "from typing import List\n"
            "\n"
            "\n"
            "@dataclass\n"
            "class InnerStat:\n"
            "    peak_rss_kb: int = 0\n"
            "\n"
            "\n"
            "@dataclass\n"
            "class OuterReport:\n"
            "    stats: List[InnerStat] = field(default_factory=list)\n"
            "\n"
            "    def to_payload(self):\n"
            "        return asdict(self)\n",
        )
        orphans, consumed = _plumbing(detector, root)
        assert "InnerStat.peak_rss_kb" in consumed
        assert not orphans

    def test_model_dump_on_annotated_param_consumes_fields(
        self, detector, tmp_path,
    ):
        root = self._write(tmp_path, "pyd.py",
            "class ScanSettings:\n"
            "    retry_budget: int = 3\n"
            "\n"
            "\n"
            "def persist(settings: ScanSettings, out):\n"
            "    out.write_text(str(settings.model_dump()))\n",
        )
        orphans, consumed = _plumbing(detector, root)
        assert "ScanSettings.retry_budget" in consumed
        assert not orphans

    def test_double_star_unpack_consumes_fields(self, detector, tmp_path):
        root = self._write(tmp_path, "unpack.py",
            "from dataclasses import dataclass\n"
            "\n"
            "\n"
            "@dataclass\n"
            "class WriterOpts:\n"
            "    flush_interval: int = 5\n"
            "\n"
            "\n"
            "def run(writer):\n"
            "    opts = WriterOpts()\n"
            "    writer(**opts)\n",
        )
        orphans, consumed = _plumbing(detector, root)
        assert "WriterOpts.flush_interval" in consumed
        assert not orphans

    def test_manual_to_dict_that_drops_field_stays_orphaned(
        self, detector, tmp_path,
    ):
        """A hand-written to_dict with explicit string keys is NOT
        wholesale serialization — a field it omits is genuinely
        unconsumed and must keep firing."""
        root = self._write(tmp_path, "manual.py",
            "from dataclasses import dataclass\n"
            "\n"
            "\n"
            "@dataclass\n"
            "class QueryResult:\n"
            "    query: str = ''\n"
            "    dropped_extra: int = 0\n"
            "\n"
            "    def to_dict(self):\n"
            "        return {'query': self.query}\n"
            "\n"
            "\n"
            "def emit(out):\n"
            "    out.write(str(QueryResult().to_dict()))\n",
        )
        orphans, consumed = _plumbing(detector, root)
        assert "QueryResult.dropped_extra" in orphans
        assert "QueryResult.dropped_extra" not in consumed


def _env_findings(detector, root: Path):
    idx = _index(detector, root)
    findings, _sup, info = detector.find_plumbing(idx)
    orphans = {f["name"] for f in findings if f["kind"] == "orphan_env_var"}
    external = {i["name"] for i in info
                if i["kind"] == "env_var_consumed_externally"}
    return orphans, external


class TestEnvVarConsumptionRealism:
    def test_global_write_never_read_is_orphaned(self, detector, tmp_path):
        pkg = tmp_path / "core" / "boot"
        pkg.mkdir(parents=True)
        (pkg / "setup_env.py").write_text(
            "import os\n"
            "\n"
            "\n"
            "def prime():\n"
            "    os.environ.setdefault('RAPTOR_UNREAD_FLAG', '1')\n",
            encoding="utf-8",
        )
        orphans, external = _env_findings(detector, tmp_path)
        assert "RAPTOR_UNREAD_FLAG" in orphans
        assert "RAPTOR_UNREAD_FLAG" not in external

    def test_test_fixture_write_is_not_production_plumbing(
        self, detector, tmp_path,
    ):
        pkg = tmp_path / "core" / "boot" / "tests"
        pkg.mkdir(parents=True)
        (pkg / "test_env.py").write_text(
            "def test_tool(run):\n"
            "    env = {}\n"
            "    env['TOOL_FIXTURE_DATE'] = '2020-01-01'\n"
            "    run(env)\n",
            encoding="utf-8",
        )
        orphans, external = _env_findings(detector, tmp_path)
        assert "TOOL_FIXTURE_DATE" not in orphans
        assert "TOOL_FIXTURE_DATE" not in external

    def test_embedded_shell_wrapper_read_counts_as_read(
        self, detector, tmp_path,
    ):
        """A bash -c wrapper embedded in Python reads the var the same
        module exports into the child env (the RAPTOR_BO_OUT idiom)."""
        pkg = tmp_path / "core" / "boot"
        pkg.mkdir(parents=True)
        (pkg / "wrapper.py").write_text(
            "def run_captured(cmd, out_path, spawn):\n"
            "    env = {}\n"
            "    env['RAPTOR_WRAP_OUT'] = out_path\n"
            "    wrapper = ['bash', '-c', 'exec \"$@\" > \"$RAPTOR_WRAP_OUT\"']\n"
            "    spawn(wrapper + cmd, env=env)\n",
            encoding="utf-8",
        )
        orphans, external = _env_findings(detector, tmp_path)
        assert "RAPTOR_WRAP_OUT" not in orphans
        assert "RAPTOR_WRAP_OUT" not in external

    def test_child_env_only_write_is_consumed_externally(
        self, detector, tmp_path,
    ):
        pkg = tmp_path / "core" / "boot"
        pkg.mkdir(parents=True)
        (pkg / "spawn_tool.py").write_text(
            "def launch(target, spawn):\n"
            "    env = {}\n"
            "    env['EXT_TOOL_INPUT'] = target\n"
            "    spawn(['ext-tool'], env=env)\n",
            encoding="utf-8",
        )
        orphans, external = _env_findings(detector, tmp_path)
        assert "EXT_TOOL_INPUT" in external
        assert "EXT_TOOL_INPUT" not in orphans


class TestLocatorFunctionIdiom:
    _WRITER = (
        "import json\n"
        "\n"
        "\n"
        "def emit(out_dir, sinks):\n"
        "    with open(out_dir / 'found-sinks.json', 'w') as f:\n"
        "        json.dump(sinks, f)\n"
    )

    def _findings(self, detector, root):
        idx = _index(detector, root)
        findings, _sup = detector.find_artifacts(idx)
        return [f for f in findings if f["name"] == "found-sinks.json"]

    def test_candidate_list_reader_suppresses_write_only(
        self, detector, tmp_path,
    ):
        """The artifact literal only builds a candidate path; the parse
        happens lines below, outside the +/-2 window — the function-level
        strong-read scan must still count it as a reader."""
        pkg = tmp_path / "core" / "foo"
        pkg.mkdir(parents=True)
        (pkg / "writer.py").write_text(self._WRITER, encoding="utf-8")
        (pkg / "locator.py").write_text(
            "import json\n"
            "\n"
            "\n"
            "def find_sinks(run_dir, siblings):\n"
            "    candidates = [run_dir / 'found-sinks.json']\n"
            "    for sib in siblings:\n"
            "        candidates.append(sib / 'found-sinks.json')\n"
            "    for path in candidates:\n"
            "        try:\n"
            "            if not path.is_file():\n"
            "                continue\n"
            "            return json.loads(path.read_text())\n"
            "        except (OSError, ValueError):\n"
            "            continue\n"
            "    return None\n",
            encoding="utf-8",
        )
        assert not self._findings(detector, tmp_path)

    def test_mention_in_non_reading_fn_stays_write_only(
        self, detector, tmp_path,
    ):
        pkg = tmp_path / "core" / "foo"
        pkg.mkdir(parents=True)
        (pkg / "writer.py").write_text(self._WRITER, encoding="utf-8")
        (pkg / "banner.py").write_text(
            "def describe(run_dir):\n"
            "    label = str(run_dir / 'found-sinks.json')\n"
            "    return 'sink catalog at ' + label\n",
            encoding="utf-8",
        )
        found = self._findings(detector, tmp_path)
        assert found and found[0]["kind"] == "write_only_artifact"

    def test_writer_echoing_its_output_path_stays_write_only(
        self, detector, tmp_path,
    ):
        """A writer that prints where it wrote (and reads OTHER files in
        the same function) is not that artifact's reader."""
        pkg = tmp_path / "core" / "foo"
        pkg.mkdir(parents=True)
        (pkg / "writer.py").write_text(
            "import json\n"
            "\n"
            "\n"
            "def validate(manifest, out_dir):\n"
            "    data = json.loads(manifest.read_text())\n"
            "    with open(out_dir / 'found-sinks.json', 'w') as f:\n"
            "        json.dump(data, f)\n"
            "\n"
            "    print('detail: ' + str(out_dir / 'found-sinks.json'))\n",
            encoding="utf-8",
        )
        found = self._findings(detector, tmp_path)
        assert found and found[0]["kind"] == "write_only_artifact"

    def test_mention_in_large_pipeline_fn_stays_write_only(
        self, detector, tmp_path,
    ):
        """A path listing inside a hundreds-of-lines pipeline function
        that reads unrelated files must not count as a reader."""
        pkg = tmp_path / "core" / "foo"
        pkg.mkdir(parents=True)
        (pkg / "writer.py").write_text(self._WRITER, encoding="utf-8")
        filler = "".join(
            f"    step_{i} = {i}\n" for i in range(80)
        )
        (pkg / "pipeline.py").write_text(
            "import json\n"
            "\n"
            "\n"
            "def run_all(out_dir, cfg_path):\n"
            "    cfg = json.loads(cfg_path.read_text())\n"
            + filler +
            "    outputs = [str(out_dir / 'found-sinks.json')]\n"
            "    return cfg, outputs\n",
            encoding="utf-8",
        )
        found = self._findings(detector, tmp_path)
        assert found and found[0]["kind"] == "write_only_artifact"


class TestAtomicWriteIdiom:
    def test_tempfile_rename_writer_is_not_orphan_reader(
        self, detector, tmp_path,
    ):
        """A tempfile-then-rename writer names the artifact only where
        the destination path is built (next to an is_file() guard);
        the +/-2-line window used to classify that as read-only and
        report the artifact as an orphan reader."""
        pkg = tmp_path / "core" / "foo"
        pkg.mkdir(parents=True)
        (pkg / "writer.py").write_text(
            "import json\n"
            "import os\n"
            "import tempfile\n"
            "from pathlib import Path\n"
            "\n"
            "\n"
            "def record(output_dir, rows):\n"
            "    path = output_dir / 'accumulated-rows.json'\n"
            "    existing = []\n"
            "    if path.is_file():\n"
            "        existing = json.loads(path.read_text())\n"
            "    existing.extend(rows)\n"
            "    fd, tmp = tempfile.mkstemp(dir=str(output_dir))\n"
            "    with os.fdopen(fd, 'w') as f:\n"
            "        json.dump(existing, f)\n"
            "    Path(tmp).rename(path)\n",
            encoding="utf-8",
        )
        (pkg / "reader.py").write_text(
            "import json\n"
            "\n"
            "\n"
            "def consume(out_dir):\n"
            "    p = out_dir / 'accumulated-rows.json'\n"
            "    if p.is_file():\n"
            "        return json.loads(p.read_text())\n"
            "    return []\n",
            encoding="utf-8",
        )
        idx = _index(detector, tmp_path)
        findings, _sup = detector.find_artifacts(idx)
        orphans = [
            f for f in findings
            if f["kind"] == "orphan_reader"
            and f["name"] == "accumulated-rows.json"
        ]
        assert not orphans, (
            "tempfile+rename writer misclassified; artifact reported "
            f"as orphan reader: {orphans}"
        )
