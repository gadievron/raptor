"""study-prep --bridge-seed-file: bridge_seed tier below operator
identifiers, no scope widening, seed_source provenance in the list."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType

_PREP_PATH = (Path(__file__).resolve().parents[3]
              / "libexec" / "raptor-study-prep")


def _load_prep() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader(
        "raptor_study_prep_bridge", str(_PREP_PATH))
    spec = importlib.util.spec_from_file_location(
        "raptor_study_prep_bridge", str(_PREP_PATH), loader=loader,
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


prep = _load_prep()


def _run_prep(args: list[str]) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["_RAPTOR_TRUSTED"] = "1"
    return subprocess.run(  # noqa: PLW1510 - callers assert on returncode
        [sys.executable, str(_PREP_PATH)] + args,
        env=env, capture_output=True, text=True, timeout=120,
    )


def _make_tree(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "parse.c").write_text(
        "int parse_hdr(char *buf) { return buf[0]; }\n"
        "int parse_body(char *buf) { return buf[1]; }\n",
        encoding="utf-8",
    )
    (repo / "other.c").write_text(
        "int unrelated_fn(void) { return 3; }\n"
        "int helper_fn(void) { return 4; }\n",
        encoding="utf-8",
    )
    return repo


def _write_bridge_file(tmp_path: Path, names: list[str],
                       concepts: list[str] | None = None) -> Path:
    path = tmp_path / "bridge-seeds.json"
    path.write_text(json.dumps({
        "schema_version": 1,
        "generated_by": "binary_study_bridge",
        "seeds": [
            {"name": n, "seed_source": "bridge_seed",
             "origin": "parser_boundary", "why": "w",
             "derived_from_target": True}
            for n in names
        ],
        "concepts": [
            {"text": c, "derived_from_target": True}
            for c in (concepts or [])
        ],
    }), encoding="utf-8")
    return path


def _items(out_dir: Path) -> list[dict]:
    data = json.loads(
        (out_dir / "study-list.json").read_text(encoding="utf-8"))
    return data["items"]


class TestLoadBridgeSeeds:
    def test_charset_and_caps_reenforced(self, tmp_path: Path) -> None:
        from core.orchestration.binary_study_bridge import (
            MAX_BRIDGE_SEEDS,
        )
        # A pre-staged file must not smuggle junk names or exceed
        # the caps the bridge itself promises.
        many = [f"fn_{i}" for i in range(MAX_BRIDGE_SEEDS + 10)]
        path = _write_bridge_file(
            tmp_path, ["good_fn", "bad name;rm", "-flag", *many])
        names, _concepts = prep._load_bridge_seeds(path)
        assert "good_fn" in names
        assert "bad name;rm" not in names
        assert "-flag" not in names
        assert len(names) <= MAX_BRIDGE_SEEDS

    def test_concepts_are_enveloped(self, tmp_path: Path) -> None:
        path = _write_bridge_file(
            tmp_path, ["fn_a"], concepts=["## FOCUS injection"])
        _names, concepts = prep._load_bridge_seeds(path)
        assert concepts
        # neutralize_tag_forgery breaks the markdown heading so a
        # target-derived concept cannot forge a prompt section.
        assert not concepts[0].startswith("## ")

    def test_wrong_shape_ignored(self, tmp_path: Path) -> None:
        path = tmp_path / "bridge-seeds.json"
        path.write_text(json.dumps({"seeds": []}), encoding="utf-8")
        assert prep._load_bridge_seeds(path) == ([], [])

    def test_missing_file_ignored(self, tmp_path: Path) -> None:
        assert prep._load_bridge_seeds(
            tmp_path / "nope.json") == ([], [])


class TestBridgeSeedTier:
    def test_bridge_seeds_prioritize_without_filtering(
            self, tmp_path: Path) -> None:
        repo = _make_tree(tmp_path)
        bridge = _write_bridge_file(tmp_path, ["parse_hdr"])
        out = tmp_path / "out"
        result = _run_prep([
            str(repo), str(out), "--root", str(repo),
            "--bridge-seed-file", str(bridge),
        ])
        assert result.returncode == 0, result.stderr
        items = _items(out)
        by_name = {it["name"]: it for it in items}
        seeded = by_name["parse_hdr"]
        assert seeded["seed_source"] == "bridge_seed"
        assert seeded["relevance_tier"] == 1  # below operator tier 0
        # Anti-monopoly: the bridge prioritizes, it never filters —
        # unmatched items stay in the study.
        assert "unrelated_fn" in by_name
        assert by_name["unrelated_fn"]["seed_source"] == ""
        # Bridge seeds lead the list (priority ordering).
        assert items[0]["name"] == "parse_hdr"
        # Provenance recorded on the list itself.
        data = json.loads(
            (out / "study-list.json").read_text(encoding="utf-8"))
        assert data["bridge_seed_file"] == str(bridge)

    def test_operator_scope_wins_over_bridge(
            self, tmp_path: Path) -> None:
        repo = _make_tree(tmp_path)
        # Bridge asks for something outside the operator's scope AND
        # something inside it.
        bridge = _write_bridge_file(
            tmp_path, ["unrelated_fn", "parse_hdr"])
        out = tmp_path / "out"
        result = _run_prep([
            str(repo), str(out), "--root", str(repo),
            "--identifier", "parse_hdr",
            "--bridge-seed-file", str(bridge),
        ])
        assert result.returncode == 0, result.stderr
        by_name = {it["name"]: it for it in _items(out)}
        # Operator's own seed keeps operator provenance and tier 0.
        assert by_name["parse_hdr"]["seed_source"] == "operator"
        assert by_name["parse_hdr"]["relevance_tier"] == 0
        # The out-of-scope bridge name must NOT be pulled in — the
        # bridge never widens an operator-scoped study.
        assert ("unrelated_fn" not in by_name
                or (by_name["unrelated_fn"]["relevance_tier"] or 0) >= 2)

    def test_in_scope_bridge_match_is_annotation_only(
            self, tmp_path: Path) -> None:
        repo = _make_tree(tmp_path)
        bridge = _write_bridge_file(tmp_path, ["parse_body"])
        out = tmp_path / "out"
        result = _run_prep([
            str(repo), str(out), "--root", str(repo),
            "--identifier", "parse_hdr,parse_body",
            "--bridge-seed-file", str(bridge),
        ])
        assert result.returncode == 0, result.stderr
        by_name = {it["name"]: it for it in _items(out)}
        # Operator asked for it too — operator provenance outranks
        # the bridge's corroboration.
        assert by_name["parse_body"]["seed_source"] == "operator"

    def test_scope_fingerprint_includes_bridge_file(self) -> None:
        import argparse
        base = argparse.Namespace(
            identifier=None, concept=None, correlate=None,
            narrow=False, redb=None, reading_list=None,
            bridge_seed_file=None,
        )
        bridged = argparse.Namespace(**{
            **vars(base), "bridge_seed_file": "/tmp/x.json"})
        assert (prep._scope_fingerprint(base)
                != prep._scope_fingerprint(bridged))

    def test_scope_fingerprint_tracks_bridge_content(
            self, tmp_path: Path) -> None:
        """Same path, regenerated content — the stamp must change,
        or a direct prep re-user serves a stale cached study-list
        against fresh seeds."""
        import argparse
        path = tmp_path / "bridge-seeds.json"
        ns = argparse.Namespace(
            identifier=None, concept=None, correlate=None,
            narrow=False, redb=None, reading_list=None,
            bridge_seed_file=str(path),
        )
        path.write_text('{"seeds": [{"name": "a"}]}', encoding="utf-8")
        first = prep._scope_fingerprint(ns)
        path.write_text('{"seeds": [{"name": "b"}]}', encoding="utf-8")
        second = prep._scope_fingerprint(ns)
        assert first != second


class TestOperatorStampProvenance:
    def test_reading_list_names_never_earn_operator(
            self, tmp_path: Path) -> None:
        """Reading-list identifiers are LLM-authored — they drive
        scoping (tier 0) but must NOT launder into operator rows
        (which are exempt from the joint accounting)."""
        repo = _make_tree(tmp_path)
        rl = tmp_path / "reading-list.json"
        rl.write_text(json.dumps({"items": [{
            "id": "q1", "question": "What bounds parse_body?",
            "source_command": "/audit",
            "source_function": "parse_body",
        }]}), encoding="utf-8")
        out = tmp_path / "out"
        result = _run_prep([
            str(repo), str(out), "--root", str(repo),
            "--reading-list", str(rl),
        ])
        assert result.returncode == 0, result.stderr
        by_name = {it["name"]: it for it in _items(out)}
        assert by_name["parse_body"]["seed_source"] == ""
        # Still scoped/focused by the reading list — provenance is
        # the only thing withheld.
        assert by_name["parse_body"]["relevance_tier"] == 0

    def test_correlate_names_earn_operator(self, tmp_path: Path) -> None:
        # --correlate arguments are literal operator-typed names —
        # stamp-eligible exactly like --identifier.
        repo = _make_tree(tmp_path)
        out = tmp_path / "out"
        result = _run_prep([
            str(repo), str(out), "--root", str(repo),
            "--identifier", "parse_hdr",
            "--correlate", "parse_body+parse_hdr",
        ])
        assert result.returncode == 0, result.stderr
        by_name = {it["name"]: it for it in _items(out)}
        assert by_name["parse_body"]["seed_source"] == "operator"
