"""Pack-format and loader battery: schema validity, fail-closed
refusals on hostile shapes, the never-load-from-the-target posture,
and the curated-sanitizer additive merge."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from core.taint.packs import (
    DEFAULT_PACKS_DIR,
    MAX_ENTRIES_PER_ROLE,
    MAX_PACK_BYTES,
    MAX_RATIONALE_LEN,
    SCHEMA_VERSION,
    PackLoadError,
    curated_sanitizers,
    default_pack_names,
    load_packs,
)

VALID_PACK = {
    "schema_version": SCHEMA_VERSION,
    "language": "python",
    "framework": "testfw",
    "pack": "valid",
    "sources": [
        {"kind": "call_return", "match": "testfw.read",
         "taint_classes": ["user-input"],
         "provenance": "framework_catalog", "rationale": "test source"},
    ],
    "sinks": [
        {"kind": "dotted_callee", "match": "testfw.run", "args": [0],
         "kwargs": ["cmd"], "sink_class": "command-injection",
         "cwe": "CWE-78", "unless_kwargs": {"shell": "False"},
         "provenance": "framework_catalog", "rationale": "test sink"},
    ],
    "sanitizers": [
        {"kind": "dotted_callee", "match": "testfw.clean",
         "semantics": "kill", "sink_classes": ["command-injection"],
         "provenance": "framework_catalog", "rationale": "test kill"},
    ],
    "propagators": [
        {"kind": "dotted_callee", "match": "testfw.join",
         "flow": [{"from": "Argument[*]", "to": "ReturnValue"}],
         "provenance": "framework_catalog", "rationale": "test propagator"},
    ],
}


def write_pack(tmp_path: Path, data: dict, *, name: str | None = None) -> Path:
    """Write *data* as ``<tmp>/packs/python/<pack>.json``; returns the
    extra-dir root to pass to ``load_packs``."""
    pack_name = name or data.get("pack", "valid")
    pack_dir = tmp_path / "packs" / "python"
    pack_dir.mkdir(parents=True, exist_ok=True)
    (pack_dir / f"{pack_name}.json").write_text(
        json.dumps(data), encoding="utf-8",
    )
    return tmp_path / "packs"


def mutate(**top_level) -> dict:
    data = json.loads(json.dumps(VALID_PACK))
    data.update(top_level)
    return data


def mutate_entry(role: str, index: int, **fields) -> dict:
    data = json.loads(json.dumps(VALID_PACK))
    entry = data[role][index]
    for key, value in fields.items():
        if value is None:
            entry.pop(key, None)
        else:
            entry[key] = value
    return data


def load_one(tmp_path: Path, data: dict) -> object:
    extra = write_pack(tmp_path, data)
    return load_packs([f"python/{data['pack']}"], extra_dirs=[extra])


def refuse(tmp_path: Path, data: dict, fragment: str) -> None:
    extra = write_pack(tmp_path, data)
    with pytest.raises(PackLoadError, match=fragment):
        load_packs([f"python/{data['pack']}"], extra_dirs=[extra])


# ── happy path ───────────────────────────────────────────────────────


def test_valid_pack_loads_typed(tmp_path):
    ps = load_one(tmp_path, VALID_PACK)
    (src,) = ps.sources
    assert src.kind == "call_return" and src.taint_classes == ("user-input",)
    assert src.tier == "pack" and src.pack == "valid" and src.framework == "testfw"
    (sink,) = ps.sinks
    assert sink.args == (0,) and sink.kwargs == ("cmd",)
    assert sink.unless_kwargs == (("shell", "False"),)
    assert sink.confidence == "exact" and sink.cwe == "CWE-78"
    pack_sanitizers = [s for s in ps.sanitizers if s.tier == "pack"]
    (kill,) = pack_sanitizers
    assert kill.semantics == "kill" and not kill.is_wildcard
    (prop,) = ps.propagators
    assert prop.flows[0].src == "Argument[*]" and prop.flows[0].dst == "ReturnValue"
    assert prop.narrowing is False
    assert "command-injection" in ps.taint_class_vocabulary()
    assert "user-input" in ps.taint_class_vocabulary()


def test_shipped_seed_packs_load():
    names = default_pack_names("python")
    assert "python/web-injection-core" in names
    ps = load_packs(names)
    assert ps.sources and ps.sinks and ps.propagators
    assert ps.curated_sanitizers  # merged automatically


def test_narrowing_refused_from_config_dir(tmp_path):
    """Narrowing reduces the propagation floor — reserved for
    review-gated in-tree packs; a config-dir pack may only widen."""
    data = mutate_entry("propagators", 0, narrowing=True)
    refuse(tmp_path, data, "reserved for packs shipped in-tree")


def test_narrowing_legal_in_tree(tmp_path, monkeypatch):
    import core.taint.packs as packs_mod

    data = mutate_entry("propagators", 0, narrowing=True)
    extra = write_pack(tmp_path, data)
    monkeypatch.setattr(packs_mod, "DEFAULT_PACKS_DIR", extra)
    ps = packs_mod.load_packs(["python/valid"])
    assert ps.propagators[0].narrowing is True


def test_stored_taint_kinds_parse(tmp_path):
    data = mutate(
        pack="stored",
        sources=[{
            "kind": "stored_read", "match": "cache.get",
            "store_key": "session-cache", "taint_classes": ["user-input"],
            "provenance": "framework_catalog", "rationale": "stored read",
        }],
        sinks=[{
            "kind": "stored_write", "match": "cache.set", "args": [1],
            "store_key": "session-cache", "sink_class": "stored-taint",
            "cwe": "CWE-501", "provenance": "framework_catalog",
            "rationale": "stored write",
        }],
    )
    ps = load_one(tmp_path, data)
    assert ps.sources[0].store_key == "session-cache"
    assert ps.sinks[0].store_key == "session-cache"


# ── fail-closed schema battery ───────────────────────────────────────


def test_top_level_not_object(tmp_path):
    pack_dir = tmp_path / "packs" / "python"
    pack_dir.mkdir(parents=True)
    (pack_dir / "valid.json").write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(PackLoadError, match="top level must be an object"):
        load_packs(["python/valid"], extra_dirs=[tmp_path / "packs"])


def test_wrong_schema_version(tmp_path):
    refuse(tmp_path, mutate(schema_version=2), "schema_version")


def test_unknown_top_level_key(tmp_path):
    refuse(tmp_path, mutate(extra_key=1), "unknown key")


def test_unknown_entry_key(tmp_path):
    refuse(tmp_path, mutate_entry("sinks", 0, surprise=1), "unknown key")


def test_unknown_language(tmp_path):
    refuse(tmp_path, mutate(language="ruby"), "language")


def test_pack_field_must_match_file_name(tmp_path):
    data = mutate()  # declares pack="valid", written as renamed.json
    extra = write_pack(tmp_path, data, name="renamed")
    with pytest.raises(PackLoadError, match="must equal the file name"):
        load_packs(["python/renamed"], extra_dirs=[extra])


@pytest.mark.parametrize("kind", ["mystery", "", None, 3])
def test_unknown_source_kind(tmp_path, kind):
    refuse(tmp_path, mutate_entry("sources", 0, kind=kind), "kind")


@pytest.mark.parametrize("match", [
    "os.system; rm -rf /",       # shell metachars
    "a..b",                       # empty dotted segment
    "os.system\x1b[31m",          # terminal escape
    "матч.module",                # non-ASCII
    "a-b.c",                      # dash in identifier
    "x" * 300,                    # over the length bound
])
def test_bad_dotted_match_refused(tmp_path, match):
    refuse(tmp_path, mutate_entry("sinks", 0, match=match), "match")


def test_method_name_sink_requires_heuristic_confidence(tmp_path):
    data = mutate_entry(
        "sinks", 0, kind="method_name", match="execute",
        receiver_hint="cursor", confidence="exact",
    )
    refuse(tmp_path, data, "heuristic")


def test_method_name_sink_defaults_heuristic(tmp_path):
    data = mutate_entry(
        "sinks", 0, kind="method_name", match="execute",
        receiver_hint="cursor", confidence=None, unless_kwargs=None,
    )
    ps = load_one(tmp_path, data)
    assert ps.sinks[0].confidence == "heuristic"


def test_method_name_sink_rejects_dotted_match(tmp_path):
    data = mutate_entry("sinks", 0, kind="method_name", match="a.execute",
                        confidence="heuristic")
    refuse(tmp_path, data, "identifier grammar")


def test_receiver_hint_only_on_method_name(tmp_path):
    refuse(tmp_path, mutate_entry("sinks", 0, receiver_hint="cursor"),
           "receiver_hint")


@pytest.mark.parametrize("cwe", [None, "78", "CWE-0", "CWE-", "cwe-78", "CWE-999999"])
def test_sink_cwe_required_and_validated(tmp_path, cwe):
    refuse(tmp_path, mutate_entry("sinks", 0, cwe=cwe), "cwe")


def test_sink_needs_args_or_kwargs(tmp_path):
    refuse(tmp_path, mutate_entry("sinks", 0, args=[], kwargs=[]),
           "at least one")


@pytest.mark.parametrize("args", [[0, 0], [-1], [99], [True], ["0"], "0"])
def test_sink_args_validated(tmp_path, args):
    refuse(tmp_path, mutate_entry("sinks", 0, args=args), "args")


@pytest.mark.parametrize("value", [
    {"shell": False},                 # evaluated boolean, not a literal token
    {"shell": {"nested": 1}},         # nested structure
    {"shell": ""},                    # empty token
    {"shell": "x" * 100},             # over the value bound
    {"shell": "Fal\x00se"},           # control byte
    {"not an ident!": "False"},       # bad key
])
def test_unless_kwargs_literal_token_only(tmp_path, value):
    refuse(tmp_path, mutate_entry("sinks", 0, unless_kwargs=value),
           "unless_kwargs")


def test_wildcard_kill_sanitizer_refused(tmp_path):
    data = mutate_entry("sanitizers", 0, sink_classes=["*"])
    refuse(tmp_path, data, "explicit sink_classes")


def test_wildcard_tag_sanitizer_allowed(tmp_path):
    data = mutate_entry("sanitizers", 0, semantics="tag", sink_classes=["*"])
    ps = load_one(tmp_path, data)
    tags = [s for s in ps.sanitizers if s.tier == "pack"]
    assert tags[0].is_wildcard


def test_wildcard_mixed_with_classes_refused(tmp_path):
    data = mutate_entry("sanitizers", 0, semantics="tag",
                        sink_classes=["*", "xss"])
    refuse(tmp_path, data, "class grammar")


def test_pack_cannot_shadow_curated_sanitizer(tmp_path):
    data = mutate_entry("sanitizers", 0, match="shlex.quote")
    refuse(tmp_path, data, "curated known-safe callee")


def test_bad_access_path_refused(tmp_path):
    data = mutate_entry(
        "propagators", 0,
        flow=[{"from": "Argument[0]); DROP TABLE", "to": "ReturnValue"}],
    )
    refuse(tmp_path, data, "access-path grammar")


def test_flow_edge_shape_enforced(tmp_path):
    data = mutate_entry("propagators", 0, flow=[{"from": "Argument[0]"}])
    refuse(tmp_path, data, "exactly 'from' and 'to'")


def test_narrowing_must_be_boolean(tmp_path):
    refuse(tmp_path, mutate_entry("propagators", 0, narrowing="yes"),
           "narrowing")


@pytest.mark.parametrize("provenance", [None, "llm_prior", "made_up"])
def test_provenance_gate(tmp_path, provenance):
    refuse(tmp_path, mutate_entry("sources", 0, provenance=provenance),
           "provenance")


def test_rationale_required(tmp_path):
    refuse(tmp_path, mutate_entry("sources", 0, rationale=None), "rationale")


def test_rationale_bounded(tmp_path):
    long = "x" * (MAX_RATIONALE_LEN + 1)
    refuse(tmp_path, mutate_entry("sources", 0, rationale=long), "rationale")


def test_rationale_printable_only(tmp_path):
    refuse(tmp_path, mutate_entry("sources", 0, rationale="ok\x1b[2Jbad"),
           "non-printable")


def test_taint_classes_required_and_validated(tmp_path):
    refuse(tmp_path, mutate_entry("sources", 0, taint_classes=[]),
           "taint_classes")
    refuse(tmp_path, mutate_entry("sources", 0, taint_classes=["Bad_Class"]),
           "class grammar")


def test_route_param_takes_no_match(tmp_path):
    data = mutate_entry("sources", 0, kind="route_param", match="flask.request")
    refuse(tmp_path, data, "route_param")


def test_stored_read_requires_store_key(tmp_path):
    data = mutate_entry("sources", 0, kind="stored_read")
    refuse(tmp_path, data, "store_key")


def test_store_key_only_on_stored_kinds(tmp_path):
    refuse(tmp_path, mutate_entry("sources", 0, store_key="cache"),
           "store_key")
    refuse(tmp_path, mutate_entry("sinks", 0, store_key="cache"),
           "store_key")


def test_one_bad_entry_fails_whole_pack(tmp_path):
    """Fail-closed: no partial entry set survives one violation."""
    data = mutate()
    data["sinks"].append({"kind": "dotted_callee"})  # missing everything
    extra = write_pack(tmp_path, data)
    with pytest.raises(PackLoadError):
        load_packs(["python/valid"], extra_dirs=[extra])


def test_error_message_escapes_hostile_bytes(tmp_path):
    data = mutate_entry("sinks", 0, match="evil\x1b]0;pwned\x07")
    extra = write_pack(tmp_path, data)
    with pytest.raises(PackLoadError) as exc_info:
        load_packs(["python/valid"], extra_dirs=[extra])
    message = str(exc_info.value)
    assert "\x1b" not in message and "\x07" not in message
    assert "\\x1b" in message


def test_path_refusal_messages_escape_hostile_bytes(tmp_path):
    """A symlink's TARGET string is chosen by whoever wrote the link;
    the resolve-time refusal messages must render it inertly."""
    hostile = tmp_path / "target" / "x\x1b]0;pwned\x07"
    hostile.mkdir(parents=True)
    (hostile / "p1.json").write_text("{}", encoding="utf-8")
    config = tmp_path / "cfg" / "python"
    config.mkdir(parents=True)
    (config / "p1.json").symlink_to(hostile / "p1.json")
    with pytest.raises(PackLoadError) as exc_info:
        load_packs(["python/p1"], extra_dirs=[tmp_path / "cfg"])
    message = str(exc_info.value)
    assert "\x1b" not in message and "\x07" not in message
    assert "\\x1b" in message


def test_config_dir_refusal_message_escapes_hostile_bytes(tmp_path):
    target = tmp_path / "scan\x1btree"
    extra = target / "packs"
    extra.mkdir(parents=True)
    with pytest.raises(PackLoadError) as exc_info:
        load_packs(["python/valid"], extra_dirs=[extra], target_root=target)
    message = str(exc_info.value)
    assert "\x1b" not in message
    assert "\\x1b" in message


def test_violation_list_bounded(tmp_path):
    data = mutate(sources=[
        {"kind": "call_return", "match": f"bad name {i}",
         "taint_classes": ["user-input"],
         "provenance": "framework_catalog", "rationale": "r"}
        for i in range(60)
    ])
    extra = write_pack(tmp_path, data)
    with pytest.raises(PackLoadError) as exc_info:
        load_packs(["python/valid"], extra_dirs=[extra])
    assert "more violations" in str(exc_info.value)
    assert len(str(exc_info.value)) < 8000


# ── worst-shape pricing ──────────────────────────────────────────────


def test_oversize_pack_refused_fast(tmp_path):
    pack_dir = tmp_path / "packs" / "python"
    pack_dir.mkdir(parents=True)
    blob = '{"schema_version": 1, "pad": "' + "A" * (MAX_PACK_BYTES + 4096) + '"}'
    (pack_dir / "valid.json").write_text(blob, encoding="utf-8")
    start = time.monotonic()
    with pytest.raises(PackLoadError, match="budget"):
        load_packs(["python/valid"], extra_dirs=[tmp_path / "packs"])
    # stat()-gated: the refusal never reads the body, so it is
    # effectively instant; 2s is pure CI-noise headroom.
    assert time.monotonic() - start < 2.0


def test_deeply_nested_pack_refused(tmp_path):
    pack_dir = tmp_path / "packs" / "python"
    pack_dir.mkdir(parents=True)
    depth = 200_000
    (pack_dir / "valid.json").write_text(
        "[" * depth + "]" * depth, encoding="utf-8",
    )
    start = time.monotonic()
    with pytest.raises(PackLoadError):
        load_packs(["python/valid"], extra_dirs=[tmp_path / "packs"])
    assert time.monotonic() - start < 5.0


def test_row_flood_refused(tmp_path):
    entry = {
        "kind": "call_return", "match": "m.f", "taint_classes": ["user-input"],
        "provenance": "framework_catalog", "rationale": "r",
    }
    data = mutate(sources=[dict(entry) for _ in range(MAX_ENTRIES_PER_ROLE + 1)])
    start = time.monotonic()
    refuse(tmp_path, data, "cap")
    assert time.monotonic() - start < 5.0


# ── trust posture: packs never come from the scanned tree ────────────


@pytest.mark.parametrize("name", [
    "../evil", "/etc/passwd", "python/../../evil", "a/b/c",
    "python/evil.json", "python/.hidden", "PYTHON/pack", "py thon/x",
])
def test_pack_name_traversal_spellings_refused(name):
    with pytest.raises(PackLoadError, match="pack name"):
        load_packs([name])


def test_pack_path_inside_scanned_tree_refuses(tmp_path):
    """The pinned posture test: a pack that lives in the target repo
    is never loaded, even when an operator points a config dir at it."""
    target = tmp_path / "scanned-repo"
    write_pack(target, VALID_PACK)  # target ships a "raptor pack"
    with pytest.raises(PackLoadError, match="scanned tree"):
        load_packs(
            ["python/valid"],
            extra_dirs=[target / "packs"],
            target_root=target,
        )


def test_config_dir_outside_target_loads_with_target_root(tmp_path):
    target = tmp_path / "scanned-repo"
    target.mkdir()
    extra = write_pack(tmp_path / "operator-config", VALID_PACK)
    ps = load_packs(
        ["python/valid"], extra_dirs=[extra], target_root=target,
    )
    assert ps.sinks


def test_symlinked_pack_into_target_refuses(tmp_path):
    target = tmp_path / "scanned-repo"
    inner = write_pack(target, VALID_PACK)
    config = tmp_path / "operator-config" / "packs" / "python"
    config.mkdir(parents=True)
    (config / "valid.json").symlink_to(inner / "python" / "valid.json")
    with pytest.raises(PackLoadError, match="refusing"):
        load_packs(
            ["python/valid"],
            extra_dirs=[tmp_path / "operator-config" / "packs"],
            target_root=target,
        )


def test_self_scan_loads_in_tree_packs(tmp_path):
    """Identity exemption: scanning this very checkout must still
    load the shipped packs — the in-tree dir is trusted because it
    ships with the tool, not because of where the scan points."""
    repo_root = Path(__file__).resolve().parents[3]
    ps = load_packs(["python/web-injection-core"], target_root=repo_root)
    assert ps.sinks


def test_self_scan_still_refuses_config_dir_inside_target(tmp_path):
    """The identity exemption never extends to config dirs: an extra
    dir inside the (self-scan) target still refuses."""
    target = tmp_path / "checkout"
    extra = write_pack(target, VALID_PACK)
    with pytest.raises(PackLoadError, match="scanned tree"):
        load_packs(["python/valid"], extra_dirs=[extra], target_root=target)


def test_duplicate_json_keys_refused(tmp_path):
    """Last-wins duplicate keys would let a second spelling of a key
    silently replace the reviewed row — refuse at parse."""
    pack_dir = tmp_path / "packs" / "python"
    pack_dir.mkdir(parents=True)
    body = json.dumps(VALID_PACK)[:-1] + ', "sanitizers": []}'
    (pack_dir / "valid.json").write_text(body, encoding="utf-8")
    with pytest.raises(PackLoadError, match="duplicate JSON key"):
        load_packs(["python/valid"], extra_dirs=[tmp_path / "packs"])


def test_non_finite_json_refused(tmp_path):
    pack_dir = tmp_path / "packs" / "python"
    pack_dir.mkdir(parents=True)
    body = json.dumps(VALID_PACK)[:-1] + ', "schema_version": NaN}'
    (pack_dir / "valid.json").write_text(body, encoding="utf-8")
    with pytest.raises(PackLoadError):
        load_packs(["python/valid"], extra_dirs=[tmp_path / "packs"])


# ── trailing-newline battery ─────────────────────────────────────────
# In Python re, $ also matches just before a trailing newline, so
# "os.system\n" would validate as "os.system" while remaining a
# distinct string — the invisible twin that exact-match joins
# (curated-shadow detection, sink pairing, dedup) treat as different.
# Every grammar-validated field must refuse the trailing-\n form.

NEWLINE_CASES = [
    ("sources", 0, {"match": "testfw.read\n"}),
    ("sources", 0, {"taint_classes": ["user-input\n"]}),
    ("sources", 0, {"kind": "stored_read", "store_key": "cache\n"}),
    ("sources", 0, {"provenance": "framework_catalog\n"}),
    ("sinks", 0, {"match": "testfw.run\n"}),
    ("sinks", 0, {"kind": "method_name", "match": "execute\n",
                  "confidence": "heuristic", "unless_kwargs": None}),
    ("sinks", 0, {"kind": "method_name", "match": "execute",
                  "receiver_hint": "cursor\n",
                  "confidence": "heuristic", "unless_kwargs": None}),
    ("sinks", 0, {"sink_class": "command-injection\n"}),
    ("sinks", 0, {"cwe": "CWE-78\n"}),
    ("sinks", 0, {"kwargs": ["cmd\n"]}),
    ("sinks", 0, {"unless_kwargs": {"shell\n": "False"}}),
    ("sinks", 0, {"unless_kwargs": {"shell": "False\n"}}),
    ("sinks", 0, {"confidence": "exact\n"}),
    ("sanitizers", 0, {"match": "testfw.clean\n"}),
    ("sanitizers", 0, {"semantics": "kill\n"}),
    ("sanitizers", 0, {"sink_classes": ["command-injection\n"]}),
    ("propagators", 0, {"match": "testfw.join\n"}),
    ("propagators", 0, {"flow": [{"from": "Argument[*]",
                                  "to": "ReturnValue\n"}]}),
    ("propagators", 0, {"flow": [{"from": "Argument[*]\n",
                                  "to": "ReturnValue"}]}),
]


@pytest.mark.parametrize("role,index,fields", NEWLINE_CASES)
def test_trailing_newline_fields_refused(tmp_path, role, index, fields):
    extra = write_pack(tmp_path, mutate_entry(role, index, **fields))
    with pytest.raises(PackLoadError):
        load_packs(["python/valid"], extra_dirs=[extra])


@pytest.mark.parametrize("top", [
    {"language": "python\n"}, {"framework": "testfw\n"},
])
def test_trailing_newline_top_level_refused(tmp_path, top):
    refuse(tmp_path, mutate(**top), "top-level")


def test_trailing_newline_pack_name_refused(tmp_path):
    extra = write_pack(tmp_path, VALID_PACK)
    with pytest.raises(PackLoadError, match="pack name"):
        load_packs(["python/valid\n"], extra_dirs=[extra])


def test_newline_twin_cannot_shadow_curated(tmp_path):
    """The concrete attack the anchors close: a kill sanitizer named
    "shlex.quote\\n" — visually identical to the curated entry,
    distinct string — must refuse at the grammar, never load beside
    the curated kill."""
    data = mutate_entry("sanitizers", 0, match="shlex.quote\n")
    extra = write_pack(tmp_path, data)
    with pytest.raises(PackLoadError, match="match"):
        load_packs(["python/valid"], extra_dirs=[extra])


def test_unknown_pack_name_refused():
    with pytest.raises(PackLoadError, match="not found"):
        load_packs(["python/does-not-exist"])


def test_duplicate_pack_name_refused(tmp_path):
    extra = write_pack(tmp_path, VALID_PACK)
    with pytest.raises(PackLoadError, match="twice"):
        load_packs(["python/valid", "python/valid"], extra_dirs=[extra])


# ── curated sanitizer merge ──────────────────────────────────────────


def test_curated_sanitizers_semantics():
    curated = {s.match: s for s in curated_sanitizers("python")}
    assert curated["shlex.quote"].semantics == "kill"
    assert curated["shlex.quote"].sink_classes == ("command-injection",)
    assert curated["html.escape"].semantics == "kill"
    assert curated["html.escape"].sink_classes == ("xss",)
    assert curated["werkzeug.security.safe_join"].sink_classes == (
        "path-traversal",
    )
    for spec in curated.values():
        assert spec.tier == "curated"
        assert spec.rationale  # soundness note carried, bounded
        assert len(spec.rationale) <= MAX_RATIONALE_LEN


def test_curated_merge_is_additive(tmp_path):
    ps = load_one(tmp_path, VALID_PACK)
    matches = [s.match for s in ps.sanitizers]
    assert "shlex.quote" in matches      # curated present
    assert "testfw.clean" in matches     # pack added beside it
    assert len(ps.curated_sanitizers) == len(curated_sanitizers("python"))


def test_default_packs_dir_is_in_tree():
    assert DEFAULT_PACKS_DIR.is_dir()
    repo_root = Path(__file__).resolve().parents[3]
    assert DEFAULT_PACKS_DIR.is_relative_to(repo_root)


def test_default_pack_names_rejects_bad_language():
    assert default_pack_names("../python") == ()
