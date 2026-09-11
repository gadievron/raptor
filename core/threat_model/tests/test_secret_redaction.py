"""Redaction invariant for context-map ``hardcoded_secrets`` entries.

The ``hardcoded_secrets`` schema is unenforced — the producer can put
the literal matched credential value into ``name`` / ``id`` / ``entry``
or a dedicated value field. No string sourced from such an entry may
reach ``render_markdown`` / ``save_model`` / the project threat-model
``sync`` write / the ``export`` print unredacted, while benign labels
(variable names, file paths, line numbers) must stay readable so the
operator can still locate the finding.

Covers all three persistence sinks with the real functions: the
``save_model`` write, and the CLI ``sync`` and ``export`` actions via
``_handle_threat_model``.
"""

import json
from pathlib import Path
from types import SimpleNamespace

from core.json import save_json
from core.threat_model import (
    from_context_map,
    project_threat_model_paths,
    save_model,
)

# Synthetic, obviously-fake credential-shaped values. The token is a
# generic high-entropy shape (mixed case + digits, 40 chars) that
# carries no vendor prefix; the PEM block matches the vendor pattern
# lane. Neither is a real credential.
FAKE_TOKEN = "Xk4FAKEfake2TOKENtoken8NOTrealNOTreal3Qz"
FAKE_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEvQIBADANBFAKEfakeFAKEfakeFAKEfakeFAKE\n"
    "-----END RSA PRIVATE KEY-----"
)


def _project(tmp_path: Path):
    return SimpleNamespace(
        name="redaction-demo",
        target=str(tmp_path / "target"),
        output_dir=str(tmp_path / "out"),
    )


def _hostile_context_map() -> dict:
    return {
        "entry_points": [{"name": "POST /login", "file": "routes.py"}],
        "hardcoded_secrets": [
            # Credential value smuggled into the label field.
            {"name": FAKE_TOKEN, "file": "config/settings.py", "line": 12},
            # PEM material in the ``entry`` fallback label field.
            {"entry": FAKE_PEM, "file": "keys.py", "line": 3},
            # Dedicated value field — dropped wholesale.
            {
                "name": "signing key",
                "value": FAKE_TOKEN,
                "file": "signer.py",
                "line": 9,
            },
            # Benign label — must stay readable.
            {"name": "MASTER_PASSWORD", "file": "auth.py", "line": 7},
            # Long benign dotted label without digits — must stay
            # readable (guards the heuristic against overreach).
            {
                "name": "backend.auth.MasterPasswordProvider",
                "file": "auth.py",
                "line": 21,
            },
        ],
    }


def _assert_clean(text: str) -> None:
    assert FAKE_TOKEN not in text
    assert "MIIEvQIBADANBFAKE" not in text
    # ``_safe_for_render`` swaps ``[`` / ``]`` for lookalikes in
    # markdown output, so match the marker word, not the brackets.
    assert "REDACTED" in text


def _assert_labels_readable(text: str) -> None:
    assert "MASTER_PASSWORD" in text
    assert "backend.auth.MasterPasswordProvider" in text
    assert "auth.py:7" in text
    assert "config/settings.py:12" in text


def test_model_fields_are_redacted_at_source(tmp_path):
    model = from_context_map(_project(tmp_path), _hostile_context_map())

    all_fields = "\n".join(
        model.focus_areas
        + model.known_bug_shapes
        + [str(t.get("title")) for t in model.threats]
    )
    _assert_clean(all_fields)
    _assert_labels_readable(all_fields)


def test_save_model_sink_writes_no_credential_material(tmp_path):
    project = _project(tmp_path)
    model = from_context_map(project, _hostile_context_map())
    json_path, md_path = project_threat_model_paths(project)

    save_model(model, json_path, md_path)

    md_text = md_path.read_text(encoding="utf-8")
    json_text = json_path.read_text(encoding="utf-8")
    for text in (md_text, json_text):
        _assert_clean(text)
    _assert_labels_readable(md_text)


def _setup_project_with_hostile_model(tmp_path):
    """ProjectManager + project whose threat model was initialised from
    a hostile context-map through the real CLI init action."""
    from core.project.cli import _handle_threat_model
    from core.project.project import ProjectManager

    proj_dir = tmp_path / "projects"
    proj_dir.mkdir()
    mgr = ProjectManager(projects_dir=proj_dir)
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    project = mgr.create(
        name="redaction-cli",
        target=str(tmp_path / "target"),
        output_dir=str(out_dir),
    )
    save_json(proj_dir / "redaction-cli.json", project.to_dict())

    cmap_path = tmp_path / "context-map.json"
    cmap_path.write_text(
        json.dumps(_hostile_context_map()), encoding="utf-8"
    )
    args = SimpleNamespace(
        action="init",
        name="redaction-cli",
        field=None,
        value=None,
        from_context_map=str(cmap_path),
        context_map=None,
        json_out=False,
    )
    _handle_threat_model(mgr, args)
    json_path = out_dir / "threat-model.json"
    md_path = out_dir / "THREAT_MODEL.md"
    assert json_path.exists() and md_path.exists()
    return mgr, json_path, md_path


def test_cli_sync_sink_writes_no_credential_material(tmp_path, capsys):
    from core.project.cli import _handle_threat_model

    mgr, json_path, md_path = _setup_project_with_hostile_model(tmp_path)
    md_path.write_text("stale", encoding="utf-8")

    args = SimpleNamespace(
        action="sync",
        name="redaction-cli",
        field=None,
        value=None,
        from_context_map=None,
        context_map=None,
        json_out=False,
    )
    _handle_threat_model(mgr, args)
    capsys.readouterr()

    md_text = md_path.read_text(encoding="utf-8")
    assert md_text != "stale"
    _assert_clean(md_text)
    _assert_labels_readable(md_text)


def test_cli_export_sink_prints_no_credential_material(tmp_path, capsys):
    from core.project.cli import _handle_threat_model

    mgr, json_path, md_path = _setup_project_with_hostile_model(tmp_path)
    capsys.readouterr()

    args = SimpleNamespace(
        action="export",
        name="redaction-cli",
        field=None,
        value=None,
        from_context_map=None,
        context_map=None,
        json_out=False,
    )
    _handle_threat_model(mgr, args)

    out = capsys.readouterr().out
    _assert_clean(out)
    _assert_labels_readable(out)


def test_string_entries_and_nested_values_are_redacted(tmp_path):
    """Producers sometimes emit bare strings or nest evidence lists."""
    model = from_context_map(_project(tmp_path), {
        "hardcoded_secrets": [
            f"api token {FAKE_TOKEN} in client.py",
            {
                "name": "nested",
                "file": "deep.py",
                "line": 4,
                "details": {"token": FAKE_TOKEN, "note": FAKE_PEM},
            },
        ],
    })
    dumped = json.dumps(model.to_dict())
    _assert_clean(dumped)


def test_improvised_secret_value_keys_dropped_but_label_keys_kept(tmp_path):
    """Keys mentioning the material (``secret_value``, camel-case
    variants) are dropped wholesale even when the value is too short
    for the shape heuristics; label-ish keys (``secret_type``) stay."""
    from core.threat_model import _sanitise_hardcoded_literal_entry

    entry = {
        "name": "db password",
        "secret_value": "hunter2short",
        "secretValue": "hunter2short",
        "secret_type": "postgres-dsn-password",
        "file": "db.py",
        "line": 5,
    }
    redacted = _sanitise_hardcoded_literal_entry(entry)
    assert redacted["secret_value"] == "[REDACTED]"
    assert redacted["secretValue"] == "[REDACTED]"
    assert redacted["secret_type"] == "postgres-dsn-password"
    assert redacted["name"] == "db password"
    assert redacted["file"] == "db.py"

    model = from_context_map(_project(tmp_path), {
        "hardcoded_secrets": [entry],
    })
    dumped = json.dumps(model.to_dict())
    assert "hunter2short" not in dumped


def test_label_glued_hex_and_single_case_secrets_redacted():
    from core.threat_model import _redact_free_text
    # Hex glued to a label survives no more (search, not fullmatch)...
    glued = "key_" + "3f2a" * 10
    assert "3f2a" not in _redact_free_text(glued)
    # ...and long separator-free single-case blobs with digits go too.
    upper_secret = "QK7" + "ZR4TXW" * 4
    assert upper_secret not in _redact_free_text(f"token {upper_secret}")


def test_identifier_labels_survive_redaction():
    from core.threat_model import _redact_free_text
    # Two-direction guard: separator-carrying identifiers are labels,
    # not secret material — file:line triage depends on them.
    for label in ("SHA256_DIGEST_LENGTH", "MASTER_PASSWORD_SETTING",
                  "config.v2.some_key_name", "getApiKeyFromEnvOrFile"):
        assert label in _redact_free_text(f"see {label} usage"), label


def test_context_map_ingestion_clips_oversized_fields(tmp_path):
    from core.threat_model import _MAX_STRING_BYTES, from_context_map
    project = SimpleNamespace(name="p", target="/t", output_dir=str(tmp_path))
    huge = "B" * 100_000
    model = from_context_map(project, {
        "entry_points": [{"id": "EP-1", "name": "POST /x"}],
        "sinks": [{"id": "S-1", "name": "exec"}],
        "unchecked_flows": [{
            "entry_point": "EP-1", "sink": "S-1",
            "missing_boundary": huge, "severity": "high",
        }],
    })
    flow = model.data_flows[0]
    assert len(flow["boundary"]) <= _MAX_STRING_BYTES + 16
    assert huge not in json.dumps(model.to_dict())


def test_from_dict_caps_nested_dict_fields():
    from core.threat_model import _MAX_STRING_BYTES, ThreatModel
    huge = "C" * 100_000
    model = ThreatModel.from_dict({
        "project_name": "p", "target": "/t",
        "threats": [{
            "id": "T-1", "title": "t",
            "metadata": {"nested": {"blob": huge}},
            "listy": [{"inner": huge}],
        }],
    })
    dumped = json.dumps(model.to_dict())
    assert huge not in dumped
    assert len(dumped) < 3 * _MAX_STRING_BYTES + 4096
