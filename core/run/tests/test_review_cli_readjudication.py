"""raptor-review's re-adjudication view: dual queue homes and
per-shape rendering.

The queue has two homes — the run-local file the /validate import
writes and the project-level ``_report`` file the completion hook and
/project report write. The reader must fold both (a sibling-run
contradiction only exists in the latter) and word each record by its
shape: a later claim, an overturned confirmed verdict, or an
intra-run split.
"""

import importlib.util
import io
import json
from contextlib import redirect_stdout
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[3]

QUEUE_NAME = "readjudication-queue.jsonl"


def _load_review_module():
    cli_path = str(REPO_ROOT / "libexec" / "raptor-review")
    loader = SourceFileLoader("raptor_review_cli_readj", cli_path)
    spec = importlib.util.spec_from_loader("raptor_review_cli_readj", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _record(shape=None, claim_status="not_disproven",
            disproof_status="disproven", claim_source="run-old",
            disproof_source="run-new", file="a.c", function="f"):
    rec = {
        "kind": "readjudication",
        "action": "queued",
        "site": {"file": file, "function": function, "line": 3},
        "new_claim": {"source": claim_source, "status": claim_status,
                      "mechanism": ["buffer_overflow"]},
        "disproof": {"source": disproof_source, "status": disproof_status},
        "mechanism_match": True,
    }
    if shape is not None:
        rec["shape"] = shape
    return rec


def _write_queue(path: Path, records: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in records),
                    encoding="utf-8")


def _show(mod, out_dir, project_dir):
    buf = io.StringIO()
    with redirect_stdout(buf):
        mod._show_function(
            "a.c", "f", None, [], {}, None, SimpleNamespace(),
            out_dir=out_dir, project_dir=project_dir,
        )
    return buf.getvalue()


class TestDualQueueHomes:

    def test_project_report_queue_is_read(self, tmp_path):
        mod = _load_review_module()
        proj = tmp_path / "proj"
        run = proj / "run_b"
        run.mkdir(parents=True)
        _write_queue(proj / "_report" / QUEUE_NAME, [_record()])
        records, suppressed = mod._load_readjudication_records(
            run, "a.c", "f", project_dir=proj)
        assert len(records) == 1
        assert suppressed == 0

    def test_both_homes_folded_with_suppressed_sum(self, tmp_path):
        mod = _load_review_module()
        proj = tmp_path / "proj"
        run = proj / "run_b"
        run.mkdir(parents=True)
        _write_queue(run / QUEUE_NAME, [
            _record(),
            {"action": "truncated", "suppressed": 2},
        ])
        _write_queue(proj / "_report" / QUEUE_NAME, [
            _record(shape="disproof_after_confirmed",
                    claim_status="confirmed",
                    disproof_status="ruled_out"),
            {"action": "truncated", "suppressed": 3},
        ])
        records, suppressed = mod._load_readjudication_records(
            run, "a.c", "f", project_dir=proj)
        assert len(records) == 2
        assert suppressed == 5

    def test_missing_homes_tolerated(self, tmp_path):
        mod = _load_review_module()
        records, suppressed = mod._load_readjudication_records(
            tmp_path / "absent", "a.c", "f",
            project_dir=tmp_path / "also-absent")
        assert records == []
        assert suppressed == 0


class TestShapeRendering:

    def test_overturn_record_worded_as_overturn(self, tmp_path):
        mod = _load_review_module()
        run = tmp_path / "run"
        run.mkdir()
        _write_queue(run / QUEUE_NAME, [_record(
            shape="disproof_after_confirmed", claim_status="confirmed",
            disproof_status="ruled_out")])
        out = _show(mod, run, None)
        assert "overturn-shaped" in out
        assert "prior confirmed verdict from run-old" in out
        assert "disproven by later ruled_out from run-new" in out
        assert "nothing auto-overturned" in out

    def test_split_record_worded_as_split(self, tmp_path):
        mod = _load_review_module()
        run = tmp_path / "run"
        run.mkdir()
        _write_queue(run / QUEUE_NAME, [_record(
            shape="intra_run_split", claim_status="confirmed",
            disproof_status="ruled_out", claim_source="run-x",
            disproof_source="run-x")])
        out = _show(mod, run, None)
        assert "intra-run split in run-x" in out
        assert "confirmed and ruled_out both final" in out

    def test_shapeless_record_renders_as_legacy_claim(self, tmp_path):
        # Pre-shape queue files keep their original wording.
        mod = _load_review_module()
        run = tmp_path / "run"
        run.mkdir()
        _write_queue(run / QUEUE_NAME, [_record()])
        out = _show(mod, run, None)
        assert "new buffer_overflow claim from run-old" in out
        assert "overturn-shaped" not in out
        assert "intra-run split" not in out
