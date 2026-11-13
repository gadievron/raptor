"""Keep conversion and emission refusals in learned-model summaries."""

from types import SimpleNamespace

import pytest

from core.config import RaptorConfig
from core.dataflow.extension_pack import ConversionResult, ModelRow, RejectedRow
from packages.codeql.agent import CodeQLAgent


@pytest.mark.parametrize("conversion_count,emission_count", [(2, 1), (0, 0)])
def test_summary_counts_both_rejection_stages(
    tmp_path, monkeypatch, conversion_count, emission_count,
):
    query_root = tmp_path / "queries"
    (query_root / "cpp").mkdir(parents=True)
    monkeypatch.setattr(RaptorConfig, "CODEQL_QUERIES_DIR", query_root)
    monkeypatch.setattr(RaptorConfig, "CODEQL_LEARNED_MODELS_ENABLED", True)
    specs = [object()]
    monkeypatch.setattr("core.iris.api.load_project_specs", lambda **kwargs: specs)
    conversion = ConversionResult(
        rows=tuple(
            ModelRow(role="source", provenance="annotation", name=f"source_{i}")
            for i in range(emission_count + 1)
        ),
        rejected=tuple(RejectedRow(str(i), "conversion refusal") for i in range(conversion_count)),
    )

    def convert(actual_specs, *, language):
        assert actual_specs is specs
        assert language == "cpp"
        return conversion

    monkeypatch.setattr("core.dataflow.extension_pack.rows_from_taint_specs", convert)
    calls = []

    def measure(database, queries, rows, **kwargs):
        assert database == tmp_path / "owned-db-name"
        assert queries == [str(query_root / "cpp")]
        assert rows is conversion.rows
        calls.append(rows)
        return SimpleNamespace(
            pack=SimpleNamespace(
                rows_written=1,
                rejected=tuple(RejectedRow(str(i), "emission refusal") for i in range(emission_count)),
            ),
            diff=SimpleNamespace(new_ids=(), suppressed_ids=(), baseline_count=1, augmented_count=1),
        )

    monkeypatch.setattr("core.dataflow.codeql_augmented_run.run_learned_models_measurement", measure)
    agent = SimpleNamespace(repo_path=tmp_path, out_dir=tmp_path / "out")
    summary = CodeQLAgent._run_learned_models_pass(agent, {"cpp": tmp_path / "owned-db-name"})
    assert calls == [conversion.rows]
    assert summary["cpp"]["rows_written"] == 1
    assert summary["cpp"]["rows_rejected"] == conversion_count + emission_count
    assert summary["cpp"]["baseline_count"] == summary["cpp"]["augmented_count"] == 1
    assert summary["cpp"]["candidates"] == 0
