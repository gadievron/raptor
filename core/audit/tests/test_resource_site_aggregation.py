"""Function refutation requires evidence for every accumulation site."""
import pytest

from core.audit import resource_bounds as rb

pytest.importorskip("tree_sitter_c")


def _check(tmp_path, conditions, *, budget_s=None):
    left, right = conditions
    source = ("void grow(void)\n{\n    if (ready) {\n"
              f"        if ({left}) {{\n            list_add(x, y);\n        }}\n"
              "    } else {\n"
              f"        if ({right}) {{\n            list_add(x, y);\n        }}\n"
              "    }\n}\n")
    (tmp_path / "owned.c").write_text(source)
    return rb.run_resource_bounds_check(
        tmp_path, "owned.c", "grow", "the list grows without limit",
        source_texts={"owned.c": source}, budget_s=budget_s,
    )


@pytest.mark.parametrize("reverse", [False, True])
def test_bounded_site_cannot_hide_an_unresolved_sibling(tmp_path, reverse):
    conditions = ["g_session_count < 4", "other_count < incoming_value"]
    if reverse:
        conditions.reverse()
    result = _check(tmp_path, conditions)
    assert result.outcome == "inconclusive", result.reason
    assert rb.REASON_GUARD_UNDECIDED in result.reason
    assert result.bound_search["sites_complete"] is True
    assert {site["outcome"] for site in result.bound_search["site_results"]} == {
        "refuted", "inconclusive",
    }


def test_all_sites_with_local_bounds_can_refute(tmp_path):
    result = _check(tmp_path, ["g_session_count < 4", "other_count < 8"])
    assert result.outcome == "refuted", result.reason
    # Aggregated snapshots must not alias their enclosing receipt.
    import json
    assert json.loads(json.dumps(result.to_dict()))["outcome"] == "refuted"


def test_confirmed_site_remains_existential(tmp_path):
    result = _check(tmp_path, ["g_session_count < 4", "ready"])
    assert result.outcome == "confirmed", result.reason


def test_deadline_after_a_bounded_site_cannot_refute_remaining_sites(tmp_path, monkeypatch):
    from types import SimpleNamespace

    completed = []
    real_adjudicate = rb._adjudicate_site

    def adjudicate(*args, **kwargs):
        result = real_adjudicate(*args, **kwargs)
        completed.append(result.outcome)
        return result

    monkeypatch.setattr(rb, "_adjudicate_site", adjudicate)
    monkeypatch.setattr(rb, "time", SimpleNamespace(monotonic=lambda: 100.0 if completed else 0.0))
    result = _check(tmp_path, ["g_session_count < 4", "ready"], budget_s=10.0)
    assert completed == ["refuted"]
    assert result.outcome == "inconclusive", result.reason
    assert rb.REASON_BUDGET_EXHAUSTED in result.reason
    assert result.bound_search["sites_complete"] is False
    assert [site["outcome"] for site in result.bound_search["site_results"]] == ["refuted"]
