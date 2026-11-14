"""Parameter caps must not manufacture truncated route identities."""
import pytest

from core.analysis import route_models as mod


def pattern(names, syntax):
    return "/" + "/".join(("<" + n + ">") if syntax == "angle" else ("{" + n + "}") for n in names)


@pytest.fixture(autouse=True)
def no_graph_work(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("parameter-only test attempted route/graph construction")
    monkeypatch.setattr(mod, "build_route_models", forbidden)
    monkeypatch.setattr(mod, "build_package_callgraph", forbidden)


@pytest.mark.parametrize("syntax", ["angle", "brace"])
def test_oversized_names_drop_without_aliasing_or_hiding_neighbor(syntax):
    prefix = "x" * mod._MAX_PARAM_NAME
    stats = {}
    result = mod._params_from_pattern(pattern([prefix + "a", prefix + "b", "ok"], syntax), syntax, stats)
    assert [p.name for p in result] == ["ok"]
    assert stats == {"params_dropped_cap": 2}


@pytest.mark.parametrize("syntax", ["angle", "brace"])
def test_name_at_cap_is_preserved_whole(syntax):
    name = "x" * mod._MAX_PARAM_NAME
    stats = {}
    assert [p.name for p in mod._params_from_pattern(pattern([name], syntax), syntax, stats)] == [name]
    assert stats == {}


def test_parameter_count_cap_is_unchanged():
    stats = {}
    names = ["p" + str(i) for i in range(mod._MAX_PARAMS + 1)]
    result = mod._params_from_pattern(pattern(names, "angle"), "angle", stats)
    assert [p.name for p in result] == names[:mod._MAX_PARAMS]
    assert stats == {"params_dropped_cap": 1}


def test_bounded_regex_group_behavior_is_unchanged():
    stats = {}
    text = "(?P<" + "x" * (mod._MAX_PARAM_NAME + 1) + ">.*)/(?P<ok>.*)"
    assert [p.name for p in mod._params_from_pattern(text, "regex", stats)] == ["ok"]
